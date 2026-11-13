"""Rewrite synthetic TCP streams of the plaintext (``-p``) pcap to their real tuples.

Option 5 pins every fd-less TLS connection to a synthetic ``198.18.0.0/15``
tuple while capturing (see :mod:`friTap.endpoint_pinner`). When a real tuple
was learned for that connection later on, this module switches its stream to
the real tuple once the capture has stopped -- but only where that is safe:

* a real tuple was learned for the connection, **and**
* no other stream in the file (and no stream rewritten before it) already
  uses that real 4-tuple, in either orientation.

A conflict keeps the stream synthetic: merging two sequence spaces onto one
tuple would break Wireshark's TCP / HTTP/2 reassembly. Without a real tuple
the stream also stays synthetic.

Each matching packet is re-encoded through the IP/TCP builders the writers use
(:mod:`friTap.sinks.tcp_state`), keeping the original timestamp, seq, ack,
flags, window and payload; a real IPv6 tuple turns the packet into IPv6. The
rewritten packets get valid IPv4 header and TCP checksums.

Both containers ``-p`` writes are supported: classic pcap and pcapng, each
with ``LINKTYPE_RAW`` packets. The file is rewritten atomically (a temp file
next to it, then :func:`os.replace`); on any error the original is kept and the
returned summary carries an ``error`` entry.
"""

from __future__ import annotations

import logging
import os
import shutil
import struct
import tempfile
from dataclasses import dataclass
from functools import partial
from typing import BinaryIO, Callable, Dict, Iterable, Iterator, List, Optional, Tuple

from ._fs_util import remove_quietly
from .output.pcapng_blocks import (
    BT_EPB,
    BT_IDB,
    BT_SHB,
    LINKTYPE_RAW,
    build_block,
    pad4,
)
from .pcap_utility import PCAP_MAGIC_TO_ENDIAN
from .sinks.tcp_state import (
    InvalidEndpointError,
    build_ipv4_tcp_packet,
    build_ipv6_tcp_packet,
    ipv4_address_int,
    ipv6_address_bytes,
)

_LOGGER = logging.getLogger("friTap.pcap_tuple_rewrite")

ACTION_REWRITTEN = "rewritten"
ACTION_KEPT_SYNTHETIC = "kept_synthetic"
ACTION_CONFLICT = "conflict"
ACTION_NOT_IN_PCAP = "not_in_pcap"

_TCP_PROTOCOL = 6
_TCP_MIN_HEADER = 20
_IPV4_HEADER = 20
_IPV6_HEADER = 40

# Synthetic pins live in 198.18.0.0/15: first octet 198, second 18 or 19.
_SYNTHETIC_FIRST_OCTET = 198
_SYNTHETIC_SECOND_OCTET = 18
_SYNTHETIC_SECOND_OCTET_MASK = 0xFE
_PCAPNG_SHB_TYPE = struct.pack("<I", BT_SHB)  # a palindrome: same in both orders
_PCAPNG_BOM_LITTLE = b"\x4d\x3c\x2b\x1a"


class PcapRewriteError(Exception):
    """The capture cannot be rewritten (unknown container, truncated record...)."""


# --- Endpoints and streams --------------------------------------------------

@dataclass(frozen=True)
class Endpoint:
    """One side of a TCP stream: packed IP (4 or 16 bytes) and port."""
    ip: bytes
    port: int


StreamKey = frozenset  # frozenset({Endpoint, Endpoint}): orientation-free


def stream_key(a: Endpoint, b: Endpoint) -> StreamKey:
    return frozenset((a, b))


@dataclass(frozen=True)
class TcpPacket:
    """The fields of a RAW IP/TCP packet the rewrite preserves."""
    src: Endpoint
    dst: Endpoint
    seq: int
    ack: int
    control: bytes      # data offset + flags (2 bytes)
    window: bytes       # 2 bytes
    urgent: bytes       # 2 bytes
    payload: bytes


@dataclass(frozen=True)
class _TcpLayout:
    """Where the addresses and the TCP segment sit inside a RAW IP packet."""
    ip_size: int        # 4 or 16
    src_at: int
    dst_at: int
    tcp_start: int
    tcp_end: int        # end of the segment, clipped to the captured bytes


def _ipv4_tcp_layout(packet: bytes) -> Optional[_TcpLayout]:
    header_len = (packet[0] & 0x0F) * 4
    if packet[9] != _TCP_PROTOCOL or header_len < _IPV4_HEADER:
        return None
    total_len = struct.unpack_from(">H", packet, 2)[0]
    return _TcpLayout(4, 12, 16, header_len, min(total_len, len(packet)))


def _ipv6_tcp_layout(packet: bytes) -> Optional[_TcpLayout]:
    if packet[6] != _TCP_PROTOCOL:
        return None
    payload_len = struct.unpack_from(">H", packet, 4)[0]
    return _TcpLayout(16, 8, 24, _IPV6_HEADER, min(_IPV6_HEADER + payload_len, len(packet)))


def _tcp_layout(packet: Optional[bytes]) -> Optional[_TcpLayout]:
    """The layout of a plain IP/TCP *packet* with a whole TCP header, else ``None``."""
    if not packet or len(packet) < _IPV4_HEADER:
        return None
    version = packet[0] >> 4
    if version == 4:
        layout = _ipv4_tcp_layout(packet)
    elif version == 6 and len(packet) >= _IPV6_HEADER:
        layout = _ipv6_tcp_layout(packet)
    else:
        return None
    if layout is None or layout.tcp_end - layout.tcp_start < _TCP_MIN_HEADER:
        return None
    return layout


def _endpoints_at(packet: bytes, layout: _TcpLayout) -> Tuple[Endpoint, Endpoint]:
    """(src, dst) of *packet*, ports read in place with ``struct.unpack_from``."""
    sport, dport = struct.unpack_from(">HH", packet, layout.tcp_start)
    size = layout.ip_size
    return (Endpoint(packet[layout.src_at:layout.src_at + size], sport),
            Endpoint(packet[layout.dst_at:layout.dst_at + size], dport))


def read_stream_key(packet: Optional[bytes]) -> Optional["StreamKey"]:
    """The orientation-free 4-tuple of a plain IP/TCP *packet* (no payload copy)."""
    layout = _tcp_layout(packet)
    return stream_key(*_endpoints_at(packet, layout)) if layout else None


def _is_synthetic_ipv4_at(packet: bytes, offset: int) -> bool:
    return (packet[offset] == _SYNTHETIC_FIRST_OCTET
            and packet[offset + 1] & _SYNTHETIC_SECOND_OCTET_MASK == _SYNTHETIC_SECOND_OCTET)


def has_synthetic_ipv4_endpoint(packet: Optional[bytes]) -> bool:
    """Raw-byte prefilter: an IPv4 *packet* whose src or dst is in 198.18.0.0/15.

    Synthetic pins are always IPv4, so only such packets can need a rewrite.
    """
    return (bool(packet) and len(packet) >= _IPV4_HEADER and packet[0] >> 4 == 4
            and (_is_synthetic_ipv4_at(packet, 12) or _is_synthetic_ipv4_at(packet, 16)))


def parse_tcp_packet(packet: Optional[bytes]) -> Optional[TcpPacket]:
    """*packet* as a :class:`TcpPacket`, or ``None`` when it is not plain IP/TCP."""
    layout = _tcp_layout(packet)
    if layout is None:
        return None
    src, dst = _endpoints_at(packet, layout)
    start = layout.tcp_start
    seq, ack = struct.unpack_from(">II", packet, start + 4)
    data_offset = (packet[start + 12] >> 4) * 4
    return TcpPacket(src, dst, seq, ack, packet[start + 12:start + 14],
                     packet[start + 14:start + 16], packet[start + 18:start + 20],
                     packet[start + data_offset:layout.tcp_end])


# --- Checksums ----------------------------------------------------------------

def _ones_complement_sum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f">{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return total


def internet_checksum(data: bytes) -> int:
    """RFC 1071 checksum of *data*."""
    return ~_ones_complement_sum(data) & 0xFFFF


def _tcp_pseudo_header(src_ip: bytes, dst_ip: bytes, tcp_length: int) -> bytes:
    if len(src_ip) == 4:
        return src_ip + dst_ip + struct.pack(">BBH", 0, _TCP_PROTOCOL, tcp_length)
    return src_ip + dst_ip + struct.pack(">IxxxB", tcp_length, _TCP_PROTOCOL)


def with_checksums(packet: bytes, src_ip: bytes, dst_ip: bytes) -> bytes:
    """*packet* (as built, zero checksums) with IPv4 header and TCP checksums set."""
    buf = bytearray(packet)
    ip_len = _IPV4_HEADER if len(src_ip) == 4 else _IPV6_HEADER
    if ip_len == _IPV4_HEADER:
        struct.pack_into(">H", buf, 10, internet_checksum(bytes(buf[:ip_len])))
    segment = bytes(buf[ip_len:])
    pseudo = _tcp_pseudo_header(src_ip, dst_ip, len(segment))
    struct.pack_into(">H", buf, ip_len + 16, internet_checksum(pseudo + segment))
    return bytes(buf)


# --- Re-encoding --------------------------------------------------------------

def _build_tcp_packet(src: Endpoint, dst: Endpoint, tcp: TcpPacket) -> bytes:
    if len(src.ip) == 4:
        return build_ipv4_tcp_packet(int.from_bytes(src.ip, "big"), src.port,
                                     int.from_bytes(dst.ip, "big"), dst.port,
                                     tcp.seq, tcp.ack, tcp.payload)
    return build_ipv6_tcp_packet(src.ip.hex(), src.port, dst.ip.hex(), dst.port,
                                 tcp.seq, tcp.ack, tcp.payload)


def reencode_tcp_packet(tcp: TcpPacket, src: Endpoint, dst: Endpoint) -> bytes:
    """*tcp* re-addressed to *src* -> *dst*, keeping seq/ack/flags/window/payload."""
    if len(tcp.control) != 2 or (tcp.control[0] >> 4) * 4 != _TCP_MIN_HEADER:
        raise PcapRewriteError("TCP options are not supported by the rewrite")
    buf = bytearray(_build_tcp_packet(src, dst, tcp))
    tcp_start = _IPV4_HEADER if len(src.ip) == 4 else _IPV6_HEADER
    buf[tcp_start + 12:tcp_start + 14] = tcp.control
    buf[tcp_start + 14:tcp_start + 16] = tcp.window
    buf[tcp_start + 18:tcp_start + 20] = tcp.urgent
    return with_checksums(bytes(buf), src.ip, dst.ip)


@dataclass(frozen=True)
class StreamRewrite:
    """Maps each synthetic endpoint of one stream to its real counterpart."""
    endpoint_map: Dict[Endpoint, Endpoint]

    def apply(self, tcp: TcpPacket) -> bytes:
        return reencode_tcp_packet(tcp, self.endpoint_map[tcp.src],
                                   self.endpoint_map[tcp.dst])


# --- Containers ---------------------------------------------------------------

@dataclass(frozen=True)
class CaptureRecord:
    """One record of the capture: its exact bytes, and its RAW IP packet if any."""
    raw: bytes
    packet: Optional[bytes] = None
    encode: Optional[Callable[[bytes], bytes]] = None


def _read_exact(fh: BinaryIO, size: int) -> bytes:
    data = fh.read(size)
    if len(data) != size:
        raise PcapRewriteError("truncated capture record")
    return data


def _classic_record_bytes(endian: str, ts_sec: int, ts_frac: int, packet: bytes) -> bytes:
    return struct.pack(endian + "IIII", ts_sec, ts_frac, len(packet), len(packet)) + packet


def _classic_records(fh: BinaryIO, endian: str, header: bytes) -> Iterator[CaptureRecord]:
    linktype = struct.unpack(endian + "I", header[20:24])[0] & 0x0FFFFFFF
    yield CaptureRecord(header)
    while True:
        record_header = fh.read(16)
        if not record_header:
            return
        if len(record_header) != 16:
            raise PcapRewriteError("truncated pcap record header")
        ts_sec, ts_frac, incl_len, orig_len = struct.unpack(endian + "IIII", record_header)
        data = _read_exact(fh, incl_len)
        is_whole_raw = linktype == LINKTYPE_RAW and incl_len == orig_len
        yield CaptureRecord(record_header + data, data if is_whole_raw else None,
                            partial(_classic_record_bytes, endian, ts_sec, ts_frac))


def _pcapng_epb_bytes(endian: str, interface: int, ts_high: int, ts_low: int,
                      options: bytes, packet: bytes) -> bytes:
    padding = b"\x00" * (pad4(len(packet)) - len(packet))
    body = (struct.pack(endian + "IIIII", interface, ts_high, ts_low, len(packet), len(packet))
            + packet + padding + options)
    return build_block(BT_EPB, body, endian)


def _read_pcapng_block(fh: BinaryIO, endian: str) -> Optional[Tuple[bytes, str]]:
    """The next block's bytes and the (possibly new) section byte order."""
    block_type = fh.read(4)
    if not block_type:
        return None
    if len(block_type) != 4:
        raise PcapRewriteError("truncated pcapng block")
    if block_type == _PCAPNG_SHB_TYPE:
        length_and_bom = _read_exact(fh, 8)
        endian = "<" if length_and_bom[4:8] == _PCAPNG_BOM_LITTLE else ">"
        head = block_type + length_and_bom
    else:
        head = block_type + _read_exact(fh, 4)
    length = struct.unpack(endian + "I", head[4:8])[0]
    if length < len(head) + 4 or length % 4:
        raise PcapRewriteError("malformed pcapng block length")
    return head + _read_exact(fh, length - len(head)), endian


def _pcapng_epb_record(block: bytes, endian: str, raw_interfaces: List[bool]) -> CaptureRecord:
    interface, ts_high, ts_low, cap_len, orig_len = struct.unpack(endian + "IIIII", block[8:28])
    data = block[28:28 + cap_len]
    options = block[28 + pad4(cap_len):-4]
    is_raw = interface < len(raw_interfaces) and raw_interfaces[interface]
    packet = data if is_raw and cap_len == orig_len else None
    return CaptureRecord(block, packet,
                         partial(_pcapng_epb_bytes, endian, interface, ts_high, ts_low, options))


def _pcapng_records(fh: BinaryIO) -> Iterator[CaptureRecord]:
    endian, raw_interfaces = "<", []
    while True:
        read = _read_pcapng_block(fh, endian)
        if read is None:
            return
        block, endian = read
        block_type = struct.unpack(endian + "I", block[:4])[0]
        if block_type == BT_SHB:
            raw_interfaces = []
        elif block_type == BT_IDB:
            raw_interfaces.append(struct.unpack(endian + "H", block[8:10])[0] == LINKTYPE_RAW)
        elif block_type == BT_EPB:
            yield _pcapng_epb_record(block, endian, raw_interfaces)
            continue
        yield CaptureRecord(block)


def iter_capture_records(fh: BinaryIO) -> Iterator[CaptureRecord]:
    """Every record of a classic pcap or pcapng file, in file order."""
    magic = fh.read(4)
    if magic == _PCAPNG_SHB_TYPE:
        fh.seek(0)
        return _pcapng_records(fh)
    endian = PCAP_MAGIC_TO_ENDIAN.get(magic)
    if endian is None:
        raise PcapRewriteError("not a pcap or pcapng file")
    return _classic_records(fh, endian, magic + _read_exact(fh, 20))


# --- Planning -----------------------------------------------------------------

def _pinned_endpoint(pinned, ss_family: str) -> Optional[Endpoint]:
    """A pinner :class:`~friTap.endpoint_pinner.PinnedEndpoint` as an :class:`Endpoint`."""
    try:
        if ss_family == "AF_INET6":
            ip = ipv6_address_bytes(pinned.raw)
        else:
            ip = ipv4_address_int(pinned.raw).to_bytes(4, "big")
    except (InvalidEndpointError, OverflowError):
        return None
    return Endpoint(ip, int(pinned.port))


def _pair_endpoints(pair) -> Optional[Tuple[Endpoint, Endpoint]]:
    """(client, server) of an :class:`~friTap.endpoint_pinner.EndpointPair`."""
    if pair is None:
        return None
    client = _pinned_endpoint(pair.client, pair.ss_family)
    server = _pinned_endpoint(pair.server, pair.ss_family)
    return (client, server) if client and server else None


def _pair_json(pair) -> Optional[dict]:
    if pair is None:
        return None
    return {"client_addr": pair.client.addr, "client_port": pair.client.port,
            "server_addr": pair.server.addr, "server_port": pair.server.port,
            "ss_family": pair.ss_family}


@dataclass
class RewritePlan:
    """Per-mapping actions and the rewrites to apply, keyed by synthetic stream."""
    actions: List[Tuple[object, str]]
    rewrites: Dict[StreamKey, StreamRewrite]


def _decide(entry, file_streams: set, claimed: set) -> Tuple[str, Optional[StreamRewrite]]:
    """The action for one mapping row: without a real tuple it is always
    ``kept_synthetic`` (whether or not its stream is in the file), so the
    result does not depend on whether the file was scanned at all."""
    synthetic = _pair_endpoints(entry.synthetic)
    if synthetic is None:
        return ACTION_NOT_IN_PCAP, None
    real = _pair_endpoints(entry.real)
    if real is None:
        return ACTION_KEPT_SYNTHETIC, None
    if stream_key(*synthetic) not in file_streams:
        return ACTION_NOT_IN_PCAP, None
    real_key = stream_key(*real)
    if real_key in file_streams or real_key in claimed:
        return ACTION_CONFLICT, None
    claimed.add(real_key)
    return ACTION_REWRITTEN, StreamRewrite({synthetic[0]: real[0], synthetic[1]: real[1]})


def plan_rewrites(mappings: Iterable, file_streams: set) -> RewritePlan:
    """Decide, in pin order, which synthetic streams switch to their real tuple."""
    plan, claimed = RewritePlan([], {}), set()
    for entry in mappings:
        action, rewrite = _decide(entry, file_streams, claimed)
        plan.actions.append((entry, action))
        if rewrite is not None:
            plan.rewrites[stream_key(*rewrite.endpoint_map)] = rewrite
        elif action == ACTION_CONFLICT:
            _LOGGER.info("synthetic stream of client_random %s... kept: its real tuple "
                         "is already used by another stream", entry.client_random[:16])
    return plan


def collect_stream_keys(path: str) -> set:
    """The orientation-free 4-tuples of every TCP stream in the capture."""
    keys = set()
    with open(path, "rb") as fh:
        for record in iter_capture_records(fh):
            key = read_stream_key(record.packet)
            if key is not None:
                keys.add(key)
    return keys


def _has_rewritable_mapping(mappings: List) -> bool:
    """Whether any row has a usable real tuple (else no stream can be rewritten)."""
    return any(_pair_endpoints(entry.real) is not None for entry in mappings)


# --- Rewriting ----------------------------------------------------------------

def _rewritten_record(record: CaptureRecord, rewrites: Dict[StreamKey, StreamRewrite]) -> bytes:
    if not has_synthetic_ipv4_endpoint(record.packet):
        return record.raw
    tcp = parse_tcp_packet(record.packet)
    rewrite = rewrites.get(stream_key(tcp.src, tcp.dst)) if tcp else None
    if rewrite is None:
        return record.raw
    return record.encode(rewrite.apply(tcp))


def _write_rewritten_copy(path: str, temp_path: str,
                          rewrites: Dict[StreamKey, StreamRewrite]) -> None:
    with open(path, "rb") as source, open(temp_path, "wb") as target:
        for record in iter_capture_records(source):
            target.write(_rewritten_record(record, rewrites))


def rewrite_file_atomically(path: str, rewrites: Dict[StreamKey, StreamRewrite]) -> None:
    """Rewrite *path* through a temp file in its directory; the original survives errors."""
    directory = os.path.dirname(os.path.abspath(path))
    fd, temp_path = tempfile.mkstemp(prefix=f".{os.path.basename(path)}.",
                                     suffix=".rewrite", dir=directory)
    os.close(fd)
    try:
        _write_rewritten_copy(path, temp_path, rewrites)
        shutil.copymode(path, temp_path)
        os.replace(temp_path, path)
    except BaseException:
        remove_quietly(temp_path)
        raise


# --- Summary ------------------------------------------------------------------

def _summary(actions: List[Tuple[object, str]], error: Optional[str] = None) -> dict:
    counts = {ACTION_REWRITTEN: 0, ACTION_KEPT_SYNTHETIC: 0, ACTION_CONFLICT: 0}
    entries = []
    for entry, action in actions:
        if action in counts:
            counts[action] += 1
        entries.append({"cr": entry.client_random, "synthetic": _pair_json(entry.synthetic),
                        "real": _pair_json(entry.real), "action": action})
    summary = {"rewritten": counts[ACTION_REWRITTEN],
               "kept_synthetic": counts[ACTION_KEPT_SYNTHETIC],
               "conflicts": counts[ACTION_CONFLICT], "map": entries}
    if error:
        summary["error"] = error
    return summary


def _failure_actions(mappings: List) -> List[Tuple[object, str]]:
    return [(entry, ACTION_KEPT_SYNTHETIC) for entry in mappings]


def rewrite_synthetic_endpoints(path: str, mappings: Iterable,
                                logger: Optional[logging.Logger] = None) -> dict:
    """Switch the safe synthetic streams of *path* to their real tuples.

    *mappings* are the pinner's :class:`~friTap.endpoint_pinner.MappingEntry`
    rows. Returns ``{rewritten, kept_synthetic, conflicts, map: [{cr,
    synthetic, real|None, action}]}``; the counts are disjoint and
    ``not_in_pcap`` entries are counted in none. A row without a real tuple is
    ``kept_synthetic`` whether or not its stream is in the file; when no row
    has one the file is not read at all (nothing could be rewritten). Never
    raises: on any error the original file is kept and the summary gains an
    ``error`` entry.
    """
    log = logger or _LOGGER
    mappings = list(mappings)
    try:
        file_streams = collect_stream_keys(path) if _has_rewritable_mapping(mappings) else set()
        plan = plan_rewrites(mappings, file_streams)
        if plan.rewrites:
            rewrite_file_atomically(path, plan.rewrites)
    except Exception as exc:  # noqa: BLE001 - finalize must never break
        log.warning("Could not rewrite synthetic endpoints in %s (kept as is): %s", path, exc)
        return _summary(_failure_actions(mappings), error=str(exc))
    summary = _summary(plan.actions)
    log.info("Synthetic endpoints in %s: %d rewritten to real tuples, %d kept synthetic, "
             "%d conflicts", path, summary["rewritten"], summary["kept_synthetic"],
             summary["conflicts"])
    return summary
