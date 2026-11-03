#!/usr/bin/env python3

"""TCP session state tracker and IP/TCP packet construction for PCAPNG output.

Builds synthetic IPv4/IPv6 + TCP headers around decrypted TLS payload data
so that Wireshark/tshark can parse the resulting PCAPNG packets correctly.
The header format matches the legacy PCAP writer in ``friTap/pcap.py``.
"""

from __future__ import annotations

import ipaddress
import logging
import random
import struct
import threading
from collections import OrderedDict
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..schemas.canonical import AddressFamily, DataCanonical


SessionKey = tuple[object, int, object, int]

# --- Segmentation ---------------------------------------------------------
# IP length fields are 16 bit, so one synthetic packet holds at most 65535
# bytes. Both families are capped so the WHOLE IP datagram fits in 65535
# bytes: that satisfies the IPv4 Total Length and the IPv6 Payload Length
# fields, and keeps every frame within the 65535-byte snaplen of the legacy
# ``-p`` pcap header (friTap/pcap.py).
MAX_IP_PACKET = 0xFFFF
IPV4_HEADER_LEN = 20
IPV6_HEADER_LEN = 40
TCP_HEADER_LEN = 20
UDP_HEADER_LEN = 8
MAX_PORT = 0xFFFF

_IP_HEADER_LEN = {"AF_INET": IPV4_HEADER_LEN, "AF_INET6": IPV6_HEADER_LEN}
_TRANSPORT_HEADER_LEN = {"tcp": TCP_HEADER_LEN, "udp": UDP_HEADER_LEN}


def max_segment_payload(family: str, transport: str = "tcp") -> int:
    """Largest payload one IP+TCP/UDP packet of *family* can carry.

    IPv4+TCP: 65535-20-20 = 65495, IPv6+TCP: 65535-40-20 = 65475,
    IPv4+UDP: 65507, IPv6+UDP: 65487. Unknown families use the IPv6 (smaller)
    limit and unknown transports the TCP one.
    """
    ip_len = _IP_HEADER_LEN.get(family, IPV6_HEADER_LEN)
    l4_len = _TRANSPORT_HEADER_LEN.get(transport, TCP_HEADER_LEN)
    return MAX_IP_PACKET - ip_len - l4_len


def split_payload(data: bytes, limit: int) -> list[bytes]:
    """Split *data* into chunks of at most *limit* bytes (``[b""]`` for empty data)."""
    if not data:
        return [bytes(data)]
    return [bytes(data[i:i + limit]) for i in range(0, len(data), limit)]


# --- Endpoint validation --------------------------------------------------
# Addresses and ports come from agent messages; a tampered or buggy message
# must cost one dropped record, never a struct.error in the writer.

class InvalidEndpointError(ValueError):
    """An address or port that cannot be packed into an IP/TCP/UDP header.

    ``kind`` (e.g. ``"invalid port"``) names the problem without the value, so
    drop warnings can be rate limited per kind.
    """

    def __init__(self, kind: str, value: object) -> None:
        super().__init__(f"{kind} {value!r}")
        self.kind = kind


_logger = logging.getLogger("friTap")
_warned_drop_reasons: set[str] = set()
_warned_lock = threading.Lock()


def warn_dropped_record(reason: str, logger: logging.Logger | None = None) -> None:
    """Log a dropped-record warning once per distinct *reason* (rate limit)."""
    with _warned_lock:
        if reason in _warned_drop_reasons:
            return
        _warned_drop_reasons.add(reason)
    (logger or _logger).warning(
        "pcap: dropping plaintext record with %s (further drops of this kind "
        "are not logged)", reason)


def reset_drop_warnings() -> None:
    """Forget which drop reasons were logged (tests, new sessions)."""
    with _warned_lock:
        _warned_drop_reasons.clear()


def validate_port(port: object) -> int:
    """Return *port* if it is an int in 0..65535, else raise InvalidEndpointError.

    A missing port (None or "", content-only packets) is the 0 placeholder.
    """
    if port is None or port == "":
        return 0
    if not isinstance(port, int) or isinstance(port, bool) or not 0 <= port <= MAX_PORT:
        raise InvalidEndpointError("invalid port", port)
    return port


def _is_placeholder(addr: object) -> bool:
    """Content-only packets carry no address: "", None or 0 become 0.0.0.0 / ::."""
    return addr is None or addr == "" or addr == 0


def ipv4_address_int(addr: object) -> int:
    """32-bit form of an IPv4 address given as int or dotted string.

    Placeholders and other strings keep the historic 0.0.0.0 fallback; an int
    outside 0..2**32-1 raises InvalidEndpointError.
    """
    if _is_placeholder(addr):
        return 0
    if isinstance(addr, int) and not isinstance(addr, bool):
        try:
            return int(ipaddress.IPv4Address(addr))
        except ipaddress.AddressValueError as exc:
            raise InvalidEndpointError("invalid IPv4 address", addr) from exc
    if isinstance(addr, str):
        try:
            return int(ipaddress.IPv4Address(addr))
        except ipaddress.AddressValueError:
            return 0
    raise InvalidEndpointError("invalid IPv4 address", addr)


def ipv6_address_bytes(addr: object) -> bytes:
    """16-byte form of an IPv6 address given as 32-char hex, text form or int.

    Placeholders map to ``::``; anything else malformed raises
    InvalidEndpointError.
    """
    if _is_placeholder(addr):
        return bytes(16)
    try:
        if isinstance(addr, int) and not isinstance(addr, bool):
            return ipaddress.IPv6Address(addr).packed
        if isinstance(addr, str):
            return _ipv6_text_to_bytes(addr)
    except (ValueError, ipaddress.AddressValueError) as exc:
        raise InvalidEndpointError("invalid IPv6 address", addr) from exc
    raise InvalidEndpointError("invalid IPv6 address", addr)


def _ipv6_text_to_bytes(addr: str) -> bytes:
    if len(addr) == 32 and ":" not in addr:
        return bytes.fromhex(addr)
    return ipaddress.IPv6Address(addr).packed


@dataclass
class _SessionState:
    client_seq: int
    server_seq: int


class TcpSessionTracker:
    """Thread-safe tracker for fake TCP sequence/acknowledgment numbers.

    Each unique connection gets a random initial sequence number pair.
    Sequence numbers advance monotonically with each packet's data length.
    State is held in an LRU with ``MAX_SESSIONS`` entries — evicted sessions
    reappear with fresh ISNs, which Wireshark sees as a new TCP connection.
    """

    MAX_SESSIONS = 8192

    def __init__(self, max_sessions: int | None = None) -> None:
        self._lock = threading.Lock()
        self._sessions: OrderedDict[SessionKey, _SessionState] = OrderedDict()
        self._max = max_sessions if max_sessions is not None else self.MAX_SESSIONS

    def get_seq_ack(
        self, session_key: SessionKey, is_read: bool, data_len: int
    ) -> tuple[int, int]:
        """Return (seq, ack) for this packet and advance counters."""
        with self._lock:
            state = self._sessions.get(session_key)
            if state is None:
                if len(self._sessions) >= self._max:
                    self._sessions.popitem(last=False)
                state = _SessionState(
                    client_seq=random.randint(0, 0xFFFFFFFF),
                    server_seq=random.randint(0, 0xFFFFFFFF),
                )
                self._sessions[session_key] = state
            else:
                self._sessions.move_to_end(session_key)

            if is_read:
                seq, ack = state.server_seq, state.client_seq
                state.server_seq = (state.server_seq + data_len) & 0xFFFFFFFF
            else:
                seq, ack = state.client_seq, state.server_seq
                state.client_seq = (state.client_seq + data_len) & 0xFFFFFFFF

            return seq, ack

    def clear(self) -> None:
        with self._lock:
            self._sessions.clear()


def make_session_key(
    src_addr: int | str,
    src_port: int,
    dst_addr: int | str,
    dst_port: int,
    is_read: bool,
) -> SessionKey:
    """Return a direction-independent tuple key (server-side first)."""
    if is_read:
        return (src_addr, src_port, dst_addr, dst_port)
    return (dst_addr, dst_port, src_addr, src_port)


def build_ipv4_tcp_packet(
    src_addr: int,
    src_port: int,
    dst_addr: int,
    dst_port: int,
    seq: int,
    ack: int,
    payload: bytes,
) -> bytes:
    """Return 20-byte IPv4 + 20-byte TCP header + payload.

    Checksums are zero (valid for synthetic pcap data).
    TCP flags are PSH+ACK (0x5018) matching friTap/pcap.py.
    """
    total_len = 40 + len(payload)
    header = struct.pack(
        ">BBHHHBBHIIHHIIHHHH",
        0x45, 0, total_len,         # Version/IHL, ToS, Total Length
        0, 0x4000, 0xFF, 6, 0,      # ID, Flags/FragOff, TTL, Protocol, IP checksum
        src_addr, dst_addr,
        src_port, dst_port,
        seq, ack,
        0x5018, 0xFFFF, 0, 0,       # DataOff+Flags, Window, TCP checksum, Urgent
    )
    return header + payload


def build_ipv6_tcp_packet(
    src_addr_hex: str,
    src_port: int,
    dst_addr_hex: str,
    dst_port: int,
    seq: int,
    ack: int,
    payload: bytes,
) -> bytes:
    """Return 40-byte IPv6 + 20-byte TCP header + payload.

    Addresses are 32-character hex strings.
    """
    tcp_payload_len = 20 + len(payload)
    header = struct.pack(
        ">IHBB16s16sHHIIHHHH",
        0x60000000,                    # Version/Traffic Class/Flow Label
        tcp_payload_len, 6, 0xFF,      # Payload Length, Next Header, Hop Limit
        bytes.fromhex(src_addr_hex),
        bytes.fromhex(dst_addr_hex),
        src_port, dst_port,
        seq, ack,
        0x5018, 0xFFFF, 0, 0,
    )
    return header + payload


def build_ipv4_udp_packet(
    src_addr: int,
    src_port: int,
    dst_addr: int,
    dst_port: int,
    payload: bytes,
) -> bytes:
    """Return 20-byte IPv4 + 8-byte UDP header + payload.

    Protocol is 17 (UDP), used for QUIC plaintext. Checksums are zero
    (valid for synthetic pcap data). UDP is connectionless, so there is
    no seq/ack bookkeeping.
    """
    total_len = 28 + len(payload)
    header = struct.pack(
        ">BBHHHBBHIIHHHH",
        0x45, 0, total_len,         # Version/IHL, ToS, Total Length
        0, 0x4000, 0xFF, 17, 0,     # ID, Flags/FragOff, TTL, Protocol, IP checksum
        src_addr, dst_addr,
        src_port, dst_port,
        8 + len(payload), 0,        # UDP Length, UDP checksum
    )
    return header + payload


def build_ipv6_udp_packet(
    src_addr_hex: str,
    src_port: int,
    dst_addr_hex: str,
    dst_port: int,
    payload: bytes,
) -> bytes:
    """Return 40-byte IPv6 + 8-byte UDP header + payload.

    Next-header is 17 (UDP), used for QUIC plaintext. Addresses are
    32-character hex strings. UDP is connectionless, so there is no
    seq/ack bookkeeping.
    """
    udp_payload_len = 8 + len(payload)
    header = struct.pack(
        ">IHBB16s16sHHHH",
        0x60000000,                    # Version/Traffic Class/Flow Label
        udp_payload_len, 17, 0xFF,     # Payload Length, Next Header, Hop Limit
        bytes.fromhex(src_addr_hex),
        bytes.fromhex(dst_addr_hex),
        src_port, dst_port,
        udp_payload_len, 0,            # UDP Length, UDP checksum
    )
    return header + payload


def _as_ipv6_hex(addr: int | str) -> str:
    return addr if isinstance(addr, str) else format(addr, '032x')


def _as_ipv4_int(addr: int | str) -> int:
    return addr if isinstance(addr, int) else 0


def _family_name(ss_family: "AddressFamily | str") -> str:
    from ..schemas.canonical import AddressFamily

    return ss_family.value if isinstance(ss_family, AddressFamily) else ss_family


def _validated_endpoints(family: str, src_addr, src_port, dst_addr, dst_port):
    """Return (src, sport, dst, dport) ready for the builders, or raise.

    IPv4 addresses come back as ints, IPv6 addresses as 32-char hex strings.
    """
    if family == "AF_INET6":
        src, dst = ipv6_address_bytes(src_addr).hex(), ipv6_address_bytes(dst_addr).hex()
    else:
        src, dst = ipv4_address_int(src_addr), ipv4_address_int(dst_addr)
    return src, validate_port(src_port), dst, validate_port(dst_port)


def _udp_packets(family, src, sport, dst, dport, data) -> list[bytes]:
    build = build_ipv6_udp_packet if family == "AF_INET6" else build_ipv4_udp_packet
    limit = max_segment_payload(family, "udp")
    return [build(src, sport, dst, dport, seg) for seg in split_payload(data, limit)]


def _tcp_packets(family, src, sport, dst, dport, is_read, data, tracker) -> list[bytes]:
    """One IP+TCP packet per segment; each segment advances the tracker's seq."""
    build = build_ipv6_tcp_packet if family == "AF_INET6" else build_ipv4_tcp_packet
    key = make_session_key(src, sport, dst, dport, is_read)
    packets = []
    for seg in split_payload(data, max_segment_payload(family, "tcp")):
        seq, ack = tracker.get_seq_ack(key, is_read, len(seg))
        packets.append(build(src, sport, dst, dport, seq, ack, seg))
    return packets


def build_framed_packets_from_fields(
    ss_family: "AddressFamily | str",
    src_addr: int | str,
    src_port: int,
    dst_addr: int | str,
    dst_port: int,
    is_read: bool,
    data: bytes,
    tracker: TcpSessionTracker,
    transport: str = "tcp",
) -> list[bytes]:
    """Build the framed IP+TCP / IP+UDP packet(s) for one plaintext record.

    Payloads larger than one IP datagram (see :func:`max_segment_payload`) are
    split into several packets with contiguous TCP sequence numbers. Invalid
    addresses or ports drop the record: the result is ``[]`` and a warning is
    logged once per kind (never raises).
    """
    family = _family_name(ss_family)
    try:
        src, sport, dst, dport = _validated_endpoints(
            family, src_addr, src_port, dst_addr, dst_port)
    except InvalidEndpointError as exc:
        warn_dropped_record(exc.kind)
        return []
    if transport == "udp":
        return _udp_packets(family, src, sport, dst, dport, data)
    return _tcp_packets(family, src, sport, dst, dport, is_read, data, tracker)


def build_framed_packet_from_fields(
    ss_family: "AddressFamily | str",
    src_addr: int | str,
    src_port: int,
    dst_addr: int | str,
    dst_port: int,
    is_read: bool,
    data: bytes,
    tracker: TcpSessionTracker,
    transport: str = "tcp",
) -> bytes:
    """Build a framed IP+TCP or IP+UDP packet from raw connection fields.

    This is the low-level entry point shared by both the modern
    ``DataCanonical``-based sink and the legacy ``DatalogEvent``-based
    handler. Dispatches to IPv4 or IPv6 based on ``ss_family``.

    When ``transport == "udp"`` (QUIC plaintext) the packet is framed as
    IP+UDP (protocol 17) and the seq/ack tracker is skipped — UDP is
    connectionless. Otherwise the default TCP framing is used.

    Accepts both :class:`~friTap.schemas.canonical.AddressFamily` enum
    values and raw strings for backward compatibility with legacy events.

    Single-packet API kept for existing callers: an invalid record yields
    ``b""`` and an oversized payload only its FIRST segment (the tracker
    still advances over the whole payload). Use
    :func:`build_framed_packets_from_fields` to get every segment.
    """
    packets = build_framed_packets_from_fields(
        ss_family, src_addr, src_port, dst_addr, dst_port,
        is_read, data, tracker, transport)
    if len(packets) > 1:
        warn_dropped_record(
            "a payload larger than one IP packet via the single-packet API "
            "(only the first segment is kept)")
    return packets[0] if packets else b""


def build_framed_packets(event: "DataCanonical", tracker: TcpSessionTracker) -> list[bytes]:
    """Build every framed IP+TCP packet for a ``DataCanonical`` event."""
    from ..schemas.canonical import Direction

    return build_framed_packets_from_fields(
        ss_family=event.ss_family,
        src_addr=event.src_addr_raw,
        src_port=event.src.port,
        dst_addr=event.dst_addr_raw,
        dst_port=event.dst.port,
        is_read=(event.direction == Direction.READ),
        data=event.data,
        tracker=tracker,
    )


def build_framed_packet(event: "DataCanonical", tracker: TcpSessionTracker) -> bytes:
    """Build a framed IP+TCP packet from a ``DataCanonical`` event."""
    from ..schemas.canonical import Direction

    return build_framed_packet_from_fields(
        ss_family=event.ss_family,
        src_addr=event.src_addr_raw,
        src_port=event.src.port,
        dst_addr=event.dst_addr_raw,
        dst_port=event.dst.port,
        is_read=(event.direction == Direction.READ),
        data=event.data,
        tracker=tracker,
    )
