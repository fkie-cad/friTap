"""Hand-rolled, sequence-indexed TCP reassembly shared by the offline decryptors.

Not scapy's ``tcp_reassemble``: stream ciphers (AES-CTR in MTProto, RC4) are
position-dependent, so one missing or misordered byte corrupts the rest.
Segments are anchored on the first observed seq, buffered, deduped, and only a
strictly contiguous in-order run is exposed. A gap at the start, or one the
segments cannot fill, marks the direction ``degraded``.
"""

from __future__ import annotations

import bisect
import os
from dataclasses import dataclass, field
from typing import Dict, Iterable, Iterator, List, Optional, Tuple, Type

from .capture_validation import capture_read_guard, validate_capture_file


class TcpStreamReassembler:
    """Reassemble one TCP direction; the anchor is the SYN's seq if seen, else the lowest seq fed."""

    def __init__(self) -> None:
        self._segments: Dict[int, bytes] = {}  # seq -> payload (deduped/longest)
        self._anchor: Optional[int] = None
        self._saw_syn = False
        # Derived views, invalidated on feed() and read repeatedly afterwards.
        self._contig_cache: Optional[bytes] = None
        self._ordered_cache: Optional[List[Tuple[int, bytes]]] = None
        self._after_gap_cache: Optional[bytes] = None
        # seq -> earliest capture time seen for that seq (retransmits never move it).
        self._seq_ts: Dict[int, float] = {}
        # (start offset within the contiguous run, capture ts), built with the run.
        self._span_starts: List[int] = []
        self._span_ts: List[float] = []

    def feed(
        self,
        seq: int,
        payload: bytes,
        syn: bool = False,
        fin: bool = False,
        ts: float = 0.0,
    ) -> None:
        """Buffer one segment (SYN consumes one seq, data starts at seq+1).

        ``ts`` is the capture time (0.0 = unknown); the earliest time per seq is kept so a retransmit never moves it later.
"""
        # A new segment can change the anchor or the run; cached because degraded checks and the decryptor read it repeatedly.
        self._contig_cache = None
        self._ordered_cache = None
        self._after_gap_cache = None
        if syn:
            self._saw_syn = True
            data_seq = (seq + 1) & 0xFFFFFFFF
            if self._anchor is None:
                self._anchor = data_seq
        else:
            if self._anchor is None:
                self._anchor = seq

        if payload:
            data_seq = seq
            existing = self._segments.get(data_seq)
            # Dedupe retransmits; keep the longest copy at a given seq.
            if existing is None or len(payload) > len(existing):
                self._segments[data_seq] = payload
            self._record_seq_ts(data_seq, ts)

    def _record_seq_ts(self, seq: int, ts: float) -> None:
        """Keep the minimum known (> 0) capture time for *seq*."""
        if ts <= 0:
            self._seq_ts.setdefault(seq, 0.0)
            return
        known = self._seq_ts.get(seq, 0.0)
        if known <= 0 or ts < known:
            self._seq_ts[seq] = ts

    @property
    def has_anchor(self) -> bool:
        return self._anchor is not None

    @property
    def saw_syn(self) -> bool:
        """True when the opening SYN was seen. Without it the anchor is the lowest seq, so a mid-flow capture's first bytes need not be the stream's opening bytes."""
        return self._saw_syn

    @property
    def has_start_gap(self) -> bool:
        """True when the earliest observed byte begins after the anchor (a start gap, unlike a later mid-stream gap where the prefix is still decryptable)."""
        if self._anchor is None:
            return True
        ordered = self._ordered()
        if not ordered:
            return False  # no data yet (handshake only)
        return self._rel(ordered[0][0]) > 0

    def _rel(self, seq: int) -> int:
        """Signed distance of *seq* from the anchor, wrap-safe (RFC 1982 serial math); negative before the anchor. Requires ``_anchor``."""
        d = (seq - self._anchor) & 0xFFFFFFFF
        return d - 0x100000000 if d > 0x80000000 else d

    def _ordered(self) -> List[Tuple[int, bytes]]:
        """Buffered segments in stream order; memoized until the next :meth:`feed`."""
        if self._ordered_cache is None:
            if self._anchor is None:
                self._ordered_cache = sorted(self._segments.items())
            else:
                self._ordered_cache = sorted(
                    self._segments.items(), key=lambda kv: self._rel(kv[0])
                )
        return self._ordered_cache

    def contiguous_bytes(self) -> bytes:
        """The in-order byte run from the anchor to the first gap; memoized until :meth:`feed`."""
        if self._contig_cache is not None:
            return self._contig_cache
        self._span_starts = []
        self._span_ts = []
        if self._anchor is None:
            self._contig_cache = b""
            return self._contig_cache
        self._contig_cache = self._collect_run(0, self._span_starts, self._span_ts)
        return self._contig_cache

    def _collect_run(
        self, start_rel: int, span_starts: List[int], span_ts: List[float]
    ) -> bytes:
        """In-order bytes from *start_rel* (anchor-relative) to the first gap; appends segment offsets and times to *span_starts* / *span_ts*. Requires ``_anchor``."""
        next_rel = start_rel  # offset (from the anchor) of the next expected byte
        out = bytearray()
        for seq, payload in self._ordered():
            rel = self._rel(seq)
            if rel > next_rel:
                break  # gap ends the contiguous run
            end_rel = rel + len(payload)
            if end_rel <= next_rel:
                continue  # fully-overlapping retransmit already covered
            span_starts.append(next_rel - start_rel)
            span_ts.append(self._seq_ts.get(seq, 0.0))
            # Trim overlap with bytes already emitted.
            out += payload[next_rel - rel:]
            next_rel = end_rel
        return bytes(out)

    def bytes_after_start_gap(self) -> bytes:
        """The contiguous run from the earliest buffered byte, past a start gap.

        For record-framed protocols that can resync (mid-stream TLS); equals :meth:`contiguous_bytes` without a start gap.
"""
        if not self.has_start_gap or not self._segments:
            return self.contiguous_bytes()
        if self._after_gap_cache is None:
            first_rel = self._rel(self._ordered()[0][0])
            self._after_gap_cache = self._collect_run(first_rel, [], [])
        return self._after_gap_cache

    def timestamp_at(self, offset: int) -> float:
        """Capture time of the segment delivering byte *offset* of :meth:`contiguous_bytes`; 0.0 if outside the run or untimed."""
        run = self.contiguous_bytes()
        if offset < 0 or offset >= len(run) or not self._span_starts:
            return 0.0
        idx = bisect.bisect_right(self._span_starts, offset) - 1
        return self._span_ts[idx] if idx >= 0 else 0.0

    @property
    def degraded(self) -> bool:
        """True if the start is missing (first segment past the anchor) or buffered segments exist beyond the contiguous run."""
        if self._anchor is None:
            return True
        ordered = self._ordered()
        if not ordered:
            return False  # no data yet (e.g. handshake only)
        if self._rel(ordered[0][0]) > 0:
            return True  # start gap
        # Mid-stream gap: the run starts at the anchor, so its end offset is its length.
        contiguous_end_rel = len(self.contiguous_bytes())
        last_seq, last_payload = ordered[-1]
        if self._rel(last_seq) + len(last_payload) > contiguous_end_rel:
            return True
        return False


@dataclass
class TcpStreamPair:
    """Both directions of one TCP conversation (``client`` is client->server); ``client_addr``/``server_addr`` are normalized endpoints."""

    client_addr: Tuple[str, int]
    server_addr: Tuple[str, int]
    ss_family: str  # "AF_INET" | "AF_INET6"
    client: TcpStreamReassembler = field(default_factory=TcpStreamReassembler)
    server: TcpStreamReassembler = field(default_factory=TcpStreamReassembler)


def normalized_key(
    a_addr: str, a_port: int, b_addr: str, b_port: int
) -> Tuple[str, int, str, int]:
    """Order the two endpoints deterministically so both directions share a key."""
    side_a = (a_addr, a_port)
    side_b = (b_addr, b_port)
    lo, hi = sorted((side_a, side_b))
    return (lo[0], lo[1], hi[0], hi[1])


def tcp_payload(ip, tcp, raw_cls) -> bytes:
    """Raw TCP payload bytes, independent of scapy's dissection.

    ``pkt[Raw]`` is not enough: with ``scapy.layers.tls`` imported (bound to TCP/443),
    port-443 payloads are dissected as TLS and dropped (MTProto's DCs use 443 too).
    Rebuilding ``tcp.payload`` returns the original bytes; link-layer padding is trimmed via IP length.
"""
    payload_layer = tcp.payload
    if isinstance(payload_layer, raw_cls):
        return bytes(payload_layer.load)
    if not payload_layer:
        return b""
    data = bytes(payload_layer)
    expected = ip_payload_length(ip, tcp)
    if expected is not None and 0 <= expected <= len(data):
        data = data[:expected]
    return data


def ip_payload_length(ip, tcp):
    """TCP payload length from the IP header, or None when unknown."""
    header_len = int(tcp.dataofs or 5) * 4
    total = getattr(ip, "len", None)
    if total is not None and hasattr(ip, "ihl"):
        return int(total) - int(ip.ihl or 5) * 4 - header_len
    plen = getattr(ip, "plen", None)
    if plen is not None:
        return int(plen) - header_len
    return None


def reassemble_pcap(
    pcap_path: str,
    *,
    server_ports: Tuple[int, ...] = (443,),
    pair_cls: Type[TcpStreamPair] = TcpStreamPair,
    parsed: Optional["ParsedCapture"] = None,
) -> Dict[Tuple[str, int, str, int], TcpStreamPair]:
    """Reassemble all TCP conversations in ``pcap_path``; returns ``{normalized_4tuple: pair}`` built as *pair_cls*.

    The client is the endpoint that dialed a ``server_ports`` port (reliable for
    mid-stream captures); else the first payload sender, then the first-seen endpoint.

    The parse is shared: an explicit *parsed* capture is used as is, else the active
    :func:`~friTap.offline.net.capture_cache.capture_cache_scope` parse, else it is
    parsed here. Pairs share reassemblers with other callers (:meth:`ParsedCapture.pairs`).
"""
    if parsed is None:
        from .capture_cache import active_parsed_capture

        parsed = active_parsed_capture(pcap_path)
    if parsed is None:
        parsed = parse_pcap(pcap_path)
    return parsed.pairs(server_ports, pair_cls)


class ParsedCapture:
    """Every TCP conversation of one capture, parsed once, roles not yet fixed.

    :meth:`pairs` orients them for a server-port set and may be called repeatedly;
    each call returns fresh pairs, but the reassemblers inside are shared and
    read-only (never feed them).
"""

    def __init__(self, builders: Dict[Tuple[str, int, str, int], "ConvBuilder"]):
        self._builders = builders

    def __len__(self) -> int:
        return len(self._builders)

    def pairs(
        self,
        server_ports: Tuple[int, ...] = (443,),
        pair_cls: Type[TcpStreamPair] = TcpStreamPair,
    ) -> Dict[Tuple[str, int, str, int], TcpStreamPair]:
        """``{normalized_4tuple: pair}`` oriented for *server_ports*."""
        return {
            key: builder.finalize(server_ports=server_ports, pair_cls=pair_cls)
            for key, builder in self._builders.items()
        }


#: ``FRITAP_PCAP_PARSER=scapy`` selects :func:`parse_pcap_scapy` over the fast parser.
PCAP_PARSER_ENV = "FRITAP_PCAP_PARSER"

#: One TCP segment as both parsers yield it:
#: ``(family, src, sport, dst, dport, seq, payload, syn, fin, ts)``.
Segment = Tuple[str, str, int, str, int, int, bytes, bool, bool, float]


def parse_pcap(pcap_path: str) -> ParsedCapture:
    """Read ``pcap_path`` and buffer every TCP segment per conversation.

    Uses the scapy-free :mod:`.pcap_fast`, which hands packets it cannot decode
    (tunnels, PPPoE, IPv6 extension headers) to :func:`_scapy_fallback_segment`.
    ``FRITAP_PCAP_PARSER=scapy`` selects :func:`parse_pcap_scapy`. Roles are decided
    later, so one parse serves every decryptor.
"""
    if os.environ.get(PCAP_PARSER_ENV, "").strip().lower() == "scapy":
        return parse_pcap_scapy(pcap_path)
    from .pcap_fast import iter_tcp_segments

    return _build_capture(iter_tcp_segments(pcap_path, fallback=_scapy_fallback_segment))


def parse_pcap_scapy(pcap_path: str) -> ParsedCapture:
    """Legacy parser: full scapy dissection of every packet (slow, reference)."""
    return _build_capture(_iter_scapy_segments(pcap_path))


def _iter_scapy_segments(pcap_path: str) -> Iterator[Segment]:
    # Import the IP layers first: PcapReader resolves its link-layer class at open time and raw-IP link types register on import.
    import scapy.layers.inet  # noqa: F401
    import scapy.layers.inet6  # noqa: F401
    from scapy.utils import PcapReader

    validate_capture_file(pcap_path)  # scapy allocates each record's length unchecked
    with capture_read_guard(pcap_path), PcapReader(pcap_path) as reader:
        for pkt in reader:
            segment = _scapy_segment(pkt)
            if segment is not None:
                yield segment


def _scapy_segment(pkt) -> Optional[Segment]:
    """Extract the TCP segment of one scapy-dissected packet, or None."""
    from scapy.layers.inet import IP, TCP
    from scapy.layers.inet6 import IPv6
    from scapy.packet import Raw

    if IP in pkt:
        ip = pkt[IP]
        family = "AF_INET"
    elif IPv6 in pkt:
        ip = pkt[IPv6]
        family = "AF_INET6"
    else:
        return None
    if TCP not in pkt:
        return None
    tcp = pkt[TCP]
    flags = int(tcp.flags)
    return (
        family, ip.src, int(tcp.sport), ip.dst, int(tcp.dport), int(tcp.seq),
        tcp_payload(ip, tcp, Raw), bool(flags & 0x02), bool(flags & 0x01),
        float(pkt.time),
    )


def _scapy_fallback_segment(pkt) -> Optional[Segment]:
    """:func:`_scapy_segment` for the fast parser's fallback packets, minus padding.

    scapy attaches link-layer padding to an empty segment as a ``Padding`` layer that
    :func:`tcp_payload` returns; the fast parser never does, so phantom zero bytes
    must not leak into the stream. :func:`_scapy_segment` stays the reference.
"""
    segment = _scapy_segment(pkt)
    if segment is None or not segment[6] or not _tcp_payload_is_padding(pkt):
        return segment
    return segment[:6] + (b"",) + segment[7:]


def _tcp_payload_is_padding(pkt) -> bool:
    from scapy.layers.inet import TCP
    from scapy.packet import Padding

    return isinstance(pkt[TCP].payload, Padding)


def _build_capture(segments: Iterable[Segment]) -> ParsedCapture:
    """Group *segments* into per-conversation builders (roles not yet fixed)."""
    pending: Dict[Tuple[str, int, str, int], "ConvBuilder"] = {}
    for family, src, sport, dst, dport, seq, payload, syn, fin, ts in segments:
        key = normalized_key(src, sport, dst, dport)
        builder = pending.get(key)
        if builder is None:
            builder = ConvBuilder(family, ())
            pending[key] = builder
        builder.add(src, sport, dst, dport, seq, payload, syn, fin, ts=ts)
    return ParsedCapture(pending)


class ConvBuilder:
    """Accumulates segments for one 4-tuple before client/server roles are fixed."""

    def __init__(
        self,
        family: str,
        server_ports: Tuple[int, ...],
        pair_cls: Type[TcpStreamPair] = TcpStreamPair,
    ):
        self.family = family
        self.server_ports = server_ports
        self.pair_cls = pair_cls
        # endpoint -> reassembler, keyed by (addr, port)
        self._reasm: Dict[Tuple[str, int], TcpStreamReassembler] = {}
        self._endpoints: List[Tuple[str, int]] = []
        self._first_payload_src: Optional[Tuple[str, int]] = None
        self._dst_ports: Dict[Tuple[str, int], int] = {}

    def add(self, src, sport, dst, dport, seq, payload, syn, fin, ts: float = 0.0) -> None:
        src_ep = (src, sport)
        dst_ep = (dst, dport)
        for ep in (src_ep, dst_ep):
            if ep not in self._endpoints:
                self._endpoints.append(ep)
        self._dst_ports[src_ep] = dport
        r = self._reasm.get(src_ep)
        if r is None:
            r = TcpStreamReassembler()
            self._reasm[src_ep] = r
        r.feed(seq, payload, syn=syn, fin=fin, ts=ts)
        if payload and self._first_payload_src is None:
            self._first_payload_src = src_ep

    def _choose_client(
        self, server_ports: Optional[Tuple[int, ...]] = None,
    ) -> Tuple[str, int]:
        # A mid-stream capture can begin with the server's bytes, so "first payload sender" can misorient roles and apply traffic secrets to the wrong directions; the endpoint that dialed a server port is reliable, the others are fallbacks.
        if server_ports is None:
            server_ports = self.server_ports
        for ep in self._endpoints:
            if self._dst_ports.get(ep) in server_ports:
                return ep
        if self._first_payload_src is not None:
            return self._first_payload_src
        return self._endpoints[0] if self._endpoints else ("", 0)

    def finalize(
        self,
        server_ports: Optional[Tuple[int, ...]] = None,
        pair_cls: Optional[Type[TcpStreamPair]] = None,
    ) -> TcpStreamPair:
        """Orient the conversation and wrap its reassemblers in a new pair; pure and repeatable (*server_ports* / *pair_cls* default to the constructor's)."""
        client_ep = self._choose_client(server_ports)
        server_ep = next((ep for ep in self._endpoints if ep != client_ep), ("", 0))
        pair = (pair_cls or self.pair_cls)(
            client_addr=client_ep,
            server_addr=server_ep,
            ss_family=self.family,
        )
        if client_ep in self._reasm:
            pair.client = self._reasm[client_ep]
        if server_ep in self._reasm:
            pair.server = self._reasm[server_ep]
        return pair
