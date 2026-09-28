"""Hand-rolled, sequence-indexed TCP reassembly for the MTProto path.

We deliberately do NOT use scapy's ``tcp_reassemble``: MTProto's obfuscated
transport is AES-CTR, whose keystream is position-dependent, so a single missing
or misordered byte corrupts everything after it. We therefore anchor on the first
observed sequence number, buffer segments by ``seq``, dedupe retransmits, and only
expose a strictly contiguous in-order byte run. Any gap at the stream start, or a
gap that the available segments cannot fill, marks the direction ``degraded``.
"""

from __future__ import annotations

import bisect
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# 64-byte obfuscation init block — a stream missing this cannot be de-obfuscated.
INIT_BLOCK_LEN = 64


class TcpStreamReassembler:
    """Reassemble ONE TCP direction into a contiguous byte stream.

    Feed each segment with :meth:`feed`. The anchor (initial sequence number) is
    taken from the SYN if seen, otherwise from the lowest sequence number fed.
    """

    def __init__(self) -> None:
        self._segments: Dict[int, bytes] = {}  # seq -> payload (deduped/longest)
        self._anchor: Optional[int] = None
        self._saw_syn = False
        self._contig_cache: Optional[bytes] = None  # invalidated on feed()
        # seq -> earliest capture time seen for that seq (retransmits never move it).
        self._seq_ts: Dict[int, float] = {}
        # [(start offset within the contiguous run, capture ts)] — built with the run.
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
        """Buffer one segment. SYN consumes one sequence number (data starts at seq+1).

        ``ts`` is the segment's capture time (pcap epoch seconds; 0.0 = unknown).
        The earliest time seen for a sequence number is kept, so a retransmit
        never moves a byte's timestamp later.
        """
        # Any new segment can change the anchor or the contiguous run; the run is
        # read repeatedly afterwards (degraded checks + the decryptor), so cache it.
        self._contig_cache = None
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
        """True when the opening SYN was observed, so the anchor is the REAL start.

        Without a SYN the anchor is merely the lowest sequence number seen, which
        for a capture that began mid-flow is NOT the connection start — the first
        contiguous bytes are then not guaranteed to be the obfuscation init block.
        """
        return self._saw_syn

    @property
    def has_start_gap(self) -> bool:
        """True when the earliest observed byte begins after the anchor.

        A start gap means the opening (init) bytes were never captured. It is
        distinct from a later mid-stream gap, where the init block is intact and a
        contiguous prefix is still decryptable.
        """
        if self._anchor is None:
            return True
        ordered = self._ordered()
        if not ordered:
            return False  # no data yet (handshake only) — not a start gap per se
        return self._rel(ordered[0][0]) > 0

    def _rel(self, seq: int) -> int:
        """Signed distance of *seq* from the anchor, wrap-safe (RFC 1982 serial math).

        TCP sequence numbers are mod 2^32; comparing them with plain ``<``/``+``
        breaks across the 32-bit wrap (a long-lived stream that wraps would treat
        the post-wrap bytes as a giant gap and drop the rest). Returns a small
        NEGATIVE value for bytes before the anchor (old retransmits) and a small
        POSITIVE value for bytes after, so the contiguous-run logic below behaves
        identically with or without a wrap. Caller guarantees ``_anchor`` is set.
        """
        d = (seq - self._anchor) & 0xFFFFFFFF
        return d - 0x100000000 if d > 0x80000000 else d

    def _ordered(self) -> List[Tuple[int, bytes]]:
        if self._anchor is None:
            return sorted(self._segments.items())
        return sorted(self._segments.items(), key=lambda kv: self._rel(kv[0]))

    def contiguous_bytes(self) -> bytes:
        """Return the in-order byte run starting at the anchor, stopping at the first gap.

        Memoized: the result is reused across the repeated reads (``degraded``,
        ``StreamPair.degraded``, the decryptor) and invalidated whenever
        :meth:`feed` buffers a new segment.
        """
        if self._contig_cache is not None:
            return self._contig_cache
        self._span_starts = []
        self._span_ts = []
        if self._anchor is None:
            self._contig_cache = b""
            return self._contig_cache
        next_rel = 0  # offset (from the anchor) of the next expected byte
        out = bytearray()
        for seq, payload in self._ordered():
            rel = self._rel(seq)
            if rel > next_rel:
                break  # gap — stop the contiguous run
            end_rel = rel + len(payload)
            if end_rel <= next_rel:
                continue  # fully-overlapping retransmit already covered
            # The bytes this segment contributes start at the current run end.
            self._span_starts.append(next_rel)
            self._span_ts.append(self._seq_ts.get(seq, 0.0))
            # Trim any overlap with what we've already emitted.
            out += payload[next_rel - rel:]
            next_rel = end_rel
        self._contig_cache = bytes(out)
        return self._contig_cache

    def timestamp_at(self, offset: int) -> float:
        """Capture time of the segment that delivered byte *offset* of the run.

        *offset* indexes :meth:`contiguous_bytes` (0 = the anchor byte). Returns
        0.0 when the offset lies outside the run or its segment had no timestamp.
        """
        run = self.contiguous_bytes()
        if offset < 0 or offset >= len(run) or not self._span_starts:
            return 0.0
        idx = bisect.bisect_right(self._span_starts, offset) - 1
        return self._span_ts[idx] if idx >= 0 else 0.0

    @property
    def degraded(self) -> bool:
        """True if the stream start is missing or a gap interrupts the data.

        A start gap means the very first segment's seq is past the anchor (we
        never observed the opening bytes). A mid-stream gap means buffered
        segments exist beyond the contiguous run that we could not reach.
        """
        if self._anchor is None:
            return True
        ordered = self._ordered()
        if not ordered:
            return False  # no data yet (e.g. handshake only) — not degraded per se
        if self._rel(ordered[0][0]) > 0:
            return True  # start gap (earliest segment begins after the anchor)
        # Detect a mid-stream gap: bytes buffered beyond the contiguous reach. The
        # run starts at the anchor (rel 0), so its end offset == its length.
        contiguous_end_rel = len(self.contiguous_bytes())
        last_seq, last_payload = ordered[-1]
        if self._rel(last_seq) + len(last_payload) > contiguous_end_rel:
            return True
        return False


@dataclass
class StreamPair:
    """Both directions of one MTProto conversation.

    ``client`` is the client->server direction (carries the obfuscation init
    block); ``server`` is server->client. ``client_addr``/``server_addr`` are the
    normalized endpoint tuples.
    """

    client_addr: Tuple[str, int]
    server_addr: Tuple[str, int]
    ss_family: str  # "AF_INET" | "AF_INET6"
    client: TcpStreamReassembler = field(default_factory=TcpStreamReassembler)
    server: TcpStreamReassembler = field(default_factory=TcpStreamReassembler)

    @property
    def degraded(self) -> bool:
        """A stream is degraded if the client direction lacks the first 64 bytes."""
        if self.client.degraded:
            return True
        return len(self.client.contiguous_bytes()) < INIT_BLOCK_LEN


def _normalized_key(
    a_addr: str, a_port: int, b_addr: str, b_port: int
) -> Tuple[str, int, str, int]:
    """Order the two endpoints deterministically so both directions share a key."""
    side_a = (a_addr, a_port)
    side_b = (b_addr, b_port)
    lo, hi = sorted((side_a, side_b))
    return (lo[0], lo[1], hi[0], hi[1])


def _tcp_payload(ip, tcp, raw_cls) -> bytes:
    """Return the raw TCP payload bytes, independent of scapy's dissection.

    ``pkt[Raw]`` is not enough: once any code in the process imports
    ``scapy.layers.tls`` (bound to TCP/443), scapy dissects port-443 payloads
    as TLS records, so the bytes end up in TLS layers instead of a ``Raw``
    layer and would be silently dropped. MTProto's DCs listen on 443 too.
    Rebuilding ``tcp.payload`` returns the original bytes (scapy caches the
    raw bytes of every dissected layer); link-layer padding is trimmed via
    the IP length fields.
    """
    payload_layer = tcp.payload
    if isinstance(payload_layer, raw_cls):
        return bytes(payload_layer.load)
    if not payload_layer:
        return b""
    data = bytes(payload_layer)
    expected = _ip_payload_length(ip, tcp)
    if expected is not None and 0 <= expected <= len(data):
        data = data[:expected]
    return data


def _ip_payload_length(ip, tcp):
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
    server_ports: Tuple[int, ...] = (443, 80, 5222),
) -> Dict[Tuple[str, int, str, int], StreamPair]:
    """Reassemble all TCP conversations in ``pcap_path`` into per-direction streams.

    Returns ``{normalized_4tuple: StreamPair}``. The CLIENT is the endpoint that
    sent the first payload byte of the conversation; if no payload is seen, the
    side whose destination port is in ``server_ports`` is treated as the client.
    """
    from scapy.layers.inet import IP, TCP
    from scapy.layers.inet6 import IPv6
    from scapy.packet import Raw
    from scapy.utils import PcapReader

    # Provisional per-key state until we decide which side is the client.
    pending: Dict[Tuple[str, int, str, int], "_ConvBuilder"] = {}

    with PcapReader(pcap_path) as reader:
        for pkt in reader:
            if IP in pkt:
                ip = pkt[IP]
                family = "AF_INET"
                src, dst = ip.src, ip.dst
            elif IPv6 in pkt:
                ip = pkt[IPv6]
                family = "AF_INET6"
                src, dst = ip.src, ip.dst
            else:
                continue
            if TCP not in pkt:
                continue
            tcp = pkt[TCP]
            sport, dport = int(tcp.sport), int(tcp.dport)
            payload = _tcp_payload(ip, tcp, Raw)
            flags = int(tcp.flags)
            syn = bool(flags & 0x02)
            fin = bool(flags & 0x01)
            seq = int(tcp.seq)
            ts = float(pkt.time)

            key = _normalized_key(src, sport, dst, dport)
            builder = pending.get(key)
            if builder is None:
                builder = _ConvBuilder(family, server_ports)
                pending[key] = builder
            builder.add(src, sport, dst, dport, seq, payload, syn, fin, ts=ts)

    return {key: b.finalize() for key, b in pending.items()}


class _ConvBuilder:
    """Accumulates segments for one 4-tuple before client/server roles are fixed."""

    def __init__(self, family: str, server_ports: Tuple[int, ...]):
        self.family = family
        self.server_ports = server_ports
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

    def _choose_client(self) -> Tuple[str, int]:
        if self._first_payload_src is not None:
            return self._first_payload_src
        # Fallback: the side whose dst port is a server port is the client.
        for ep in self._endpoints:
            if self._dst_ports.get(ep) in self.server_ports:
                return ep
        return self._endpoints[0] if self._endpoints else ("", 0)

    def finalize(self) -> StreamPair:
        client_ep = self._choose_client()
        server_ep = next((ep for ep in self._endpoints if ep != client_ep), ("", 0))
        pair = StreamPair(
            client_addr=client_ep,
            server_addr=server_ep,
            ss_family=self.family,
        )
        if client_ep in self._reasm:
            pair.client = self._reasm[client_ep]
        if server_ep in self._reasm:
            pair.server = self._reasm[server_ep]
        return pair
