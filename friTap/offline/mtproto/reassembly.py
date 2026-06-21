"""Hand-rolled, sequence-indexed TCP reassembly for the MTProto path.

We deliberately do NOT use scapy's ``tcp_reassemble``: MTProto's obfuscated
transport is AES-CTR, whose keystream is position-dependent, so a single missing
or misordered byte corrupts everything after it. We therefore anchor on the first
observed sequence number, buffer segments by ``seq``, dedupe retransmits, and only
expose a strictly contiguous in-order byte run. Any gap at the stream start, or a
gap that the available segments cannot fill, marks the direction ``degraded``.
"""

from __future__ import annotations

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

    def feed(self, seq: int, payload: bytes, syn: bool = False, fin: bool = False) -> None:
        """Buffer one segment. SYN consumes one sequence number (data starts at seq+1)."""
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

    @property
    def has_anchor(self) -> bool:
        return self._anchor is not None

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
            # Trim any overlap with what we've already emitted.
            out += payload[next_rel - rel:]
            next_rel = end_rel
        self._contig_cache = bytes(out)
        return self._contig_cache

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
            payload = bytes(pkt[Raw].load) if Raw in pkt else b""
            flags = int(tcp.flags)
            syn = bool(flags & 0x02)
            fin = bool(flags & 0x01)
            seq = int(tcp.seq)

            key = _normalized_key(src, sport, dst, dport)
            builder = pending.get(key)
            if builder is None:
                builder = _ConvBuilder(family, server_ports)
                pending[key] = builder
            builder.add(src, sport, dst, dport, seq, payload, syn, fin)

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

    def add(self, src, sport, dst, dport, seq, payload, syn, fin) -> None:
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
        r.feed(seq, payload, syn=syn, fin=fin)
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
