"""Fast, scapy-dissection-free TCP segment extraction from pcap / pcapng files.

Full scapy dissection of every packet dominated offline conversion time. This
module reads records with scapy's ``RawPcapReader`` (pcap, pcapng, gzip) and
decodes the link, IP and TCP headers itself with ``struct`` slicing. The output
is the same segment tuple the scapy parser yields::

    (family, src, sport, dst, dport, seq, payload, syn, fin, ts)

Coverage mirrors what scapy would decode, with the rare cases handed back to
scapy one packet at a time through the *fallback* callable (``scapy packet ->
segment or None``) so the result stays exact:

* link types: Ethernet (with 802.1Q / 802.1ad tags), Linux SLL / SLL2, raw IP
  (12, 14, 101, 228, 229), BSD loopback NULL (0) and LOOP (108);
* to scapy, from the link layer: unknown link types, LLC / PPPoE / MPLS and any
  other unhandled ethertype, a version nibble that disagrees with the ethertype,
  truncated link headers;
* to scapy, from the IP layer: TCP behind IPv4 options or IPv6 extension headers,
  tunnels (IP protocols 4/41/47/..., UDP tunnel ports), IPv6 extension headers
  other than hop-by-hop / destination options / fragment, and malformed IP/TCP
  headers.

Packets that provably cannot yield a scapy ``TCP`` layer are skipped without
scapy (which would also load scapy's inet layers for nothing): IPv4 with options
whose protocol is not TCP (IGMP with Router Alert), IPv6 hop-by-hop /
destination-options / fragment chains ending in a non-TCP header (MLD reports)
or in a non-first fragment, and Linux cooked-capture pseudo-protocols scapy
binds to nothing (802.2 LLC on Android).

Deliberate differences from the scapy parser (decided, not accidental):

* an empty TCP segment never returns link-layer padding as payload (scapy
  attaches the padding to the empty segment, which leaked phantom zero bytes
  into reassembled streams);
* loopback address families are decoded platform-independently (2/0 = IPv4;
  24/28/30/10 = IPv6, each only with a matching IP version nibble), NULL headers
  written big-endian are byte-swapped, and anything else is skipped;
* link type 14 is raw IP on every platform;
* simple packet blocks (pcapng, no timestamp) get ``ts = 0.0`` ("unknown").

Leaf module: only the stdlib and (lazily) scapy; it never imports friTap.
"""

from __future__ import annotations

import logging
import socket
import struct
from dataclasses import dataclass
from decimal import Decimal
from functools import lru_cache
from typing import Any, Callable, Iterator, Optional, Tuple

logger = logging.getLogger(__name__)

#: ``(family, src, sport, dst, dport, seq, payload, syn, fin, ts)``
Segment = Tuple[str, str, int, str, int, int, bytes, bool, bool, float]
#: Turns one scapy-dissected packet (``pkt.time`` already set) into a segment.
ScapyFallback = Callable[[Any], Optional[Segment]]

# --- link types -----------------------------------------------------------
DLT_NULL = 0
DLT_EN10MB = 1
DLT_RAW_12 = 12
DLT_RAW_14 = 14
DLT_RAW = 101
DLT_LOOP = 108
DLT_LINUX_SLL = 113
DLT_IPV4 = 228
DLT_IPV6 = 229
DLT_LINUX_SLL2 = 276

ETH_IPV4 = 0x0800
ETH_IPV6 = 0x86DD
VLAN_TAGS = frozenset({0x8100, 0x88A8})
#: Ethertypes that can never carry TCP (ARP, RARP, LLDP, EAPOL).
NON_IP_ETHERTYPES = frozenset({0x0806, 0x8035, 0x88CC, 0x888E})
#: Linux SLL / SLL2 pseudo-protocols (``ETH_P_802_2`` LLC, ``ETH_P_CAN``,
#: ``ETH_P_CANFD``) that scapy binds to no layer, so it dissects them as Raw.
#: Guarded by a unit test against scapy's live ``CookedLinux`` bindings.
SLL_UNBOUND_PROTOCOLS = frozenset({0x0004, 0x000C, 0x000D})

LOOPBACK_AF_IPV4 = frozenset({0, 2})
#: AF_INET6 on the BSDs (24), FreeBSD (28), Darwin (30) and Linux (10).
LOOPBACK_AF_IPV6 = frozenset({10, 24, 28, 30})

# --- IP payload classification ---------------------------------------------
IPPROTO_TCP = 6
IPPROTO_UDP = 17
#: IPv6 extension headers walked without scapy: hop-by-hop options (0) and
#: destination options (60), both ``(hdr_ext_len + 1) * 8`` bytes long, and the
#: fixed 8-byte fragment header (44).
IPV6_HOP_BY_HOP = 0
IPV6_FRAGMENT = 44
IPV6_DEST_OPTS = 60
IPV6_WALKED_HEADERS = frozenset({IPV6_HOP_BY_HOP, IPV6_FRAGMENT, IPV6_DEST_OPTS})
#: "No next header": what a non-first fragment amounts to (scapy dissects its
#: payload as Raw).
IPV6_NO_NEXT_HEADER = 59
#: Longest extension-header chain walked before handing the packet to scapy.
MAX_IPV6_WALKED_HEADERS = 8
#: UDP ports scapy binds to a tunnel whose payload may hold an inner TCP
#: segment: Mobile IP (434, IP-in-UDP tunnel data), L2TP (1701), GRE-in-UDP
#: (4754) and the VXLAN family (4789, 4790, 6633, 8472, 48879). Guarded by a
#: unit test against scapy's live ``UDP.payload_guess`` bindings.
TUNNEL_UDP_PORTS = frozenset({434, 1701, 4754, 4789, 4790, 6633, 8472, 48879})
#: IP protocols / IPv6 next headers that can never lead scapy to a ``TCP``
#: layer (ICMP and ICMPv6 quote headers as ``TCPerror``, not ``TCP``).
NON_TCP_PROTOCOLS = frozenset({1, 2, 50, 58, 59, 89, 103, 112, 132})

# --- per-packet decode verdicts ---------------------------------------------
_SKIP = "skip"            # no TCP segment in this packet
_LINK_FALLBACK = "link"   # let scapy dissect the whole frame
_IP_FALLBACK = "ip"       # let scapy dissect from the IP header

_ntoa = socket.inet_ntoa
_ntop = socket.inet_ntop
_AF_INET6 = socket.AF_INET6
_U16 = struct.Struct("!H").unpack_from
_U32_BE = struct.Struct("!I").unpack_from
_U32_LE = struct.Struct("<I").unpack_from
_TCP_PORTS_SEQ = struct.Struct("!HHI").unpack_from


@dataclass
class ParseStats:
    """Per-parse counters (handy for tests and debug logging)."""

    packets: int = 0
    fast_segments: int = 0
    skipped: int = 0
    link_fallbacks: int = 0
    ip_fallbacks: int = 0
    fallback_segments: int = 0

    @property
    def fallbacks(self) -> int:
        return self.link_fallbacks + self.ip_fallbacks


# --- link layer ----------------------------------------------------------------
# Each decoder returns ``(ip_version, offset)`` or a verdict string.

def _ip_after(buf: bytes, off: int, version: int, on_mismatch: str):
    """``(version, off)`` when the header at *off* has the expected version nibble."""
    if len(buf) > off and buf[off] >> 4 == version:
        return version, off
    return on_mismatch


def _link_ethernet(buf: bytes):
    if len(buf) < 14:
        return _LINK_FALLBACK
    ethertype = _U16(buf, 12)[0]
    off = 14
    while ethertype in VLAN_TAGS:
        if len(buf) < off + 4:
            return _LINK_FALLBACK
        ethertype = _U16(buf, off + 2)[0]
        off += 4
    return _by_ethertype(buf, ethertype, off)


def _by_ethertype(buf: bytes, ethertype: int, off: int):
    if ethertype == ETH_IPV4:
        return _ip_after(buf, off, 4, _LINK_FALLBACK)
    if ethertype == ETH_IPV6:
        return _ip_after(buf, off, 6, _LINK_FALLBACK)
    if ethertype in NON_IP_ETHERTYPES:
        return _SKIP
    return _LINK_FALLBACK


def _link_sll(buf: bytes):
    if len(buf) < 16:
        return _LINK_FALLBACK
    return _by_sll_protocol(buf, _U16(buf, 14)[0], 16)


def _link_sll2(buf: bytes):
    if len(buf) < 20:
        return _LINK_FALLBACK
    return _by_sll_protocol(buf, _U16(buf, 0)[0], 20)


def _by_sll_protocol(buf: bytes, protocol: int, off: int):
    if protocol in SLL_UNBOUND_PROTOCOLS:
        return _SKIP  # scapy leaves these Raw: never a TCP layer
    return _by_ethertype(buf, protocol, off)


def _link_raw(buf: bytes):
    version = buf[0] >> 4 if buf else 0
    if version in (4, 6):
        return version, 0
    return _LINK_FALLBACK


def _link_ipv4(buf: bytes):
    return _ip_after(buf, 0, 4, _LINK_FALLBACK)


def _link_ipv6(buf: bytes):
    return _ip_after(buf, 0, 6, _LINK_FALLBACK)


def _link_null(buf: bytes):
    """DLT_NULL: host-endian AF; a big-endian writer shows up byte-swapped."""
    if len(buf) < 4:
        return _SKIP
    family = _U32_LE(buf, 0)[0]
    if family & 0xFFFF0000:
        family = _U32_BE(buf, 0)[0]
    return _by_loopback_family(buf, family)


def _link_loop(buf: bytes):
    """DLT_LOOP: AF in network byte order."""
    if len(buf) < 4:
        return _SKIP
    return _by_loopback_family(buf, _U32_BE(buf, 0)[0])


def _by_loopback_family(buf: bytes, family: int):
    if family in LOOPBACK_AF_IPV4:
        return _ip_after(buf, 4, 4, _SKIP)
    if family in LOOPBACK_AF_IPV6:
        return _ip_after(buf, 4, 6, _SKIP)
    return _SKIP


_LINK_DECODERS = {
    DLT_EN10MB: _link_ethernet,
    DLT_LINUX_SLL: _link_sll,
    DLT_LINUX_SLL2: _link_sll2,
    DLT_RAW: _link_raw,
    DLT_RAW_12: _link_raw,
    DLT_RAW_14: _link_raw,
    DLT_IPV4: _link_ipv4,
    DLT_IPV6: _link_ipv6,
    DLT_NULL: _link_null,
    DLT_LOOP: _link_loop,
}


# --- IP / TCP --------------------------------------------------------------------

def _decode_ipv4(buf: bytes, off: int, ts: float):
    if len(buf) - off < 20:
        return _IP_FALLBACK  # truncated
    ihl = buf[off] & 0x0F
    proto = buf[off + 9]
    if ihl != 5:
        return _classify_ipv4_options(buf, off, ihl, proto)
    if proto != IPPROTO_TCP:
        return _classify_non_tcp(buf, proto, off + 20)
    if _U16(buf, off + 6)[0] & 0x1FFF:
        return _SKIP  # non-first fragment: scapy binds TCP only at offset 0
    total_len = _U16(buf, off + 2)[0]
    # scapy IP.extract_padding: a total length below the header (e.g. 0 from
    # TSO) means "the rest of the frame"; otherwise the rest is link padding.
    end = off + total_len if total_len >= 20 else len(buf)
    return _decode_tcp(
        buf, off + 20, end, "AF_INET",
        _ntoa(buf[off + 12:off + 16]), _ntoa(buf[off + 16:off + 20]), ts,
    )


def _classify_ipv4_options(buf: bytes, off: int, ihl: int, proto: int) -> str:
    """Verdict for an IPv4 header with options (or a malformed IHL).

    Options never change what the payload is, so a non-TCP payload is
    classified like any other; TCP behind options stays with scapy.
    """
    l4_off = off + ihl * 4
    if proto == IPPROTO_TCP or ihl < 5 or len(buf) < l4_off:
        return _IP_FALLBACK
    return _classify_non_tcp(buf, proto, l4_off)


def _decode_ipv6(buf: bytes, off: int, ts: float):
    if len(buf) - off < 40:
        return _IP_FALLBACK
    next_header = buf[off + 6]
    if next_header in IPV6_WALKED_HEADERS:
        return _classify_ipv6_extension_chain(buf, off)
    if next_header != IPPROTO_TCP:
        return _classify_non_tcp(buf, next_header, off + 40)
    payload_len = _U16(buf, off + 4)[0]
    if payload_len == 0:
        return _SKIP  # scapy: no payload bytes, so no TCP layer
    start = off + 40
    return _decode_tcp(
        buf, start, start + payload_len, "AF_INET6",
        _ntop(_AF_INET6, buf[off + 8:off + 24]),
        _ntop(_AF_INET6, buf[off + 24:off + 40]), ts,
    )


def _classify_ipv6_extension_chain(buf: bytes, off: int) -> str:
    """Verdict for an IPv6 packet opening with a walked extension header.

    Walks the chain to the upper-layer protocol: a non-TCP one is classified
    like any other (MLD -> ICMPv6 -> skip; a non-first fragment -> skip); TCP,
    other extension headers and chains leaving the payload stay with scapy.
    """
    upper = _ipv6_upper_layer(buf, off)
    if upper is None:
        return _IP_FALLBACK
    next_header, l4_off = upper
    if next_header == IPPROTO_TCP:
        return _IP_FALLBACK
    return _classify_non_tcp(buf, next_header, l4_off)


def _ipv6_upper_layer(buf: bytes, off: int) -> Optional[Tuple[int, int]]:
    """``(next_header, offset)`` after the walked headers, or None when unsure."""
    end = min(off + 40 + _U16(buf, off + 4)[0], len(buf))
    next_header, pos = buf[off + 6], off + 40
    for _ in range(MAX_IPV6_WALKED_HEADERS):
        if next_header not in IPV6_WALKED_HEADERS:
            return next_header, pos
        header = _ipv6_extension_header(buf, pos, end, next_header)
        if header is None:
            return None  # header cut by the payload length or the capture
        next_header, pos = header
    return None


def _ipv6_extension_header(buf: bytes, pos: int, end: int,
                           kind: int) -> Optional[Tuple[int, int]]:
    """``(next_header, end of header)`` of one walked header, None if cut short."""
    if kind == IPV6_FRAGMENT:
        if pos + 8 > end:
            return None
        if _U16(buf, pos + 2)[0] >> 3:
            return IPV6_NO_NEXT_HEADER, pos + 8  # non-first fragment
        return buf[pos], pos + 8
    if pos + 2 > end:
        return None
    header_end = pos + (buf[pos + 1] + 1) * 8
    return (buf[pos], header_end) if header_end <= end else None


def _classify_non_tcp(buf: bytes, proto: int, l4_off: int) -> str:
    """Verdict for a non-TCP IP payload: skip it, or let scapy look for TCP inside."""
    if proto == IPPROTO_UDP:
        if len(buf) < l4_off + 4:
            return _IP_FALLBACK
        sport, dport = _U16(buf, l4_off)[0], _U16(buf, l4_off + 2)[0]
        if sport in TUNNEL_UDP_PORTS or dport in TUNNEL_UDP_PORTS:
            return _IP_FALLBACK
        return _SKIP
    if proto in NON_TCP_PROTOCOLS:
        return _SKIP
    return _IP_FALLBACK  # tunnels, extension headers, anything unusual


def _decode_tcp(buf: bytes, start: int, end: int, family: str,
                src: str, dst: str, ts: float):
    region_len = min(end, len(buf)) - start
    if region_len < 20:
        return _IP_FALLBACK
    header_len = (buf[start + 12] >> 4) * 4
    if header_len < 20 or header_len > region_len:
        return _IP_FALLBACK  # scapy has its own repair rules for these
    sport, dport, seq = _TCP_PORTS_SEQ(buf, start)
    flags = buf[start + 13]
    payload = buf[start + header_len:end]
    return (family, src, sport, dst, dport, seq, payload,
            bool(flags & 0x02), bool(flags & 0x01), ts)


_IP_DECODERS = {4: _decode_ipv4, 6: _decode_ipv6}


# --- scapy fallback ----------------------------------------------------------------

def _scapy_link_class(linktype: int):
    """The class scapy's PcapReader would dissect *linktype* with."""
    import scapy.layers.inet  # noqa: F401 - registers raw-IP link types
    import scapy.layers.inet6  # noqa: F401
    from scapy.config import conf

    return conf.l2types.num2layer.get(linktype, conf.raw_layer)


def _scapy_ip_class(version: int):
    if version == 6:
        from scapy.layers.inet6 import IPv6

        return IPv6
    from scapy.layers.inet import IP

    return IP


def _run_fallback(cls, data: bytes, ts: float, fallback: ScapyFallback) -> Optional[Segment]:
    """Dissect *data* as *cls* like scapy's PcapReader (failure -> Raw -> no TCP)."""
    try:
        pkt = cls(data)
    except Exception:  # noqa: BLE001 - PcapReader degrades to Raw, which has no TCP
        return None
    pkt.time = ts
    return fallback(pkt)


# --- timestamps -------------------------------------------------------------------------

@lru_cache(maxsize=None)
def _is_power_of_ten(value: int) -> bool:
    if value <= 0:
        return False
    while value % 10 == 0:
        value //= 10
    return value == 1


def _pcapng_time(meta) -> float:
    """``float(pkt.time)`` exactly as scapy's PcapNgReader computes it."""
    if meta.tshigh is None:
        return 0.0  # simple packet block: no timestamp
    ticks = (meta.tshigh << 32) + meta.tslow
    resolution = meta.tsresol
    if _is_power_of_ten(resolution):
        return ticks / resolution  # exact rational, correctly rounded
    return float(Decimal(ticks) / Decimal(resolution))


def _packet_clock(reader) -> Callable[[Any], float]:
    """Per-record timestamp function for *reader* (pcap or pcapng)."""
    if hasattr(reader, "interfaces"):
        return _pcapng_time
    divisor = 10 ** 9 if getattr(reader, "nano", False) else 10 ** 6

    def pcap_time(meta) -> float:
        return (meta.sec * divisor + meta.usec) / divisor

    return pcap_time


def _open_raw_reader(path: str):
    from scapy.utils import RawPcapReader

    return RawPcapReader(path)  # falls over to RawPcapNgReader by magic


# --- public API ----------------------------------------------------------------------

def iter_tcp_segments(
    path: str,
    fallback: ScapyFallback,
    stats: Optional[ParseStats] = None,
) -> Iterator[Segment]:
    """Yield every TCP segment of the capture at *path*, in file order.

    *fallback* dissects the rare packets this module leaves to scapy; *stats*
    (optional) collects the decode counters.
    """
    stats = stats if stats is not None else ParseStats()
    with _open_raw_reader(path) as reader:
        clock = _packet_clock(reader)
        file_linktype = getattr(reader, "linktype", None)
        for buf, meta in reader:
            stats.packets += 1
            linktype = getattr(meta, "linktype", file_linktype)
            segment = _decode_packet(linktype, buf, clock(meta), fallback, stats)
            if segment is not None:
                yield segment
    logger.debug("pcap_fast %s: %s", path, stats)


def _decode_packet(linktype, buf: bytes, ts: float,
                   fallback: ScapyFallback, stats: ParseStats) -> Optional[Segment]:
    link_decoder = _LINK_DECODERS.get(linktype)
    link = link_decoder(buf) if link_decoder is not None else _LINK_FALLBACK
    if link == _SKIP:
        stats.skipped += 1
        return None
    if link == _LINK_FALLBACK:
        stats.link_fallbacks += 1
        return _counted(_run_fallback(_scapy_link_class(linktype), buf, ts, fallback), stats)
    version, off = link
    result = _IP_DECODERS[version](buf, off, ts)
    if result == _SKIP:
        stats.skipped += 1
        return None
    if result == _IP_FALLBACK:
        stats.ip_fallbacks += 1
        return _counted(_run_fallback(_scapy_ip_class(version), buf[off:], ts, fallback), stats)
    stats.fast_segments += 1
    return result


def _counted(segment: Optional[Segment], stats: ParseStats) -> Optional[Segment]:
    if segment is not None:
        stats.fallback_segments += 1
    return segment


def first_packet_time(path: str) -> float:
    """Capture time of the first record in *path*, identical to scapy's ``float(pkt.time)``.

    Returns ``0.0`` for a capture without records. Unreadable files raise (the
    caller decides how to degrade).
    """
    with _open_raw_reader(path) as reader:
        clock = _packet_clock(reader)
        for _buf, meta in reader:
            return clock(meta)
    return 0.0


# --- UDP presence probe ---------------------------------------------------------------

IPPROTO_ICMP = 1
IPPROTO_IGMP = 2
IPPROTO_ICMPV6 = 58
#: ICMP echo request/reply quote no packet (unlike the error types).
ICMP_ECHO_TYPES = frozenset({0, 8})
#: ICMPv6 types >= 128 are informational (echo, NDP, MLD) and quote no packet.
ICMPV6_FIRST_INFO_TYPE = 128
#: IPv6 extension headers with the generic (next header, length in 8-byte units)
#: layout: hop-by-hop, routing, destination options.
IPV6_GENERIC_EXT_HEADERS = frozenset({0, 43, 60})


def _ipv4_may_carry_udp(buf: bytes, off: int) -> bool:
    """False only for an IPv4 packet that certainly holds no UDP datagram."""
    if len(buf) < off + 20:
        return True
    proto = buf[off + 9]
    if proto in (IPPROTO_TCP, IPPROTO_IGMP):
        return False
    l4 = off + (buf[off] & 0x0F) * 4
    return not (proto == IPPROTO_ICMP and len(buf) > l4
                and buf[l4] in ICMP_ECHO_TYPES)


def _ipv6_may_carry_udp(buf: bytes, off: int) -> bool:
    """False only for an IPv6 packet that certainly holds no UDP datagram.

    Walks the generic extension headers (hop-by-hop, routing, destination
    options), so MLD reports behind a hop-by-hop header are recognised.
    """
    if len(buf) < off + 40:
        return True
    next_header, pos = buf[off + 6], off + 40
    while next_header in IPV6_GENERIC_EXT_HEADERS and len(buf) >= pos + 2:
        next_header, pos = buf[pos], pos + (buf[pos + 1] + 1) * 8
    if next_header == IPPROTO_TCP:
        return False
    return not (next_header == IPPROTO_ICMPV6 and len(buf) > pos
                and buf[pos] >= ICMPV6_FIRST_INFO_TYPE)


_IP_UDP_PROBES = {4: _ipv4_may_carry_udp, 6: _ipv6_may_carry_udp}


def _record_may_carry_udp(linktype, buf: bytes) -> bool:
    link_decoder = _LINK_DECODERS.get(linktype)
    link = link_decoder(buf) if link_decoder is not None else None
    if link == _SKIP:
        return False
    return not isinstance(link, tuple) or _IP_UDP_PROBES[link[0]](buf, link[1])


def capture_may_carry_udp(path: str) -> bool:
    """Conservatively tell whether the capture at *path* may hold any UDP datagram.

    False only when every record decodes to a non-IP frame or to an IP packet
    that certainly carries no UDP (TCP, IGMP, ICMP echo, informational ICMPv6).
    Anything undecodable (an unknown link type, a tunnel, a fragment chain, an
    unreadable file) counts as "may carry UDP". Stops at the first such record.
    """
    try:
        with _open_raw_reader(path) as reader:
            file_linktype = getattr(reader, "linktype", None)
            for buf, meta in reader:
                if _record_may_carry_udp(getattr(meta, "linktype", file_linktype), buf):
                    return True
    except Exception:
        logger.debug("UDP probe failed for %s; assuming UDP", path, exc_info=True)
        return True
    return False
