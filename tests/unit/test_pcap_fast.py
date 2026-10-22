"""pcap_fast: the scapy-free TCP segment parser.

Three groups:

* agreement: synthetic captures for every link type and edge case, where the
  fast parser must yield exactly what the legacy scapy parser yields;
* divergence: the deliberate differences (no link padding as payload,
  platform-independent loopback, link type 14, simple packet blocks);
* mechanics: fallback counters, the ``FRITAP_PCAP_PARSER`` opt-out, and a
  guard that the tunnel/skip tables still match scapy's live bindings.
"""

from __future__ import annotations

import struct

import pytest

pytest.importorskip("scapy.all")

import scapy.all  # noqa: E402,F401 - load every default layer binding
from scapy.layers.inet import (  # noqa: E402
    GRE,
    ICMP,
    IP,
    TCP,
    UDP,
    IPerror,
    IPOption_Router_Alert,
    IPOption_RR,
    TCPerror,
)
from scapy.layers.inet6 import (  # noqa: E402
    ICMPv6DestUnreach,
    ICMPv6EchoRequest,
    ICMPv6MLReport2,
    IPerror6,
    IPv6,
    IPv6ExtHdrDestOpt,
    IPv6ExtHdrFragment,
    IPv6ExtHdrHopByHop,
    IPv6ExtHdrRouting,
    RouterAlert,
)
from scapy.layers.l2 import (  # noqa: E402
    ARP,
    LLC,
    SNAP,
    CookedLinux,
    CookedLinuxV2,
    Dot1AD,
    Dot1Q,
    Ether,
    Loopback,
    LoopbackOpenBSD,
)
from scapy.layers.ppp import PPP, PPPoE  # noqa: E402
from scapy.layers.vxlan import VXLAN  # noqa: E402
from scapy.packet import Padding, Raw  # noqa: E402

from friTap.offline.net import pcap_fast, tcp_reassembly  # noqa: E402
from friTap.offline.net.pcap_fast import (  # noqa: E402
    NON_TCP_PROTOCOLS,
    SLL_UNBOUND_PROTOCOLS,
    TUNNEL_UDP_PORTS,
    ParseStats,
    first_packet_time,
    iter_tcp_segments,
)
from friTap.offline.net.tcp_reassembly import (  # noqa: E402
    _iter_scapy_segments,
    _scapy_fallback_segment,
    _scapy_segment,
    parse_pcap,
    parse_pcap_scapy,
)

C4, S4 = "10.0.0.1", "93.184.216.34"
C6, S6 = "2001:db8::1", "2001:db8::2"
MAC = dict(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
BASE_SEC = 1_700_000_000


# --- capture writers ---------------------------------------------------------------

def write_pcap(path, linktype, frames, nano=False):
    """Classic little-endian pcap; frame i gets a distinct, sub-second timestamp."""
    with open(path, "wb") as f:
        magic = 0xA1B23C4D if nano else 0xA1B2C3D4
        f.write(struct.pack("<IHHiIII", magic, 2, 4, 0, 0, 0xFFFF, linktype))
        for i, frame in enumerate(frames):
            data = bytes(frame)
            frac = (123_457 * (i + 1)) % 1_000_000
            if nano:
                frac = frac * 1000 + 789
            f.write(struct.pack("<IIII", BASE_SEC + i, frac, len(data), len(data)))
            f.write(data)
    return str(path)


def _block(block_type, body):
    body += b"\0" * (-len(body) % 4)
    total = len(body) + 12
    return struct.pack("<II", block_type, total) + body + struct.pack("<I", total)


def _idb(linktype, tsresol_code=None):
    options = b""
    if tsresol_code is not None:
        options = struct.pack("<HH", 9, 1) + bytes([tsresol_code]) + b"\0\0\0"
        options += struct.pack("<HH", 0, 0)
    return _block(1, struct.pack("<HHI", linktype, 0, 0xFFFF) + options)


def _epb(ifid, ticks, data):
    data = bytes(data)
    head = struct.pack("<IIIII", ifid, ticks >> 32, ticks & 0xFFFFFFFF, len(data), len(data))
    return _block(6, head + data)


def _spb(data):
    data = bytes(data)
    return _block(3, struct.pack("<I", len(data)) + data)


def write_pcapng(path, interfaces, records):
    """*interfaces*: [(linktype, tsresol_code|None)]; *records*: [(ifid, ticks, frame)]
    or ("spb", frame)."""
    shb = _block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    with open(path, "wb") as f:
        f.write(shb)
        for linktype, code in interfaces:
            f.write(_idb(linktype, code))
        for rec in records:
            f.write(_spb(rec[1]) if rec[0] == "spb" else _epb(*rec))
    return str(path)


def fast(path, stats=None):
    return list(iter_tcp_segments(path, _scapy_segment, stats))


def legacy(path):
    return list(_iter_scapy_segments(path))


# --- frame builders --------------------------------------------------------------

def tcp4(payload=b"", flags="PA", sport=50000, dport=443, seq=1000):
    return IP(src=C4, dst=S4) / TCP(sport=sport, dport=dport, seq=seq, flags=flags) / payload


def tcp6(payload=b"", flags="PA", sport=50000, dport=443, seq=1000):
    return IPv6(src=C6, dst=S6) / TCP(sport=sport, dport=dport, seq=seq, flags=flags) / payload


def eth(l3):
    if isinstance(l3, (bytes, bytearray)):  # hand-mangled header: set the type
        return Ether(type=0x86DD if l3[0] >> 4 == 6 else 0x0800, **MAC) / Raw(bytes(l3))
    return Ether(**MAC) / l3


def conversation4():
    return [tcp4(flags="S", seq=99), tcp4(b"hello", seq=100), tcp4(b"world", seq=105),
            tcp4(flags="FA", seq=110)]


def conversation6():
    return [tcp6(flags="S", seq=99), tcp6(b"hello6", seq=100), tcp6(flags="FA", seq=106)]


def truncated(frame, keep):
    return bytes(frame)[:keep]


def with_tcp_dataofs(l3, dataofs):
    raw = bytearray(bytes(l3))
    ihl = (raw[0] & 0x0F) * 4
    raw[ihl + 12] = (dataofs << 4) | (raw[ihl + 12] & 0x0F)
    return bytes(raw)


def with_ihl(l3, ihl):
    raw = bytearray(bytes(l3))
    raw[0] = 0x40 | ihl
    return bytes(raw)


def ip4_router_alert(proto=2):
    return IP(src=C4, dst=S4, proto=proto, options=[IPOption_Router_Alert()])


def ip6(**fields):
    return IPv6(**{"src": C6, "dst": S6, **fields})


def hbh_router_alert():
    return IPv6ExtHdrHopByHop(options=[RouterAlert()])


def hop_by_hop_cut_by_payload_length():
    """Hop-by-hop header claiming 16 bytes inside an 8-byte IPv6 payload."""
    raw = bytearray(bytes(ip6() / IPv6ExtHdrHopByHop(nh=58, len=1, autopad=0) / (b"\x01\x0c" + bytes(12))))
    raw[4:6] = (8).to_bytes(2, "big")
    return bytes(raw)


# Each case: linktype, frames, number of TCP segments the legacy parser finds.
AGREEMENT_CASES = {
    "ethernet_ipv4": (1, [eth(f) for f in conversation4()], 4),
    "ethernet_ipv6": (1, [eth(f) for f in conversation6()], 3),
    "vlan": (1, [Ether(**MAC) / Dot1Q(vlan=7) / f for f in conversation4()], 4),
    "qinq": (1, [Ether(**MAC) / Dot1AD(vlan=1) / Dot1Q(vlan=2) / f for f in conversation6()], 3),
    "sll_ipv4": (113, [CookedLinux(proto=0x0800) / f for f in conversation4()], 4),
    "sll_ipv6": (113, [CookedLinux(proto=0x86DD) / f for f in conversation6()], 3),
    "sll2": (276, [CookedLinuxV2(proto=0x0800) / f for f in conversation4()], 4),
    "raw_101_mixed": (101, conversation4() + conversation6(), 7),
    "raw_12": (12, conversation4(), 4),
    "ipv4_228": (228, conversation4(), 4),
    "ipv6_229": (229, conversation6(), 3),
    "null_af_inet": (0, [Loopback(type=2) / f for f in conversation4()], 4),
    "null_af_zero": (0, [Loopback(type=0) / f for f in conversation4()], 4),
    "loop_108_af_inet": (108, [LoopbackOpenBSD(type=2) / f for f in conversation4()], 4),
    "ipv4_options": (1, [eth(IP(src=C4, dst=S4, options=[IPOption_RR()]) / TCP(seq=5) / b"opt")], 1),
    "first_fragment_is_tcp": (1, [eth(IP(src=C4, dst=S4, flags="MF", frag=0) / TCP(seq=7) / b"frag0")], 1),
    "later_fragment_skipped": (1, [eth(IP(src=C4, dst=S4, proto=6, frag=3) / bytes(TCP() / b"xxxx"))], 0),
    "tso_total_length_zero": (1, [eth(IP(src=C4, dst=S4, len=0) / TCP(seq=9) / (b"T" * 3000))], 1),
    "tso_total_length_below_header": (1, [eth(IP(src=C4, dst=S4, len=12) / TCP(seq=9) / b"short")], 1),
    "snaplen_truncated_payload": (1, [truncated(eth(tcp4(b"P" * 200)), 14 + 20 + 20 + 50)], 1),
    "ip_length_beyond_capture": (1, [truncated(eth(tcp4(b"Q" * 64)), 14 + 20 + 20 + 10)], 1),
    "ipv6_plen_zero": (1, [eth(IPv6(src=C6, dst=S6, plen=0) / TCP() / b"jumbo?")], 0),
    "ipv6_hop_by_hop": (1, [eth(IPv6(src=C6, dst=S6) / IPv6ExtHdrHopByHop() / TCP(seq=3) / b"hbh")], 1),
    "ipv6_fragment_header": (1, [eth(IPv6(src=C6, dst=S6) / IPv6ExtHdrFragment(m=1) / TCP() / b"f")], 1),
    "gre": (1, [eth(IP(src="1.1.1.1", dst="2.2.2.2") / GRE() / tcp4(b"in-gre"))], 1),
    "ip_in_ip": (1, [eth(IP(src="1.1.1.1", dst="2.2.2.2") / tcp4(b"ipip"))], 1),
    "ipv6_in_ipv4": (1, [eth(IP(src="1.1.1.1", dst="2.2.2.2") / tcp6(b"6in4"))], 1),
    "ipv4_in_ipv6": (1, [eth(IPv6(src="::5", dst="::6") / tcp4(b"4in6"))], 1),
    "gre_in_udp": (1, [eth(IP(src="1.1.1.1", dst="2.2.2.2") / UDP(sport=1, dport=4754) / GRE() / tcp4(b"g"))], 1),
    "vxlan": (1, [eth(IP(src="1.1.1.1", dst="2.2.2.2") / UDP(sport=1, dport=4789) / VXLAN(vni=5)
                      / eth(tcp4(b"vx")))], 1),
    "plain_udp_skipped": (1, [eth(IP(src=C4, dst=S4) / UDP(sport=53, dport=5353) / bytes(TCP()))], 0),
    "pppoe_session": (1, [Ether(**MAC) / PPPoE(sessionid=1) / PPP(proto=0x0021) / tcp4(b"ppp")], 1),
    "llc_snap": (1, [Ether(**MAC) / LLC(dsap=0xAA, ssap=0xAA, ctrl=3) / SNAP(code=0x0800)
                     / tcp4(b"snap")], 1),
    "arp_skipped": (1, [Ether(**MAC) / ARP()], 0),
    "icmp_quoting_tcp": (1, [eth(IP(src=C4, dst=S4) / ICMP(type=3) / IPerror(src=S4, dst=C4) / TCPerror())], 0),
    "icmpv6_quoting_tcp": (1, [eth(IPv6(src=C6, dst=S6) / ICMPv6DestUnreach() / IPerror6() / TCPerror())], 0),
    "short_ethernet_frame": (1, [b"\x02\x00\x00\x00\x00\x01\x02"], 0),
    "ethertype_ipv4_carrying_ipv6": (1, [Ether(type=0x0800, **MAC) / tcp6(b"liar")], 0),
    "tcp_dataofs_below_five": (1, [eth(with_tcp_dataofs(tcp4(b"abcdefgh"), 3))], 1),
    "tcp_dataofs_beyond_segment": (1, [eth(with_tcp_dataofs(tcp4(b"abc"), 15))], 1),
    "ipv4_ihl_below_five": (1, [eth(with_ihl(tcp4(b"x"), 4))], 0),
    "ipv4_header_truncated": (1, [truncated(eth(tcp4(b"x")), 14 + 10)], 0),
    "tcp_header_truncated": (1, [truncated(eth(tcp4(b"x")), 14 + 20 + 12)], 0),
    "unknown_linktype": (147, conversation4(), 0),
    "padding_after_payload": (1, [eth(tcp4(b"abc")) / Padding(b"\0" * 10)], 1),
    "port_443_tls_record": (1, [eth(tcp4(bytes.fromhex("170303000a") + b"0123456789"))], 1),
    "port_443_garbage": (1, [eth(tcp4(b"\x16\x03\x01\xff\xffnot really tls"))], 1),
    # Pre-checks: provably TCP-free packets are skipped without scapy.
    "igmp_with_router_alert": (1, [eth(ip4_router_alert() / bytes.fromhex("1600fa0ae0000016"))], 0),
    "ipv4_options_plain_udp": (1, [eth(ip4_router_alert(17) / UDP(sport=53, dport=5353) / b"x")], 0),
    "ipv4_options_udp_tunnel": (1, [eth(ip4_router_alert(17) / UDP(sport=1, dport=4789) / VXLAN(vni=5)
                                        / eth(tcp4(b"vx-opt")))], 1),
    "ipv4_options_tcp": (1, [eth(ip4_router_alert(6) / TCP(seq=4) / b"opt-tcp")], 1),
    "mld_report_hop_by_hop": (1, [eth(ip6(dst="ff02::16") / hbh_router_alert() / ICMPv6MLReport2())], 0),
    "dest_opts_icmpv6": (1, [eth(ip6() / IPv6ExtHdrDestOpt() / ICMPv6EchoRequest())], 0),
    "hop_by_hop_dest_opts_udp": (1, [eth(ip6() / IPv6ExtHdrHopByHop() / IPv6ExtHdrDestOpt()
                                         / UDP(sport=53, dport=53) / b"u")], 0),
    "hop_by_hop_udp_tunnel": (1, [eth(ip6() / hbh_router_alert() / UDP(sport=1, dport=4789)
                                      / VXLAN(vni=5) / eth(tcp4(b"vx6")))], 1),
    "hop_by_hop_dest_opts_tcp": (1, [eth(ip6() / hbh_router_alert() / IPv6ExtHdrDestOpt()
                                         / TCP(seq=8) / b"chain")], 1),
    "hop_by_hop_routing_tcp": (1, [eth(ip6() / IPv6ExtHdrHopByHop() / IPv6ExtHdrRouting()
                                       / TCP(seq=8) / b"rt")], 1),
    "hop_by_hop_cut_by_payload_length": (1, [eth(hop_by_hop_cut_by_payload_length())], 0),
    "hop_by_hop_jumbo_payload_length_zero": (1, [eth(ip6(plen=0) / IPv6ExtHdrHopByHop() / TCP() / b"j")], 0),
    "ipv6_non_first_fragment": (1, [eth(ip6() / IPv6ExtHdrFragment(nh=6, offset=181) / bytes(TCP() / b"f"))], 0),
    "ipv6_first_fragment_udp": (1, [eth(ip6() / IPv6ExtHdrFragment(m=1) / UDP(sport=53, dport=53) / b"f")], 0),
    "sll_llc_802_2": (113, [CookedLinux(proto=0x0004) / bytes.fromhex("aaaa030000000800") / tcp4(b"x")], 0),
    "sll2_llc_802_2": (276, [CookedLinuxV2(proto=0x0004) / bytes.fromhex("0001af81") / tcp4(b"x")], 0),
}


#: Cases that must reach scapy; every other case must stay on the fast path.
FALLBACK_CASES = {
    "ethertype_ipv4_carrying_ipv6", "gre", "gre_in_udp", "ip_in_ip", "ipv4_header_truncated",
    "ipv4_ihl_below_five", "ipv4_in_ipv6", "ipv4_options", "ipv6_fragment_header",
    "ipv6_hop_by_hop", "ipv6_in_ipv4", "llc_snap", "pppoe_session", "short_ethernet_frame",
    "tcp_dataofs_below_five", "tcp_dataofs_beyond_segment", "tcp_header_truncated",
    "unknown_linktype", "vxlan",
    "ipv4_options_udp_tunnel", "ipv4_options_tcp", "hop_by_hop_udp_tunnel", "hop_by_hop_dest_opts_tcp",
    "hop_by_hop_routing_tcp", "hop_by_hop_cut_by_payload_length", "hop_by_hop_jumbo_payload_length_zero",
}


@pytest.mark.parametrize("case", sorted(AGREEMENT_CASES))
def test_fast_parser_agrees_with_scapy(tmp_path, case):
    linktype, frames, expected = AGREEMENT_CASES[case]
    path = write_pcap(tmp_path / f"{case}.pcap", linktype, frames)
    stats = ParseStats()
    got = fast(path, stats)
    assert got == legacy(path)
    assert len(got) == expected
    assert (stats.fallbacks > 0) == (case in FALLBACK_CASES)


def test_nanosecond_pcap_timestamps_agree(tmp_path):
    path = write_pcap(tmp_path / "nano.pcap", 1, [eth(f) for f in conversation4()], nano=True)
    assert fast(path) == legacy(path)
    assert first_packet_time(path) == float(next(iter(scapy.all.PcapReader(path))).time)


@pytest.mark.parametrize("tsresol_code", [None, 9, 3, 0x80 | 20, 0x80 | 30])
def test_pcapng_timestamps_and_linktypes_agree(tmp_path, tsresol_code):
    ticks = 1_700_000_000_123_456_789_123 >> 10
    records = [(0, ticks + i * 7919, eth(f)) for i, f in enumerate(conversation4())]
    records += [(1, ticks + 99991 + i, f) for i, f in enumerate(conversation6())]
    path = write_pcapng(tmp_path / "t.pcapng", [(1, tsresol_code), (101, tsresol_code)], records)
    got = fast(path)
    assert got == legacy(path)
    assert len(got) == 7
    with scapy.all.PcapNgReader(path) as reader:
        assert first_packet_time(path) == float(next(iter(reader)).time)


def test_first_packet_time_of_empty_capture_is_zero(tmp_path):
    path = write_pcap(tmp_path / "empty.pcap", 1, [])
    assert first_packet_time(path) == 0.0
    assert fast(path) == []


def test_first_packet_time_matches_scapy_for_classic_pcap(tmp_path):
    path = write_pcap(tmp_path / "f.pcap", 113, [CookedLinux(proto=0x0806) / ARP()])
    assert first_packet_time(path) == float(next(iter(scapy.all.PcapReader(path))).time)


def test_parse_pcap_builds_the_same_state_as_the_scapy_parser(tmp_path):
    frames = [eth(f) for f in conversation4() + conversation6()]
    frames += [eth(IP(src="1.1.1.1", dst="2.2.2.2") / GRE() / tcp4(b"tunnel", sport=1, seq=5))]
    path = write_pcap(tmp_path / "mixed.pcap", 1, frames)

    def state(parsed):
        return [(key, b.family, b._endpoints, b._first_payload_src, b._dst_ports,
                 [(ep, r._anchor, r._saw_syn, r._segments, r._seq_ts, r.contiguous_bytes(),
                   r.degraded) for ep, r in b._reasm.items()])
                for key, b in parsed._builders.items()]

    assert state(parse_pcap(path)) == state(parse_pcap_scapy(path))


# --- deliberate divergences ------------------------------------------------------------

def test_empty_segment_does_not_return_link_padding(tmp_path):
    frames = [eth(tcp4(flags="A", seq=50)) / Padding(b"\0" * 6),
              eth(tcp6(flags="A", seq=60)) / Padding(b"\xaa" * 6)]
    path = write_pcap(tmp_path / "pad.pcap", 1, frames)
    old, new = legacy(path), fast(path)
    assert [seg[6] for seg in old] == [b"\0" * 6, b"\xaa" * 6]  # the legacy bug
    assert [seg[6] for seg in new] == [b"", b""]
    assert [seg[:6] + seg[7:] for seg in new] == [seg[:6] + seg[7:] for seg in old]


def test_padding_fix_keeps_phantom_bytes_out_of_the_stream(tmp_path):
    frames = [eth(tcp4(flags="S", seq=99)), eth(tcp4(b"data", seq=100)),
              eth(tcp4(flags="A", seq=104)) / Padding(b"\0" * 6)]
    path = write_pcap(tmp_path / "stream.pcap", 1, frames)
    (pair,) = parse_pcap(path).pairs((443,)).values()
    assert pair.client.contiguous_bytes() == b"data"
    (old_pair,) = parse_pcap_scapy(path).pairs((443,)).values()
    assert old_pair.client.contiguous_bytes() == b"data" + b"\0" * 6


def null_header(family, big_endian=False):
    return struct.pack(">I" if big_endian else "<I", family)


@pytest.mark.parametrize("family", [10, 24, 28, 30])
def test_null_loopback_ipv6_families_are_platform_independent(tmp_path, family):
    path = write_pcap(tmp_path / "lo6.pcap", 0, [null_header(family) + bytes(f) for f in conversation6()])
    got = fast(path)
    assert [(s[0], s[1], s[3], s[6]) for s in got] == [
        ("AF_INET6", C6, S6, b""), ("AF_INET6", C6, S6, b"hello6"), ("AF_INET6", C6, S6, b"")]


def test_loop_108_ipv6_family_is_decoded(tmp_path):
    path = write_pcap(tmp_path / "loop6.pcap", 108, [null_header(30, True) + bytes(tcp6(b"z"))])
    assert [s[6] for s in fast(path)] == [b"z"]


def test_big_endian_null_header_is_byte_swapped(tmp_path):
    path = write_pcap(tmp_path / "be.pcap", 0, [null_header(2, True) + bytes(tcp4(b"be"))])
    assert [(s[0], s[6]) for s in fast(path)] == [("AF_INET", b"be")]


@pytest.mark.parametrize("header,l3", [
    (null_header(2), tcp6(b"v6 under AF_INET")),
    (null_header(24), tcp4(b"v4 under AF_INET6")),
    (null_header(7), tcp4(b"unknown family")),
    (b"\x00\x1c\x42\x00", tcp4(b"ethernet mislabelled as NULL")),
    (b"\x02\x00", b""),
])
def test_null_loopback_mismatch_or_garbage_is_skipped(tmp_path, header, l3):
    path = write_pcap(tmp_path / "bad.pcap", 0, [header + bytes(l3)])
    stats = ParseStats()
    assert fast(path, stats) == []
    assert stats.skipped == 1 and stats.fallbacks == 0


def test_linktype_14_is_raw_ip(tmp_path):
    path = write_pcap(tmp_path / "raw14.pcap", 14, conversation4())
    assert [s[6] for s in fast(path)] == [b"", b"hello", b"world", b""]


def test_simple_packet_block_has_unknown_timestamp(tmp_path):
    path = write_pcapng(tmp_path / "spb.pcapng", [(1, None)], [("spb", eth(tcp4(b"spb")))])
    (seg,) = fast(path)
    assert seg[6] == b"spb" and seg[9] == 0.0
    assert first_packet_time(path) == 0.0


# --- mechanics ---------------------------------------------------------------------------

def test_fallback_counters_and_packet_time(tmp_path):
    frames = [eth(tcp4(b"fast")),
              eth(IP(src="1.1.1.1", dst="2.2.2.2") / GRE() / tcp4(b"ip-fallback")),
              Ether(**MAC) / PPPoE(sessionid=1) / PPP(proto=0x0021) / tcp4(b"link-fallback"),
              eth(IP(src=C4, dst=S4) / UDP(sport=5, dport=6))]
    path = write_pcap(tmp_path / "mech.pcap", 1, frames)
    seen_times = []

    def spy(pkt):
        seen_times.append(float(pkt.time))
        return _scapy_segment(pkt)

    stats = ParseStats()
    segments = list(iter_tcp_segments(path, spy, stats))
    assert [s[6] for s in segments] == [b"fast", b"ip-fallback", b"link-fallback"]
    assert (stats.packets, stats.fast_segments, stats.skipped) == (4, 1, 1)
    assert (stats.ip_fallbacks, stats.link_fallbacks, stats.fallback_segments) == (1, 1, 2)
    assert seen_times == [s[9] for s in segments[1:]]


def test_plain_tcp_never_touches_the_fallback(tmp_path):
    path = write_pcap(tmp_path / "plain.pcap", 1, [eth(f) for f in conversation4() + conversation6()])

    def forbidden(pkt):
        raise AssertionError("fallback used for plain TCP")

    assert len(list(iter_tcp_segments(path, forbidden))) == 7


def test_failing_scapy_dissection_degrades_to_no_segment(tmp_path, monkeypatch):
    class Exploding:
        def __init__(self, data):
            raise ValueError("boom")

    monkeypatch.setattr(pcap_fast, "_scapy_link_class", lambda linktype: Exploding)
    path = write_pcap(tmp_path / "boom.pcap", 1, [Ether(**MAC) / PPPoE() / PPP() / tcp4(b"x")])
    stats = ParseStats()
    assert fast(path, stats) == []
    assert stats.link_fallbacks == 1 and stats.fallback_segments == 0


@pytest.mark.parametrize("value", ["scapy", " SCAPY "])
def test_env_switch_selects_the_scapy_parser(tmp_path, monkeypatch, value):
    path = write_pcap(tmp_path / "env.pcap", 1, [eth(tcp4(b"x"))])
    monkeypatch.setenv(tcp_reassembly.PCAP_PARSER_ENV, value)
    monkeypatch.setattr(pcap_fast, "iter_tcp_segments",
                        lambda *a, **k: pytest.fail("fast parser used despite opt-out"))
    assert len(parse_pcap(path)) == 1


@pytest.mark.parametrize("value", [None, "", "fast"])
def test_fast_parser_is_the_default(tmp_path, monkeypatch, value):
    path = write_pcap(tmp_path / "default.pcap", 1, [eth(tcp4(b"x"))])
    if value is None:
        monkeypatch.delenv(tcp_reassembly.PCAP_PARSER_ENV, raising=False)
    else:
        monkeypatch.setenv(tcp_reassembly.PCAP_PARSER_ENV, value)
    monkeypatch.setattr(tcp_reassembly, "parse_pcap_scapy",
                        lambda p: pytest.fail("scapy parser used by default"))
    assert len(parse_pcap(path)) == 1


# --- guards against scapy's live bindings ----------------------------------------------

def _reaches_tcp(cls, seen=None):
    """True when scapy's payload bindings can lead from *cls* to a TCP layer."""
    import scapy.layers.inet6 as inet6

    seen = set() if seen is None else seen
    if isinstance(cls, str):
        cls = getattr(inet6, cls, None)
    if not isinstance(cls, type):
        return False  # dispatcher functions (DHCPv6) never yield TCP
    if cls is TCP:
        return True
    if cls in seen:
        return False
    seen.add(cls)
    if issubclass(cls, inet6._IPv6GuessPayload):
        return True  # IPv6 extension headers chain via ipv6nhcls (TCP included)
    for layer in getattr(cls, "aliastypes", None) or [cls]:
        if any(_reaches_tcp(nxt, seen) for _, nxt in layer.payload_guess):
            return True
    return False


def test_tunnel_udp_ports_cover_every_scapy_binding_that_reaches_tcp():
    reaching = {port for fields, cls in UDP.payload_guess if _reaches_tcp(cls)
                for name, port in fields.items() if name in ("sport", "dport")}
    assert reaching <= TUNNEL_UDP_PORTS, sorted(reaching - TUNNEL_UDP_PORTS)


def test_skipped_ip_protocols_never_reach_tcp_in_scapy():
    import scapy.layers.inet6 as inet6

    bound = [(fields.get("proto"), cls) for fields, cls in IP.payload_guess]
    bound += [(fields.get("nh"), cls) for fields, cls in IPv6.payload_guess]
    bound += list(inet6.ipv6nhcls.items())
    leaking = {proto for proto, cls in bound if proto in NON_TCP_PROTOCOLS and _reaches_tcp(cls)}
    assert not leaking


def test_raw_payload_class_contract():
    # tcp_payload's isinstance(Raw) check is what made scapy return padding.
    assert issubclass(Padding, Raw)


def test_sll_unbound_protocols_have_no_scapy_binding():
    from scapy.layers.l2 import CookedLinux, CookedLinuxV2

    for cls in (CookedLinux, CookedLinuxV2):
        bound = {fields.get("proto") for fields, _ in cls.payload_guess}
        assert not bound & SLL_UNBOUND_PROTOCOLS, (cls.__name__, bound & SLL_UNBOUND_PROTOCOLS)


def _random_extension_chain(rng):
    """IPv6 behind 1-3 random hop-by-hop / dest-opts / fragment headers."""
    kinds = [0, 60, 44]
    chain = [rng.choice(kinds) for _ in range(rng.randint(1, 3))]
    upper = rng.choice([6, 17, 58, 59, 43, 4])
    body = b""
    for kind, nh in reversed(list(zip(chain, chain[1:] + [upper]))):
        if kind == 44:
            offset = rng.choice([0, 0, rng.randint(1, 8191)])
            body = bytes([nh, 0]) + ((offset << 3) | rng.randint(0, 1)).to_bytes(2, "big") \
                + rng.randbytes(4) + body
        else:
            ext_len = rng.randint(0, 2)
            body = bytes([nh, ext_len]) + rng.randbytes((ext_len + 1) * 8 - 2) + body
    upper_bytes = bytes(TCP(sport=rng.randint(1, 65535), dport=443, seq=rng.randint(0, 2**32 - 1))
                        / rng.randbytes(rng.randint(0, 16)))
    if upper == 17:
        upper_bytes = bytes(UDP(sport=rng.randint(1, 65535), dport=rng.choice([53, 4789])) / b"u")
    payload = body + upper_bytes
    plen = len(payload) + rng.choice([0, 0, 0, -4, 3])  # sometimes cut or padded
    return eth(bytes(IPv6(src=C6, dst=S6, nh=chain[0], plen=max(plen, 0)) / payload))


def test_random_extension_chains_agree_with_scapy(tmp_path):
    import random

    rng = random.Random(0x16)
    frames = [_random_extension_chain(rng) for _ in range(400)]
    path = write_pcap(tmp_path / "chains.pcap", 1, frames)
    stats = ParseStats()
    assert fast(path, stats) == legacy(path)
    assert stats.skipped > 0 and stats.ip_fallbacks > 0  # both verdicts exercised


# --- fallback packets never return link padding --------------------------------------------

def _padded(frame, size=60):
    return frame if len(frame) >= size else frame / Padding(b"\0" * (size - len(frame)))


def _mpls(l3):
    from scapy.contrib.mpls import MPLS

    return Ether(type=0x8847, **MAC) / MPLS(label=16, s=1, ttl=64) / l3


def _fallback_padding_frames(wrap):
    def seg(payload, flags, seq):
        return _padded(wrap(TCP(sport=5000, dport=443, flags=flags, seq=seq) / payload))
    return [seg(b"", "S", 99), seg(b"", "A", 100), seg(b"hello", "PA", 100)]


FALLBACK_PADDING_CASES = {
    "mpls": lambda tcp: _mpls(IP(src=C4, dst=S4) / tcp),
    "ipv4_router_alert": lambda tcp: eth(IP(src=C4, dst=S4, options=[IPOption_Router_Alert()]) / tcp),
}


@pytest.mark.parametrize("case", sorted(FALLBACK_PADDING_CASES))
def test_fallback_segment_drops_padding_of_empty_segments(tmp_path, case):
    path = write_pcap(tmp_path / f"{case}.pcap", 1, _fallback_padding_frames(FALLBACK_PADDING_CASES[case]))
    stats = ParseStats()
    reference = list(iter_tcp_segments(path, _scapy_segment))
    fixed = list(iter_tcp_segments(path, _scapy_fallback_segment, stats))
    assert stats.fallbacks == 3
    assert [s[6] for s in reference] == [b"\0\0", b"\0\0", b"hello"]  # scapy's padding leak
    assert [s[6] for s in fixed] == [b"", b"", b"hello"]
    assert [s[:6] + s[7:] for s in fixed] == [s[:6] + s[7:] for s in reference]


@pytest.mark.parametrize("case", sorted(FALLBACK_PADDING_CASES))
def test_parse_pcap_keeps_fallback_padding_out_of_the_stream(tmp_path, case):
    path = write_pcap(tmp_path / f"{case}.pcap", 1, _fallback_padding_frames(FALLBACK_PADDING_CASES[case]))
    (pair,) = parse_pcap(path).pairs((443,)).values()
    assert pair.client._segments == {100: b"hello"}
    assert pair.client.contiguous_bytes() == b"hello"


def test_fallback_segment_keeps_real_payload_and_non_tcp():
    tcp_pkt = Ether(bytes(Ether(**MAC) / IP(src=C4, dst=S4, options=[IPOption_RR()]) / TCP(seq=1) / b"data"))
    assert _scapy_fallback_segment(tcp_pkt) == _scapy_segment(tcp_pkt)
    assert _scapy_fallback_segment(tcp_pkt)[6] == b"data"
    udp_pkt = Ether(bytes(Ether(**MAC) / IP(src=C4, dst=S4) / UDP()))
    assert _scapy_fallback_segment(udp_pkt) is None


# --- capture_may_carry_udp ----------------------------------------------------

def _write_udp_probe_pcap(path, packets):
    from scapy.utils import wrpcap

    wrpcap(str(path), packets)
    return str(path)


def _udp_probe_tcp_packet():
    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether

    return Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80) / b"hi"


def test_udp_probe_false_for_tcp_only_capture(tmp_path):
    from scapy.layers.inet import ICMP, IP
    from scapy.layers.inet6 import ICMPv6MLReport, IPv6, IPv6ExtHdrHopByHop
    from scapy.layers.l2 import ARP, Ether

    path = _write_udp_probe_pcap(tmp_path / "tcp.pcap", [
        _udp_probe_tcp_packet(),
        Ether() / ARP(),
        Ether() / IP(dst="10.0.0.2") / ICMP(type=8),
        Ether() / IPv6(dst="ff02::16") / IPv6ExtHdrHopByHop() / ICMPv6MLReport(),
    ])
    assert pcap_fast.capture_may_carry_udp(path) is False


def test_udp_probe_true_with_udp(tmp_path):
    from scapy.layers.inet import IP, UDP
    from scapy.layers.l2 import Ether

    path = _write_udp_probe_pcap(tmp_path / "udp.pcap", [
        _udp_probe_tcp_packet(),
        Ether() / IP(dst="10.0.0.2") / UDP(sport=5353, dport=443) / b"q",
    ])
    assert pcap_fast.capture_may_carry_udp(path) is True


def test_udp_probe_true_for_icmp_error_and_unreadable(tmp_path):
    from scapy.layers.inet import ICMP, IP, UDP
    from scapy.layers.l2 import Ether

    error = Ether() / IP() / ICMP(type=3) / IP() / UDP(dport=443)
    assert pcap_fast.capture_may_carry_udp(_write_udp_probe_pcap(tmp_path / "e.pcap", [error])) is True
    junk = tmp_path / "junk.pcap"
    junk.write_bytes(b"not a pcap")
    assert pcap_fast.capture_may_carry_udp(str(junk)) is True
    assert pcap_fast.capture_may_carry_udp(str(tmp_path / "missing.pcap")) is True
