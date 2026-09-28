"""Mixed-linktype full capture (--loopback) must yield a parseable pcap.

With --loopback, the primary NIC (Ethernet) and the loopback adapter
(DLT_NULL on macOS lo0 / Windows Npcap) share one classic pcap whose single
linktype is fixed by the first packet. Minority-linktype packets must be
normalized to the file's linktype, not stored raw (which parses as garbage).
"""

import logging
import types

import pytest

scapy_all = pytest.importorskip("scapy.all")

from scapy.layers.inet import IP, TCP  # noqa: E402
from scapy.layers.inet6 import IPv6  # noqa: E402
from scapy.layers.l2 import ARP, Ether, Loopback  # noqa: E402
from scapy.utils import rdpcap, wrpcap  # noqa: E402

from friTap.pcap import (  # noqa: E402
    PCAP,
    _existing_pcap_linktype,
    _normalize_to_linktype,
)

BSD_AF_INET = 2
DARWIN_AF_INET6 = 30


def _make_capture_thread(tmp_path):
    stub = types.SimpleNamespace(
        pcap_file_name=str(tmp_path / "capture.pcap"),
        is_Mobile=False,
        logger=logging.getLogger("test_pcap_loopback_linktype"),
    )
    return PCAP.get_instance_of_FullCaptureThread(stub)


def _ether_ipv4():
    return (Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02")
            / IP(src="192.168.1.10", dst="93.184.216.34")
            / TCP(sport=50000, dport=443))


def _loopback_ipv4():
    return (Loopback(type=BSD_AF_INET) / IP(src="127.0.0.1", dst="127.0.0.1")
            / TCP(sport=50001, dport=8443))


def _loopback_ipv6():
    return (Loopback(type=DARWIN_AF_INET6) / IPv6(src="::1", dst="::1")
            / TCP(sport=50002, dport=9443))


def _assert_ip(pkt, layer, src, dst, sport, dport):
    assert pkt.haslayer(layer), pkt.summary()
    assert (pkt[layer].src, pkt[layer].dst) == (src, dst)
    assert (pkt[TCP].sport, pkt[TCP].dport) == (sport, dport)


def test_mixed_ether_and_loopback_packets_all_parse_as_ip(tmp_path):
    thread = _make_capture_thread(tmp_path)
    for pkt in (_ether_ipv4(), _loopback_ipv4(), _loopback_ipv6()):
        thread.write_packet_to_pcap(pkt)

    packets = rdpcap(thread.tmp_pcap_name)

    assert len(packets) == 3
    assert all(isinstance(p, Ether) for p in packets)
    _assert_ip(packets[0], IP, "192.168.1.10", "93.184.216.34", 50000, 443)
    _assert_ip(packets[1], IP, "127.0.0.1", "127.0.0.1", 50001, 8443)
    _assert_ip(packets[2], IPv6, "::1", "::1", 50002, 9443)


def test_packets_of_file_linktype_are_written_unchanged(tmp_path):
    thread = _make_capture_thread(tmp_path)
    original = _ether_ipv4()
    thread.write_packet_to_pcap(original)

    assert bytes(rdpcap(thread.tmp_pcap_name)[0]) == bytes(original)


def test_loopback_first_file_keeps_loopback_linktype(tmp_path):
    thread = _make_capture_thread(tmp_path)
    thread.write_packet_to_pcap(_loopback_ipv4())
    thread.write_packet_to_pcap(_loopback_ipv6())

    packets = rdpcap(thread.tmp_pcap_name)

    assert all(isinstance(p, Loopback) for p in packets)
    _assert_ip(packets[1], IPv6, "::1", "::1", 50002, 9443)


def test_unrepresentable_packet_is_dropped_not_corrupted(tmp_path):
    thread = _make_capture_thread(tmp_path)
    thread.write_packet_to_pcap(_loopback_ipv4())
    thread.write_packet_to_pcap(_ether_ipv4())  # Ether into a DLT_NULL file

    packets = rdpcap(thread.tmp_pcap_name)

    assert len(packets) == 1
    assert thread._warned_linktype_drop is True


def test_append_to_existing_file_uses_its_header_linktype(tmp_path):
    thread = _make_capture_thread(tmp_path)
    wrpcap(thread.tmp_pcap_name, _ether_ipv4())

    thread.write_packet_to_pcap(_loopback_ipv4())

    packets = rdpcap(thread.tmp_pcap_name)
    assert len(packets) == 2
    _assert_ip(packets[1], IP, "127.0.0.1", "127.0.0.1", 50001, 8443)


def test_existing_pcap_linktype_reads_header(tmp_path):
    ether_file = tmp_path / "ether.pcap"
    null_file = tmp_path / "null.pcap"
    wrpcap(str(ether_file), _ether_ipv4())
    wrpcap(str(null_file), _loopback_ipv4())

    assert _existing_pcap_linktype(str(ether_file)) == 1
    assert _existing_pcap_linktype(str(null_file)) == 0
    assert _existing_pcap_linktype(str(tmp_path / "missing.pcap")) is None


def test_normalize_preserves_timestamp_and_drops_non_ip():
    pkt = _loopback_ipv4()
    pkt.time = 1234.5

    assert _normalize_to_linktype(pkt, 1).time == 1234.5
    assert _normalize_to_linktype(Loopback() / ARP(), 1) is None
