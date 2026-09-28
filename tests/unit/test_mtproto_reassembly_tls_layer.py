"""Reassembly must keep port-443 payloads even when scapy's TLS layer is loaded.

Importing ``scapy.layers.tls`` (any test or code path may do it) binds TCP/443
to scapy's TLS dissector for the whole process. Payloads that look like TLS
records then land in TLS layers instead of ``Raw``; reassembly used to read
only ``pkt[Raw]`` and silently dropped them, which made the offline MTProto
golden tests fail intermittently depending on their random bytes.
"""

import pytest

scapy_all = pytest.importorskip("scapy.all")
pytest.importorskip("scapy.layers.tls.record")  # binds TCP/443 -> TLS

from scapy.all import IP, TCP, Ether, Padding, wrpcap  # noqa: E402

from friTap.offline.mtproto.reassembly import reassemble_pcap  # noqa: E402

CLIENT = ("10.0.0.5", 50000)
SERVER = ("149.154.167.51", 443)
# Starts like a TLS application-data record, then continues with opaque bytes.
TLS_LOOKING = b"\x17\x03\x03\x00\x05hello" + bytes(range(200))


def _seg(src, dst, seq, payload, *, flags="PA"):
    return IP(src=src[0], dst=dst[0]) / TCP(
        sport=src[1], dport=dst[1], seq=seq, flags=flags) / payload


def _client_stream(pcap_path):
    pairs = reassemble_pcap(str(pcap_path))
    assert len(pairs) == 1
    pair = next(iter(pairs.values()))
    return pair.client.contiguous_bytes()


def test_tls_looking_payload_on_443_is_kept(tmp_path):
    pkts = [
        _seg(CLIENT, SERVER, 1000, b"", flags="S"),
        _seg(CLIENT, SERVER, 1001, TLS_LOOKING),
    ]
    path = tmp_path / "tls_looking.pcap"
    wrpcap(str(path), pkts)
    assert _client_stream(path) == TLS_LOOKING


def test_link_layer_padding_is_trimmed(tmp_path):
    payload = b"\x16\x03\x01ab"  # short TLS-looking payload -> Ethernet pads it
    frame = Ether() / _seg(CLIENT, SERVER, 1001, payload) / Padding(b"\x00" * 10)
    syn = Ether() / _seg(CLIENT, SERVER, 1000, b"", flags="S")
    path = tmp_path / "padded.pcap"
    wrpcap(str(path), [syn, frame])
    assert _client_stream(path) == payload
