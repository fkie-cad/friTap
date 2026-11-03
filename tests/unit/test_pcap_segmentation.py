"""Oversized payloads and tampered endpoints in the plaintext (-p) pcap writers.

IP/UDP length fields are 16 bit: a datalog payload over ~64 KiB used to raise
``struct.error`` and silently vanish from the ``-p`` pcap, and an out-of-range
port or IPv4 int from a tampered agent message raised as well. Large payloads
are now split into contiguous segments; invalid endpoints drop the record
with a once-per-kind warning.
"""

from __future__ import annotations

import logging
import struct
import types
from unittest.mock import MagicMock, patch

import pytest

pytest.importorskip("scapy")
from scapy.layers.inet import IP, TCP, UDP  # noqa: E402
from scapy.layers.inet6 import IPv6  # noqa: E402
from scapy.utils import PcapReader  # noqa: E402

from friTap.constants import SSL_READ, SSL_WRITE  # noqa: E402
from friTap.pcap import PCAP  # noqa: E402
from friTap.sinks import tcp_state  # noqa: E402
from friTap.sinks.tcp_state import (  # noqa: E402
    TcpSessionTracker,
    build_framed_packet_from_fields,
    build_framed_packets_from_fields,
    max_segment_payload,
    split_payload,
)

_SRC4 = 0x0A000001          # 10.0.0.1
_DST4 = 0x0A000002          # 10.0.0.2
_SRC6 = "20010db8000000000000000000000001"
_DST6 = "20010db8000000000000000000000002"
_BIG = bytes(range(256)) * 800   # 204800 bytes, a 200 KB datalog
_READ = next(iter(SSL_READ))
_WRITE = next(iter(SSL_WRITE))


@pytest.fixture(autouse=True)
def _fresh_drop_warnings():
    tcp_state.reset_drop_warnings()
    yield
    tcp_state.reset_drop_warnings()


def _writer(tmp_path):
    """A PCAP stub writing a real pcap file (header + records) under tmp_path."""
    stub = types.SimpleNamespace()
    stub.logger = MagicMock()
    stub.SSL_READ = SSL_READ
    stub.SSL_WRITE = SSL_WRITE
    stub.ssl_sessions = {}
    stub._observed_server_ports = {"tcp": set(), "udp": set()}
    stub._record_server_port = PCAP._record_server_port.__get__(stub)
    stub._log_plaintext_payload_udp = PCAP._log_plaintext_payload_udp.__get__(stub)
    stub.log_plaintext_payload = PCAP.log_plaintext_payload.__get__(stub)
    path = tmp_path / "plain.pcap"
    stub.path = path
    stub.pcap_file = open(path, "wb")
    PCAP.write_pcap_header(stub, stub.pcap_file)
    return stub


def _packets(stub):
    stub.pcap_file.close()
    with PcapReader(str(stub.path)) as reader:
        return list(reader)


# ------------------------------------------------------------- helpers

class TestSegmentLimits:
    @pytest.mark.parametrize("family, transport, limit", [
        ("AF_INET", "tcp", 65535 - 20 - 20),
        ("AF_INET6", "tcp", 65535 - 40 - 20),
        ("AF_INET", "udp", 65535 - 20 - 8),
        ("AF_INET6", "udp", 65535 - 40 - 8),
    ])
    def test_limits_per_family(self, family, transport, limit):
        assert max_segment_payload(family, transport) == limit

    def test_split_keeps_every_byte(self):
        chunks = split_payload(_BIG, 65495)
        assert b"".join(chunks) == _BIG
        assert all(len(c) <= 65495 for c in chunks)

    def test_split_of_empty_payload_is_one_empty_segment(self):
        assert split_payload(b"", 100) == [b""]


# ---------------------------------------------------- legacy -p writer

class TestLegacyPcapWriter:
    @pytest.mark.parametrize("family, src, dst, ip_layer", [
        ("AF_INET", _SRC4, _DST4, IP),
        ("AF_INET6", _SRC6, _DST6, IPv6),
    ])
    def test_200k_tcp_datalog_becomes_contiguous_segments(
            self, tmp_path, family, src, dst, ip_layer):
        stub = _writer(tmp_path)
        stub.log_plaintext_payload(family, _WRITE, src, 51234, dst, 443, _BIG)
        packets = _packets(stub)

        assert len(packets) == 4
        tcps = [p[TCP] for p in packets]
        for prev, cur in zip(tcps, tcps[1:]):
            assert cur.seq == (prev.seq + len(bytes(prev.payload))) & 0xFFFFFFFF
            assert cur.ack == prev.ack
        assert b"".join(bytes(t.payload) for t in tcps) == _BIG
        assert all(p.haslayer(ip_layer) for p in packets)
        assert len({float(p.time) for p in packets}) == 1
        stub.logger.warning.assert_not_called()

    def test_next_record_continues_after_the_last_segment(self, tmp_path):
        stub = _writer(tmp_path)
        stub.log_plaintext_payload("AF_INET", _WRITE, _SRC4, 51234, _DST4, 443, _BIG)
        stub.log_plaintext_payload("AF_INET", _WRITE, _SRC4, 51234, _DST4, 443, b"tail")
        packets = _packets(stub)

        first = packets[0][TCP].seq
        assert packets[-1][TCP].seq == (first + len(_BIG)) & 0xFFFFFFFF

    def test_sequence_number_wraps_instead_of_raising(self, tmp_path):
        stub = _writer(tmp_path)
        with patch("friTap.pcap.random.randint", return_value=0xFFFFFF00):
            stub.log_plaintext_payload("AF_INET", _WRITE, _SRC4, 1, _DST4, 443, _BIG)
            stub.log_plaintext_payload("AF_INET", _WRITE, _SRC4, 1, _DST4, 443, b"x")
        assert len(_packets(stub)) == 5

    @pytest.mark.parametrize("family, src, dst", [
        ("AF_INET", _SRC4, _DST4), ("AF_INET6", _SRC6, _DST6)])
    def test_large_udp_payload_is_split_into_datagrams(self, tmp_path, family, src, dst):
        stub = _writer(tmp_path)
        stub.log_plaintext_payload(family, _READ, src, 443, dst, 51234, _BIG,
                                   transport="udp")
        packets = _packets(stub)

        assert len(packets) == 4
        assert b"".join(bytes(p[UDP].payload) for p in packets) == _BIG
        assert all(p[UDP].len == 8 + len(bytes(p[UDP].payload)) for p in packets)

    def test_small_record_is_one_packet_as_before(self, tmp_path):
        stub = _writer(tmp_path)
        stub.log_plaintext_payload("AF_INET", _READ, _SRC4, 443, _DST4, 51234, b"hello")
        (packet,) = _packets(stub)
        assert packet[IP].len == 45 and bytes(packet[TCP].payload) == b"hello"

    @pytest.mark.parametrize("src_addr, src_port, dst_port", [
        (_SRC4, 70000, 443),
        (_SRC4, 51234, -1),
        (2 ** 32, 51234, 443),
        (-5, 51234, 443),
    ])
    def test_invalid_endpoint_is_dropped_without_raising(
            self, tmp_path, src_addr, src_port, dst_port):
        stub = _writer(tmp_path)
        stub.log_plaintext_payload("AF_INET", _WRITE, src_addr, src_port,
                                   _DST4, dst_port, b"payload")
        assert _packets(stub) == []
        assert stub.ssl_sessions == {}
        stub.logger.warning.assert_called_once()

    def test_invalid_endpoint_warning_is_rate_limited(self, tmp_path):
        stub = _writer(tmp_path)
        for _ in range(5):
            stub.log_plaintext_payload("AF_INET", _WRITE, _SRC4, 99999,
                                       _DST4, 443, b"payload")
        stub.log_plaintext_payload("AF_INET", _WRITE, _SRC4, 1, _DST4, 443, b"ok")
        assert len(_packets(stub)) == 1
        assert stub.logger.warning.call_count == 1

    def test_content_only_placeholders_still_written(self, tmp_path):
        stub = _writer(tmp_path)
        stub.log_plaintext_payload("AF_INET", _READ, "", "", None, None, b"e2e")
        (packet,) = _packets(stub)
        assert packet[IP].src == "0.0.0.0" and packet[TCP].sport == 0


# ---------------------------------------------------- pcapng sink framing

class TestTcpStateFraming:
    @pytest.mark.parametrize("family, src, dst, ip_layer", [
        ("AF_INET", _SRC4, _DST4, IP),
        ("AF_INET6", _SRC6, _DST6, IPv6),
    ])
    def test_200k_payload_becomes_valid_contiguous_packets(self, family, src, dst, ip_layer):
        tracker = TcpSessionTracker()
        packets = build_framed_packets_from_fields(
            family, src, 51234, dst, 443, False, _BIG, tracker)

        parsed = [ip_layer(p) for p in packets]
        assert len(parsed) == 4
        assert all(len(p) <= 65535 for p in packets)
        tcps = [p[TCP] for p in parsed]
        for prev, cur in zip(tcps, tcps[1:]):
            assert cur.seq == (prev.seq + len(bytes(prev.payload))) & 0xFFFFFFFF
        assert b"".join(bytes(t.payload) for t in tcps) == _BIG

        follow = build_framed_packets_from_fields(
            family, src, 51234, dst, 443, False, b"next", tracker)
        assert ip_layer(follow[0])[TCP].seq == (tcps[0].seq + len(_BIG)) & 0xFFFFFFFF

    def test_udp_payload_is_split(self):
        packets = build_framed_packets_from_fields(
            "AF_INET6", _SRC6, 443, _DST6, 51234, True, _BIG,
            TcpSessionTracker(), transport="udp")
        assert b"".join(bytes(IPv6(p)[UDP].payload) for p in packets) == _BIG

    @pytest.mark.parametrize("family, src, sport", [
        ("AF_INET", 2 ** 32, 1),
        ("AF_INET", _SRC4, 65536),
        ("AF_INET6", "not-hex-at-all", 1),
        ("AF_INET6", -1, 1),
        ("AF_INET", _SRC4, "443"),
    ])
    def test_invalid_endpoint_is_dropped(self, family, src, sport, caplog):
        dst = _DST6 if family == "AF_INET6" else _DST4
        with caplog.at_level(logging.WARNING, logger="friTap"):
            packets = build_framed_packets_from_fields(
                family, src, sport, dst, 443, False, b"data", TcpSessionTracker())
        assert packets == []
        assert "dropping plaintext record" in caplog.text

    def test_single_packet_api_never_raises(self):
        tracker = TcpSessionTracker()
        assert build_framed_packet_from_fields(
            "AF_INET", _SRC4, 70000, _DST4, 443, False, b"x", tracker) == b""
        first = build_framed_packet_from_fields(
            "AF_INET", _SRC4, 1, _DST4, 443, False, _BIG, tracker)
        assert IP(first).len == 65535

    def test_small_packet_bytes_unchanged(self):
        tracker = TcpSessionTracker()
        with patch("friTap.sinks.tcp_state.random.randint", return_value=7):
            packet = build_framed_packet_from_fields(
                "AF_INET", _SRC4, 1, _DST4, 443, True, b"hi", tracker)
        expected = struct.pack(
            ">BBHHHBBHIIHHIIHHHH", 0x45, 0, 42, 0, 0x4000, 0xFF, 6, 0,
            _SRC4, _DST4, 1, 443, 7, 7, 0x5018, 0xFFFF, 0, 0) + b"hi"
        assert packet == expected

    def test_text_form_ipv6_and_dotted_ipv4_are_accepted(self):
        tracker = TcpSessionTracker()
        (v6,) = build_framed_packets_from_fields(
            "AF_INET6", "2001:db8::1", 1, _DST6, 443, False, b"x", tracker)
        (v4,) = build_framed_packets_from_fields(
            "AF_INET", "10.0.0.1", 1, _DST4, 443, False, b"x", tracker)
        assert IPv6(v6).src == "2001:db8::1"
        assert IP(v4).src == "10.0.0.1"


# --------------------------------------------- scapy reads of the temp file

class TestTempCaptureValidation:
    def _pcap(self, tmp_path, name):
        pcap = object.__new__(PCAP)
        pcap.pcap_file_name = str(tmp_path / name)
        pcap.logger = MagicMock()
        return pcap

    @staticmethod
    def _huge_record_capture(path):
        header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        record = struct.pack("<IIII", 0, 0, 0xFFFFFFF0, 0xFFFFFFF0)
        path.write_bytes(header + record + b"\x00" * 64)

    def test_pcapng_finalize_rejects_a_huge_record_length(self, tmp_path):
        source = tmp_path / "_cap.pcap"
        self._huge_record_capture(source)
        pcap = self._pcap(tmp_path, "cap.pcapng")

        with patch("friTap.pcap.PcapReader") as reader:
            pcap._emit_pcapng_with_dsb(str(source), pcap.pcap_file_name, ["CLIENT_RANDOM a b"])

        reader.assert_not_called()
        assert "malformed or truncated" in pcap.logger.error.call_args[0][0]
        assert (tmp_path / "cap.pcapng").stat().st_size > 0   # keys-only output

    def test_filtered_classic_finalize_keeps_the_temp_file(self, tmp_path):
        source = tmp_path / "_cap.pcap"
        self._huge_record_capture(source)
        pcap = self._pcap(tmp_path, "cap.pcap")

        with patch("friTap.pcap.sniff") as sniff:
            pcap._emit_final(str(source), [], bpf_filter="tcp port 443")

        sniff.assert_not_called()
        assert source.exists()
        assert "malformed or truncated" in pcap.logger.error.call_args[0][0]

    def test_memory_error_from_scapy_is_caught(self, tmp_path):
        source = tmp_path / "_cap.pcap"
        source.write_bytes(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        pcap = self._pcap(tmp_path, "cap.pcapng")

        with patch("friTap.pcap.PcapReader", side_effect=MemoryError("boom")):
            pcap._emit_pcapng_with_dsb(str(source), pcap.pcap_file_name, [])

        assert "MemoryError" in pcap.logger.error.call_args[0][2]
