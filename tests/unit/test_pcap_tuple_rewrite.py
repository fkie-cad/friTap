"""Option 5: rewriting synthetic -p streams to their real tuples at stop."""

import ipaddress
import json
import logging
import os
import shutil
import subprocess
import types

import pytest
from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv6
from scapy.utils import PcapNgReader, PcapReader

from friTap import pcap_tuple_rewrite as rewrite_module
from friTap.constants import SSL_READ, SSL_WRITE
from friTap.endpoint_pinner import (
    EndpointPair,
    MappingEntry,
    PinnedEndpoint,
    synthetic_pair,
)
from friTap.output.pcapng_blocks import build_dsb, build_epb, build_idb, build_shb
from friTap.pcap import PCAP
from friTap.pcap_tuple_rewrite import (
    ACTION_CONFLICT,
    ACTION_KEPT_SYNTHETIC,
    ACTION_NOT_IN_PCAP,
    ACTION_REWRITTEN,
    Endpoint,
    internet_checksum,
    parse_tcp_packet,
    reencode_tcp_packet,
    rewrite_synthetic_endpoints,
)
from friTap.sinks.tcp_state import build_ipv4_tcp_packet

READ_FN = next(iter(SSL_READ))
WRITE_FN = next(iter(SSL_WRITE))

CR_MAPPED = "11" * 32
CR_CONFLICT = "22" * 32
CR_NO_REAL = "33" * 32
CR_ABSENT = "44" * 32
CR_IPV6 = "55" * 32

REAL_V6_CLIENT = "20010db8000000000000000000000001"
REAL_V6_SERVER = "20010db8000000000000000000000002"


def _ip(text):
    return int(ipaddress.IPv4Address(text))


def _real_v4(client, client_port, server, server_port=443):
    return EndpointPair(PinnedEndpoint(client, client_port, _ip(client)),
                        PinnedEndpoint(server, server_port, _ip(server)), "AF_INET")


REAL_MAPPED = _real_v4("10.0.0.5", 40001, "93.184.216.34")
REAL_TAKEN = _real_v4("10.0.0.5", 40002, "142.250.1.1")
REAL_V6 = EndpointPair(
    PinnedEndpoint("2001:db8::1", 40003, REAL_V6_CLIENT),
    PinnedEndpoint("2001:db8::2", 443, REAL_V6_SERVER), "AF_INET6")


def _mappings():
    return [
        MappingEntry(CR_MAPPED, synthetic_pair(CR_MAPPED), REAL_MAPPED),
        MappingEntry(CR_CONFLICT, synthetic_pair(CR_CONFLICT), REAL_TAKEN),
        MappingEntry(CR_NO_REAL, synthetic_pair(CR_NO_REAL), None),
        MappingEntry(CR_ABSENT, synthetic_pair(CR_ABSENT), REAL_MAPPED),
        MappingEntry(CR_IPV6, synthetic_pair(CR_IPV6), REAL_V6),
    ]


def _pair_args(pair, is_read):
    client, server = pair.client, pair.server
    src, dst = (server, client) if is_read else (client, server)
    return pair.ss_family, src.raw, src.port, dst.raw, dst.port


def _exchange(pair, request=b"GET / HTTP/1.1\r\n\r\n", response=b"HTTP/1.1 200 OK\r\n\r\n"):
    family, *write_tuple = _pair_args(pair, is_read=False)
    _, *read_tuple = _pair_args(pair, is_read=True)
    return [(family, WRITE_FN, *write_tuple, request),
            (family, READ_FN, *read_tuple, response)]


def _records():
    """The mixed file: three synthetic streams plus a real stream on REAL_TAKEN."""
    records = []
    for cr in (CR_MAPPED, CR_CONFLICT, CR_NO_REAL, CR_IPV6):
        records += _exchange(synthetic_pair(cr))
    records += _exchange(REAL_TAKEN, b"real-request", b"real-response")
    return records


def _write_classic_pcap(path):
    """Write the -p file through PCAP's own writer (header + log_plaintext_payload)."""
    writer = types.SimpleNamespace(
        logger=logging.getLogger("test_pcap_tuple_rewrite"), ssl_sessions={},
        _observed_server_ports={"tcp": set(), "udp": set()})
    writer._record_server_port = PCAP._record_server_port.__get__(writer)
    writer.log_plaintext_payload = PCAP.log_plaintext_payload.__get__(writer)
    with open(path, "wb") as fh:
        PCAP.write_pcap_header(writer, fh)
        for family, function, src, sport, dst, dport, data in _records():
            writer.log_plaintext_payload(family, function, src, sport, dst, dport, data)


def _write_pcapng(path):
    """Write a -p style pcapng (SHB + RAW IDB + DSB + EPBs) via the shared builders."""
    from friTap.sinks.tcp_state import (
        TcpSessionTracker,
        build_framed_packets_from_fields,
    )
    tracker = TcpSessionTracker()
    with open(path, "wb") as fh:
        fh.write(build_shb() + build_idb() + build_dsb(b"CLIENT_RANDOM aa bb\n"))
        for index, (family, function, src, sport, dst, dport, data) in enumerate(_records()):
            for packet in build_framed_packets_from_fields(
                    ss_family=family, src_addr=src, src_port=sport, dst_addr=dst,
                    dst_port=dport, is_read=function == READ_FN, data=data,
                    tracker=tracker):
                fh.write(build_epb(packet, 1_700_000_000_000_000 + index))


def _packets(path):
    reader_cls = PcapNgReader if path.endswith(".pcapng") else PcapReader
    with reader_cls(path) as reader:
        return [(float(p.time), bytes(p)) for p in reader]


def _scapy_packet(raw):
    return IP(raw) if raw[0] >> 4 == 4 else IPv6(raw)


def _endpoints(raw):
    pkt = _scapy_packet(raw)
    layer = pkt[IP] if IP in pkt else pkt[IPv6]
    return {(layer.src, pkt[TCP].sport), (layer.dst, pkt[TCP].dport)}


def _pair_set(pair):
    def text(endpoint):
        if pair.ss_family == "AF_INET6":
            return str(ipaddress.IPv6Address(bytes.fromhex(endpoint.raw)))
        return endpoint.addr
    return {(text(pair.client), pair.client.port), (text(pair.server), pair.server.port)}


def _assert_checksums_valid(raw):
    pkt = _scapy_packet(raw)
    rebuilt = _scapy_packet(raw)
    if IP in rebuilt:
        del rebuilt[IP].chksum
    del rebuilt[TCP].chksum
    rebuilt = _scapy_packet(bytes(rebuilt))
    if IP in pkt:
        assert pkt[IP].chksum == rebuilt[IP].chksum
    assert pkt[TCP].chksum == rebuilt[TCP].chksum


@pytest.fixture(params=["classic", "pcapng"])
def capture(request, tmp_path):
    if request.param == "classic":
        path = str(tmp_path / "plain.pcap")
        _write_classic_pcap(path)
    else:
        path = str(tmp_path / "plain.pcapng")
        _write_pcapng(path)
    return path


class TestMixedFile:
    def test_summary_actions(self, capture):
        summary = rewrite_synthetic_endpoints(capture, _mappings())
        actions = {row["cr"]: row["action"] for row in summary["map"]}
        assert actions == {CR_MAPPED: ACTION_REWRITTEN, CR_CONFLICT: ACTION_CONFLICT,
                           CR_NO_REAL: ACTION_KEPT_SYNTHETIC, CR_ABSENT: ACTION_NOT_IN_PCAP,
                           CR_IPV6: ACTION_REWRITTEN}
        assert (summary["rewritten"], summary["kept_synthetic"], summary["conflicts"]) == (2, 1, 1)
        no_real = next(row for row in summary["map"] if row["cr"] == CR_NO_REAL)
        assert no_real["real"] is None
        assert no_real["synthetic"]["server_port"] == 443
        assert "error" not in summary

    def test_streams_after_rewrite(self, capture):
        before = _packets(capture)
        rewrite_synthetic_endpoints(capture, _mappings())
        after = _packets(capture)
        assert len(before) == len(after)
        streams_after = [frozenset(_endpoints(raw)) for _, raw in after]
        assert frozenset(_pair_set(REAL_MAPPED)) in streams_after
        assert frozenset(_pair_set(REAL_V6)) in streams_after
        assert frozenset(_pair_set(synthetic_pair(CR_MAPPED))) not in streams_after
        for kept in (CR_CONFLICT, CR_NO_REAL):
            assert frozenset(_pair_set(synthetic_pair(kept))) in streams_after
        assert streams_after.count(frozenset(_pair_set(REAL_TAKEN))) == 2

    def test_rewrite_preserves_time_seq_ack_flags_payload(self, capture):
        before = _packets(capture)
        rewrite_synthetic_endpoints(capture, _mappings())
        for (t0, raw0), (t1, raw1) in zip(before, _packets(capture)):
            p0, p1 = _scapy_packet(raw0)[TCP], _scapy_packet(raw1)[TCP]
            assert t0 == t1
            assert (p0.seq, p0.ack, p0.flags, p0.window) == (p1.seq, p1.ack, p1.flags, p1.window)
            assert bytes(p0.payload) == bytes(p1.payload)

    def test_ipv4_synthetic_becomes_ipv6(self, capture):
        rewrite_synthetic_endpoints(capture, _mappings())
        v6 = [raw for _, raw in _packets(capture) if raw[0] >> 4 == 6]
        assert len(v6) == 2
        assert all(_endpoints(raw) == _pair_set(REAL_V6) for raw in v6)

    def test_rewritten_checksums_valid(self, capture):
        rewrite_synthetic_endpoints(capture, _mappings())
        rewritten_streams = (_pair_set(REAL_MAPPED), _pair_set(REAL_V6))
        rewritten = [raw for _, raw in _packets(capture) if _endpoints(raw) in rewritten_streams]
        assert len(rewritten) == 4
        for raw in rewritten:
            _assert_checksums_valid(raw)

    @pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark not installed")
    def test_tshark_validates_rewritten_checksums(self, capture):
        rewrite_synthetic_endpoints(capture, _mappings())
        result = subprocess.run(
            ["tshark", "-r", capture, "-o", "tcp.check_checksum:TRUE",
             "-o", "ip.check_checksum:TRUE", "-T", "fields", "-e", "tcp.srcport",
             "-e", "tcp.dstport", "-e", "tcp.checksum.status", "-e", "ip.checksum.status"],
            capture_output=True, text=True, timeout=60)
        assert result.returncode == 0, result.stderr
        rows = [line.split("\t") for line in result.stdout.splitlines()]
        rewritten_client_ports = {"40001", "40003"}
        rewritten = [row for row in rows if rewritten_client_ports & {row[0], row[1]}]
        assert len(rewritten) == 4
        assert all(row[2] == "1" for row in rewritten)  # 1 = Good
        assert all(row[3] in ("", "1") for row in rewritten)  # IPv6 has no header checksum

    def test_untouched_when_nothing_to_rewrite(self, capture):
        with open(capture, "rb") as fh:
            original = fh.read()
        mappings = [MappingEntry(CR_NO_REAL, synthetic_pair(CR_NO_REAL), None)]
        summary = rewrite_synthetic_endpoints(capture, mappings)
        assert summary["kept_synthetic"] == 1
        with open(capture, "rb") as fh:
            assert fh.read() == original


class TestPlanning:
    def test_two_connections_on_one_real_tuple_second_conflicts(self, tmp_path):
        path = str(tmp_path / "plain.pcap")
        _write_classic_pcap(path)
        mappings = [MappingEntry(CR_MAPPED, synthetic_pair(CR_MAPPED), REAL_MAPPED),
                    MappingEntry(CR_NO_REAL, synthetic_pair(CR_NO_REAL), REAL_MAPPED)]
        summary = rewrite_synthetic_endpoints(path, mappings)
        assert [row["action"] for row in summary["map"]] == [ACTION_REWRITTEN, ACTION_CONFLICT]

    def test_reversed_real_tuple_in_file_conflicts(self, tmp_path):
        path = str(tmp_path / "plain.pcap")
        _write_classic_pcap(path)
        reversed_taken = EndpointPair(REAL_TAKEN.server, REAL_TAKEN.client, "AF_INET")
        mappings = [MappingEntry(CR_MAPPED, synthetic_pair(CR_MAPPED), reversed_taken)]
        assert rewrite_synthetic_endpoints(path, mappings)["conflicts"] == 1


class TestAtomicFailure:
    def test_write_failure_keeps_original(self, tmp_path, monkeypatch):
        path = str(tmp_path / "plain.pcap")
        _write_classic_pcap(path)
        with open(path, "rb") as fh:
            original = fh.read()

        def explode(*_args, **_kwargs):
            raise OSError("disk full")

        monkeypatch.setattr(rewrite_module, "_write_rewritten_copy", explode)
        summary = rewrite_synthetic_endpoints(path, _mappings())
        assert summary["error"] == "disk full"
        assert summary["rewritten"] == 0
        with open(path, "rb") as fh:
            assert fh.read() == original
        assert os.listdir(tmp_path) == ["plain.pcap"]

    def test_truncated_file_keeps_original(self, tmp_path):
        path = str(tmp_path / "plain.pcap")
        _write_classic_pcap(path)
        with open(path, "rb+") as fh:
            fh.truncate(os.path.getsize(path) - 3)
        with open(path, "rb") as fh:
            original = fh.read()
        summary = rewrite_synthetic_endpoints(path, _mappings())
        assert "error" in summary
        with open(path, "rb") as fh:
            assert fh.read() == original

    def test_not_a_capture(self, tmp_path):
        path = tmp_path / "plain.pcap"
        path.write_bytes(b"not a pcap at all")
        assert "error" in rewrite_synthetic_endpoints(str(path), _mappings())


class TestPacketHelpers:
    def test_checksum_of_known_ipv4_header(self):
        header = bytes.fromhex("450000730000400040110000c0a80001c0a800c7")
        assert internet_checksum(header) == 0xB861

    def test_reencode_keeps_fields(self):
        raw = build_ipv4_tcp_packet(_ip("198.18.0.1"), 50000, _ip("198.19.0.1"), 443,
                                    7, 9, b"payload")
        tcp = parse_tcp_packet(raw)
        out = reencode_tcp_packet(tcp, Endpoint(bytes([10, 0, 0, 1]), 1111),
                                  Endpoint(bytes([10, 0, 0, 2]), 443))
        parsed = parse_tcp_packet(out)
        assert (parsed.seq, parsed.ack, parsed.payload, parsed.control) == (7, 9, b"payload",
                                                                            tcp.control)
        _assert_checksums_valid(out)

    def test_non_tcp_is_not_parsed(self):
        from friTap.sinks.tcp_state import build_ipv4_udp_packet
        assert parse_tcp_packet(build_ipv4_udp_packet(1, 2, 3, 4, b"x")) is None
        assert parse_tcp_packet(None) is None


class TestPcapFinalize:
    def _pcap(self, path, mappings):
        pcap = PCAP.__new__(PCAP)
        pcap.pcap_file_name = path
        pcap.logger = logging.getLogger("test_pcap_tuple_rewrite")
        pinner = types.SimpleNamespace(mappings=lambda: mappings)
        pcap.set_endpoint_pinner(pinner)
        return pcap

    def test_manifest_records_summary(self, tmp_path):
        path = str(tmp_path / "plain.pcap")
        _write_classic_pcap(path)
        self._pcap(path, _mappings()).finalize_plaintext_capture()
        with open(path + ".fritap.json", encoding="utf-8") as fh:
            manifest = json.load(fh)
        assert set(manifest) == {"synthetic_endpoints"}
        summary = manifest["synthetic_endpoints"]
        assert (summary["rewritten"], summary["kept_synthetic"], summary["conflicts"]) == (2, 1, 1)
        mapped = next(row for row in summary["map"] if row["cr"] == CR_MAPPED)
        assert mapped["real"] == {"client_addr": "10.0.0.5", "client_port": 40001,
                                  "server_addr": "93.184.216.34", "server_port": 443,
                                  "ss_family": "AF_INET"}
        assert mapped["synthetic"]["client_addr"].startswith("198.18.")

    def test_no_mappings_no_manifest(self, tmp_path):
        path = str(tmp_path / "plain.pcap")
        _write_classic_pcap(path)
        self._pcap(path, []).finalize_plaintext_capture()
        assert not os.path.exists(path + ".fritap.json")

    def test_without_pinner_is_noop(self, tmp_path):
        path = str(tmp_path / "plain.pcap")
        _write_classic_pcap(path)
        pcap = PCAP.__new__(PCAP)
        pcap.pcap_file_name = path
        pcap.logger = logging.getLogger("test_pcap_tuple_rewrite")
        pcap.finalize_plaintext_capture()
        assert not os.path.exists(path + ".fritap.json")

    def test_missing_file_is_noop(self, tmp_path):
        path = str(tmp_path / "never_written.pcap")
        self._pcap(path, _mappings()).finalize_plaintext_capture()
        assert not os.path.exists(path + ".fritap.json")


class TestWithRealPinner:
    def test_pinner_mapping_drives_rewrite(self, tmp_path):
        from friTap.endpoint_pinner import EndpointPinner, RecordEndpoints
        pinner = EndpointPinner()
        pinner.resolve(CR_MAPPED, "tcp", False, None)
        real = RecordEndpoints("10.0.0.5", 40001, "93.184.216.34", 443,
                               _ip("10.0.0.5"), _ip("93.184.216.34"), "AF_INET")
        pinner.resolve(CR_MAPPED, "tcp", False, real)
        path = str(tmp_path / "plain.pcap")
        _write_classic_pcap(path)
        summary = rewrite_synthetic_endpoints(path, pinner.mappings())
        assert summary["rewritten"] == 1
        streams = {frozenset(_endpoints(raw)) for _, raw in _packets(path)}
        assert frozenset(_pair_set(REAL_MAPPED)) in streams


class TestFastPaths:
    def test_no_real_tuple_skips_the_scan(self, tmp_path, monkeypatch):
        path = str(tmp_path / "plain.pcap")
        _write_classic_pcap(path)

        def must_not_scan(_path):
            raise AssertionError("pass 1 must be skipped")

        monkeypatch.setattr(rewrite_module, "collect_stream_keys", must_not_scan)
        mappings = [MappingEntry(CR_NO_REAL, synthetic_pair(CR_NO_REAL), None),
                    MappingEntry(CR_ABSENT, synthetic_pair(CR_ABSENT), None)]
        summary = rewrite_synthetic_endpoints(path, mappings)
        assert [row["action"] for row in summary["map"]] == [ACTION_KEPT_SYNTHETIC] * 2
        assert summary["kept_synthetic"] == 2 and "error" not in summary

    def test_absent_stream_without_real_is_kept_synthetic_after_a_scan(self, capture):
        mappings = [MappingEntry(CR_MAPPED, synthetic_pair(CR_MAPPED), REAL_MAPPED),
                    MappingEntry(CR_ABSENT, synthetic_pair(CR_ABSENT), None)]
        summary = rewrite_synthetic_endpoints(capture, mappings)
        assert [row["action"] for row in summary["map"]] == [
            ACTION_REWRITTEN, ACTION_KEPT_SYNTHETIC]

    def test_stream_key_matches_full_parse(self, capture):
        for _, raw in _packets(capture):
            tcp = parse_tcp_packet(raw)
            assert rewrite_module.read_stream_key(raw) == rewrite_module.stream_key(
                tcp.src, tcp.dst)

    def test_synthetic_prefilter(self):
        synthetic = build_ipv4_tcp_packet(_ip("198.19.0.7"), 1, _ip("10.0.0.1"), 2, 0, 0, b"")
        reverse = build_ipv4_tcp_packet(_ip("10.0.0.1"), 2, _ip("198.18.4.4"), 1, 0, 0, b"")
        outside = build_ipv4_tcp_packet(_ip("198.20.0.1"), 1, _ip("10.0.0.1"), 2, 0, 0, b"")
        assert rewrite_module.has_synthetic_ipv4_endpoint(synthetic)
        assert rewrite_module.has_synthetic_ipv4_endpoint(reverse)
        assert not rewrite_module.has_synthetic_ipv4_endpoint(outside)
        assert not rewrite_module.has_synthetic_ipv4_endpoint(None)


class TestMappingOverflow:
    def test_overflow_count_lands_in_manifest(self, tmp_path):
        path = str(tmp_path / "plain.pcap")
        _write_classic_pcap(path)
        pcap = PCAP.__new__(PCAP)
        pcap.pcap_file_name = path
        pcap.logger = logging.getLogger("test_pcap_tuple_rewrite")
        pcap.set_endpoint_pinner(types.SimpleNamespace(
            mappings=_mappings, mapping_overflow_count=3))
        pcap.finalize_plaintext_capture()
        with open(path + ".fritap.json", encoding="utf-8") as fh:
            assert json.load(fh)["synthetic_endpoints"]["mapping_overflow"] == 3

    def test_zero_overflow_is_omitted(self):
        summary = {}
        PCAP._add_mapping_overflow(summary, types.SimpleNamespace(mapping_overflow_count=0))
        assert summary == {}
