#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Unit tests for the offline metadata producer (Phase 2).

The pure parsers (``parse_tls_metadata_fields`` / ``parse_ssh_fields``) are fed
hand-built tab-separated tshark output, so they need no tshark binary. The
wiring tests monkeypatch the tshark boundary (``extract_tls_metadata`` /
``extract_ssh_connections`` / ``list_tls_streams`` / ``follow_tls_stream`` /
``find_tshark``) and run a minimal conversion through a real FlowCollector +
EventBus, asserting the resulting flow carries the stamped metadata.

A single gated integration test runs the real tshark binary; it is skipped
when tshark is unavailable (as it is in this environment).
"""

from __future__ import annotations

import shutil

import pytest

from friTap.offline import tshark as tshark_mod
from friTap.offline import pcap_to_tap as p2t
from friTap.flow.tap_reader import TapReader


# ---------------------------------------------------------------------------
# parse_tls_metadata_fields (pure)
# ---------------------------------------------------------------------------

def _tls_row(stream, hs_type, sni="", cipher="", version="",
             supported_version="", alpn=""):
    """Build one tab-separated TLS-metadata row in the canonical column order."""
    return "\t".join([str(stream), hs_type, sni, cipher, version,
                      supported_version, alpn])


def test_parse_tls_metadata_merges_client_and_server_hello():
    output = "\n".join([
        # ClientHello carries SNI.
        _tls_row(0, "1", sni="example.com"),
        # ServerHello carries the negotiated suite/version/alpn. TLS 1.3 puts
        # the real version in the supported_version extension (handshake.version
        # is frozen at 0x0303).
        _tls_row(0, "2", cipher="0x1301", version="0x0303",
                 supported_version="0x0304", alpn="h2"),
    ])
    meta = tshark_mod.parse_tls_metadata_fields(output)
    assert meta[0] == {
        "sni": "example.com",
        "cipher": "TLS_AES_128_GCM_SHA256",
        "version": "TLS 1.3",
        "alpn": "h2",
    }


def test_parse_tls_metadata_supported_version_preferred_over_handshake_version():
    output = _tls_row(3, "2", cipher="0x1302", version="0x0303",
                      supported_version="0x0304")
    meta = tshark_mod.parse_tls_metadata_fields(output)
    assert meta[3]["version"] == "TLS 1.3"  # 0x0304, not 0x0303


def test_parse_tls_metadata_falls_back_to_handshake_version():
    # No supported_version extension -> use handshake.version (TLS 1.2 path).
    output = _tls_row(1, "2", cipher="0xc02f", version="0x0303")
    meta = tshark_mod.parse_tls_metadata_fields(output)
    assert meta[1]["version"] == "TLS 1.2"
    assert meta[1]["cipher"] == "ECDHE-RSA-AES128-GCM-SHA256"


def test_parse_tls_metadata_unknown_ciphersuite_hex_passthrough():
    output = _tls_row(2, "2", cipher="0xdead", version="0x0303")
    meta = tshark_mod.parse_tls_metadata_fields(output)
    # Unknown codepoint -> raw hex passthrough (canonicalized).
    assert meta[2]["cipher"] == "0xdead"


def test_parse_tls_metadata_alpn_takes_first_token():
    output = _tls_row(0, "2", alpn="h2,http/1.1")
    meta = tshark_mod.parse_tls_metadata_fields(output)
    assert meta[0]["alpn"] == "h2"


def test_parse_tls_metadata_does_not_overwrite_set_value():
    output = "\n".join([
        _tls_row(0, "1", sni="first.example.com"),
        _tls_row(0, "1", sni="second.example.com"),  # later row must not win
    ])
    meta = tshark_mod.parse_tls_metadata_fields(output)
    assert meta[0]["sni"] == "first.example.com"


def test_parse_tls_metadata_skips_malformed_rows():
    output = "\n".join([
        "garbage-without-tabs-or-stream",
        "\t\t\t",            # empty stream column
        _tls_row(5, "1", sni="ok.example.com"),
    ])
    meta = tshark_mod.parse_tls_metadata_fields(output)
    assert set(meta) == {5}
    assert meta[5]["sni"] == "ok.example.com"


def test_parse_tls_metadata_empty_output():
    assert tshark_mod.parse_tls_metadata_fields("") == {}


# ---------------------------------------------------------------------------
# parse_ssh_fields (pure)
# ---------------------------------------------------------------------------

def _ssh_row(stream, ip_src="", ipv6_src="", ip_dst="", ipv6_dst="",
             srcport="", dstport="", banner="", kex="", cipher="", mac=""):
    """Build one tab-separated SSH-metadata row in the canonical column order."""
    return "\t".join([str(stream), ip_src, ipv6_src, ip_dst, ipv6_dst,
                      str(srcport), str(dstport), banner, kex, cipher, mac])


def test_parse_ssh_fields_single_connection():
    output = "\n".join([
        # Client banner + KEXINIT lists (first row from the client side).
        _ssh_row(0, ip_src="10.0.0.1", ip_dst="10.0.0.2",
                 srcport=51000, dstport=22,
                 banner="SSH-2.0-OpenSSH_9.6",
                 kex="curve25519-sha256,ecdh-sha2-nistp256",
                 cipher="chacha20-poly1305@openssh.com,aes256-gcm@openssh.com",
                 mac="umac-64-etm@openssh.com,hmac-sha2-256"),
        # Server banner (distinct value -> server_version).
        _ssh_row(0, ip_src="10.0.0.2", ip_dst="10.0.0.1",
                 srcport=22, dstport=51000,
                 banner="SSH-2.0-OpenSSH_8.9"),
    ])
    conns = tshark_mod.parse_ssh_fields(output)
    assert len(conns) == 1
    c = conns[0]
    assert c["client_version"] == "SSH-2.0-OpenSSH_9.6"
    assert c["server_version"] == "SSH-2.0-OpenSSH_8.9"
    assert c["kex"] == "curve25519-sha256"
    assert c["cipher"] == "chacha20-poly1305@openssh.com"
    assert c["mac"] == "umac-64-etm@openssh.com"
    assert (c["src_addr"], c["src_port"]) == ("10.0.0.1", 51000)
    assert (c["dst_addr"], c["dst_port"]) == ("10.0.0.2", 22)


def test_parse_ssh_fields_ipv6_endpoints():
    output = _ssh_row(1, ipv6_src="2001:db8::1", ipv6_dst="2001:db8::2",
                      srcport=40000, dstport=22,
                      banner="SSH-2.0-OpenSSH_9.0")
    conns = tshark_mod.parse_ssh_fields(output)
    assert conns[0]["src_addr"] == "2001:db8::1"
    assert conns[0]["dst_addr"] == "2001:db8::2"


def test_parse_ssh_fields_multiple_connections():
    output = "\n".join([
        _ssh_row(0, ip_src="10.0.0.1", ip_dst="10.0.0.2", srcport=1, dstport=22,
                 banner="SSH-2.0-A"),
        _ssh_row(1, ip_src="10.0.0.3", ip_dst="10.0.0.4", srcport=2, dstport=22,
                 banner="SSH-2.0-B"),
    ])
    conns = tshark_mod.parse_ssh_fields(output)
    assert len(conns) == 2


def test_parse_ssh_fields_skips_malformed_rows():
    output = "\n".join([
        "no-stream-here",
        _ssh_row(2, ip_src="10.0.0.1", ip_dst="10.0.0.2", srcport=1, dstport=22,
                 banner="SSH-2.0-OK"),
    ])
    conns = tshark_mod.parse_ssh_fields(output)
    assert len(conns) == 1
    assert conns[0]["client_version"] == "SSH-2.0-OK"


def test_parse_ssh_fields_empty_output():
    assert tshark_mod.parse_ssh_fields("") == []


# ---------------------------------------------------------------------------
# extract_ipsec_connections is a stub
# ---------------------------------------------------------------------------

def test_extract_ipsec_connections_is_stub():
    assert tshark_mod.extract_ipsec_connections("/usr/bin/tshark", "cap.pcap") == []


# ---------------------------------------------------------------------------
# Wiring: TLS handshake metadata is stamped onto the flow
# ---------------------------------------------------------------------------

def _tls_ek_packets(endpoints, segments, *, stream=0, t0=1700000000.0):
    """Build TLS single-pass ``-T ek`` packet dicts from follow-style segments
    (one ``data.data`` frame per direction-tagged segment, oriented by
    direction). Lets the old ``(endpoints, segments)`` fixtures drive the new
    single-pass path unchanged."""
    c_addr, c_port, s_addr, s_port = endpoints
    packets = []
    for i, (direction, data) in enumerate(segments):
        if direction == "write":
            src_a, src_p, dst_a, dst_p = c_addr, c_port, s_addr, s_port
        else:
            src_a, src_p, dst_a, dst_p = s_addr, s_port, c_addr, c_port
        packets.append({"layers": {
            "frame_time_epoch": [f"{t0 + i}"],
            "ip_src": [src_a], "ip_dst": [dst_a],
            "tcp_stream": [str(stream)],
            "tcp_srcport": [str(src_p)], "tcp_dstport": [str(dst_p)],
            "data_data": [data.hex()],
        }})
    return packets


def _tls_stream_dispatch(packets):
    """A ``stream_packets`` fake returning *packets* for the TLS export command
    (identified by the ``data.data`` field) and nothing for the QUIC command."""
    def fake(cmd):
        return iter(packets) if "data.data" in cmd else iter(())
    return fake


def test_convert_stamps_tls_metadata_onto_flow(tmp_path, monkeypatch):
    request = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"
    endpoints = ("10.0.0.1", 50000, "93.184.216.34", 443)
    segments = [("write", request), ("read", response)]

    fixed_meta = {0: {
        "sni": "example.com",
        "cipher": "TLS_AES_128_GCM_SHA256",
        "version": "TLS 1.3",
        "alpn": "h2",
    }}

    monkeypatch.setattr(p2t, "find_tshark", lambda *a, **k: "/usr/bin/tshark")
    monkeypatch.setattr(p2t, "tshark_version", lambda path: (4, 6, 0))
    monkeypatch.setattr(p2t, "extract_tls_metadata", lambda *a, **k: fixed_meta)
    monkeypatch.setattr(p2t, "extract_ssh_connections", lambda *a, **k: [])
    monkeypatch.setattr(p2t, "stream_packets",
                        _tls_stream_dispatch(_tls_ek_packets(endpoints, segments)))

    pcap = tmp_path / "cap.pcapng"
    pcap.write_bytes(b"\x00")
    keylog = tmp_path / "keys.log"
    keylog.write_text("")
    tap = tmp_path / "cap.tap"

    p2t.convert_pcap_to_tap(str(pcap), keylog_path=str(keylog), tap_path=str(tap))

    with TapReader(str(tap)) as reader:
        flows = reader.read_all_flows()

    tls_flows = [f for f in flows if f.tls.sni]
    assert tls_flows, "no flow carried stamped TLS metadata"
    flow = tls_flows[0]
    assert flow.tls.sni == "example.com"
    assert flow.tls.version == "TLS 1.3"
    assert flow.tls.alpn == "h2"
    assert flow.tls.cipher == "TLS_AES_128_GCM_SHA256"


def test_convert_without_tls_metadata_still_produces_flow(tmp_path, monkeypatch):
    """No metadata for the stream -> no SessionEvent, but the flow still exists
    (additive behavior — the decrypted-bytes path is unaffected)."""
    request = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"
    endpoints = ("10.0.0.1", 50000, "93.184.216.34", 443)

    monkeypatch.setattr(p2t, "find_tshark", lambda *a, **k: "/usr/bin/tshark")
    monkeypatch.setattr(p2t, "tshark_version", lambda path: (4, 6, 0))
    monkeypatch.setattr(p2t, "extract_tls_metadata", lambda *a, **k: {})
    monkeypatch.setattr(p2t, "extract_ssh_connections", lambda *a, **k: [])
    monkeypatch.setattr(p2t, "stream_packets",
                        _tls_stream_dispatch(_tls_ek_packets(
                            endpoints, [("write", request)])))

    pcap = tmp_path / "cap.pcapng"
    pcap.write_bytes(b"\x00")
    keylog = tmp_path / "keys.log"
    keylog.write_text("")
    tap = tmp_path / "cap.tap"

    result = p2t.convert_pcap_to_tap(
        str(pcap), keylog_path=str(keylog), tap_path=str(tap))
    assert result.flow_count >= 1
    with TapReader(str(tap)) as reader:
        flows = reader.read_all_flows()
    assert len(flows) >= 1


# ---------------------------------------------------------------------------
# Wiring: SSH synthetic flow
# ---------------------------------------------------------------------------

def test_convert_creates_ssh_synthetic_flow(tmp_path, monkeypatch):
    ssh_conn = {
        "src_addr": "10.0.0.1", "src_port": 51000,
        "dst_addr": "10.0.0.2", "dst_port": 22,
        "client_version": "SSH-2.0-OpenSSH_9.6",
        "server_version": "SSH-2.0-OpenSSH_8.9",
        "kex": "curve25519-sha256",
        "cipher": "chacha20-poly1305@openssh.com",
        "mac": "umac-64-etm@openssh.com",
    }

    monkeypatch.setattr(p2t, "find_tshark", lambda *a, **k: "/usr/bin/tshark")
    monkeypatch.setattr(p2t, "tshark_version", lambda path: (4, 6, 0))
    monkeypatch.setattr(p2t, "list_tls_streams", lambda *a, **k: [])
    monkeypatch.setattr(p2t, "extract_tls_metadata", lambda *a, **k: {})
    monkeypatch.setattr(p2t, "extract_ssh_connections", lambda *a, **k: [ssh_conn])
    monkeypatch.setattr(p2t, "stream_packets", lambda cmd: iter(()))

    pcap = tmp_path / "cap.pcapng"
    pcap.write_bytes(b"\x00")
    keylog = tmp_path / "keys.log"
    keylog.write_text("")
    tap = tmp_path / "cap.tap"

    p2t.convert_pcap_to_tap(str(pcap), keylog_path=str(keylog), tap_path=str(tap))

    with TapReader(str(tap)) as reader:
        flows = reader.read_all_flows()

    ssh_flows = [f for f in flows if f.detected_protocol == "SSH"]
    assert ssh_flows, "no SSH synthetic flow was written"
    flow = ssh_flows[0]
    assert flow.ssh.client_version == "SSH-2.0-OpenSSH_9.6"
    assert flow.ssh.server_version == "SSH-2.0-OpenSSH_8.9"
    assert flow.ssh.kex == "curve25519-sha256"
    assert flow.ssh.cipher == "chacha20-poly1305@openssh.com"
    assert flow.ssh.mac == "umac-64-etm@openssh.com"
    assert (flow.src_addr, flow.src_port) == ("10.0.0.1", 51000)
    assert (flow.dst_addr, flow.dst_port) == ("10.0.0.2", 22)


def test_ssh_extraction_failure_does_not_abort_conversion(tmp_path, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("tshark blew up on the SSH pass")

    monkeypatch.setattr(p2t, "find_tshark", lambda *a, **k: "/usr/bin/tshark")
    monkeypatch.setattr(p2t, "tshark_version", lambda path: (4, 6, 0))
    monkeypatch.setattr(p2t, "list_tls_streams", lambda *a, **k: [])
    monkeypatch.setattr(p2t, "extract_tls_metadata", lambda *a, **k: {})
    monkeypatch.setattr(p2t, "extract_ssh_connections", boom)
    monkeypatch.setattr(p2t, "stream_packets", lambda cmd: iter(()))

    pcap = tmp_path / "cap.pcapng"
    pcap.write_bytes(b"\x00")
    keylog = tmp_path / "keys.log"
    keylog.write_text("")
    # Must not raise — SSH failure is swallowed.
    result = p2t.convert_pcap_to_tap(
        str(pcap), keylog_path=str(keylog), tap_path=str(tmp_path / "out.tap"))
    assert result.flow_count == 0


def test_tls_metadata_failure_does_not_abort_conversion(tmp_path, monkeypatch):
    request = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"
    endpoints = ("10.0.0.1", 50000, "93.184.216.34", 443)

    def boom(*a, **k):
        raise RuntimeError("tshark blew up on the TLS metadata pass")

    monkeypatch.setattr(p2t, "find_tshark", lambda *a, **k: "/usr/bin/tshark")
    monkeypatch.setattr(p2t, "tshark_version", lambda path: (4, 6, 0))
    monkeypatch.setattr(p2t, "extract_tls_metadata", boom)
    monkeypatch.setattr(p2t, "extract_ssh_connections", lambda *a, **k: [])
    monkeypatch.setattr(p2t, "stream_packets",
                        _tls_stream_dispatch(_tls_ek_packets(
                            endpoints, [("write", request)])))

    pcap = tmp_path / "cap.pcapng"
    pcap.write_bytes(b"\x00")
    keylog = tmp_path / "keys.log"
    keylog.write_text("")
    result = p2t.convert_pcap_to_tap(
        str(pcap), keylog_path=str(keylog), tap_path=str(tmp_path / "out.tap"))
    # Decrypted-bytes path unaffected: the flow still exists.
    assert result.flow_count >= 1


# ---------------------------------------------------------------------------
# Gated real-tshark smoke test (skipped when tshark is absent)
# ---------------------------------------------------------------------------

@pytest.mark.skipif(shutil.which("tshark") is None,
                    reason="real tshark binary unavailable")
def test_extract_tls_metadata_returns_dict_with_real_tshark(tmp_path):
    """Smoke test: against a real tshark, extract_tls_metadata returns a dict.

    Uses an empty/synthetic pcap (no TLS handshakes), so the dict is expected
    to be empty — we only assert the return TYPE and that no exception escapes.
    """
    import struct
    pcap = tmp_path / "empty.pcap"
    # Minimal classic pcap global header (us-resolution, little-endian).
    pcap.write_bytes(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    tshark_bin = tshark_mod.find_tshark()
    meta = tshark_mod.extract_tls_metadata(tshark_bin, str(pcap), None)
    assert isinstance(meta, dict)
