#!/usr/bin/env python3

"""Unit tests for the offline metadata producer (Phase 2).

The pure metadata folds (:class:`TlsMetadataAccumulator` / ``parse_ssh_fields``)
are fed hand-built tab-separated tshark rows, so they need no tshark binary. The
wiring tests replace the tshark boundary with the fake combined ``-T ek`` pass
of ``tests/unit/_fake_tshark.py`` and run a minimal conversion through a real
FlowCollector + EventBus, asserting the resulting flow carries the stamped
metadata.

A single gated integration test runs the real tshark binary; it is skipped
when tshark is unavailable (as it is in this environment).
"""

from __future__ import annotations

import shutil

import pytest

from friTap.flow.tap_reader import TapReader
from friTap.offline import pcap_to_tap as p2t
from friTap.offline import tshark as tshark_mod
from tests.unit import _fake_tshark as ft

# ---------------------------------------------------------------------------
# TlsMetadataAccumulator (pure)
# ---------------------------------------------------------------------------

def _fold_tls_rows(output: str) -> dict:
    """Fold tab-separated TLS-metadata rows (blank lines skipped) into metadata."""
    accumulator = tshark_mod.TlsMetadataAccumulator()
    for line in output.splitlines():
        if line.strip():
            accumulator.feed_columns(line.split("\t"))
    return accumulator.result()


def _tls_row(stream, hs_type, sni="", cipher="", version="",
             supported_version="", alpn=""):
    """Build one tab-separated TLS-metadata row in the canonical column order."""
    return "\t".join([str(stream), hs_type, sni, cipher, version,
                      supported_version, alpn])


def test_tls_metadata_accumulator_merges_client_and_server_hello():
    output = "\n".join([
        # ClientHello carries SNI.
        _tls_row(0, "1", sni="example.com"),
        # ServerHello carries the negotiated suite/version/alpn. TLS 1.3 puts
        # the real version in the supported_version extension (handshake.version
        # is frozen at 0x0303).
        _tls_row(0, "2", cipher="0x1301", version="0x0303",
                 supported_version="0x0304", alpn="h2"),
    ])
    meta = _fold_tls_rows(output)
    assert meta[0] == {
        "sni": "example.com",
        "cipher": "TLS_AES_128_GCM_SHA256",
        "version": "TLS 1.3",
        "alpn": "h2",
    }


def test_tls_metadata_accumulator_supported_version_preferred_over_handshake_version():
    output = _tls_row(3, "2", cipher="0x1302", version="0x0303",
                      supported_version="0x0304")
    meta = _fold_tls_rows(output)
    assert meta[3]["version"] == "TLS 1.3"  # 0x0304, not 0x0303


def test_tls_metadata_accumulator_falls_back_to_handshake_version():
    # No supported_version extension -> use handshake.version (TLS 1.2 path).
    output = _tls_row(1, "2", cipher="0xc02f", version="0x0303")
    meta = _fold_tls_rows(output)
    assert meta[1]["version"] == "TLS 1.2"
    assert meta[1]["cipher"] == "ECDHE-RSA-AES128-GCM-SHA256"


def test_tls_metadata_accumulator_unknown_ciphersuite_hex_passthrough():
    output = _tls_row(2, "2", cipher="0xdead", version="0x0303")
    meta = _fold_tls_rows(output)
    # Unknown codepoint -> raw hex passthrough (canonicalized).
    assert meta[2]["cipher"] == "0xdead"


def test_tls_metadata_accumulator_alpn_takes_first_token():
    output = _tls_row(0, "2", alpn="h2,http/1.1")
    meta = _fold_tls_rows(output)
    assert meta[0]["alpn"] == "h2"


def test_tls_metadata_accumulator_does_not_overwrite_set_value():
    output = "\n".join([
        _tls_row(0, "1", sni="first.example.com"),
        _tls_row(0, "1", sni="second.example.com"),  # later row must not win
    ])
    meta = _fold_tls_rows(output)
    assert meta[0]["sni"] == "first.example.com"


def test_tls_metadata_accumulator_skips_malformed_rows():
    output = "\n".join([
        "garbage-without-tabs-or-stream",
        "\t\t\t",            # empty stream column
        _tls_row(5, "1", sni="ok.example.com"),
    ])
    meta = _fold_tls_rows(output)
    assert set(meta) == {5}
    assert meta[5]["sni"] == "ok.example.com"


def test_tls_metadata_accumulator_empty_output():
    assert _fold_tls_rows("") == {}


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


def _banner_exchange(first, second, *, client_port=51000, server_port=22,
                     client_banner="SSH-2.0-CLIENT", server_banner="SSH-2.0-SERVER"):
    """Two banner rows of one connection; *first*/*second* are "client"/"server"."""
    client = ("10.0.0.1", client_port, client_banner)
    server = ("10.0.0.2", server_port, server_banner)
    sides = {"client": (client, server), "server": (server, client)}
    rows = []
    for who in (first, second):
        (src, sport, banner), (dst, dport, _) = sides[who]
        rows.append(_ssh_row(0, ip_src=src, ip_dst=dst, srcport=sport,
                             dstport=dport, banner=banner))
    return "\n".join(rows)


@pytest.mark.parametrize("order", [("server", "client"), ("client", "server")])
@pytest.mark.parametrize("client_port, server_port", [(51000, 22), (51000, 2222),
                                                      (1022, 22)])
def test_parse_ssh_fields_attributes_banners_by_port_not_order(
        order, client_port, server_port):
    conns = tshark_mod.parse_ssh_fields(_banner_exchange(
        *order, client_port=client_port, server_port=server_port))
    c = conns[0]
    assert (c["client_version"], c["server_version"]) == (
        "SSH-2.0-CLIENT", "SSH-2.0-SERVER")
    # Endpoints are oriented client -> server whoever spoke first.
    assert (c["src_addr"], c["src_port"]) == ("10.0.0.1", client_port)
    assert (c["dst_addr"], c["dst_port"]) == ("10.0.0.2", server_port)


def test_parse_ssh_fields_identical_banners_fill_both_versions():
    conns = tshark_mod.parse_ssh_fields(_banner_exchange(
        "server", "client", client_banner="SSH-2.0-OpenSSH_9.6",
        server_banner="SSH-2.0-OpenSSH_9.6"))
    assert conns[0]["client_version"] == "SSH-2.0-OpenSSH_9.6"
    assert conns[0]["server_version"] == "SSH-2.0-OpenSSH_9.6"


def test_parse_ssh_fields_server_banner_only():
    output = _banner_exchange("server", "server")
    c = tshark_mod.parse_ssh_fields(output)[0]
    assert (c["client_version"], c["server_version"]) == ("", "SSH-2.0-SERVER")
    assert (c["src_port"], c["dst_port"]) == (51000, 22)


def test_parse_ssh_fields_equal_ports_fall_back_to_banner_order():
    conns = tshark_mod.parse_ssh_fields(_banner_exchange(
        "server", "client", client_port=2222, server_port=2222))
    c = conns[0]
    assert (c["client_version"], c["server_version"]) == (
        "SSH-2.0-SERVER", "SSH-2.0-CLIENT")
    assert c["src_addr"] == "10.0.0.2"  # first row's sender, unchanged


def test_ssh_accumulator_server_first_ek_rows():
    accumulator = tshark_mod.SshConnectionAccumulator()
    accumulator.feed_ek(ft.ssh_row(src=_SSH_SERVER, dst=_SSH_CLIENT,
                                   banner="SSH-2.0-OpenSSH_8.9")["layers"])
    accumulator.feed_ek(ft.ssh_row(src=_SSH_CLIENT, dst=_SSH_SERVER,
                                   banner="SSH-2.0-OpenSSH_9.6")["layers"])
    c = accumulator.result()[0]
    assert c["client_version"] == "SSH-2.0-OpenSSH_9.6"
    assert c["server_version"] == "SSH-2.0-OpenSSH_8.9"
    assert (c["src_addr"], c["src_port"]) == _SSH_CLIENT


# ---------------------------------------------------------------------------
# Wiring: TLS handshake metadata is stamped onto the flow
# ---------------------------------------------------------------------------
#
# The keyed conversion reads the handshake metadata, the decrypted data and the
# SSH metadata from ONE combined `-T ek` pass, so these tests feed that pass's
# rows (tests/unit/_fake_tshark.py) instead of patching per-pass extractors.

_REQUEST = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
_RESPONSE = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"


def _write_pcap_inputs(tmp_path, *, pcap_name="cap.pcapng"):
    """Create the existence-only pcap + empty keylog the mocked tshark path needs.

    Returns ``(pcap_path, keylog_path)`` as strings. tshark is always
    monkeypatched in these wiring tests, so the file *contents* are irrelevant —
    only their presence (the decryptable precondition) matters."""
    pcap = tmp_path / pcap_name
    pcap.write_bytes(b"\x00")
    keylog = tmp_path / "keys.log"
    keylog.write_text("")
    return str(pcap), str(keylog)


def _http_exchange_rows():
    """The request (client) and response (server) app-data rows of tcp.stream 0."""
    return [
        ft.tls_app_data_row(_REQUEST, ts=1700000001.0),
        ft.tls_app_data_row(_RESPONSE, src=ft.SERVER, dst=ft.CLIENT, ts=1700000002.0),
    ]


def _convert(tmp_path, monkeypatch, rows) -> tuple:
    """Run a keyed conversion over *rows*; return ``(result, flows, fake)``."""
    fake = ft.FakeTshark(rows).install(monkeypatch)
    pcap, keylog = _write_pcap_inputs(tmp_path)
    tap = tmp_path / "cap.tap"
    result = p2t.convert_pcap_to_tap(pcap, keylog_path=keylog, tap_path=str(tap))
    with TapReader(str(tap)) as reader:
        flows = reader.read_all_flows()
    return result, flows, fake


def test_convert_stamps_tls_metadata_onto_flow(tmp_path, monkeypatch):
    rows = [
        ft.tls_handshake_row(hs_types=("1",), sni="example.com",
                             ciphersuites=("0x1301", "0xc02f"), ts=1699999999.0),
        ft.server_hello_row(cipher="0x1301", supported_version="0x0304", alpn="h2",
                            ts=1700000000.0),
        *_http_exchange_rows(),
    ]

    result, flows, fake = _convert(tmp_path, monkeypatch, rows)

    tls_flows = [f for f in flows if f.tls.sni]
    assert tls_flows, "no flow carried stamped TLS metadata"
    flow = tls_flows[0]
    assert flow.tls.sni == "example.com"
    assert flow.tls.version == "TLS 1.3"
    assert flow.tls.alpn == "h2"
    assert flow.tls.cipher == "TLS_AES_128_GCM_SHA256"
    # The handshake rows never become data: only the two app-data rows do.
    assert result.decrypted_packet_count == 2
    # One tshark run served the metadata AND the data.
    assert len(fake.calls) == 1 and fake.run_capture_calls == []


def test_convert_without_tls_metadata_still_produces_flow(tmp_path, monkeypatch):
    """No handshake rows for the stream -> no SessionEvent, but the flow still
    exists (additive behavior — the decrypted-bytes path is unaffected)."""
    result, flows, _fake = _convert(
        tmp_path, monkeypatch, [ft.tls_app_data_row(_REQUEST)])
    assert result.flow_count >= 1
    assert len(flows) >= 1
    assert not any(f.tls.sni for f in flows)


# ---------------------------------------------------------------------------
# Wiring: SSH synthetic flow
# ---------------------------------------------------------------------------

_SSH_CLIENT = ("10.0.0.1", 51000)
_SSH_SERVER = ("10.0.0.2", 22)


def _ssh_rows():
    """Banner from each side, then the client's KEXINIT, on tcp.stream 5."""
    return [
        ft.ssh_row(src=_SSH_CLIENT, dst=_SSH_SERVER, banner="SSH-2.0-OpenSSH_9.6"),
        ft.ssh_row(src=_SSH_SERVER, dst=_SSH_CLIENT, banner="SSH-2.0-OpenSSH_8.9"),
        ft.ssh_row(src=_SSH_CLIENT, dst=_SSH_SERVER, kex="curve25519-sha256,ext-info-c",
                   cipher="chacha20-poly1305@openssh.com,aes128-ctr",
                   mac="umac-64-etm@openssh.com,hmac-sha2-256"),
    ]


def test_convert_creates_ssh_synthetic_flow(tmp_path, monkeypatch):
    _result, flows, fake = _convert(tmp_path, monkeypatch, _ssh_rows())

    ssh_flows = [f for f in flows if f.detected_protocol == "SSH"]
    assert ssh_flows, "no SSH synthetic flow was written"
    flow = ssh_flows[0]
    assert flow.ssh.client_version == "SSH-2.0-OpenSSH_9.6"
    assert flow.ssh.server_version == "SSH-2.0-OpenSSH_8.9"
    assert flow.ssh.kex == "curve25519-sha256"
    assert flow.ssh.cipher == "chacha20-poly1305@openssh.com"
    assert flow.ssh.mac == "umac-64-etm@openssh.com"
    assert (flow.src_addr, flow.src_port) == _SSH_CLIENT
    assert (flow.dst_addr, flow.dst_port) == _SSH_SERVER
    # SSH rode the combined pass: no separate SSH tshark run.
    assert len(fake.calls) == 1 and fake.run_capture_calls == []


def test_ssh_row_failure_does_not_abort_conversion(tmp_path, monkeypatch):
    def boom(self, layers):
        raise RuntimeError("cannot fold this SSH row")

    monkeypatch.setattr(tshark_mod.SshConnectionAccumulator, "feed_ek", boom)
    result, flows, _fake = _convert(tmp_path, monkeypatch, _ssh_rows())
    # Must not raise — the bad rows are skipped, so no SSH flow is built.
    assert result.flow_count == 0
    assert not [f for f in flows if f.detected_protocol == "SSH"]


def test_ssh_extraction_failure_in_its_own_pass_is_swallowed(monkeypatch):
    """With an independent decryptor and no keys, SSH keeps its own pass; a
    failing extraction there is still swallowed."""
    def boom(*a, **k):
        raise RuntimeError("tshark blew up on the SSH pass")

    monkeypatch.setattr(p2t, "extract_ssh_connections", boom)
    added = []
    monkeypatch.setattr(p2t, "_add_ssh_synthetic_flows",
                        lambda *a, **k: added.append(a))
    ctx = p2t._ConversionContext(
        pcap_path="cap.pcap", keylog_path=None, tap_path="cap.tap", tls_ports=(),
        quic_ports=(), extra_decode_as=(), heuristic=False, capture_target="",
        resync_search_depth=None, tls_midstream_secrets=None, progress=None,
        has_keys=False, independent_entries=[object()], tshark_bin="tshark",
    )
    p2t._run_tshark_stage(ctx)  # must not raise
    assert added == []


def test_tls_metadata_failure_does_not_abort_conversion(tmp_path, monkeypatch):
    def boom(self, layers):
        raise RuntimeError("cannot fold this TLS handshake row")

    monkeypatch.setattr(tshark_mod.TlsMetadataAccumulator, "feed_ek", boom)
    rows = [ft.tls_handshake_row(sni="example.com"), ft.tls_app_data_row(_REQUEST)]
    result, flows, _fake = _convert(tmp_path, monkeypatch, rows)
    # Decrypted-bytes path unaffected: the flow still exists, just unstamped.
    assert result.flow_count >= 1
    assert not any(f.tls.sni for f in flows)


# ---------------------------------------------------------------------------
# Gated real-tshark smoke test (skipped when tshark is absent)
# ---------------------------------------------------------------------------

@pytest.mark.skipif(shutil.which("tshark") is None,
                    reason="real tshark binary unavailable")
def test_combined_pass_tls_metadata_with_real_tshark(tmp_path):
    """Smoke test: against a real tshark, the combined pass folds TLS metadata.

    Uses an empty/synthetic pcap (no TLS handshakes), so the dict is expected
    to be empty — we only assert the return TYPE and that no exception escapes.
    """
    import struct
    pcap = tmp_path / "empty.pcap"
    # Minimal classic pcap global header (us-resolution, little-endian).
    pcap.write_bytes(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    tshark_bin = tshark_mod.find_tshark()
    cmd = tshark_mod.build_combined_command(str(pcap), None)
    cmd[0] = tshark_bin
    accumulator = tshark_mod.TlsMetadataAccumulator()
    for pkt in tshark_mod.stream_packets(cmd):
        accumulator.feed_ek(pkt.get("layers") or {})
    assert accumulator.result() == {}
