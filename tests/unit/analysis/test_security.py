"""Tests for the TLS-hygiene analyzer and its digest/registry wiring."""

from __future__ import annotations

import json

from friTap.analysis import Severity
from friTap.analysis.security import TlsHygieneAnalyzer
from friTap.flow.layers import QuicLayer, TlsLayer
from friTap.flow.models import Flow, FlowState
from friTap.parsers.base import ParseResult


def _tls_flow(version="", cipher="", *, dst_port=443, sni="api.example.com",
              transport="tls"):
    flow = Flow(flow_id="f1", connection_id="c1", src_addr="10.0.0.1", src_port=5000,
                dst_addr="93.184.216.34", dst_port=dst_port, state=FlowState.COMPLETE,
                started=1_700_000_000.0, transport=transport)
    layer_cls = QuicLayer if transport == "quic" else TlsLayer
    flow.add_layer(layer_cls(version=version, cipher=cipher, sni=sni))
    return flow


def _cleartext_flow(*, dst_port=80, with_http=True):
    flow = Flow(flow_id="f2", connection_id="c2", src_addr="10.0.0.1", src_port=5001,
                dst_addr="93.184.216.34", dst_port=dst_port, state=FlowState.COMPLETE,
                started=1_700_000_000.0)
    if with_http:
        flow.request = ParseResult(protocol="HTTP/1.1", method="GET", url="/",
                                   host="insecure.example.com", is_complete=True)
    return flow


# --------------------------------------------------------------------------
# Version checks
# --------------------------------------------------------------------------

def test_deprecated_tls_10_is_flagged_medium():
    findings = TlsHygieneAnalyzer().analyze_flow(_tls_flow(version="TLS 1.0"))
    [f] = [f for f in findings if f.metadata.get("check") == "weak_tls_version"]
    assert f.severity is Severity.MEDIUM
    assert f.category == "network"
    assert f.metadata.get("cwe")


def test_sslv3_is_flagged_high():
    findings = TlsHygieneAnalyzer().analyze_flow(_tls_flow(version="SSLv3"))
    [f] = [f for f in findings if f.metadata.get("check") == "weak_tls_version"]
    assert f.severity is Severity.HIGH


def test_tls_12_and_13_are_not_flagged():
    for good in ("TLS 1.2", "TLS 1.3", "TLSv1.2"):
        findings = TlsHygieneAnalyzer().analyze_flow(_tls_flow(version=good))
        assert [f for f in findings if f.metadata.get("check") == "weak_tls_version"] == []


def test_unknown_version_is_left_alone():
    findings = TlsHygieneAnalyzer().analyze_flow(_tls_flow(version="weird-thing"))
    assert [f for f in findings if f.metadata.get("check") == "weak_tls_version"] == []


# --------------------------------------------------------------------------
# Cipher checks
# --------------------------------------------------------------------------

def test_rc4_cipher_is_high():
    findings = TlsHygieneAnalyzer().analyze_flow(
        _tls_flow(version="TLS 1.2", cipher="TLS_RSA_WITH_RC4_128_SHA"))
    [f] = [f for f in findings if f.metadata.get("check") == "weak_cipher"]
    assert f.severity is Severity.HIGH
    assert "RC4" in f.title


def test_3des_cipher_is_medium_sweet32():
    findings = TlsHygieneAnalyzer().analyze_flow(
        _tls_flow(version="TLS 1.2", cipher="TLS_RSA_WITH_3DES_EDE_CBC_SHA"))
    [f] = [f for f in findings if f.metadata.get("check") == "weak_cipher"]
    assert f.severity is Severity.MEDIUM


def test_static_rsa_is_low_no_pfs():
    findings = TlsHygieneAnalyzer().analyze_flow(
        _tls_flow(version="TLS 1.2", cipher="TLS_RSA_WITH_AES_128_GCM_SHA256"))
    [f] = [f for f in findings if f.metadata.get("check") == "weak_cipher"]
    assert f.severity is Severity.LOW


def test_strong_tls13_suite_is_not_flagged():
    findings = TlsHygieneAnalyzer().analyze_flow(
        _tls_flow(version="TLS 1.3", cipher="TLS_AES_128_GCM_SHA256"))
    assert findings == []


def test_strong_ecdhe_suite_openssl_name_is_not_flagged():
    findings = TlsHygieneAnalyzer().analyze_flow(
        _tls_flow(version="TLS 1.2", cipher="ECDHE-RSA-AES128-GCM-SHA256"))
    assert findings == []


def test_quic_weak_cipher_is_flagged_but_quic_version_is_not():
    # A QUIC transport version ("1") must not trip the TLS-version rule, but a
    # weak AEAD suite still should.
    findings = TlsHygieneAnalyzer().analyze_flow(
        _tls_flow(version="1", cipher="TLS_RSA_WITH_RC4_128_SHA", transport="quic"))
    checks = {f.metadata.get("check") for f in findings}
    assert "weak_cipher" in checks
    assert "weak_tls_version" not in checks


# --------------------------------------------------------------------------
# Cleartext checks
# --------------------------------------------------------------------------

def test_cleartext_http_on_port_80_is_flagged():
    findings = TlsHygieneAnalyzer().analyze_flow(_cleartext_flow(dst_port=80))
    [f] = findings
    assert f.metadata.get("check") == "cleartext_transport"
    assert f.severity is Severity.MEDIUM
    assert f.category == "network"


def test_layerless_flow_on_443_is_not_cleartext():
    # A live decrypted-TLS flow carries no handshake metadata (no layer) but is
    # not cleartext — the port gate prevents a false positive.
    findings = TlsHygieneAnalyzer().analyze_flow(_cleartext_flow(dst_port=443))
    assert findings == []


def test_cleartext_requires_parsed_http():
    findings = TlsHygieneAnalyzer().analyze_flow(_cleartext_flow(dst_port=80, with_http=False))
    assert findings == []


def test_tls_flow_is_never_cleartext():
    findings = TlsHygieneAnalyzer().analyze_flow(
        _tls_flow(version="TLS 1.3", cipher="TLS_AES_128_GCM_SHA256", dst_port=80))
    assert [f for f in findings if f.metadata.get("check") == "cleartext_transport"] == []


# --------------------------------------------------------------------------
# Registry / focus wiring
# --------------------------------------------------------------------------

def test_registered_and_resolvable():
    from friTap.analysis.registry import available_analyzers, resolve_analyzers

    assert "tls_hygiene" in available_analyzers()
    [analyzer] = resolve_analyzers("tls_hygiene")
    assert analyzer.name == "tls_hygiene"


def test_runs_under_security_focus_not_privacy():
    from friTap.analysis.digest import builtin_analyzers

    security_names = {a.name for a in builtin_analyzers(False, focus="security")}
    privacy_names = {a.name for a in builtin_analyzers(False, focus="privacy")}
    assert "tls_hygiene" in security_names
    assert "tls_hygiene" not in privacy_names


# --------------------------------------------------------------------------
# build_digest integration (+ MASVS opt-in / byte-identical default)
# --------------------------------------------------------------------------

def _weak_tls_tap(tmp_path):
    from tests.unit._digest_helpers import http_flow, write_tap

    flow = http_flow("f1", host="insecure.example.com")
    flow.add_layer(TlsLayer(version="TLS 1.0", cipher="TLS_RSA_WITH_RC4_128_SHA",
                            sni="insecure.example.com"))
    return str(write_tap(tmp_path / "weak.tap", [flow]))


def test_security_focus_surfaces_tls_hygiene_finding(tmp_path):
    from friTap.analysis.digest import build_digest

    doc = build_digest(_weak_tls_tap(tmp_path), focus="security")
    sources = {row["source"] for row in doc["findings"]["top"]}
    assert "tls_hygiene" in sources


def test_masvs_default_off_is_byte_identical(tmp_path):
    from friTap.analysis.digest import build_digest

    doc = build_digest(_weak_tls_tap(tmp_path), focus="security")
    assert "masvs" not in doc["params"]
    assert "masvs" not in json.dumps(doc)  # no MASVS artifact anywhere by default


def test_masvs_opt_in_tags_findings(tmp_path):
    from friTap.analysis.digest import build_digest

    doc = build_digest(_weak_tls_tap(tmp_path), focus="security", masvs=True)
    assert doc["params"]["masvs"] is True
    tagged = [row for row in doc["findings"]["top"] if row.get("masvs")]
    assert tagged, "expected at least one MASVS-tagged finding"
    assert any("MASVS-NETWORK-1" in row["masvs"] for row in tagged)
