"""`scan_flows` — digest an in-memory flow list (the no-.tap-file seam)."""

from __future__ import annotations

from friTap.analysis.digest import (
    FlowSelector,
    build_digest,
    builtin_analyzers,
    scan_flows,
)
from friTap.flow.layers import TlsLayer
from tests.unit._digest_helpers import http_flow


def _flows():
    weak = http_flow("f1", host="legacy.example.com", url="/ping")
    weak.add_layer(TlsLayer(version="TLS 1.0", cipher="TLS_RSA_WITH_RC4_128_SHA"))
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig"
    secret = http_flow("f2", host="api.example.com", url="/v2/me",
                       headers={"authorization": f"Bearer {jwt}"})
    secret.add_layer(TlsLayer(version="TLS 1.3", cipher="TLS_AES_128_GCM_SHA256"))
    return [weak, secret]


def test_scan_flows_counts_and_ordinals():
    scan = scan_flows(_flows(), FlowSelector(), builtin_analyzers(False, "security"))
    assert scan.flows_total == 2
    assert set(scan.ordinals.values()) == {1, 2}
    assert scan.findings  # analyzers ran


def test_build_digest_from_in_memory_scan():
    scan = scan_flows(_flows(), FlowSelector(), builtin_analyzers(False, "security"))
    digest = build_digest("(live capture)", focus="security", masvs=True, scan=scan)
    assert digest["source"]["file"] == "(live capture)"
    tops = digest["findings"]["top"]
    assert any(r["source"] == "tls_hygiene" for r in tops)      # weak-TLS surfaced
    assert any(r.get("masvs") for r in tops)                    # MASVS tags present


def test_selector_filters_in_memory_flows():
    # app_protocol that matches nothing -> no selected flows, still a valid digest.
    scan = scan_flows(_flows(), FlowSelector(app_protocol="grpc"))
    assert scan.selected == 0
    assert scan.flows_total == 2
