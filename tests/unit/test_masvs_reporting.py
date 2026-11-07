"""MASVS column/field in the human reporters, the digest MD renderer and `analyze`."""

from __future__ import annotations

import json

from friTap.analysis import Finding, Severity
from friTap.analysis.reporters import (
    CsvReporter,
    JsonReporter,
    MarkdownReporter,
    TableReporter,
)


def _secret_finding():
    return Finding(severity=Severity.HIGH,
                   title="Bearer token in Authorization header",
                   description="Bearer token found in request to api.example.com/v1",
                   source="credentials", flow_id="f1",
                   metadata={"category": "secret"})


# --------------------------------------------------------------------------
# Reporters: opt-in on, byte-identical off
# --------------------------------------------------------------------------

def test_table_masvs_column():
    f = _secret_finding()
    on = TableReporter(masvs=True).report([f])
    assert "MASVS" in on and "MASVS-AUTH-1" in on
    off = TableReporter().report([f])
    assert "MASVS" not in off


def test_csv_masvs_column():
    f = _secret_finding()
    on = CsvReporter(masvs=True).report([f])
    header = on.splitlines()[0]
    assert "masvs" in header
    assert "MASVS-AUTH-1;MASVS-CRYPTO-1" in on
    off = CsvReporter().report([f])
    assert "masvs" not in off.splitlines()[0]


def test_json_masvs_field():
    f = _secret_finding()
    on = json.loads(JsonReporter(masvs=True).report([f]))
    assert on["findings"][0]["masvs"] == ["MASVS-AUTH-1", "MASVS-CRYPTO-1"]
    off = json.loads(JsonReporter().report([f]))
    assert "masvs" not in off["findings"][0]


def test_markdown_masvs_line():
    f = _secret_finding()
    on = MarkdownReporter(masvs=True).report([f])
    assert "**MASVS:**" in on and "MASVS-AUTH-1" in on
    assert "**MASVS:**" not in MarkdownReporter().report([f])


def test_unmapped_finding_gets_no_masvs_column_value():
    # A plain network IOC maps to no control -> blank cell, not a crash.
    ioc = Finding(severity=Severity.INFO, title="Domain: x.example", description="d",
                  source="ioc", metadata={"category": "network"})
    on = CsvReporter(masvs=True).report([ioc])
    # header has the column, but the value cell is empty for this finding
    assert "masvs" in on.splitlines()[0]
    assert json.loads(JsonReporter(masvs=True).report([ioc]))["findings"][0].get("masvs") is None


# --------------------------------------------------------------------------
# Digest markdown renderer
# --------------------------------------------------------------------------

def test_digest_md_finding_line_includes_masvs():
    from friTap.analysis.digest_render import _finding_line

    row = {"severity": "high", "category": "secret", "count": 2, "ref": "f1",
           "masvs": ["MASVS-AUTH-1", "MASVS-CRYPTO-1"],
           "untrusted": {"title": "t", "description": "d"}}
    assert "[MASVS-AUTH-1, MASVS-CRYPTO-1]" in _finding_line(row)
    row.pop("masvs")
    assert "MASVS" not in _finding_line(row)


# --------------------------------------------------------------------------
# analyze_tap_report integration
# --------------------------------------------------------------------------

def _sec_tap(tmp_path):
    from friTap.flow.layers import TlsLayer
    from tests.unit._digest_helpers import http_flow, write_tap

    weak = http_flow("f1", host="legacy.example.com", url="/ping")
    weak.add_layer(TlsLayer(version="TLS 1.0", cipher="TLS_RSA_WITH_RC4_128_SHA"))
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig"
    secret = http_flow("f2", host="api.example.com", url="/v2/me",
                       headers={"authorization": f"Bearer {jwt}"})
    secret.add_layer(TlsLayer(version="TLS 1.3", cipher="TLS_AES_128_GCM_SHA256"))
    return str(write_tap(tmp_path / "sec.tap", [weak, secret]))


def test_analyze_report_masvs_on_and_off(tmp_path):
    from friTap.commands.analyze import analyze_tap_report

    tap = _sec_tap(tmp_path)
    on = analyze_tap_report(tap, report_format="table", masvs=True).rendered
    assert "MASVS-NETWORK-1" in on  # from the weak-TLS flow
    off = analyze_tap_report(tap, report_format="table").rendered
    assert "MASVS" not in off
