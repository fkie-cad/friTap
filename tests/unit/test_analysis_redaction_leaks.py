#!/usr/bin/env python3

"""Regression tests for the ``fritap analyze`` redaction leak.

Before the fix, finding titles/descriptions/evidence embedded the full request
URL (``?email=alice@...&access_token=...#frag=...``) even for findings marked
redacted, and IOC (``network``) URL findings were never redacted at all.

Covers, layer by layer:

* :func:`scrub_values` / :func:`redact_finding` (unit);
* every report format of :func:`analyze_tap_report` on a synthetic ``.tap``;
* the ``<stem>.findings.json`` sidecar written by :func:`run_analyze_cli`;
* the ``fritap report`` digest and ``--flow`` drill-down;
* the analyzers themselves, which keep full fidelity (raw URLs in finding
  text): redaction happens only at those egress layers.

The ``test_regression_*`` tests pin gaps found while writing this suite (PAN in
a URL path via the IOC URL finding, query keys longer than 64 chars, query
values containing an apostrophe); all are closed in ``redaction.scrub_values``.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from friTap.analysis import Finding, Severity
from friTap.analysis.credentials import CredentialAnalyzer
from friTap.analysis.ioc import IocAnalyzer
from friTap.analysis.privacy import PrivacyAnalyzer
from friTap.analysis.redaction import (
    EMAIL_REDACTED,
    REDACTED,
    _scrub_nested,
    redact_finding,
    redact_title,
    scrub_key_material,
    scrub_values,
)
from friTap.analysis.reporters import JsonReporter, MarkdownReporter
from friTap.commands.analyze import analyze_tap_report, run_analyze_cli
from friTap.flow.models import Flow, FlowChunk, FlowState
from friTap.flow.tap_writer import TapWriter
from friTap.parsers.base import ParseResult
from friTap.pipeline import TLS_KEYLOG_LABELS

HOST = "api.example.com"
EMAIL = "alice.secret@example.org"
TOKEN = "SECRETTOKEN0123456789"
FRAGMENT = "FRAGSECRET42"
REFERER_VALUE = "REFSECRETVALUE99"
BODY_EMAIL = "bob.body@example.net"

REQUEST_URL = f"/v1/signup?email={EMAIL}&access_token={TOKEN}#frag={FRAGMENT}"
REFERER = f"https://app.example.com/welcome?ref={REFERER_VALUE}"

# None of these contain characters the Markdown reporter escapes (``_``, ``*``,
# ``#`` ...), so a substring miss really means "absent" in every format — the
# show_pii tests prove the values *are* found when not redacted.
SECRETS = (EMAIL, TOKEN, FRAGMENT, REFERER_VALUE, BODY_EMAIL)
FORMATS = ("json", "csv", "md", "table")


# ---------------------------------------------------------------------------
# Fixture helpers (same construction as tests/unit/test_report_digest.py)
# ---------------------------------------------------------------------------

def _json_body() -> bytes:
    return json.dumps({"contact": BODY_EMAIL, "plan": "free"}).encode()


def _http_flow(flow_id: str = "leak-1", *, url: str = REQUEST_URL, body: bytes | None = None) -> Flow:
    body = _json_body() if body is None else body
    headers = {"host": HOST, "content-type": "application/json", "referer": REFERER}
    flow = Flow(flow_id=flow_id, connection_id=flow_id, src_addr="10.0.0.1",
                src_port=50000, dst_addr="93.184.216.34", dst_port=443,
                state=FlowState.COMPLETE, started=1_700_000_000.0)
    flow.chunks.append(FlowChunk(data=b"x" * 100 + body, direction="write",
                                 timestamp=1_700_000_000.0))
    flow.request = ParseResult(protocol="HTTP/1.1", method="POST", url=url, host=HOST,
                               headers=headers, body=body, content_type="application/json",
                               is_complete=True)
    flow.response = ParseResult(protocol="HTTP/1.1", status_code=200, is_request=False,
                                is_complete=True)
    return flow


def _write_tap(path: Path, flows: list[Flow]) -> str:
    writer = TapWriter()
    writer.open(str(path), target="test")
    for flow in flows:
        writer.write_flow(flow)
    writer.close()
    return str(path)


def _leaked(text: str) -> list[str]:
    """Return every secret value that appears verbatim in *text*."""
    return [value for value in SECRETS if value in text]


def _serialized(finding: Finding) -> str:
    return json.dumps(finding.to_dict(), default=str)


def _analyze_in_memory(flow: Flow) -> list[Finding]:
    analyzers = (CredentialAnalyzer(), IocAnalyzer(), PrivacyAnalyzer())
    return [finding for analyzer in analyzers for finding in analyzer.analyze_flow(flow)]


def _sidecar_text(tap_path: str) -> str:
    return Path(tap_path).with_suffix(".findings.json").read_text(encoding="utf-8")


@pytest.fixture
def leak_tap(tmp_path) -> str:
    return _write_tap(tmp_path / "leak.tap", [_http_flow()])


# ---------------------------------------------------------------------------
# 1. scrub_values
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("text, expected", [
    (f"https://{HOST}/signup?email={EMAIL}&lang=en",
     f"https://{HOST}/signup?email={REDACTED}&lang={REDACTED}"),
    ("/app#access_token=abc123", f"/app#{REDACTED}"),
    ("https://user:hunter2@host.example/x", f"https://{REDACTED}@host.example/x"),
    (f"contact {EMAIL} today", f"contact {EMAIL_REDACTED} today"),
], ids=["query-values", "fragment", "userinfo", "email-anywhere"])
def test_scrub_values_masks_values_keeps_structure(text, expected):
    assert scrub_values(text) == expected


@pytest.mark.parametrize("text", [
    "Set-Cookie with domain=example.com",
    "Connection to 1.2.3.4:443",
    "HTTP request to domain api.example.com",
    "",
])
def test_scrub_values_leaves_text_without_url_values_unchanged(text):
    assert scrub_values(text) == text


def test_scrub_values_replaces_raw_values_of_min_length():
    text = "user SECRETVAL logged in from abcd"
    scrubbed = scrub_values(text, raw_values=("SECRETVAL", "abcd"))
    # "abcd" is below MIN_SCRUB_LEN and must not mangle unrelated text.
    assert scrubbed == f"user {REDACTED} logged in from abcd"


def test_scrub_values_custom_placeholder():
    assert scrub_values("/a?x=1#frag", placeholder="***") == "/a?x=***#***"


# ---------------------------------------------------------------------------
# 1b. redact_finding
# ---------------------------------------------------------------------------

def _ioc_url_finding() -> Finding:
    full_url = f"https://{HOST}{REQUEST_URL}"
    return Finding(
        severity=Severity.INFO,
        title=f"POST {HOST}{REQUEST_URL[:60]}",
        description=f"HTTP request: POST {full_url}",
        source="ioc",
        evidence={"type": "url", "value": full_url, "method": "POST", "status": "200"},
        metadata={"category": "network"},
    )


def test_redact_finding_scrubs_network_ioc_url():
    original = _ioc_url_finding()
    redacted = redact_finding(original)

    assert _leaked(_serialized(redacted)) == []
    assert "email=" in redacted.description and "access_token=" in redacted.description
    assert redacted.evidence["redacted"] is True
    assert redacted.evidence["method"] == "POST"
    # The in-memory finding keeps full fidelity.
    assert TOKEN in original.evidence["value"]


def test_redact_finding_scrubs_already_redacted_pii_text():
    url_label = f"{HOST}{REQUEST_URL}"
    finding = Finding(
        severity=Severity.LOW,
        title="PII: email",
        description=f"PII of type 'email' detected in url_query for {url_label}",
        source="privacy",
        evidence={"category": "email", "value": "a***@example.org", "redacted": True,
                  "host": url_label},
        metadata={"category": "pii"},
    )
    redacted = redact_finding(finding)

    assert _leaked(_serialized(redacted)) == []
    assert f"email={REDACTED}" in redacted.description
    assert f"email={REDACTED}" in redacted.evidence["host"]


def test_redact_finding_returns_plain_network_finding_unchanged():
    finding = Finding(
        severity=Severity.INFO,
        title="Destination IP: 203.0.113.5",
        description="Connection to 203.0.113.5:443",
        source="ioc",
        evidence={"type": "ip", "value": "203.0.113.5", "port": 443},
        metadata={"category": "network"},
    )
    assert redact_finding(finding) is finding


# ---------------------------------------------------------------------------
# 2. End to end: analyze_tap_report in every format
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("fmt", FORMATS)
def test_report_redacts_values_by_default(leak_tap, fmt):
    rendered = analyze_tap_report(leak_tap, report_format=fmt).rendered

    assert _leaked(rendered) == []
    assert "email=" in rendered and "ref=" in rendered


@pytest.mark.parametrize("fmt", ("json", "csv", "md"))
def test_report_show_pii_reveals_values(leak_tap, fmt):
    rendered = analyze_tap_report(leak_tap, report_format=fmt, show_pii=True).rendered

    assert EMAIL in rendered
    assert TOKEN in rendered


def test_table_report_show_pii_reveals_values(leak_tap):
    # The table truncates cells, so only the visible prefixes can be checked.
    rendered = analyze_tap_report(leak_tap, report_format="table", show_pii=True).rendered

    assert REFERER_VALUE in rendered
    assert f"email={EMAIL[:12]}" in rendered


def test_report_findings_keep_full_fidelity(leak_tap):
    report = analyze_tap_report(leak_tap, report_format="json")

    assert any(TOKEN in finding.description for finding in report.findings)


def test_markdown_with_evidence_does_not_leak():
    findings = _analyze_in_memory(_http_flow())
    rendered = MarkdownReporter(include_evidence=True).report(findings)

    assert "**Evidence:**" in rendered
    assert _leaked(rendered) == []
    assert f"access_token={REDACTED}" in rendered


# ---------------------------------------------------------------------------
# 3. Sidecar written by run_analyze_cli
# ---------------------------------------------------------------------------

def test_sidecar_is_redacted_by_default(leak_tap, capsys):
    assert run_analyze_cli([leak_tap]) in (0, 2)

    sidecar = _sidecar_text(leak_tap)
    assert _leaked(sidecar) == []
    assert "access_token=" in sidecar
    assert _leaked(capsys.readouterr().out) == []


def test_sidecar_show_pii_reveals_values(leak_tap, capsys):
    assert run_analyze_cli([leak_tap, "--show-pii"]) in (0, 2)
    capsys.readouterr()

    sidecar = _sidecar_text(leak_tap)
    assert EMAIL in sidecar
    assert TOKEN in sidecar


# ---------------------------------------------------------------------------
# 4. Analyzers keep full fidelity; egress layers redact
# ---------------------------------------------------------------------------

def test_analyzers_keep_full_fidelity_in_finding_text():
    findings = _analyze_in_memory(_http_flow())
    raw_url = f"{HOST}{REQUEST_URL}"

    assert any(raw_url in f.description for f in findings if f.source == "privacy")
    assert any(raw_url in f.evidence.get("host", "") for f in findings if f.source == "credentials")


@pytest.mark.parametrize("analyzer_cls", (PrivacyAnalyzer, CredentialAnalyzer))
def test_redact_finding_removes_values_from_analyzer_findings(analyzer_cls):
    findings = analyzer_cls().analyze_flow(_http_flow())

    assert findings
    for finding in findings:
        assert _leaked(_serialized(redact_finding(finding))) == []


def _access_token_finding(analyzer: CredentialAnalyzer) -> Finding:
    findings = analyzer.analyze_flow(_http_flow())
    return next(f for f in findings if f.evidence.get("parameter") == "access_token")


def test_credentials_egress_keeps_query_keys():
    finding = redact_finding(_access_token_finding(CredentialAnalyzer()))

    assert TOKEN not in finding.description
    assert "access_token=" in finding.evidence["host"]


def test_credentials_analyzer_redacts_its_own_evidence_value():
    finding = _access_token_finding(CredentialAnalyzer())

    assert TOKEN in finding.description  # full fidelity in text ...
    assert finding.evidence["value"] != TOKEN  # ... but the secret value is masked


@pytest.mark.parametrize("fmt", FORMATS)
def test_reporters_redact_analyzer_findings(fmt):
    from friTap.commands.analyze import _REPORTER_REGISTRY

    findings = _analyze_in_memory(_http_flow())
    assert _leaked(_REPORTER_REGISTRY[fmt]().report(findings)) == []


def test_digest_and_flow_detail_do_not_leak(leak_tap):
    from friTap.analysis.digest import build_digest
    from friTap.analysis.digest_flow import build_flow_detail

    assert _leaked(json.dumps(build_digest(leak_tap), ensure_ascii=False)) == []
    assert _leaked(json.dumps(build_flow_detail(leak_tap, "f1"), ensure_ascii=False)) == []


def test_digest_show_values_reveals_finding_text(leak_tap):
    from friTap.analysis.digest import build_digest

    assert TOKEN in json.dumps(build_digest(leak_tap, show_values=True), ensure_ascii=False)


def test_ioc_findings_keep_full_url_but_json_report_does_not():
    findings = IocAnalyzer().analyze_flow(_http_flow())
    url_values = [f.evidence["value"] for f in findings if f.evidence.get("type") == "url"]

    assert f"https://{HOST}{REQUEST_URL}" in url_values
    assert _leaked(JsonReporter().report(findings)) == []


# ---------------------------------------------------------------------------
# 5. KNOWN LEAKS — residual gaps, intentionally not fixed here
# ---------------------------------------------------------------------------

def test_regression_path_pan_via_ioc_url_finding(tmp_path):
    pan = "4111111111111111"
    tap = _write_tap(tmp_path / "pan.tap", [_http_flow(url=f"/v1/card/{pan}/charge", body=b"")])

    rendered = analyze_tap_report(tap, report_format="json").rendered

    assert pan not in rendered


def test_regression_long_query_key_value():
    scrubbed = scrub_values(f"https://{HOST}/x?{'k' * 70}=LONGKEYSECRET")

    assert "LONGKEYSECRET" not in scrubbed


def test_regression_query_value_after_apostrophe():
    scrubbed = scrub_values(f"https://{HOST}/x?name=d'ArtagnanSECRET&a=1")

    assert "ArtagnanSECRET" not in scrubbed


# ---------------------------------------------------------------------------
# 6. Shared redaction helpers
# ---------------------------------------------------------------------------

def test_redact_title_matches_full_redaction():
    pii = Finding(severity=Severity.LOW, title=f"E-mail {EMAIL} seen", description="d",
                  source="ioc", evidence={"value": EMAIL}, metadata={"category": "pii"})
    for finding in (pii, _ioc_url_finding()):
        for placeholder in (REDACTED, "…"):
            assert redact_title(finding, placeholder=placeholder) == \
                redact_finding(finding, placeholder=placeholder).title


def test_scrub_nested_reports_changes():
    assert _scrub_nested({"a": ["x", 1, ("y",)]}, REDACTED) == ({"a": ["x", 1, ("y",)]}, False)
    scrubbed, changed = _scrub_nested({"a": [f"/p?k={TOKEN}"]}, REDACTED)
    assert changed and scrubbed == {"a": [f"/p?k={REDACTED}"]}


@pytest.mark.parametrize("label", sorted(TLS_KEYLOG_LABELS) + [
    "CLIENT_TRAFFIC_SECRET_3", "SERVER_TRAFFIC_SECRET_12", "EARLY_EXPORTER_SECRET"])
def test_scrub_key_material_covers_every_tls_keylog_label(label):
    line = f"{label} {'ab' * 32} {'cd' * 48}"
    assert scrub_key_material(f"x {line} y") == "x <keylog-redacted> y"
