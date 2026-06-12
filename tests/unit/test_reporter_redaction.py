"""Reporter-layer redaction tests.

Redaction is deny-by-default: for a pii/secret finding, every evidence string
value is masked unless its key is a known-safe descriptive context key. These
tests lock in that no sensitive value leaks into a rendered report — including
values stored under keys the reporter was never explicitly told about.
"""

from __future__ import annotations

import json

from friTap.analysis import Finding, Severity
from friTap.analysis.reporters import (
    JsonReporter,
    CsvReporter,
    MarkdownReporter,
    TableReporter,
)

_ALL_REPORTERS = (JsonReporter, CsvReporter, MarkdownReporter, TableReporter)

_SECRET = "sekret-claims-abcdef123456"


def _secret_finding(evidence_key: str) -> Finding:
    """A secret finding whose sensitive value lives under *evidence_key* and is
    also echoed into the title (the IOC-email leak shape)."""
    return Finding(
        severity=Severity.HIGH,
        title=f"Token {_SECRET} in header",
        description=f"value {_SECRET} sent to api.example.com",
        source="credentials",
        evidence={evidence_key: _SECRET, "location": "request_header", "host": "api.example.com"},
        metadata={"category": "secret"},
    )


def test_redacted_by_default_for_known_and_unknown_keys():
    # 'value' is an obvious sensitive key; 'payload'/'bearer' are NOT special-cased
    # but must still be masked under deny-by-default.
    for key in ("value", "payload", "bearer", "authorization"):
        f = _secret_finding(key)
        for R in _ALL_REPORTERS:
            out = R().report([f])
            assert _SECRET not in out, f"{R.__name__} leaked secret under key {key!r}"


def test_show_pii_reveals_raw_value():
    f = _secret_finding("payload")
    for R in _ALL_REPORTERS:
        out = R(redact_pii=False).report([f])
        assert _SECRET in out, f"{R.__name__} should reveal raw value with redact_pii=False"


def test_safe_context_keys_preserved_in_json():
    f = _secret_finding("value")
    data = json.loads(JsonReporter().report([f]))
    ev = data["findings"][0]["evidence"]
    assert ev["host"] == "api.example.com"        # safe key preserved
    assert ev["location"] == "request_header"      # safe key preserved
    assert ev["value"] != _SECRET                  # sensitive key masked
    assert ev["redacted"] is True


def test_non_sensitive_finding_untouched():
    f = Finding(
        severity=Severity.INFO,
        title="Destination IP 203.0.113.5",
        description="connection",
        source="ioc",
        evidence={"value": "203.0.113.5", "type": "ip"},
        metadata={"category": "network"},
    )
    out = JsonReporter().report([f])
    assert "203.0.113.5" in out  # network findings are not redacted


def test_analyzer_self_redacted_finding_not_double_masked():
    # A finding the analyzer already redacted (evidence["redacted"]=True, e.g.
    # PrivacyAnalyzer) is passed through untouched by the reporter.
    f = Finding(
        severity=Severity.LOW,
        title="PII: email",
        description="email found",
        source="privacy",
        evidence={"value": "j****@example.com", "redacted": True, "location": "body"},
        metadata={"category": "pii"},
    )
    out = JsonReporter().report([f])
    data = json.loads(out)
    assert data["findings"][0]["evidence"]["value"] == "j****@example.com"
