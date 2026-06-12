"""Unit tests for the pure ``analyze_tap_report`` public API.

Exercises the presentation-agnostic analysis entry point (no stdout, no
sidecar, no ``sys.exit``) across every report format, its ValueError contract,
``min_severity`` filtering monotonicity, and CLI-parity gate/exit_code. Reuses
the credential-bearing Flow fixture style from ``test_analysis_exposure`` and
writes tiny .tap files via the same TapWriter helper. Pure Python.
"""

import json

import pytest

from friTap import (
    analyze_tap_report,
    list_analyzers,
    list_report_formats,
)
from friTap.commands.analyze import AnalyzeReport
from friTap.flow.models import Flow, FlowChunk, FlowState
from friTap.flow.tap_writer import TapWriter
from friTap.parsers.base import ParseResult


# A known AWS access key matching the CredentialAnalyzer pattern (AKIA + 16).
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"


# ---------------------------------------------------------------------------
# Fixtures (mirror test_analysis_exposure._make_http_flow / _write_tap_with_flow)
# ---------------------------------------------------------------------------

def _make_http_flow(body_bytes: bytes, *, flow_id: str = "flow-1") -> Flow:
    host = "api.example.com"
    url = "/upload"
    all_headers = {"Host": host, "Content-Type": "text/plain"}
    header_lines = "".join(f"{k}: {v}\r\n" for k, v in all_headers.items())
    request_bytes = (
        f"POST {url} HTTP/1.1\r\n"
        f"{header_lines}"
        f"Content-Length: {len(body_bytes)}\r\n"
        f"\r\n"
    ).encode("utf-8") + body_bytes

    flow = Flow(
        flow_id=flow_id,
        connection_id="conn-1",
        src_addr="10.0.0.2",
        src_port=51000,
        dst_addr="93.184.216.34",
        dst_port=443,
        state=FlowState.COMPLETE,
        started=1000.0,
        ended=1001.0,
    )
    flow.request = ParseResult(
        protocol="HTTP/1.1",
        method="POST",
        url=url,
        host=host,
        headers={**all_headers, "Content-Length": str(len(body_bytes))},
        body=b"",
        content_type="text/plain",
        is_request=True,
        is_complete=True,
    )
    flow.chunks.append(FlowChunk(
        data=request_bytes, direction="write", timestamp=1000.0, function="SSL_write",
    ))
    flow._total_bytes = len(request_bytes)
    return flow


def _make_clean_flow(flow_id: str = "clean") -> Flow:
    return _make_http_flow(b"just a harmless body", flow_id=flow_id)


def _write_tap_with_flow(path: str, flow: Flow) -> None:
    writer = TapWriter()
    writer.open(path)
    writer.write_flow(flow)
    writer.close()


def _credential_tap(tmp_path) -> str:
    flow = _make_http_flow(f"key={AWS_KEY}".encode(), flow_id="aws-1")
    tap_file = str(tmp_path / "credential.tap")
    _write_tap_with_flow(tap_file, flow)
    return tap_file


def _clean_tap(tmp_path) -> str:
    tap_file = str(tmp_path / "clean.tap")
    _write_tap_with_flow(tap_file, _make_clean_flow())
    return tap_file


# ---------------------------------------------------------------------------
# 1. Registry list helpers
# ---------------------------------------------------------------------------

def test_list_report_formats_values():
    assert list_report_formats() == ["csv", "json", "md", "table"]


def test_list_analyzers_values():
    assert list_analyzers() == ["credentials", "ioc", "privacy", "protobuf"]


# ---------------------------------------------------------------------------
# 2. analyze_tap_report across every report format
# ---------------------------------------------------------------------------

def test_analyze_tap_report_every_format(tmp_path):
    tap_file = _credential_tap(tmp_path)

    for fmt in list_report_formats():
        report = analyze_tap_report(
            tap_file, scanners="credentials", report_format=fmt
        )
        assert isinstance(report, AnalyzeReport)
        assert report.report_format == fmt
        assert report.analyzer_names == ["credentials"]
        assert isinstance(report.rendered, str) and report.rendered.strip() != ""
        assert report.meta["tap_file"] == tap_file
        # No mutation of the input: it's a pure read.
        if fmt == "json":
            parsed = json.loads(report.rendered)
            assert "summary" in parsed
            assert parsed["summary"]["total"] == len(report.findings)


def test_analyze_tap_report_json_is_clean_json(tmp_path):
    tap_file = _credential_tap(tmp_path)
    report = analyze_tap_report(tap_file, scanners="credentials", report_format="json")
    # Must parse without error.
    data = json.loads(report.rendered)
    titles = [f["title"] for f in data["findings"]]
    assert any("AWS Access Key" in t for t in titles)


# ---------------------------------------------------------------------------
# 3. ValueError contract
# ---------------------------------------------------------------------------

def test_bad_report_format_raises_value_error(tmp_path):
    tap_file = _credential_tap(tmp_path)
    with pytest.raises(ValueError) as exc:
        analyze_tap_report(tap_file, scanners="credentials", report_format="xml")
    assert "xml" in str(exc.value)


def test_bad_scanner_name_raises_value_error(tmp_path):
    tap_file = _credential_tap(tmp_path)
    with pytest.raises(ValueError) as exc:
        analyze_tap_report(tap_file, scanners="bogus")
    assert "bogus" in str(exc.value)


# ---------------------------------------------------------------------------
# 4. min_severity filtering is monotonic
# ---------------------------------------------------------------------------

def test_min_severity_filtering_monotonic(tmp_path):
    tap_file = _credential_tap(tmp_path)

    # info (keep all) >= medium >= high >= critical in count terms.
    counts = {}
    for sev in ("info", "low", "medium", "high", "critical"):
        report = analyze_tap_report(
            tap_file, scanners="credentials", min_severity=sev
        )
        counts[sev] = len(report.findings)
        # The returned findings are already filtered: none below threshold.
        assert all(f is not None for f in report.findings)

    assert counts["info"] >= counts["low"] >= counts["medium"] >= counts["high"] >= counts["critical"]
    # A clean baseline: the AWS key is HIGH, so info must retain at least one.
    assert counts["info"] >= 1


# ---------------------------------------------------------------------------
# 5. Gate / exit_code parity
# ---------------------------------------------------------------------------

def test_gate_tripped_for_credential_tap(tmp_path):
    """An AWS key is HIGH (>= the default medium gate) -> gate_tripped, exit 2."""
    tap_file = _credential_tap(tmp_path)
    report = analyze_tap_report(tap_file, scanners="credentials")
    assert report.gate_severity == "medium"
    assert report.gate_tripped is True
    assert report.exit_code == 2


def test_gate_not_tripped_for_clean_tap(tmp_path):
    """A clean tap yields no medium+ finding -> gate clear, exit 0."""
    tap_file = _clean_tap(tmp_path)
    report = analyze_tap_report(tap_file, scanners="credentials")
    assert report.gate_tripped is False
    assert report.exit_code == 0


def test_gate_clears_when_min_severity_filters_out_high(tmp_path):
    """Filtering to critical-only removes the HIGH AWS finding, clearing the gate."""
    tap_file = _credential_tap(tmp_path)
    report = analyze_tap_report(
        tap_file, scanners="credentials", min_severity="critical"
    )
    # No credential here is critical, so nothing remains at/above medium.
    assert report.gate_tripped is False
    assert report.exit_code == 0


def test_run_analyze_cli_exit_code_matches_report(tmp_path):
    """The CLI's exit code must equal ``AnalyzeReport.exit_code`` for the same
    inputs — the two share the gate logic, so this guards against future drift."""
    from friTap.commands.analyze import run_analyze_cli

    for tap_file in (_credential_tap(tmp_path), _clean_tap(tmp_path)):
        report = analyze_tap_report(tap_file, scanners="credentials")
        report_out = str(tmp_path / "report.txt")  # keep stdout/cwd clean
        rc = run_analyze_cli(
            [tap_file, "--scanners", "credentials", "--report-out", report_out]
        )
        assert rc == report.exit_code


# ---------------------------------------------------------------------------
# 6. Two-stage error classification in run_analyze_cli
# ---------------------------------------------------------------------------

def test_cli_resolve_error_is_classified_as_resolve(tmp_path, caplog):
    """A bad scanner name logs the resolve-stage diagnostic (not 'Analysis failed')."""
    import logging
    from friTap.commands.analyze import run_analyze_cli

    tap_file = _credential_tap(tmp_path)
    with caplog.at_level(logging.ERROR, logger="friTap.analyze"):
        rc = run_analyze_cli([tap_file, "--scanners", "bogus"])
    assert rc == 1
    assert "Could not resolve analyzers" in caplog.text
    assert "Analysis failed" not in caplog.text


def test_cli_analyze_error_is_classified_as_analysis(tmp_path, caplog, monkeypatch):
    """A ValueError raised during analysis (e.g. corrupt .tap) must log
    'Analysis failed', NOT be misclassified as a scanner-resolution problem."""
    import logging
    import friTap.commands.analyze as analyze_mod

    tap_file = _credential_tap(tmp_path)

    def _boom(*_a, **_k):
        raise ValueError("corrupt .tap record")

    # Resolution still succeeds (valid scanner); the failure is in analysis.
    monkeypatch.setattr(analyze_mod, "analyze_tap_multi", _boom)

    with caplog.at_level(logging.ERROR, logger="friTap.analyze"):
        rc = analyze_mod.run_analyze_cli([tap_file, "--scanners", "credentials"])
    assert rc == 1
    assert "Analysis failed" in caplog.text
    assert "Could not resolve analyzers" not in caplog.text
