"""Unit tests for the analyzer registry + offline CLI + live wiring (Workstream B).

Pure Python — no device/Frida/tshark. Covers resolve_analyzers, the
CredentialAnalyzer detections, the offline `fritap analyze` CLI, the reporters,
severity filtering, and the live EventBus -> FlowCollector -> AnalyzerPlugin path.
"""

import json
import sys
import types

import pytest

from friTap.analysis import AnalyzerPlugin, Finding, Severity
from friTap.analysis.credentials import CredentialAnalyzer
from friTap.analysis.registry import ANALYZER_REGISTRY, resolve_analyzers
from friTap.analysis.reporters import (
    CsvReporter,
    JsonReporter,
    MarkdownReporter,
    TableReporter,
)
from friTap.commands.analyze import (
    _REPORTER_REGISTRY,
    _SEVERITY_ORDER,
    _filter_min_severity,
    run_analyze_cli,
)
from friTap.events import DatalogEvent, EventBus, FlowEvent
from friTap.flow.collector import FlowCollector
from friTap.flow.models import Flow, FlowChunk, FlowState
from friTap.flow.tap_writer import TapWriter
from friTap.parsers.base import ParseResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_http_flow(
    body_bytes: bytes,
    *,
    flow_id: str = "flow-1",
    headers: dict | None = None,
    method: str = "POST",
    host: str = "api.example.com",
    url: str = "/upload",
    content_type: str = "text/plain",
) -> Flow:
    """Build an HTTP/1.1 request Flow whose body is recoverable from chunks.

    Mirrors the helper in test_tap_enrichment: ParseResult.body is left empty
    so get_decompressed_request_body() reconstructs it from the raw write chunk
    via h11 (the de-dup path the analyzers run against).
    """
    hdrs = dict(headers or {})
    all_headers = {"Host": host, "Content-Type": content_type, **hdrs}
    header_lines = "".join(f"{k}: {v}\r\n" for k, v in all_headers.items())
    request_bytes = (
        f"{method} {url} HTTP/1.1\r\n"
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
        method=method,
        url=url,
        host=host,
        headers={**all_headers, "Content-Length": str(len(body_bytes))},
        body=b"",
        content_type=content_type,
        is_request=True,
        is_complete=True,
    )
    flow.chunks.append(FlowChunk(
        data=request_bytes,
        direction="write",
        timestamp=1000.0,
        function="SSL_write",
    ))
    flow._total_bytes = len(request_bytes)
    return flow


# Known secret tokens that match the CredentialAnalyzer patterns exactly.
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"                      # AKIA + 16 chars
GITHUB_TOKEN = "ghp_" + "a" * 36                       # ghp_ + 36 alnum
STRIPE_KEY = "sk_live_" + "a" * 24                      # sk_live_ + 24 alnum
PRIVATE_KEY_BLOCK = (
    "-----BEGIN PRIVATE KEY-----\n"
    "MIIBVgIBADANBgkqhkiG9w0BAQEFAASCAUAwggE8AgEAAkEA\n"
    "-----END PRIVATE KEY-----"
)
# Google API Key: pattern AIza[0-9A-Za-z\-_]{35} -> "AIza" + 35 chars.
GOOGLE_API_KEY = "AIza" + "B" * 35
# Twilio API Key: pattern SK[0-9a-fA-F]{32} -> "SK" + 32 hex chars.
TWILIO_API_KEY = "SK" + "a1b2c3d4" * 4               # 32 hex chars
# SendGrid API Key: pattern SG.<22>.<43> with [A-Za-z0-9\-_] runs.
SENDGRID_API_KEY = "SG." + "C" * 22 + "." + "D" * 43


# ---------------------------------------------------------------------------
# 1. Registry resolution
# ---------------------------------------------------------------------------

def test_registry_resolution():
    builtin = len(ANALYZER_REGISTRY)
    assert builtin == 4
    assert "privacy" in ANALYZER_REGISTRY

    for spec in (None, "all", ""):
        resolved = resolve_analyzers(spec)
        assert len(resolved) == 4
        assert {a.name for a in resolved} == set(ANALYZER_REGISTRY)

    pair = resolve_analyzers("credentials,ioc")
    assert len(pair) == 2
    assert {a.name for a in pair} == {"credentials", "ioc"}

    with pytest.raises(ValueError) as exc:
        resolve_analyzers("bogus")
    msg = str(exc.value)
    assert "bogus" in msg
    # Mentions the available names.
    for name in ANALYZER_REGISTRY:
        assert name in msg


# ---------------------------------------------------------------------------
# 2. CredentialAnalyzer detections
# ---------------------------------------------------------------------------

def test_credential_analyzer_detects():
    analyzer = CredentialAnalyzer()

    cases = [
        ("aws", _make_http_flow(f"key={AWS_KEY}".encode(), flow_id="aws"),
         Severity.HIGH, "AWS Access Key"),
        ("github", _make_http_flow(f"token={GITHUB_TOKEN}".encode(), flow_id="gh"),
         Severity.HIGH, "GitHub"),
        ("stripe", _make_http_flow(f"key={STRIPE_KEY}".encode(), flow_id="stripe"),
         Severity.CRITICAL, "Stripe"),
        ("pkey", _make_http_flow(PRIVATE_KEY_BLOCK.encode(), flow_id="pkey"),
         Severity.CRITICAL, "Private Key"),
        ("google", _make_http_flow(f"key={GOOGLE_API_KEY}".encode(), flow_id="google"),
         Severity.HIGH, "Google API Key"),
        ("twilio", _make_http_flow(f"key={TWILIO_API_KEY}".encode(), flow_id="twilio"),
         Severity.HIGH, "Twilio API Key"),
        ("sendgrid", _make_http_flow(f"key={SENDGRID_API_KEY}".encode(), flow_id="sendgrid"),
         Severity.HIGH, "SendGrid API Key"),
    ]

    for label, flow, expected_sev, title_fragment in cases:
        findings = analyzer.analyze_flow(flow)
        assert findings, f"expected a finding for {label}"
        matched = [
            f for f in findings if title_fragment in f.title
        ]
        assert matched, f"no finding titled like {title_fragment!r} for {label}: {[f.title for f in findings]}"
        assert any(f.severity == expected_sev for f in matched), (
            f"expected {expected_sev} for {label}, got {[f.severity for f in matched]}"
        )

    # Basic-auth header.
    basic_flow = _make_http_flow(
        b"",
        flow_id="basic",
        headers={"Authorization": "Basic dXNlcjpwYXNzd29yZA=="},  # user:password
    )
    basic_findings = analyzer.analyze_flow(basic_flow)
    assert any(
        "Basic auth" in f.title and f.severity == Severity.CRITICAL
        for f in basic_findings
    ), [f.title for f in basic_findings]

    # Clean flow -> no findings.
    clean = _make_http_flow(b"just a harmless body", flow_id="clean")
    assert analyzer.analyze_flow(clean) == []


# ---------------------------------------------------------------------------
# 3. Offline analyze CLI end-to-end
# ---------------------------------------------------------------------------

def _write_tap_with_flow(path: str, flow: Flow) -> None:
    writer = TapWriter()
    writer.open(path)
    writer.write_flow(flow)
    writer.close()


def test_analyze_cli_end_to_end(tmp_path):
    flow = _make_http_flow(f"key={AWS_KEY}".encode(), flow_id="aws-cli")
    tap_file = str(tmp_path / "capture.tap")
    _write_tap_with_flow(tap_file, flow)

    rc = run_analyze_cli([tap_file, "--scanners", "credentials", "--report", "table"])
    # AWS key is HIGH severity -> at or above the medium gate -> rc 2.
    assert rc == 2

    sidecar = tmp_path / "capture.findings.json"
    assert sidecar.exists()
    data = json.loads(sidecar.read_text())
    assert "summary" in data
    assert data["summary"]["total"] >= 1
    titles = [f["title"] for f in data["findings"]]
    assert any("AWS Access Key" in t for t in titles)

    # --min-severity critical filters out the HIGH AWS finding.
    rc_crit = run_analyze_cli(
        [tap_file, "--scanners", "credentials", "--report", "table",
         "--min-severity", "critical"]
    )
    sidecar_data = json.loads(sidecar.read_text())
    aws_titles = [f["title"] for f in sidecar_data["findings"] if "AWS Access Key" in f["title"]]
    assert aws_titles == []
    # With AWS (high) filtered out there is no medium+ gate hit from it.
    assert rc_crit in (0, 2)
    assert rc_crit <= rc

    # Missing file -> nonzero, no crash.
    assert run_analyze_cli([str(tmp_path / "does_not_exist.tap"),
                            "--scanners", "credentials"]) != 0

    # Bad scanner name -> nonzero.
    assert run_analyze_cli([tap_file, "--scanners", "bogus"]) != 0


# ---------------------------------------------------------------------------
# 4. Reporters
# ---------------------------------------------------------------------------

def _sample_findings() -> list[Finding]:
    return [
        Finding(Severity.CRITICAL, "Stripe Secret Key detected", "in body",
                "credentials", flow_id="f1"),
        Finding(Severity.HIGH, "AWS Access Key detected", "in body",
                "credentials", flow_id="f2", confidence=0.9),
        Finding(Severity.LOW, "High-entropy string", "maybe a secret",
                "credentials", flow_id="f3", confidence=0.4),
    ]


def test_reporters():
    findings = _sample_findings()
    meta = {"tap_file": "x.tap", "analyzers": ["credentials"]}

    json_out = JsonReporter().report(findings, meta)
    parsed = json.loads(json_out)
    assert "summary" in parsed
    assert parsed["summary"]["total"] == 3
    assert len(parsed["findings"]) == 3

    csv_out = CsvReporter().report(findings, meta)
    header = csv_out.splitlines()[0]
    assert "severity" in header and "title" in header

    table_out = TableReporter().report(findings, meta)
    assert "Total: 3" in table_out

    md_out = MarkdownReporter().report(findings, meta)
    assert md_out.startswith("# friTap Analysis Report")
    assert "Total" in md_out

    # Every reporter handles the empty case.
    assert _REPORTER_REGISTRY  # registry is populated
    assert TableReporter().report([], meta).strip() != ""


# ---------------------------------------------------------------------------
# 5. Severity filtering
# ---------------------------------------------------------------------------

def test_filter_min_severity():
    findings = [
        Finding(Severity.CRITICAL, "c", "", "s"),
        Finding(Severity.HIGH, "h", "", "s"),
        Finding(Severity.MEDIUM, "m", "", "s"),
        Finding(Severity.LOW, "l", "", "s"),
        Finding(Severity.INFO, "i", "", "s"),
    ]

    high = _filter_min_severity(findings, "high")
    assert {f.severity for f in high} == {Severity.CRITICAL, Severity.HIGH}

    crit = _filter_min_severity(findings, "critical")
    assert {f.severity for f in crit} == {Severity.CRITICAL}

    info = _filter_min_severity(findings, "info")
    assert len(info) == len(findings)

    # Ordering invariant: cutoff index honored.
    assert _SEVERITY_ORDER["critical"] < _SEVERITY_ORDER["info"]


# ---------------------------------------------------------------------------
# 6. Live wiring smoke test
# ---------------------------------------------------------------------------

def _make_datalog(data: bytes, *, timestamp: float) -> DatalogEvent:
    return DatalogEvent(
        data=data,
        function="SSL_write",
        direction="write",
        src_addr="10.0.0.2",
        src_port=51000,
        dst_addr="93.184.216.34",
        dst_port=443,
        ssl_session_id="sess-1",
        client_random="",
        timestamp=timestamp,
    )


def test_live_wiring_smoke():
    bus = EventBus()
    collector = FlowCollector(event_bus=bus)
    bus.subscribe(DatalogEvent, collector.on_data)

    plugin = AnalyzerPlugin(CredentialAnalyzer())
    bus.subscribe(FlowEvent, plugin.on_flow)

    request_bytes = (
        b"POST /upload HTTP/1.1\r\n"
        b"Host: api.example.com\r\n"
        b"Content-Type: text/plain\r\n"
        b"Content-Length: " + str(len(AWS_KEY) + 4).encode() + b"\r\n"
        b"\r\n"
        b"key=" + AWS_KEY.encode()
    )

    # First event commits the flow. A second event > IDLE_THRESHOLD (30s) later
    # forces _finalize_connection, which emits a COMPLETED FlowEvent for the
    # first flow — the path AnalyzerPlugin.on_flow acts on.
    bus.emit(_make_datalog(request_bytes, timestamp=1000.0))
    bus.emit(_make_datalog(b"GET / HTTP/1.1\r\nHost: other\r\n\r\n", timestamp=1100.0))
    collector.flush()

    assert plugin.findings, "expected the live path to produce findings"
    assert any("AWS Access Key" in f.title for f in plugin.findings), (
        [f.title for f in plugin.findings]
    )


# ---------------------------------------------------------------------------
# 7. External analyzer discovery is opt-in (#7)
# ---------------------------------------------------------------------------

def _install_fake_module(name: str, source: str):
    """Build and register an in-memory module so importlib can import it."""
    module = types.ModuleType(name)
    exec(compile(source, name, "exec"), module.__dict__)
    sys.modules[name] = module
    return module


def test_external_analyzer_discovery_requires_opt_in():
    """A bare module reference must NOT instantiate unrelated classes (#7).

    Only a class defined in the module that sets ``is_fritap_analyzer = True``
    is discovered; an unrelated/duck-typed class is ignored even though it has
    a matching ``name``/``analyze_flow`` shape.
    """
    mod_name = "fritap_fake_analyzer_mod"
    source = (
        "instantiated = []\n"
        "\n"
        "class Unrelated:\n"
        "    name = 'unrelated'\n"
        "    def __init__(self):\n"
        "        instantiated.append('unrelated')\n"
        "    def analyze_flow(self, flow):\n"
        "        return []\n"
        "\n"
        "class MyAnalyzer:\n"
        "    is_fritap_analyzer = True\n"
        "    name = 'myext'\n"
        "    def __init__(self):\n"
        "        instantiated.append('myext')\n"
        "    def analyze_flow(self, flow):\n"
        "        return []\n"
    )
    module = _install_fake_module(mod_name, source)
    try:
        resolved = resolve_analyzers(None, analyzer_path=mod_name)
        names = {a.name for a in resolved}
        # The opted-in analyzer is discovered...
        assert "myext" in names
        # ...and the unrelated class was never even instantiated.
        assert module.instantiated == ["myext"], module.instantiated
    finally:
        sys.modules.pop(mod_name, None)


def test_external_analyzer_explicit_class_reference():
    """The explicit ``module:Class`` form still works without the marker."""
    mod_name = "fritap_fake_analyzer_explicit"
    source = (
        "class Explicit:\n"
        "    name = 'explicit'\n"
        "    def analyze_flow(self, flow):\n"
        "        return []\n"
    )
    _install_fake_module(mod_name, source)
    try:
        resolved = resolve_analyzers(
            "explicit", analyzer_path=f"{mod_name}:Explicit"
        )
        assert {a.name for a in resolved} == {"explicit"}
    finally:
        sys.modules.pop(mod_name, None)


def test_external_module_without_marked_analyzer_raises():
    """A module with no opted-in analyzer raises rather than silently empty."""
    mod_name = "fritap_fake_analyzer_empty"
    source = (
        "class Helper:\n"
        "    name = 'helper'\n"
        "    def analyze_flow(self, flow):\n"
        "        return []\n"
    )
    _install_fake_module(mod_name, source)
    try:
        with pytest.raises(ValueError):
            resolve_analyzers(None, analyzer_path=mod_name)
    finally:
        sys.modules.pop(mod_name, None)


# ---------------------------------------------------------------------------
# 8. Unwritable --report-out returns exit code 1 (#8)
# ---------------------------------------------------------------------------

def test_report_out_oserror_returns_one(tmp_path, monkeypatch):
    """An unwritable --report-out path returns 1 instead of raising (#8)."""
    flow = _make_http_flow(f"key={AWS_KEY}".encode(), flow_id="aws-ro")
    tap_file = str(tmp_path / "capture.tap")
    _write_tap_with_flow(tap_file, flow)

    report_out = str(tmp_path / "unwritable.txt")

    import builtins
    real_open = builtins.open

    def fake_open(file, *args, **kwargs):
        # Only the report-out write should explode; let everything else (the
        # sidecar, tap reader, etc.) use the real open.
        if file == report_out:
            raise OSError("permission denied")
        return real_open(file, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", fake_open)

    rc = run_analyze_cli(
        [tap_file, "--scanners", "credentials", "--report", "table",
         "--report-out", report_out]
    )
    assert rc == 1
