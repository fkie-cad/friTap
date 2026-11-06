"""WP7 hardening tests for the analysis framework (attacker-controlled input).

Covers per-flow analyzer isolation, bounded JSON parsing/walking, JWT shape
validation, geolocation numeric guards, regex runtime bounds, per-flow
finding caps, title truncation, and reporter output sanitisation.

Pure Python — no device/Frida/tshark.
"""

import base64
import csv
import io
import json
import time

import pytest

from friTap.analysis import (
    AnalyzerPlugin,
    Finding,
    Severity,
    analyze_tap_multi,
    run_analyzer_safely,
)
from friTap.analysis._json_walk import (
    CONTAINER,
    FIELD,
    MAX_JSON_DEPTH,
    exceeds_depth,
    iter_json,
)
from friTap.analysis._limits import (
    MAX_FINDINGS_PER_FLOW,
    bounded_text,
    cap_findings,
    clip,
    is_binary_body,
    safe_json_loads,
)
from friTap.analysis.credentials import CredentialAnalyzer, _try_decode_jwt
from friTap.analysis.ioc import _EMAIL_PATTERN, IocAnalyzer
from friTap.analysis.privacy import PrivacyAnalyzer, _to_coord
from friTap.analysis.reporters import (
    CsvReporter,
    MarkdownReporter,
    TableReporter,
    _csv_cell,
    _sanitize_text,
)
from friTap.flow.models import Flow, FlowChunk, FlowState
from friTap.flow.tap_writer import TapWriter
from friTap.parsers.base import ParseResult

# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------

def _flow(
    *,
    req_body: bytes = b"",
    resp_body: bytes = b"",
    req_headers: dict | None = None,
    req_content_type: str = "text/plain",
    resp_content_type: str = "application/json",
    resp_headers: dict | None = None,
    flow_id: str = "flow-x",
    url: str = "/upload",
) -> Flow:
    flow = Flow(
        flow_id=flow_id, connection_id="conn-1",
        src_addr="10.0.0.2", src_port=51000,
        dst_addr="93.184.216.34", dst_port=443,
        state=FlowState.COMPLETE, started=1000.0, ended=1001.0,
    )
    host = "api.example.com"
    flow.request = ParseResult(
        protocol="HTTP/1.1", method="POST", url=url, host=host,
        headers={"Host": host, "Content-Type": req_content_type, **(req_headers or {})},
        body=req_body, content_type=req_content_type,
        is_request=True, is_complete=True,
    )
    if resp_body or resp_headers:
        flow.response = ParseResult(
            protocol="HTTP/1.1", method="", url=url, host=host,
            headers={"Content-Type": resp_content_type, **(resp_headers or {})},
            body=resp_body, content_type=resp_content_type,
            is_request=False, is_complete=True,
        )
    return flow


def _tap_flow(body: bytes, flow_id: str) -> Flow:
    """A flow that survives a TapWriter/TapReader round trip (raw chunks)."""
    host = "api.example.com"
    raw = (
        f"POST /upload HTTP/1.1\r\nHost: {host}\r\nContent-Type: text/plain\r\n"
        f"Content-Length: {len(body)}\r\n\r\n"
    ).encode() + body
    flow = _flow(flow_id=flow_id)
    flow.chunks.append(FlowChunk(data=raw, direction="write", timestamp=1000.0,
                                 function="SSL_write"))
    flow._total_bytes = len(raw)
    return flow


def _b64url(obj) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")


class _ExplodingAnalyzer:
    name = "exploding"

    def analyze_flow(self, flow):
        if flow.flow_id == "bad":
            raise RuntimeError("boom")
        return [Finding(Severity.LOW, "ok", "fine", self.name, flow_id=flow.flow_id)]


# ---------------------------------------------------------------------------
# 1. Analyzer isolation
# ---------------------------------------------------------------------------

def test_raising_analyzer_does_not_abort_analyze_tap_multi(tmp_path):
    tap = str(tmp_path / "multi.tap")
    writer = TapWriter()
    writer.open(tap)
    for fid in ("good-1", "bad", "good-2"):
        writer.write_flow(_tap_flow(b"hello", fid))
    writer.close()

    findings = analyze_tap_multi([_ExplodingAnalyzer(), IocAnalyzer()], tap)

    ok_flows = {f.flow_id for f in findings if f.source == "exploding" and f.title == "ok"}
    assert ok_flows == {"good-1", "good-2"}
    errors = [f for f in findings if f.title == "Analyzer error"]
    assert len(errors) == 1
    assert errors[0].flow_id == "bad"
    assert errors[0].severity == Severity.INFO
    assert errors[0].evidence["error_type"] == "RuntimeError"
    # The other analyzer still ran on the failing flow.
    assert any(f.source == "ioc" and f.flow_id == "bad" for f in findings)


def test_run_analyzer_safely_logs_and_returns_error_finding(caplog):
    flow = _flow(flow_id="bad")
    with caplog.at_level("WARNING", logger="friTap.analysis"):
        out = run_analyzer_safely(_ExplodingAnalyzer(), flow)
    assert [f.title for f in out] == ["Analyzer error"]
    assert out[0].category == "protocol"
    assert "exploding" in caplog.text and "bad" in caplog.text


def test_analyzer_plugin_survives_exception():
    plugin = AnalyzerPlugin(_ExplodingAnalyzer())
    plugin.analyze(_flow(flow_id="bad"))
    assert plugin.findings[0].title == "Analyzer error"


# ---------------------------------------------------------------------------
# 2. Deep / huge JSON
# ---------------------------------------------------------------------------

def test_safe_json_loads_deep_nesting_returns_none():
    assert safe_json_loads(b"[" * 200_000) is None
    assert safe_json_loads(b"[" * 200_000 + b"]" * 200_000) is None


def test_safe_json_loads_size_cap():
    assert safe_json_loads(b'{"a": 1}') == {"a": 1}
    assert safe_json_loads(b" " * (1024 * 1024 + 1)) is None


def test_iter_json_depth_and_node_caps():
    deep = current = {}
    for _ in range(500):
        current["k"] = {}
        current = current["k"]
    containers = [n for n in iter_json(deep) if n.kind == CONTAINER]
    assert len(containers) <= 64

    wide = {f"k{i}": i for i in range(100_000)}
    fields = [n for n in iter_json(wide) if n.kind == FIELD]
    assert len(fields) < 50_000


def _nested_list(depth: int):
    root = current = []
    for _ in range(depth - 1):
        current.append([])
        current = current[0]
    return root


@pytest.mark.parametrize("value", [None, 1, "s", 1.5, True])
def test_exceeds_depth_scalars_are_depth_zero(value):
    assert exceeds_depth(value, max_depth=0) is False


def test_exceeds_depth_boundary():
    assert exceeds_depth(_nested_list(MAX_JSON_DEPTH)) is False
    assert exceeds_depth(_nested_list(MAX_JSON_DEPTH + 1)) is True
    assert exceeds_depth([], max_depth=1) is False
    assert exceeds_depth([], max_depth=0) is True


def test_exceeds_depth_mixed_dicts_and_lists():
    data = {"a": [1, {"b": [{"c": "x"}]}], "z": 2}  # depth 5: {} [ {} [ {}
    assert exceeds_depth(data, max_depth=5) is False
    assert exceeds_depth(data, max_depth=4) is True


def test_exceeds_depth_finds_deep_branch_among_shallow_siblings():
    data = [[1, 2], {"k": "v"}, _nested_list(10)]
    assert exceeds_depth(data, max_depth=10) is True
    assert exceeds_depth(data, max_depth=11) is False


def test_exceeds_depth_is_iterative_on_huge_depth():
    # 100k levels: a recursive walker would raise RecursionError.
    assert exceeds_depth(_nested_list(100_000)) is True


def test_iter_json_preserves_preorder():
    data = {"a": "1", "b": {"c": "2"}, "d": "3", "e": [{"f": "4"}]}
    order = [(n.kind, n.path) for n in iter_json(data)]
    assert order == [
        (CONTAINER, ""), (FIELD, "a"), (CONTAINER, "b"), (FIELD, "b.c"),
        (FIELD, "d"), (CONTAINER, "e"), (CONTAINER, "e[0]"), (FIELD, "e[0].f"),
    ]


def test_deep_json_body_does_not_crash_analyzers():
    body = b"[" * 200_000
    flow = _flow(req_body=body, req_content_type="application/json",
                 resp_body=body, resp_content_type="application/json")
    CredentialAnalyzer().analyze_flow(flow)
    PrivacyAnalyzer().analyze_flow(flow)


def test_deep_but_valid_json_is_walked_without_recursion_error():
    nested = {"password": "hunter2-secret"}
    for _ in range(900):  # below the C json parser's limit, above our depth cap
        nested = {"n": nested}
    data = {"password": "top-level-secret", "deep": nested}
    flow = _flow(req_body=json.dumps(data).encode(), req_content_type="application/json")
    findings = CredentialAnalyzer().analyze_flow(flow)
    assert any("Password in JSON field" in f.title for f in findings)


# ---------------------------------------------------------------------------
# 3. JWT shape validation
# ---------------------------------------------------------------------------

def test_jwt_with_list_header_is_rejected():
    token = f"{_b64url([1, 2])}.{_b64url({'sub': 'x'})}.c2lnbmF0dXJlLXZhbHVl"
    assert _try_decode_jwt(token) is None
    flow = _flow(req_headers={"Authorization": f"Bearer {token}"})
    CredentialAnalyzer().analyze_flow(flow)  # must not raise


def test_jwt_with_null_payload_and_non_str_alg_no_crash():
    tokens = [
        f"{_b64url({'alg': 5})}.{_b64url({'sub': 'x'})}.c2lnbmF0dXJlLXZhbHVl",
        f"{_b64url({'alg': 'HS256'})}.{_b64url(None)}.c2lnbmF0dXJlLXZhbHVl",
        f"{_b64url({'alg': ['none']})}.{_b64url({'iss': {'x': 1}, 'sub': 'y' * 500})}.c2lnbmF0dXJl",
    ]
    for token in tokens:
        flow = _flow(req_headers={"Authorization": f"Bearer {token}"})
        findings = CredentialAnalyzer().analyze_flow(flow)
        for f in findings:
            if f.title == "JWT token detected":
                assert isinstance(f.evidence["algorithm"], str)
                assert len(f.evidence["subject"]) <= 123
                assert isinstance(f.evidence["issuer"], str)


def test_jwt_alg_none_still_flagged():
    token = f"{_b64url({'alg': 'none'})}.{_b64url({'sub': 'u'})}.c2lnbmF0dXJlLXZhbHVl"
    flow = _flow(req_headers={"Authorization": f"Bearer {token}"})
    findings = CredentialAnalyzer().analyze_flow(flow)
    jwt = [f for f in findings if f.title == "JWT token detected"]
    assert jwt and jwt[0].severity == Severity.CRITICAL


# ---------------------------------------------------------------------------
# 4. Geolocation numeric guards
# ---------------------------------------------------------------------------

def test_to_coord_rejects_non_finite_and_huge():
    assert _to_coord(float("inf")) is None
    assert _to_coord(float("nan")) is None
    assert _to_coord(10 ** 400) is None
    assert _to_coord("1e999") is None
    assert _to_coord(True) is None
    assert _to_coord("52.52") == 52.52


def test_geo_infinity_and_huge_int_no_crash():
    bodies = [
        b'{"lat": Infinity, "lon": 13.4}',
        b'{"lat": NaN, "lng": 1.5}',
        b'{"lat": ' + b"9" * 400 + b', "lon": 13.4}',
        b'{"coordinates": [Infinity, 1.5]}',
        b'{"coordinates": [' + b"9" * 400 + b', 1.5]}',
        b'{"location": "1e999,2.5"}',
    ]
    for body in bodies:
        flow = _flow(req_body=body, req_content_type="application/json")
        findings = PrivacyAnalyzer().analyze_flow(flow)
        assert not [f for f in findings if f.evidence.get("category") == "geolocation"]


def test_geo_normal_coordinates_still_detected():
    flow = _flow(req_body=b'{"lat": 52.520008, "lon": 13.404954}',
                 req_content_type="application/json")
    findings = PrivacyAnalyzer().analyze_flow(flow)
    assert any(f.evidence.get("category") == "geolocation" for f in findings)


# ---------------------------------------------------------------------------
# 5. Regex runtime bounds / binary skip
# ---------------------------------------------------------------------------

_PATHOLOGICAL = [
    b"a" * (5 * 1024 * 1024),
    b"a." * (5 * 1024 * 1024 // 2),
    (b"a" * 60 + b"@") * (5 * 1024 * 1024 // 61),
    b"eyJ" + b"A" * (5 * 1024 * 1024),
    b"1" * (5 * 1024 * 1024),
]


def test_regex_scans_on_5mb_pathological_input_are_fast():
    # Guards against catastrophic regex backtracking (ReDoS). Measure CPU time,
    # not wall-clock: catastrophic backtracking explodes the CPU the scan burns
    # regardless of machine load, whereas co-scheduled load only steals
    # wall-clock. A wall-clock bound flakes under CPU contention (e.g. parallel
    # CI); a CPU-time bound stays meaningful. The ceiling is generous enough for
    # a slow CI core yet orders of magnitude below any real ReDoS.
    for body in _PATHOLOGICAL:
        flow = _flow(req_body=body, resp_body=body, resp_content_type="text/plain")
        start = time.process_time()
        CredentialAnalyzer().analyze_flow(flow)
        PrivacyAnalyzer().analyze_flow(flow)
        IocAnalyzer().analyze_flow(flow)
        cpu_elapsed = time.process_time() - start
        assert cpu_elapsed < 3.0, (body[:10], cpu_elapsed)


def test_email_pattern_still_matches_normal_addresses():
    assert _EMAIL_PATTERN.search("contact alice.smith+tag@mail.example.co.uk now").group(0) \
        == "alice.smith+tag@mail.example.co.uk"


def _emails(findings):
    return [f for f in findings if f.evidence.get("category") == "email"]


def test_binary_body_skips_privacy_freetext():
    body = bytes(range(256)) * 8 + b" alice@example.com "
    # Media/compressed types are noise: skipped.
    for ct in ("image/png", "video/mp4", "font/woff2", "application/zip",
               "application/pdf; charset=binary"):
        flow = _flow(req_body=body, req_content_type=ct)
        assert not _emails(PrivacyAnalyzer().analyze_flow(flow)), ct
    # Untyped binary-looking (non-protobuf) bodies are skipped too.
    assert is_binary_body(body, "")
    assert not is_binary_body(b"hello world", "")
    # octet-stream / unknown binary stay in scope.
    for ct in ("application/octet-stream", "application/x-custom"):
        flow = _flow(req_body=body, req_content_type=ct)
        assert _emails(PrivacyAnalyzer().analyze_flow(flow)), ct


def _pb_string_field(field_number: int, value: bytes) -> bytes:
    return bytes([(field_number << 3) | 2, len(value)]) + value


def test_email_inside_protobuf_body_is_found():
    body = (b"\x08\x96\x01" + _pb_string_field(2, b"alice@example.com")
            + _pb_string_field(3, b"\x00\x01\x02\x03"))
    for ct in ("application/x-protobuf", "application/grpc", ""):
        flow = _flow(req_body=body, req_content_type=ct)
        assert _emails(PrivacyAnalyzer().analyze_flow(flow)), ct
    assert not is_binary_body(body, "application/x-protobuf")


def test_text_body_still_scanned_for_pii():
    flow = _flow(req_body=b"mail me: alice@example.com", req_content_type="text/plain")
    findings = PrivacyAnalyzer().analyze_flow(flow)
    assert any(f.evidence.get("category") == "email" for f in findings)


def test_bounded_text_caps_length():
    assert len(bounded_text(b"x" * (3 * 1024 * 1024))) == 1024 * 1024


# ---------------------------------------------------------------------------
# 6. Finding caps + truncation
# ---------------------------------------------------------------------------

def test_cap_findings_appends_summary():
    findings = [Finding(Severity.LOW, f"t{i}", "d", "src") for i in range(250)]
    capped = cap_findings(findings, "src", "f1")
    assert len(capped) == MAX_FINDINGS_PER_FLOW + 1
    assert capped[-1].title == "Finding limit reached"
    assert capped[-1].evidence["suppressed"] == 50


def test_ioc_findings_are_capped_per_flow():
    ips = " ".join(f"8.8.{i // 250}.{i % 250 + 1}" for i in range(1000))
    flow = _flow(resp_body=ips.encode(), resp_content_type="text/plain")
    findings = IocAnalyzer().analyze_flow(flow)
    assert len(findings) == MAX_FINDINGS_PER_FLOW + 1
    assert findings[-1].evidence["suppressed"] > 0


def test_privacy_findings_are_capped_per_flow():
    emails = " ".join(f"user{i}@example.com" for i in range(600))
    flow = _flow(req_body=emails.encode(), req_content_type="text/plain")
    findings = PrivacyAnalyzer().analyze_flow(flow)
    assert len(findings) == MAX_FINDINGS_PER_FLOW + 1
    assert findings[-1].title == "Finding limit reached"


def test_long_attacker_strings_truncated_in_titles():
    long_name = "X-" + "A" * 5000
    flow = _flow(req_headers={long_name + "-Csrf": "v", "Authorization": "Weird" + "Z" * 5000 + " cred"},
                 url="/?" + "p" * 5000 + "=1&token=abc")
    flow.response = None
    findings = CredentialAnalyzer().analyze_flow(flow)
    findings += IocAnalyzer().analyze_flow(
        _flow(resp_body=b"x", resp_headers={"Server": "S" * 5000}))
    assert findings
    for f in findings:
        assert len(f.title) <= 200, f.title[:50]


def test_basic_auth_username_not_in_description_and_redacted():
    cred = base64.b64encode(b"administrator-user:pa55word").decode()
    flow = _flow(req_headers={"Authorization": f"Basic {cred}"})
    findings = CredentialAnalyzer().analyze_flow(flow)
    basic = [f for f in findings if f.title == "Basic auth credentials in request"][0]
    assert "administrator-user" not in basic.description
    assert basic.evidence["username"] != "administrator-user"
    assert basic.evidence["username"].endswith("****")


def test_clip():
    assert clip("abc") == "abc"
    assert clip("a" * 200) == "a" * 120 + "..."
    assert clip(None) == "None"


# ---------------------------------------------------------------------------
# 7. Reporter sanitisation
# ---------------------------------------------------------------------------

def _finding(title="t", description="d", evidence=None, source="ioc", flow_id="f1"):
    return Finding(Severity.HIGH, title, description, source, flow_id=flow_id,
                   evidence=evidence or {}, metadata={"category": "network"})


def test_markdown_escapes_titles_and_descriptions():
    f = _finding(title="# Evil\n## injected [x](javascript:alert(1)) <script>",
                 description="<img src=x onerror=alert(1)> *bold* | pipe")
    out = MarkdownReporter().report([f])
    assert "<script>" not in out and "<img" not in out
    assert "&lt;script&gt;" in out
    assert "\\[x\\]\\(javascript:alert\\(1\\)\\)" in out
    assert "\n## injected" not in out
    assert "\\*bold\\*" in out and "\\|" in out


def test_markdown_evidence_fence_outlasts_backticks():
    f = _finding(evidence={"value": "````` breakout"})
    out = MarkdownReporter(include_evidence=True, redact_pii=False).report([f])
    assert "``````json" in out
    lines = out.splitlines()
    assert lines.count("``````") == 1


def test_markdown_flow_id_code_span_safe():
    out = MarkdownReporter().report([_finding(flow_id="a`b")])
    assert "``a`b``" in out


def test_csv_formula_injection_neutralised():
    f = _finding(title="=HYPERLINK(\"http://evil\")", description="+cmd|' /C calc'!A0")
    out = CsvReporter().report([f, _finding(title="@SUM(1)", description="-1+1"),
                                _finding(title="\tx", description="\ry")])
    rows = list(csv.DictReader(io.StringIO(out)))
    assert rows[0]["title"].startswith("'=")
    assert rows[0]["description"].startswith("'+")
    assert rows[1]["title"].startswith("'@")
    assert rows[1]["description"].startswith("'-")
    assert rows[2]["title"].startswith("'")
    assert rows[2]["description"].startswith("'")
    assert _csv_cell("normal") == "normal"


def test_control_chars_escaped_in_text_reporters():
    evil = "ok\x1b[2J\x07\x00\x9bend"
    f = _finding(title=evil, description=evil + "\nnext")
    for reporter in (TableReporter(), CsvReporter(), MarkdownReporter()):
        out = reporter.report([f])
        assert "\x1b" not in out and "\x07" not in out
        assert "\x00" not in out and "\x9b" not in out
        assert "\\x1b" in out
    table = TableReporter().report([f])
    # Newline in a cell must not break the row.
    assert not any(line.startswith("next") for line in table.splitlines())


def test_sanitize_text_single_line():
    assert _sanitize_text("a\nb\tc", single_line=True) == "a b\\x09c"
    assert _sanitize_text("a\nb\tc") == "a\nb\tc"
