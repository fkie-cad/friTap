"""Unit tests for dev/attribution_metrics.py (SDK-attribution measuring tool)."""

import importlib.util
import json
import os
import sys
from types import SimpleNamespace

import pytest

from friTap.flow.models import Flow, FlowChunk, FlowState
from friTap.flow.tap_writer import TapWriter
from friTap.parsers.base import ParseResult

_SCRIPT = os.path.normpath(
    os.path.join(os.path.dirname(__file__), "..", "..", "dev", "attribution_metrics.py")
)


def _load_module():
    spec = importlib.util.spec_from_file_location("attribution_metrics", _SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod  # lets @dataclass resolve its module
    spec.loader.exec_module(mod)
    return mod


am = _load_module()

SDK_MAP = dict(am.DEFAULT_SDK_MAP)
ALPHA_URL = "https://httpbingo.org/anything/alpha/cronet-embedded/1731000000/2"
BETA_URL = "https://httpbingo.org/anything/beta/cronet-embedded/1731000000/0"


def _event(kind, req_id, sdk="alpha", url=ALPHA_URL, run=1, **extra):
    event = {"v": 1, "event": kind, "run": run, "sdk": sdk,
             "transport": "cronet-embedded", "req_id": req_id, "url": url,
             "method": "GET", "t_ms": 1731000000000, "thread": "t"}
    event.update(extra)
    return json.dumps(event)


def _gt(req_id="a-1", sdk="alpha", url=ALPHA_URL, transport="cronet-embedded", **kw):
    return am.GTRequest(req_id=req_id, sdk=sdk, url=url, transport=transport,
                        started=True, **kw)


def _wire(url=ALPHA_URL, conn="c1", sdk_name=None, protocol="h2", cr=None, conf=None):
    host, path = am.normalize_url(url)
    attribution = am.Attribution(sdk_name, conf) if sdk_name else None
    return am.WireFlow(flow_id=f"{conn}:{path}", connection_id=conn, transport="tls",
                       host=host, path=path, wire_protocol=protocol, decoded=True,
                       client_random=cr, attribution=attribution)


# --------------------------------------------------------------------------- #
# Ground truth parsing
# --------------------------------------------------------------------------- #

class TestGroundTruthParsing:
    def test_noise_and_blank_lines_are_ignored(self):
        lines = ["", "--------- beginning of main", "{not json", '{"v":2,"event":"start"}',
                 _event("start", "a-1")]
        gt = am.parse_ground_truth(lines)
        assert list(gt.requests) == ["a-1"]
        assert gt.noise_lines == 3

    def test_prefixed_json_line_is_accepted(self):
        assert am.parse_gt_line("I/Fixture: " + _event("start", "a-1"))["req_id"] == "a-1"

    def test_done_fields_are_folded(self):
        gt = am.parse_ground_truth([
            _event("start", "a-1"),
            _event("done", "a-1", status=200, protocol="h3", cached=True)])
        req = gt.requests["a-1"]
        assert (req.done, req.status, req.protocol, req.cached) == (True, 200, "h3", True)

    def test_skips_are_excluded_and_counted_by_reason(self):
        gt = am.parse_ground_truth([
            _event("start", "a-1"), _event("skip", "a-2", reason="no-gms"),
            _event("skip", "a-3", reason="no-gms")])
        assert [r.req_id for r in am.measurable_requests(gt)] == ["a-1"]
        assert gt.skips_by_reason == {"no-gms": 2}

    def test_run_filter_keeps_all_runs_listed(self):
        gt = am.parse_ground_truth(
            [_event("start", "a-1", run=1), _event("start", "a-2", run=2)], run="2")
        assert list(gt.requests) == ["a-2"]
        assert gt.runs == {1, 2}

    def test_fail_marks_request_failed(self):
        gt = am.parse_ground_truth([_event("start", "a-1"), _event("fail", "a-1")])
        assert gt.requests["a-1"].failed


# --------------------------------------------------------------------------- #
# URL normalisation
# --------------------------------------------------------------------------- #

class TestNormalization:
    @pytest.mark.parametrize("url, key", [
        ("https://HttpBingo.org:443/a/b?q=1#f", ("httpbingo.org", "/a/b")),
        ("https://example.com:8443/x", ("example.com:8443", "/x")),
        ("http://example.com:80", ("example.com", "/")),
    ])
    def test_normalize_url(self, url, key):
        assert am.normalize_url(url) == key

    def test_request_key_with_path_only_url(self):
        assert am.request_key("Example.COM:443", "/p?x=1") == ("example.com", "/p")

    def test_request_key_with_absolute_url(self):
        assert am.request_key("ignored", "https://h.org/p") == ("h.org", "/p")

    @pytest.mark.parametrize("raw, label", [
        ("HTTP/1.1", "h1"), ("HTTP/2", "h2"), ("HTTP/3", "h3"), ("", "")])
    def test_wire_protocol_label(self, raw, label):
        assert am.wire_protocol_label(raw) == label


# --------------------------------------------------------------------------- #
# Flow adaptation (attribution field shapes)
# --------------------------------------------------------------------------- #

class TestFlowAdaptation:
    def test_current_sdk_dict_shape(self):
        flow = SimpleNamespace(sdk={"sdk": "FritapAlpha", "vendor": "x"})
        assert am.flow_attribution(flow).name == "FritapAlpha"
        assert am.attribution_fields_present(flow) == {"sdk"}

    def test_future_originator_wins_and_confidence_is_read(self):
        flow = SimpleNamespace(sdk={"sdk": "Other"}, confidence="high", source="stack",
                               originator={"sdk": "FritapBeta"})
        attribution = am.flow_attribution(flow)
        assert (attribution.name, attribution.confidence, attribution.source) == \
            ("FritapBeta", "high", "stack")

    def test_no_attribution(self):
        assert am.flow_attribution(SimpleNamespace(sdk=None)) is None

    def test_control_frames_are_not_decoded_requests(self):
        settings = ParseResult(protocol="HTTP/2", method="SETTINGS", url="connection-setup")
        assert not am.is_decoded_request(settings)
        assert am.is_decoded_request(ParseResult(method="GET", url="/x"))

    def test_host_falls_back_to_authority_header(self):
        flow = Flow(flow_id="f")
        flow.request = ParseResult(protocol="HTTP/3", method="GET", url="/x",
                                   headers={":authority": "Cloudflare-QUIC.com:443"})
        wire = am.to_wire_flow(flow)
        assert (wire.host, wire.path, wire.wire_protocol) == ("cloudflare-quic.com", "/x", "h3")
        assert wire.client_random is None


# --------------------------------------------------------------------------- #
# Matching + aggregation
# --------------------------------------------------------------------------- #

class TestMatchingAndAggregation:
    def test_verdicts(self):
        flows = [_wire(ALPHA_URL, sdk_name="FritapAlpha"),
                 _wire(BETA_URL, sdk_name="FritapAlpha")]
        reqs = [_gt("a"), _gt("b", sdk="beta", url=BETA_URL),
                _gt("c", url=ALPHA_URL + "/none"), _gt("d", url=ALPHA_URL + "/c", cached=True)]
        verdicts = [m.verdict for m in am.match_requests(reqs, flows, SDK_MAP)]
        assert verdicts == ["correct", "wrong", "unseen", "cache"]

    def test_unattributed_and_metrics(self):
        flows = [_wire(ALPHA_URL), _wire(BETA_URL, sdk_name="fritapbeta", protocol="h3")]
        reqs = [_gt("a"), _gt("b", sdk="beta", url=BETA_URL), _gt("c", cached=True)]
        metrics = am.compute_metrics(am.match_requests(reqs, flows, SDK_MAP), False)
        assert metrics["gt_requests"] == 3 and metrics["cache"] == 1
        assert metrics["seen_plaintext"] == 2 and metrics["pct_plaintext"] == 100.0
        assert metrics["pct_attributed"] == 50.0 and metrics["pct_correct"] == 50.0
        assert metrics["wire_protocol"] == {"h2": 1, "h3": 1}
        assert metrics["has_client_random"] == "field absent"

    def test_by_confidence_only_when_present(self):
        flows = [_wire(ALPHA_URL, sdk_name="FritapAlpha", conf=0.9)]
        metrics = am.compute_metrics(am.match_requests([_gt()], flows, SDK_MAP), False)
        assert metrics["by_confidence"] == {"0.9": {"correct": 1}}

    def test_mixed_connections(self):
        flows = [_wire(ALPHA_URL, conn="shared", sdk_name="FritapAlpha"),
                 _wire(BETA_URL, conn="shared", sdk_name="FritapAlpha"),
                 _wire(ALPHA_URL + "/2", conn="solo")]
        reqs = [_gt("a"), _gt("b", sdk="beta", url=BETA_URL), _gt("c", url=ALPHA_URL + "/2")]
        mixed = am.mixed_connections(am.match_requests(reqs, flows, SDK_MAP), SDK_MAP)
        assert mixed["connections_with_matches"] == 2 and mixed["mixed"] == 1
        detail = mixed["details"][0]
        assert detail["gt_sdks"] == ["alpha", "beta"]
        assert detail["attributed_as"] == {"alpha": 2}

    def test_wire_leftovers(self):
        undecoded = am.WireFlow(host="httpbingo.org")
        flows = [_wire(ALPHA_URL), _wire("https://httpbingo.org/stray"),
                 _wire("https://www.google.com/gen_204"), undecoded]
        matched = am.match_requests([_gt()], flows, SDK_MAP)
        assert am.wire_leftovers(flows, matched) == {
            "unmatched_wire": 1, "undecoded_on_gt_hosts": 1, "other_hosts": 1}

    def test_client_random_percentage_when_field_exists(self):
        flows = [_wire(ALPHA_URL, cr="ab"), _wire(ALPHA_URL, conn="c2")]
        metrics = am.compute_metrics(am.match_requests([_gt()], flows, SDK_MAP), True)
        assert metrics["has_client_random"] == 50.0

    def test_pct_zero_denominator(self):
        assert am.pct(0, 0) is None


class TestSdkMap:
    def test_defaults(self):
        assert am.parse_sdk_map(None) == {"FritapAlpha": "alpha", "FritapBeta": "beta"}

    def test_custom_pairs(self):
        assert am.parse_sdk_map(["X=alpha", " Y = beta "]) == {"X": "alpha", "Y": "beta"}

    def test_invalid_pair_raises(self):
        with pytest.raises(ValueError):
            am.parse_sdk_map(["missing-separator"])

    def test_map_is_case_insensitive_and_passes_unknown_through(self):
        assert am.map_sdk("FRITAPALPHA", SDK_MAP) == "alpha"
        assert am.map_sdk("Firebase", SDK_MAP) == "Firebase"


CR_AA = "aabb" * 16
CR_CC = "ccdd" * 16
CR_EE = "ee" * 32
SECRET = "00" * 48


class TestKeylog:
    LINES = ["# comment", "", f"CLIENT_RANDOM {CR_AA.upper()} {SECRET}",
             f"CLIENT_TRAFFIC_SECRET_0 {CR_CC} {'11' * 32}",
             f"SERVER_TRAFFIC_SECRET_0 {CR_CC} {'22' * 32}",
             f"QUIC_CLIENT_HANDSHAKE_TRAFFIC_SECRET {CR_EE} {'33' * 32}",
             f"CLIENT_RANDOM ??? {SECRET}", "CLIENT_RANDOM short 00"]

    def test_parse_keylog(self):
        entries = am.parse_keylog(self.LINES)
        assert entries[0] == ("CLIENT_RANDOM", CR_AA)
        assert len(entries) == 4  # comment, blank, placeholder and malformed lines skipped

    def test_summary_without_client_random_field(self):
        summary = am.keylog_summary(am.parse_keylog(self.LINES), [], False)
        assert summary["distinct_client_randoms"] == 3
        assert summary["tls13_quic_usable_labels"] == [
            "CLIENT_TRAFFIC_SECRET_0", "SERVER_TRAFFIC_SECRET_0"]
        assert summary["quic_prefixed_labels"] == ["QUIC_CLIENT_HANDSHAKE_TRAFFIC_SECRET"]
        assert summary["matched_flows_with_key"] == "field absent"

    def test_flow_client_random_is_normalized(self):
        assert am.flow_client_random(SimpleNamespace(client_random=CR_AA.upper())) == CR_AA
        assert am.flow_client_random(SimpleNamespace(client_random="???")) is None

    def test_coverage_with_client_random_field(self):
        flows = [_wire(cr=CR_AA), _wire(cr="ff" * 32)]
        summary = am.keylog_summary(am.parse_keylog(self.LINES), flows, True)
        assert summary["matched_flows_with_key"] == 50.0


# --------------------------------------------------------------------------- #
# Integration: a real .tap written by friTap's TapWriter
# --------------------------------------------------------------------------- #

def _tap_flow(flow_id, url, host, sdk=None):
    flow = Flow(flow_id=flow_id, connection_id="conn-shared", state=FlowState.COMPLETE,
                started=1_731_000_000.0)
    flow.chunks.append(FlowChunk(data=b"GET", direction="write", timestamp=1_731_000_000.0))
    flow.request = ParseResult(protocol="HTTP/2", method="GET", url=url, host=host,
                               headers={":authority": host}, is_complete=True)
    flow.sdk = sdk
    return flow


def _write_tap(path, flows):
    writer = TapWriter()
    writer.open(str(path), target="test")
    for flow in flows:
        writer.write_flow(flow)
    writer.close()
    return str(path)


def test_end_to_end_on_written_tap(tmp_path, capsys):
    tap = _write_tap(tmp_path / "t.tap", [
        _tap_flow("f1", "/anything/alpha/cronet-embedded/1731000000/2", "httpbingo.org",
                  {"sdk": "FritapAlpha", "vendor": "v", "category": "c"}),
        _tap_flow("f2", "/anything/beta/cronet-embedded/1731000000/0", "httpbingo.org"),
        _tap_flow("f3", "/gen_204", "www.google.com"),
    ])
    gt_path = tmp_path / "gt.jsonl"
    gt_path.write_text("\n".join([
        "noise", _event("start", "a-1"), _event("start", "b-1", sdk="beta", url=BETA_URL),
        _event("skip", "b-2", sdk="beta", reason="no-webview")]) + "\n")
    out = tmp_path / "out.json"

    rc = am.main(["--tap", tap, "--gt", str(gt_path), "--json", str(out)])

    assert rc == 0
    report = json.loads(out.read_text())
    assert report["overall"]["seen_plaintext"] == 2
    assert report["overall"]["correct"] == 1 and report["overall"]["attributed"] == 1
    assert report["mixed_connections"]["mixed"] == 1
    assert report["wire"]["other_hosts"] == 1
    assert report["fields_present"]["sdk"] == 1
    assert report["skips_by_reason"] == {"no-webview": 1}
    assert "overall" in capsys.readouterr().out


def test_unreadable_input_is_nonzero(tmp_path):
    assert am.main(["--tap", str(tmp_path / "missing.tap"),
                    "--gt", str(tmp_path / "missing.jsonl")]) != 0


# --------------------------------------------------------------------------- #
# flow.attribution block, transport kind, caller stack, fallback guard
# --------------------------------------------------------------------------- #

def _block(kind="cronet", sdk="FritapAlpha", confidence="high", source="java-request",
           **extra):
    block = {"transport": {"module": "libcronet.so", "kind": kind},
             "originator": {"sdk": sdk, "vendor": "v", "category": "c"} if sdk else None,
             "confidence": confidence, "source": source}
    block.update(extra)
    return block


def _kind_wire(url=ALPHA_URL, kind="", stack=False, source=None, conf=None,
               sdk_name="FritapAlpha", bucket="", conn="c1"):
    wire = _wire(url, conn=conn, sdk_name=sdk_name)
    if wire.attribution:
        wire.attribution.confidence, wire.attribution.source = conf, source
    wire.transport_kind, wire.has_caller_stack, wire.bucket = kind, stack, bucket
    return wire


class TestAttributionBlock:
    def test_block_originator_confidence_source_win(self):
        flow = SimpleNamespace(
            attribution=_block(sdk="FritapBeta", confidence="medium", source="native-stack"),
            sdk={"sdk": "Other"}, originator={"sdk": "Older"}, confidence="low",
            source="stack")
        attribution = am.flow_attribution(flow)
        assert (attribution.name, attribution.confidence, attribution.source) == \
            ("FritapBeta", "medium", "native-stack")

    def test_falls_back_when_block_lacks_originator(self):
        flow = SimpleNamespace(attribution=_block(sdk=None, confidence=None, source=None),
                               sdk={"sdk": "FritapAlpha", "confidence": "low"})
        attribution = am.flow_attribution(flow)
        assert (attribution.name, attribution.confidence) == ("FritapAlpha", "low")

    def test_none_block_keeps_existing_paths(self):
        flow = SimpleNamespace(attribution=None, sdk={"sdk": "FritapAlpha"})
        assert am.flow_attribution(flow).name == "FritapAlpha"

    def test_wire_flow_gains_kind_bucket_mixed_and_caller_stack(self):
        flow = Flow(flow_id="f")
        flow.request = ParseResult(protocol="HTTP/2", method="GET", url="/x", host="h.org")
        flow.attribution = _block(kind="gms-cronet", bucket="cache", mixed=True)
        flow.caller_stack = {"transport_module": "libcronet.so"}
        wire = am.to_wire_flow(flow)
        assert (wire.transport_kind, wire.bucket, wire.mixed, wire.has_caller_stack) == \
            ("gms-cronet", "cache", True, True)
        assert "attribution" in wire.fields_present

    def test_old_flow_without_attribution_field(self):
        flow = Flow(flow_id="f")
        flow.request = ParseResult(protocol="HTTP/2", method="GET", url="/x", host="h.org")
        wire = am.to_wire_flow(flow)
        assert (wire.transport_kind, wire.bucket, wire.mixed, wire.has_caller_stack) == \
            ("", "", False, False)


class TestTransportKindAndCallerStackColumns:
    def test_tk_pct_uses_expected_kind_per_gt_transport(self):
        flows = [_kind_wire(kind="cronet", stack=True),
                 _kind_wire(BETA_URL, kind="webview")]
        reqs = [_gt("a", transport="cronet-shared"),
                _gt("b", sdk="beta", url=BETA_URL, transport="cronet-embedded")]
        metrics = am.compute_metrics(am.match_requests(reqs, flows, SDK_MAP), False)
        assert metrics["pct_transport_kind"] == 50.0
        assert metrics["pct_caller_stack"] == 50.0

    @pytest.mark.parametrize("gt_transport, kind", [
        ("gms-cronet", "gms-cronet"), ("httpengine", "httpengine"),
        ("webview", "webview"), ("chrome", "chrome")])
    def test_tk_pct_map(self, gt_transport, kind):
        matched = am.match_requests([_gt(transport=gt_transport)],
                                    [_kind_wire(kind=kind)], SDK_MAP)
        assert am.compute_metrics(matched, False)["pct_transport_kind"] == 100.0

    def test_unmapped_transport_gives_dash(self):
        matched = am.match_requests([_gt(transport="okhttp")],
                                    [_kind_wire(kind="cronet")], SDK_MAP)
        metrics = am.compute_metrics(matched, False)
        assert metrics["pct_transport_kind"] is None
        assert am._fmt(metrics["pct_transport_kind"]) == "-"

    def test_old_tap_flows_give_zero_tk_and_cs(self):
        matched = am.match_requests([_gt()], [_wire(ALPHA_URL)], SDK_MAP)
        metrics = am.compute_metrics(matched, False)
        assert (metrics["pct_transport_kind"], metrics["pct_caller_stack"]) == (0.0, 0.0)

    def test_no_matched_flows_gives_dash(self):
        metrics = am.compute_metrics(am.match_requests([_gt()], [], SDK_MAP), False)
        assert metrics["pct_transport_kind"] is None and metrics["pct_caller_stack"] is None

    def test_table_columns_sit_before_wire(self):
        report = am.build_report(
            am.parse_ground_truth([_event("start", "a-1")]),
            [_kind_wire(kind="cronet", stack=True)], SDK_MAP)
        header, _, overall = am.format_table(report)[:3]
        assert header.index("cr%") < header.index("tk%") < header.index("cs%") \
            < header.index("wire")
        assert overall.split()[-3:] == ["100.0", "100.0", "h2:1"]


class TestAttributionCounts:
    def test_counts_only_when_non_empty(self):
        counts = am.attribution_counts([_wire(ALPHA_URL)])
        assert counts == {"fallback_high": 0}

    def test_counts_and_fallback_high(self):
        flows = [_kind_wire(kind="cronet", source="connection-fallback", conf="high"),
                 _kind_wire(kind="cronet", source="connection-fallback", conf="medium"),
                 _kind_wire(kind="webview", source="java-request", conf="high",
                            bucket="cache"),
                 _kind_wire(sdk_name=None, bucket="chromium-internal")]
        counts = am.attribution_counts(flows)
        assert counts["by_source"] == {"connection-fallback": 2, "java-request": 1}
        assert counts["by_transport_kind"] == {"cronet": 2, "webview": 1}
        assert counts["buckets"] == {"cache": 1, "chromium-internal": 1}
        assert counts["fallback_high"] == 1

    def test_extras_text(self):
        flows = [_kind_wire(kind="cronet", source="java-request", conf="high",
                            bucket="cache")]
        report = am.build_report(am.parse_ground_truth([_event("start", "a-1")]),
                                 flows, SDK_MAP)
        text = "\n".join(am.format_extras(report))
        assert "by source: {'java-request': 1}" in text
        assert "by transport kind: {'cronet': 1}" in text
        assert "buckets: {'cache': 1}" in text
        assert "fallback_high: 0" in text

    def test_extras_text_without_attribution_data(self):
        report = am.build_report(am.parse_ground_truth([_event("start", "a-1")]),
                                 [_wire(ALPHA_URL)], SDK_MAP)
        text = "\n".join(am.format_extras(report))
        assert "fallback_high" not in text and "by source" not in text
        assert report["fallback_high"] == 0


def _run_main(tmp_path, monkeypatch, flows):
    monkeypatch.setattr(am, "load_wire_flows", lambda _tap: flows)
    gt_path = tmp_path / "gt.jsonl"
    gt_path.write_text(_event("start", "a-1") + "\n")
    out = tmp_path / "out.json"
    rc = am.main(["--tap", "ignored.tap", "--gt", str(gt_path), "--json", str(out)])
    return rc, json.loads(out.read_text())


def test_main_exit_code_1_on_fallback_high(tmp_path, monkeypatch, capsys):
    flows = [_kind_wire(kind="cronet", source="connection-fallback", conf="high")]
    rc, report = _run_main(tmp_path, monkeypatch, flows)
    assert rc == 1 and report["fallback_high"] == 1
    assert report["by_source"] == {"connection-fallback": 1}
    assert "fallback_high: 1" in capsys.readouterr().out


def test_main_exit_code_0_without_fallback_high(tmp_path, monkeypatch):
    flows = [_kind_wire(kind="cronet", source="java-request", conf="high")]
    rc, report = _run_main(tmp_path, monkeypatch, flows)
    assert rc == 0 and report["fallback_high"] == 0


def test_old_tap_without_attribution_end_to_end(tmp_path, capsys):
    tap = _write_tap(tmp_path / "old.tap", [
        _tap_flow("f1", "/anything/alpha/cronet-embedded/1731000000/2", "httpbingo.org")])
    gt_path = tmp_path / "gt.jsonl"
    gt_path.write_text(_event("start", "a-1") + "\n")
    out = tmp_path / "out.json"
    rc = am.main(["--tap", tap, "--gt", str(gt_path), "--json", str(out)])
    assert rc == 0
    report = json.loads(out.read_text())
    assert report["fallback_high"] == 0
    assert "by_source" not in report and "by_transport_kind" not in report
    assert report["by_transport"]["cronet-embedded"]["pct_transport_kind"] == 0.0
    assert report["overall"]["pct_caller_stack"] == 0.0
    assert "tk%" in capsys.readouterr().out


class TestSharedAttributionReaders:
    def test_fallback_constants_come_from_the_model(self):
        from friTap.flow.attribution import CONFIDENCE_HIGH, SOURCE_CONNECTION_FALLBACK
        assert am.FALLBACK_SOURCE == SOURCE_CONNECTION_FALLBACK
        assert am.HIGH_CONFIDENCE == CONFIDENCE_HIGH

    def test_transport_kind_uses_the_shared_reader(self):
        assert am.transport_kind(SimpleNamespace(
            attribution={"transport": {"kind": "foo-bar"}})) == "foo-bar"
        assert am.transport_kind(SimpleNamespace(attribution={"transport": "x"})) == ""
        assert am.transport_kind(SimpleNamespace()) == ""

    def test_attribution_originator_beats_legacy_fields(self):
        flow = SimpleNamespace(attribution={"originator": {"sdk": "FritapAlpha"}},
                               originator={"sdk": "Legacy"}, sdk={"sdk": "Older"})
        assert am.attribution_name(flow) == "FritapAlpha"

    def test_empty_attribution_originator_falls_through_to_legacy(self):
        flow = SimpleNamespace(attribution={"originator": {"sdk": ""}},
                               originator={"sdk": "Legacy"}, sdk={"sdk": "Older"})
        assert am.attribution_name(flow) == "Legacy"

    def test_lowercase_sdk_map_is_built_once_and_idempotent(self):
        lowered = am.lowercase_sdk_map(SDK_MAP)
        assert am.lowercase_sdk_map(lowered) is lowered
        assert lowered == {k.lower(): v for k, v in SDK_MAP.items()}
        assert am.map_sdk("FRITAPALPHA", lowered) == "alpha"


# --------------------------------------------------------------------------- #
# high-confidence correctness (hi_ok / hi_wrong / wrong_high)
# --------------------------------------------------------------------------- #

class TestHighConfidenceMetrics:
    def test_hi_ok_and_hi_wrong_per_group(self):
        flows = [_kind_wire(ALPHA_URL, conf="high", source="java-request"),
                 _kind_wire(BETA_URL, conf="high", source="java-request"),
                 _kind_wire(ALPHA_URL + "/m", conf="medium", source="context")]
        reqs = [_gt("a"), _gt("b", sdk="beta", url=BETA_URL),
                _gt("m", url=ALPHA_URL + "/m", transport="webview")]
        matched = am.match_requests(reqs, flows, SDK_MAP)
        metrics = am.compute_metrics(matched, False, SDK_MAP)
        assert (metrics["hi_ok"], metrics["hi_wrong"]) == (1, 1)
        assert metrics["pct_hi_ok"] == pytest.approx(33.3)
        assert metrics["pct_hi_wrong"] == pytest.approx(33.3)
        assert metrics["pct_correct"] == pytest.approx(66.7)  # old column unchanged
        groups = am.group_metrics(matched, "transport", False, SDK_MAP)
        assert groups["webview"]["hi_ok"] == 0 and groups["webview"]["correct"] == 1

    def test_hi_wrong_beats_a_correct_high_flow(self):
        flows = [_kind_wire(ALPHA_URL, conf="high", conn="c1"),
                 _kind_wire(ALPHA_URL, conf="high", conn="c2", sdk_name="FritapBeta")]
        matched = am.match_requests([_gt()], flows, SDK_MAP)[0]
        assert am.is_high_wrong(matched, SDK_MAP) and not am.is_high_ok(matched, SDK_MAP)

    def test_wrong_high_in_report_and_text(self):
        flows = [_kind_wire(kind="cronet", conf="high", source="java-request",
                            sdk_name="FritapBeta")]
        report = am.build_report(am.parse_ground_truth([_event("start", "a-1")]),
                                 flows, SDK_MAP)
        assert report["wrong_high"] == 1
        assert report["by_transport"]["cronet-embedded"]["pct_hi_wrong"] == 100.0
        assert "wrong_high: 1" in "\n".join(am.format_extras(report))
        assert am.exit_status(report) == 1

    def test_main_exit_code_1_on_wrong_high(self, tmp_path, monkeypatch):
        flows = [_kind_wire(kind="cronet", source="java-request", conf="high",
                            sdk_name="FritapBeta")]
        rc, report = _run_main(tmp_path, monkeypatch, flows)
        assert rc == 1 and report["wrong_high"] == 1 and report["fallback_high"] == 0

    def test_main_exit_code_0_on_correct_high(self, tmp_path, monkeypatch):
        flows = [_kind_wire(kind="cronet", source="java-request", conf="high")]
        rc, report = _run_main(tmp_path, monkeypatch, flows)
        assert rc == 0 and report["overall"]["pct_hi_ok"] == 100.0

    def test_table_has_new_columns_before_cr(self):
        report = am.build_report(am.parse_ground_truth([_event("start", "a-1")]),
                                 [_kind_wire(conf="high")], SDK_MAP)
        header = am.format_table(report)[0]
        assert header.index("%wrong") < header.index("%hi_ok") < header.index("%hi_wr") \
            < header.index("ctx%") < header.index("ctx_ok%") < header.index("cr%")


# --------------------------------------------------------------------------- #
# request-context coverage (REC_REQUEST_CONTEXT records)
# --------------------------------------------------------------------------- #

def _record(req_id, url=ALPHA_URL, sdk="FritapAlpha", confidence="high",
            source="java-request", stack_kind="cronet", bucket=None, method="GET"):
    record = {"req_id": req_id, "url": url, "method": method, "stack_kind": stack_kind,
              "originator": {"sdk": sdk, "vendor": "v", "category": "c"} if sdk else None,
              "confidence": confidence, "source": source}
    if bucket:
        record["bucket"] = bucket
    return {k: v for k, v in record.items() if v is not None}


class TestRequestContextCoverage:
    def test_url_key_normalizes_host_port_fragment(self):
        assert am.context_url_key("HTTPS://HttpBingo.org:443/a?q=1#frag") == \
            am.context_url_key("https://httpbingo.org/a?q=1")
        assert am.context_url_key("https://h.org/a?q=1") != am.context_url_key("https://h.org/a?q=2")
        assert am.context_url_key("") is None and am.context_url_key(None) is None

    def test_ctx_and_ctx_ok(self):
        reqs = [_gt("a"), _gt("b", sdk="beta", url=BETA_URL),
                _gt("c", url=ALPHA_URL + "/none")]
        records = [_record("r1"), _record("r2", url=BETA_URL, sdk="FritapAlpha"),
                   _record("r3", url="https://other.org/x")]
        matched = am.match_requests(reqs, [], SDK_MAP)
        assert am.attach_request_contexts(matched, records) == 1
        metrics = am.compute_metrics(matched, False, SDK_MAP)
        assert (metrics["ctx"], metrics["ctx_ok"]) == (2, 1)
        assert metrics["pct_ctx"] == pytest.approx(66.7)
        assert metrics["pct_ctx_ok"] == pytest.approx(33.3)

    @staticmethod
    def _shared_url_metrics(alpha_sdk, beta_sdk, extra_gt=()):
        """alpha starts first, beta second, both for SHARED; records arrive in
        time order on a host clock offset from the GT clock."""
        shared = ALPHA_URL + "/shared"
        reqs = [_gt("b", sdk="beta", url=shared, t_start_ms=1_000_200),
                _gt("a", url=shared, t_start_ms=1_000_100), *extra_gt]
        records = [dict(_record("r-late", url=shared, sdk=beta_sdk), t_start=55.2),
                   dict(_record("r-early", url=shared, sdk=alpha_sdk), t_start=55.1)]
        matched = am.match_requests(reqs, [], SDK_MAP)
        unmatched = am.attach_request_contexts(matched, records)
        metrics = am.compute_metrics(matched, False, SDK_MAP)
        return matched, unmatched, metrics

    def test_shared_url_correct_order_is_full_credit(self):
        matched, unmatched, metrics = self._shared_url_metrics("FritapAlpha", "FritapBeta")
        assert unmatched == 0
        assert {m.gt.req_id: m.context["req_id"] for m in matched} == \
            {"a": "r-early", "b": "r-late"}
        assert metrics["pct_ctx"] == 100.0 and metrics["pct_ctx_ok"] == 100.0

    def test_shared_url_swapped_attribution_is_zero(self):
        # The join swapped the SDKs: each record is used once, so neither GT
        # request can borrow the other's correctly-named record.
        _, unmatched, metrics = self._shared_url_metrics("FritapBeta", "FritapAlpha")
        assert unmatched == 0
        assert metrics["pct_ctx"] == 100.0 and metrics["pct_ctx_ok"] == 0.0

    def test_more_gt_than_records_leaves_latest_unpaired(self):
        third = _gt("a2", url=ALPHA_URL + "/shared", t_start_ms=1_000_300)
        matched, unmatched, metrics = self._shared_url_metrics(
            "FritapAlpha", "FritapBeta", extra_gt=(third,))
        assert unmatched == 0
        assert [m.gt.req_id for m in matched if m.context is None] == ["a2"]
        assert (metrics["ctx"], metrics["ctx_ok"]) == (2, 2)
        assert metrics["pct_ctx"] == pytest.approx(66.7)

    def test_more_records_than_gt_counts_extras_unmatched(self):
        reqs = [_gt("a", t_start_ms=1)]
        records = [dict(_record("r1"), t_start=2.0), dict(_record("r2"), t_start=1.0)]
        matched = am.match_requests(reqs, [], SDK_MAP)
        assert am.attach_request_contexts(matched, records) == 1
        assert matched[0].context["req_id"] == "r2"

    def test_gt_start_time_parsed(self):
        gt = am.parse_ground_truth([_event("start", "a-1", t_ms=42),
                                    _event("done", "a-1", t_ms=99)])
        assert gt.requests["a-1"].t_start_ms == 42

    def test_no_records_gives_dash(self):
        report = am.build_report(am.parse_ground_truth([_event("start", "a-1")]),
                                 [_wire()], SDK_MAP)
        assert report["overall"]["pct_ctx"] is None
        assert all(group["pct_ctx_ok"] is None for group in report["by_sdk"].values())
        assert report["request_contexts"]["records"] == 0
        assert "request contexts" not in "\n".join(am.format_extras(report))

    def test_extras_counts_and_cache_bucket(self):
        records = [_record("r1"),
                   _record("r2", url=BETA_URL, sdk="FritapBeta", confidence="medium",
                           source="context", stack_kind="webview"),
                   _record("r3", url=ALPHA_URL + "/c", bucket="cache"),
                   _record("r4", url="https://other.org/x", sdk=None, confidence=None,
                           source=None)]
        gt = am.parse_ground_truth([_event("start", "a-1"),
                                    _event("start", "b-1", sdk="beta", url=BETA_URL),
                                    _event("start", "c-1", url=ALPHA_URL + "/c"),
                                    _event("done", "c-1", cached=True)])
        report = am.build_report(gt, [], SDK_MAP, request_contexts=records)
        ctx = report["request_contexts"]
        assert ctx["records"] == 4 and ctx["unmatched"] == 1 and ctx["cache_bucket"] == 1
        assert ctx["by_source"] == {"context": 1, "java-request": 2}
        assert ctx["by_confidence"] == {"high": 2, "medium": 1}
        assert ctx["by_stack_kind"] == {"cronet": 3, "webview": 1}
        assert report["overall"]["ctx_ok"] == 3 and report["overall"]["cache"] == 1
        assert report["by_transport"]["cronet-embedded"]["pct_ctx_ok"] == 100.0
        assert "request contexts:" in "\n".join(am.format_extras(report))


@pytest.mark.skipif(not hasattr(TapWriter, "write_request_context"),
                    reason="TapWriter predates REC_REQUEST_CONTEXT")
def test_request_contexts_end_to_end_on_written_tap(tmp_path):
    flow = _tap_flow("f1", "/anything/alpha/cronet-embedded/1731000000/2", "httpbingo.org")
    flow.attribution = _block(sdk="FritapAlpha", confidence="high", source="java-request")
    writer = TapWriter()
    writer.open(str(tmp_path / "ctx.tap"), target="test")
    writer.write_flow(flow)
    assert writer.write_request_context(_record("r1"))
    assert writer.write_request_context(_record("r2", url=ALPHA_URL + "/c", bucket="cache"))
    writer.close()
    gt_path = tmp_path / "gt.jsonl"
    gt_path.write_text(_event("start", "a-1") + "\n")
    out = tmp_path / "out.json"

    rc = am.main(["--tap", str(tmp_path / "ctx.tap"), "--gt", str(gt_path),
                  "--json", str(out)])

    report = json.loads(out.read_text())
    assert rc == 0
    assert report["overall"]["pct_hi_ok"] == 100.0 and report["wrong_high"] == 0
    assert report["overall"]["pct_ctx"] == 100.0 and report["overall"]["pct_ctx_ok"] == 100.0
    assert report["request_contexts"]["records"] == 2
    assert report["request_contexts"]["cache_bucket"] == 1
    assert report["request_contexts"]["unmatched"] == 1
