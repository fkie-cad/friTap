"""Both FlowSummary shapes derive their common fields through
``shared_summary_fields`` and keep their own ``to_dict`` output."""

from __future__ import annotations

from friTap.flow.models import Flow, FlowChunk, FlowState, shared_summary_fields
from friTap.flow.models import FlowSummary as LiveSummary
from friTap.flow.tap_format import FlowSummary as TapSummary
from friTap.parsers.base import ParseResult

COMMON_EXPECTED = {
    "connection_id": "c", "detected_protocol": "http1", "dst_addr": "1.1.1.1",
    "dst_port": 443, "duration": 2.5, "ended": 3.5, "finding_count": 0,
    "flow_id": "http", "flow_method": "", "has_notes": True, "host": "h.example",
    "inner_e2e_protocol": "", "inner_summary": "", "method": "GET",
    "outer_app_protocol": "", "process_name": "proc", "protocol": "http1",
    "src_addr": "10.0.0.1", "src_port": 5, "ssl_session_id": "ab", "started": 1.0,
    "state": "complete", "status_code": 200, "stream_id": 3, "tag_count": 2,
    "tls_alpn": "h2", "tls_sni": "h.example", "total_bytes": 8, "transport": "tls",
    "url": "/x",
}


def _http_flow() -> Flow:
    flow = Flow(flow_id="http", connection_id="c", src_addr="10.0.0.1", src_port=5,
                dst_addr="1.1.1.1", dst_port=443, ssl_session_id="ab",
                state=FlowState.COMPLETE, started=1.0, ended=3.5)
    flow.request = ParseResult(protocol="HTTP/1.1", method="GET", url="/x",
                               host="h.example", is_request=True, body_size=7)
    flow.response = ParseResult(protocol="HTTP/1.1", status_code=200, status_text="OK",
                                body_size=11, is_request=False)
    flow.chunks = [
        FlowChunk(data=b"abc", direction="write", timestamp=1.0, stream_id=3),
        FlowChunk(data=b"defgh", direction="read", timestamp=2.0, stream_id=3),
    ]
    flow._total_bytes = 8
    flow.tls.sni, flow.tls.alpn, flow.tls.version = "h.example", "h2", "TLS1.3"
    flow.tags, flow.notes = ["a", "b"], "n"
    flow.process_name, flow.detected_protocol = "proc", "http1"
    return flow


def _synthetic_flow() -> Flow:
    flow = Flow(flow_id="synthetic", started=1.0)
    flow.outer_app_protocol = "WebSocket"
    flow.inner_e2e_protocol = "Signal"
    flow.inner_summary = "sum"
    flow.flow_method = "sendMessage"
    return flow


def test_both_to_dicts_keep_their_expected_form():
    flow = _http_flow()
    assert LiveSummary.from_flow(flow).to_dict() == COMMON_EXPECTED
    assert TapSummary.from_flow(flow).to_dict() == COMMON_EXPECTED


def test_tap_only_fields_from_flow():
    summary = TapSummary.from_flow(_http_flow())
    assert (summary.protocol, summary.status_text, summary.body_size) == ("HTTP/1.1", "OK", 11)
    assert (summary.total_size, summary.file_offset, summary.state) == (8, 0, "complete")
    assert summary.has_request and summary.has_response and not summary.has_ohttp


def test_live_only_fields_from_flow():
    summary = LiveSummary.from_flow(_http_flow())
    assert summary.state is FlowState.COMPLETE
    assert summary.request.method == "GET" and summary.request.body_size == 7
    assert summary.response.status_text == "OK" and summary.response.body_size == 11
    assert summary.has_trailing_data is False


def test_live_prefers_preset_layered_scalars_tap_does_not():
    flow = _synthetic_flow()
    live, tap = LiveSummary.from_flow(flow).to_dict(), TapSummary.from_flow(flow).to_dict()
    assert (live["outer_app_protocol"], live["inner_e2e_protocol"], live["inner_summary"]) == (
        "WebSocket", "Signal", "sum")
    assert (tap["outer_app_protocol"], tap["inner_e2e_protocol"], tap["inner_summary"]) == ("", "", "")
    assert live["flow_method"] == tap["flow_method"] == "sendMessage"
    assert {k: v for k, v in live.items() if k not in ("outer_app_protocol", "inner_e2e_protocol", "inner_summary")} == {
        k: v for k, v in tap.items() if k not in ("outer_app_protocol", "inner_e2e_protocol", "inner_summary")}


def test_shared_fields_feed_both_classes_unchanged():
    flow = _http_flow()
    shared = shared_summary_fields(flow)
    live, tap = LiveSummary.from_flow(flow), TapSummary.from_flow(flow)
    for name, value in shared.items():
        assert getattr(live, name) == value, name
        assert getattr(tap, name) == value, name


def test_shared_fields_do_not_grow_the_layer_stack():
    flow = Flow(flow_id="bare")
    shared_summary_fields(flow)
    assert flow.layer("tls") is None
