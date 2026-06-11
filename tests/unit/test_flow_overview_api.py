"""Unit tests for the flow-overview public API.

Covers the two ``FlowSummary`` shapes' ``to_dict`` key-parity guard, the
``ReplayController`` round-trip over a small in-memory .tap, ``get_flow`` /
unknown-id behaviour, and ``ParseResult.to_dict`` / ``Flow.to_dict``
JSON-safety with body include/omit. Pure Python — no device/Frida/tshark.
"""

import json

from friTap import ReplayController
from friTap.flow import models as flow_models
from friTap.flow import tap_format
from friTap.flow.models import Flow, FlowChunk, FlowState
from friTap.flow.tap_format import TapMeta
from friTap.flow.tap_writer import TapWriter
from friTap.parsers.base import ParseResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_flow(flow_id: str = "flow-1") -> Flow:
    """An HTTP/1.1 request+response flow with parsed request/response and chunks."""
    request_bytes = (
        b"POST /upload HTTP/1.1\r\n"
        b"Host: api.example.com\r\n"
        b"Content-Type: text/plain\r\n"
        b"Content-Length: 5\r\n\r\nhello"
    )
    response_bytes = (
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n"
        b"Content-Type: text/plain\r\n\r\nworld"
    )
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
        protocol="HTTP/1.1", method="POST", url="/upload", host="api.example.com",
        headers={"Host": "api.example.com", "Content-Length": "5"},
        body=b"hello", content_type="text/plain", is_request=True, is_complete=True,
    )
    flow.response = ParseResult(
        protocol="HTTP/1.1", status_code=200, status_text="OK",
        headers={"Content-Length": "5"}, body=b"world",
        content_type="text/plain", is_request=False, is_complete=True,
    )
    flow.chunks.append(FlowChunk(
        data=request_bytes, direction="write", timestamp=1000.0, function="SSL_write",
    ))
    flow.chunks.append(FlowChunk(
        data=response_bytes, direction="read", timestamp=1000.5, function="SSL_read",
    ))
    flow._total_bytes = len(request_bytes) + len(response_bytes)
    return flow


def _write_tap_with_flow(path: str, flow: Flow) -> None:
    writer = TapWriter()
    writer.open(path)
    writer.write_flow(flow)
    writer.close()


# ---------------------------------------------------------------------------
# 1. FlowSummary key-parity guard
# ---------------------------------------------------------------------------

def test_flow_summary_to_dict_key_parity():
    """Both FlowSummary shapes must emit an IDENTICAL to_dict key set so live and
    offline overviews render the same."""
    flow = _make_flow()

    models_dict = flow_models.FlowSummary.from_flow(flow).to_dict()
    tap_dict = tap_format.FlowSummary.from_flow(flow).to_dict()

    assert models_dict.keys() == tap_dict.keys(), (
        f"key mismatch: only-in-models={set(models_dict) - set(tap_dict)}, "
        f"only-in-tap={set(tap_dict) - set(models_dict)}"
    )


def test_flow_summary_duration_deterministic_and_parity_for_active_flow():
    """For an in-progress flow (ended == 0) both summary shapes must emit the
    SAME, DETERMINISTIC duration (0.0) — not the wall-clock `duration` property,
    which would diverge and change between calls."""
    flow = _make_flow("active")
    flow.ended = 0.0  # still in progress

    models_dict = flow_models.FlowSummary.from_flow(flow).to_dict()
    tap_dict = tap_format.FlowSummary.from_flow(flow).to_dict()

    assert models_dict["duration"] == 0.0
    assert tap_dict["duration"] == 0.0
    # And a full Flow.to_dict() snapshot is likewise deterministic.
    assert flow.to_dict()["duration"] == 0.0


def test_flow_summary_to_dict_json_safe_and_state_is_str():
    flow = _make_flow()
    for summary in (
        flow_models.FlowSummary.from_flow(flow),
        tap_format.FlowSummary.from_flow(flow),
    ):
        d = summary.to_dict()
        # Round-trips through JSON without error.
        json.loads(json.dumps(d))
        assert isinstance(d["state"], str)


def test_public_flow_summary_is_tap_format_shape():
    """The publicly exported ``friTap.FlowSummary`` is the tap_format shape."""
    import friTap

    assert friTap.FlowSummary is tap_format.FlowSummary


def test_live_flowevent_summary_matches_offline_summary(tmp_path):
    """A summary built from a LIVE ``FlowEvent``'s flow must render with the same
    keys — and the same stable identity values — as the offline summary read
    back from a .tap, so a consumer can show one uniform flow overview for both
    the live-capture and replay sources."""
    from friTap.events import EventBus, FlowEvent
    from friTap.flow.tap_reader import TapReader

    flow = _make_flow("flow-live")

    # Live leg: emit a FlowEvent and build the public summary from event.flow,
    # exactly as an on_flow subscriber would.
    captured = {}
    bus = EventBus()
    bus.subscribe(FlowEvent, lambda ev: captured.__setitem__("flow", ev.flow))
    bus.emit(FlowEvent(flow=flow, flow_event_type="completed"))
    live_dict = tap_format.FlowSummary.from_flow(captured["flow"]).to_dict()

    # Offline leg: persist the same flow and read its summary back.
    tap_file = str(tmp_path / "live.tap")
    _write_tap_with_flow(tap_file, flow)
    reader = TapReader(tap_file)
    try:
        reader.open()
        offline_dict = reader.read_flow_summaries()[0].to_dict()
    finally:
        reader.close()

    assert live_dict.keys() == offline_dict.keys()
    # Stable identity/overview fields must agree across the two sources.
    for key in ("flow_id", "host", "method", "status_code", "protocol",
                "src_addr", "src_port", "dst_addr", "dst_port"):
        assert live_dict[key] == offline_dict[key], (
            f"{key}: live={live_dict[key]!r} offline={offline_dict[key]!r}"
        )


# ---------------------------------------------------------------------------
# 2. ReplayController round-trip
# ---------------------------------------------------------------------------

def test_replay_controller_roundtrip(tmp_path):
    flow = _make_flow("flow-rt")
    tap_file = str(tmp_path / "replay.tap")
    _write_tap_with_flow(tap_file, flow)

    with ReplayController(tap_file) as ctrl:
        meta = ctrl.meta
        assert isinstance(meta, TapMeta)
        assert ctrl.flow_count == 1

        summaries = ctrl.get_summaries()
        assert len(summaries) == 1
        assert isinstance(summaries[0], tap_format.FlowSummary)
        assert summaries[0].flow_id == "flow-rt"

        loaded = ctrl.get_flow("flow-rt")
        assert loaded is not None
        assert loaded.flow_id == "flow-rt"
        assert loaded.request is not None
        assert loaded.request.method == "POST"
        assert loaded.response is not None
        assert loaded.response.status_code == 200


def test_replay_controller_load_returns_tap_meta(tmp_path):
    flow = _make_flow("flow-meta")
    tap_file = str(tmp_path / "meta.tap")
    _write_tap_with_flow(tap_file, flow)

    ctrl = ReplayController(tap_file)
    try:
        meta = ctrl.load()
        assert isinstance(meta, TapMeta)
        assert ctrl.flow_count == 1
    finally:
        ctrl.close()


def test_replay_controller_unknown_flow_id_returns_none(tmp_path):
    flow = _make_flow("known")
    tap_file = str(tmp_path / "unknown.tap")
    _write_tap_with_flow(tap_file, flow)

    with ReplayController(tap_file) as ctrl:
        assert ctrl.get_flow("does-not-exist") is None


def test_read_flow_summaries_finding_count_from_index(tmp_path):
    """Offline summaries must report the real finding_count from the separate
    REC_FINDING records (not 0), so a replay/web overview shows finding badges
    that match a live capture."""
    from friTap.analysis import Finding, Severity
    from friTap.flow.tap_reader import TapReader
    from friTap.flow.tap_writer import TapWriter

    flow = _make_flow("flow-find")
    tap_file = str(tmp_path / "findings.tap")
    writer = TapWriter()
    writer.open(tap_file)
    writer.write_flow(flow)
    writer.write_findings("flow-find", [
        Finding(severity=Severity.HIGH, title="t1", description="d1",
                source="test", flow_id="flow-find"),
        Finding(severity=Severity.LOW, title="t2", description="d2",
                source="test", flow_id="flow-find"),
    ])
    writer.close()

    reader = TapReader(tap_file)
    try:
        reader.open()
        summaries = reader.read_flow_summaries()
    finally:
        reader.close()

    assert len(summaries) == 1
    assert summaries[0].finding_count == 2
    assert summaries[0].to_dict()["finding_count"] == 2


# ---------------------------------------------------------------------------
# 3. ParseResult.to_dict body include/omit
# ---------------------------------------------------------------------------

def test_parse_result_to_dict_omits_body_by_default():
    pr = ParseResult(
        protocol="HTTP/1.1", method="POST", url="/x", host="h",
        body=b"secret-bytes", is_request=True,
    )
    d = pr.to_dict()
    assert "body" not in d
    # JSON-serializable.
    json.loads(json.dumps(d))


def test_parse_result_to_dict_includes_hex_body_when_requested():
    pr = ParseResult(
        protocol="HTTP/1.1", method="POST", url="/x", host="h",
        body=b"abc", is_request=True,
    )
    d = pr.to_dict(include_body=True)
    assert d["body"] == b"abc".hex()
    json.loads(json.dumps(d))


# ---------------------------------------------------------------------------
# 4. Flow.to_dict JSON-safety + body include/omit
# ---------------------------------------------------------------------------

def test_flow_to_dict_json_safe_omits_bodies_by_default():
    flow = _make_flow()
    d = flow.to_dict()
    # JSON round-trip proves it is fully serializable.
    json.loads(json.dumps(d))

    assert d["request"] is not None
    assert d["response"] is not None
    assert "body" not in d["request"]
    assert "body" not in d["response"]
    assert isinstance(d["findings"], list)


def test_flow_to_dict_includes_bodies_when_requested():
    flow = _make_flow()
    d = flow.to_dict(include_bodies=True)
    json.loads(json.dumps(d))
    assert d["request"]["body"] == b"hello".hex()
    assert d["response"]["body"] == b"world".hex()
