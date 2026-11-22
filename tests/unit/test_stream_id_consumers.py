"""Consumers of the transport stream id: HAR, agent-API flow meta, reparse, TUI."""

from __future__ import annotations

from friTap.analysis.digest_flow import _flow_meta
from friTap.analysis.export_har import flow_to_har_entry
from friTap.flow.models import Flow, FlowChunk
from friTap.flow.reparse import reparse_flow
from tests.unit._digest_helpers import http_flow


def _with_stream(flow, stream_id):
    for chunk in flow.chunks:
        chunk.stream_id = stream_id
    return flow


def test_har_entry_carries_stream_id_when_set():
    entry = flow_to_har_entry(_with_stream(http_flow("r1"), 4))
    assert entry["_streamId"] == 4


def test_har_entry_omits_stream_id_when_unset():
    assert "_streamId" not in flow_to_har_entry(http_flow("r1"))


def test_har_entry_keeps_stream_zero():
    assert flow_to_har_entry(_with_stream(http_flow("r1"), 0))["_streamId"] == 0


def test_flow_meta_carries_stream_id_when_set():
    assert _flow_meta(_with_stream(http_flow("r1"), 8), 1)["stream_id"] == 8


def test_flow_meta_omits_stream_id_when_unset():
    assert "stream_id" not in _flow_meta(http_flow("r1"), 1)


def test_reparse_keeps_plain_feed_mode(monkeypatch):
    # Reparse must not pass chunk ids: mixed id/no-id chunks would flip the
    # HTTP/3 parser between muxed and plain modes.
    from friTap.parsers import base

    seen: list = []
    original = base.SafeParserAdapter.feed

    def spy(self, data, direction, stream_id=None):
        seen.append(stream_id)
        return original(self, data, direction, stream_id=stream_id)

    monkeypatch.setattr(base.SafeParserAdapter, "feed", spy)
    flow = Flow(flow_id="f1", connection_id="c1", transport="tls")
    flow.chunks = [
        FlowChunk(data=b"GET / HTTP/1.1\r\nHost: a\r\n\r\n", direction="write",
                  timestamp=0.0, stream_id=3),
        FlowChunk(data=b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
                  direction="read", timestamp=1.0),
    ]
    reparse_flow(flow)
    assert seen == [None, None]


def test_tui_chunk_stream_suffix():
    from friTap.tui.widgets.flow_detail import FlowDetailWidget

    suffix = FlowDetailWidget._chunk_stream_suffix
    assert suffix(FlowChunk(data=b"", direction="read", timestamp=0.0, stream_id=5)) == " stream 5"
    assert suffix(FlowChunk(data=b"", direction="read", timestamp=0.0)) == ""


def _detail_text(log) -> str:
    return "\n".join(log.lines)


def _tui_flow(*stream_ids):
    flow = Flow(flow_id="q1", connection_id="c1")
    flow.chunks = [FlowChunk(data=b"\x00" * 8, direction="read", timestamp=float(i),
                             function="quiche_stream_recv", stream_id=sid)
                   for i, sid in enumerate(stream_ids)]
    return flow


def test_tui_detail_shows_stream_only_when_set():
    from tests.unit._tui_flow_helpers import make_flow_detail_widget

    widget = make_flow_detail_widget()
    widget._update_detail(_tui_flow(4, 4))
    assert "Stream:         4" in _detail_text(widget._detail_log)
    widget._update_detail(_tui_flow(4, 8))
    assert "Stream:" not in _detail_text(widget._detail_log)


def test_tui_raw_hex_labels_chunk_stream_ids():
    from tests.unit._tui_flow_helpers import make_flow_detail_widget

    widget = make_flow_detail_widget()
    log = widget._response_log
    widget._render_raw_hex(log, _tui_flow(4, None), "read", "response")
    text = _detail_text(log)
    assert "(8 bytes) stream 4" in text
    assert text.count("stream ") == 1


def test_tui_raw_hex_single_chunk_labels_stream_id():
    from tests.unit._tui_flow_helpers import make_flow_detail_widget

    widget = make_flow_detail_widget()
    log = widget._response_log
    widget._render_raw_hex(log, _tui_flow(4), "read", "response")
    assert "stream 4" in _detail_text(log)
    log = widget._request_log
    widget._render_raw_hex(log, _tui_flow(None), "read", "request")
    assert "stream " not in _detail_text(log)
