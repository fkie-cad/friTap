"""Collector QUIC stream plumbing (QuicStreamFlowMixin): per-stream HTTP/3 flows."""

import pytest

pytest.importorskip("pylsqpack")

from friTap.events import DatalogEvent  # noqa: E402
from friTap.flow.collector import FlowCollector  # noqa: E402
from friTap.flow.models import FlowState  # noqa: E402
from friTap.parsers.base import ParseResult  # noqa: E402
from friTap.parsers.http3 import Http3Parser  # noqa: E402
from tests.unit._h3_helpers import (  # noqa: E402
    FRAME_DATA,
    UNI_QPACK_ENCODER,
    control_stream_bytes,
    h3_frame,
    headers_frame,
    qpack_encoder,
    uni_stream,
)

# Client-initiated unidirectional stream ids (RFC 9000: id & 0x3 == 0x2).
CONTROL_SID = 2
ENCODER_SID = 6
LATE_SID = 8


def _event(data: bytes, stream_id, direction="write", ts=1.0,
           function="quiche_stream_send") -> DatalogEvent:
    return DatalogEvent(
        timestamp=ts, data=data, function=function, direction=direction,
        src_addr="10.0.0.1", src_port=5000,
        dst_addr="93.184.216.34", dst_port=443,
        ssl_session_id="quic-conn-1", protocol="quic", transport="udp",
        stream_id=stream_id,
    )


def _request(stream_id: int, path: str = "/", ts=1.0) -> DatalogEvent:
    encoder, _ = qpack_encoder()
    _, frame = headers_frame(encoder, stream_id, [
        (b":method", b"GET"), (b":scheme", b"https"),
        (b":authority", b"example.com"), (b":path", path.encode()),
    ])
    return _event(frame, stream_id, "write", ts)


def _response(stream_id: int, status: bytes = b"200", ts=1.5) -> DatalogEvent:
    encoder, _ = qpack_encoder()
    _, frame = headers_frame(encoder, stream_id, [(b":status", status)])
    return _event(frame, stream_id, "read", ts, "quiche_stream_recv")


def _data(stream_id: int, body: bytes, direction="write", ts=1.2) -> DatalogEvent:
    return _event(h3_frame(FRAME_DATA, body), stream_id, direction, ts)


def _encoder_stream_event(ts=0.5) -> DatalogEvent:
    # Set Dynamic Table Capacity 0 (0b001xxxxx) after the stream type.
    return _event(uni_stream(UNI_QPACK_ENCODER) + b"\x20", ENCODER_SID, ts=ts)


def _collector(show_control_frames=True) -> FlowCollector:
    return FlowCollector(show_control_frames=show_control_frames)


def _feed(collector, *events) -> FlowCollector:
    for event in events:
        collector.on_data(event)
    return collector


def _request_flows(collector) -> list:
    return [f for f in collector.get_flows()
            if f.request is not None and getattr(f.request, "method", "")
            and not getattr(f.request, "is_control_frame", False)]


def _control_flows(collector) -> list:
    return [f for f in collector.get_flows()
            if any(c.stream_id is not None and c.stream_id & 0x2 for c in f.chunks)]


def test_real_stream_ids_become_separate_request_flows():
    collector = _feed(_collector(), _request(0, "/a"), _request(4, "/b"),
                      _request(8, "/c"))
    urls = sorted(f.request.url for f in _request_flows(collector))
    assert urls == ["/a", "/b", "/c"]


def test_stream_zero_is_not_a_ghost_and_gets_its_response():
    collector = _feed(_collector(), _request(0, "/zero"), _request(4, "/four"),
                      _response(0, b"204"), _response(4, b"404"))
    by_url = {f.request.url: f for f in _request_flows(collector)}
    assert by_url["/zero"].request.stream_id > 0
    assert by_url["/zero"].response.status_code == 204
    assert by_url["/four"].response.status_code == 404
    assert len(collector.get_flows()) == 2


def test_encoder_chunk_is_buffered_until_detection_then_fed():
    collector = _feed(_collector(), _encoder_stream_event())
    assert collector.get_flows() == []

    _feed(collector, _request(0, "/x"))
    assert [f.request.url for f in _request_flows(collector)] == ["/x"]
    control = _control_flows(collector)
    assert len(control) == 1
    assert control[0].chunks[0].stream_id == ENCODER_SID


def test_resultless_data_lands_in_its_own_stream_flow():
    collector = _feed(_collector(), _request(0, "/a"), _request(4, "/b"),
                      _data(0, b"payload-for-a"))
    by_url = {f.request.url: f for f in _request_flows(collector)}
    assert [c.stream_id for c in by_url["/a"].chunks] == [0, 0]
    assert [c.stream_id for c in by_url["/b"].chunks] == [4]
    assert len(collector.get_flows()) == 2


def test_late_data_after_completed_response_opens_no_stray_flow():
    collector = _feed(_collector(), _request(0), _response(0),
                      _data(0, b"body", direction="read", ts=1.6))
    assert len(collector.get_flows()) == 1


def test_uni_streams_share_one_control_flow():
    collector = _feed(_collector(), _event(control_stream_bytes(), CONTROL_SID),
                      _request(0), _encoder_stream_event(ts=1.1))
    control = _control_flows(collector)
    assert len(control) == 1
    assert sorted(c.stream_id for c in control[0].chunks) == [CONTROL_SID, ENCODER_SID]
    assert len(_request_flows(collector)) == 1


def test_uni_streams_dropped_when_control_frames_hidden():
    collector = _feed(_collector(show_control_frames=False),
                      _event(control_stream_bytes(), CONTROL_SID),
                      _request(0), _encoder_stream_event(ts=1.1))
    assert _control_flows(collector) == []
    assert len(collector.get_flows()) == 1


def test_idle_finalize_completes_stream_and_control_flows():
    collector = _feed(_collector(), _event(control_stream_bytes(), CONTROL_SID),
                      _request(0), _request(4))
    # A later event on the same connection after the idle gap finalizes it.
    _feed(collector, _request(8, ts=100.0))
    old = [f for f in collector.get_flows() if f.started < 50]
    assert len(old) == 3
    assert all(f.state == FlowState.COMPLETE for f in old)


def test_flush_commits_still_buffered_stream_chunks():
    collector = _feed(_collector(), _encoder_stream_event())
    collector.flush()
    control = _control_flows(collector)
    assert len(control) == 1
    assert control[0].state == FlowState.COMPLETE


def test_result_for_another_stream_reaches_that_streams_flow(monkeypatch):
    original_feed = Http3Parser.feed

    def feed(self, data, direction, stream_id=None):
        if stream_id == ENCODER_SID:  # encoder bytes unblock stream 8's HEADERS
            return [ParseResult(protocol="HTTP/3", method="GET", url="/late",
                                is_request=True, is_complete=True,
                                stream_id=LATE_SID)]
        return original_feed(self, data, direction, stream_id=stream_id)

    monkeypatch.setattr(Http3Parser, "feed", feed)
    collector = _feed(_collector(), _request(0, "/first"),
                      _data(LATE_SID, b"blocked-body"),
                      _encoder_stream_event(ts=1.3))
    by_url = {f.request.url: f for f in _request_flows(collector)}
    assert set(by_url) == {"/first", "/late"}
    assert [c.stream_id for c in by_url["/late"].chunks] == [LATE_SID]
    assert by_url["/late"].request.stream_id > 0


def test_parser_stream_kind_push_is_not_control(monkeypatch):
    monkeypatch.setattr(Http3Parser, "stream_kind",
                        lambda self, sid: "push" if sid == 3 else None,
                        raising=False)
    collector = _feed(_collector(), _request(0),
                      _data(3, b"pushed", direction="read"))
    conn = next(iter(collector._connections.values()))
    assert conn.h3_control_flow_id is None
    assert 3 in conn.quic_stream_flows
    push_flow = collector.get_flow(conn.quic_stream_flows[3])
    assert [c.stream_id for c in push_flow.chunks] == [3]


def test_neqo_body_events_keep_legacy_path():
    event = _event(b"plain de-framed body bytes", 0,
                   function="neqo_read_response_data", direction="read")
    collector = _feed(_collector(), event)
    collector.flush()
    flows = collector.get_flows()
    assert flows
    assert all(c.stream_id is None for f in flows for c in f.chunks)
    conn = next(iter(collector._connections.values()))
    assert conn.quic_stream_flows == {}


def test_sentinel_stream_id_keeps_legacy_path():
    collector = _feed(_collector(), _event(b"x" * 300, -1))
    flows = collector.get_flows()
    assert flows
    assert all(c.stream_id is None for f in flows for c in f.chunks)


def test_tls_events_never_carry_a_stream_id():
    event = DatalogEvent(
        timestamp=1.0, data=b"GET / HTTP/1.1\r\nHost: a\r\n\r\n",
        function="SSL_write", direction="write",
        src_addr="10.0.0.1", src_port=5000, dst_addr="1.2.3.4", dst_port=443,
        ssl_session_id="tls-1", stream_id=4)
    collector = _feed(_collector(), event)
    assert all(c.stream_id is None for f in collector.get_flows() for c in f.chunks)
