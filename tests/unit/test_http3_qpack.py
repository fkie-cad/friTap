"""Unit tests for HTTP/3 Boundary-4 (app-api) decoded headers + multiplexing.

Covers the three risk areas of the selectable-boundary feature:
  * build_h3_result_from_headers maps already-decoded pseudo-headers correctly,
  * the message-router gate does NOT drop header-only datalog messages,
  * HTTP/3 stream multiplexing produces distinct, correctly-correlated flows
    and the real-stream-0 case never collides with the "no stream" sentinel.
"""

from friTap.events import DatalogEvent, EventBus
from friTap.flow.collector import FlowCollector
from friTap.message_router import MessageRouter
from friTap.parsers.http3 import build_h3_result_from_headers


# --------------------------------------------------------------------------
# build_h3_result_from_headers
# --------------------------------------------------------------------------
class TestBuildH3ResultFromHeaders:
    def test_response_headers(self):
        result = build_h3_result_from_headers(
            [[":status", "200"], ["content-type", "text/html"]],
            stream_id=3, direction="read",
        )
        assert result.protocol == "HTTP/3"
        assert result.status_code == 200
        assert result.is_request is False
        assert result.stream_id == 3
        assert result.content_type == "text/html"

    def test_request_headers(self):
        result = build_h3_result_from_headers(
            [[":method", "GET"], [":path", "/index.html"], [":authority", "example.com"]],
            stream_id=7, direction="write",
        )
        assert result.method == "GET"
        assert result.url == "/index.html"
        assert result.host == "example.com"
        assert result.is_request is True
        assert result.stream_id == 7

    def test_direction_inference_without_pseudo_headers(self):
        # No :method / :status -> fall back to direction ("write" == request).
        req = build_h3_result_from_headers([["x-custom", "1"]], stream_id=1, direction="write")
        resp = build_h3_result_from_headers([["x-custom", "1"]], stream_id=1, direction="read")
        assert req.is_request is True
        assert resp.is_request is False

    def test_accepts_tuple_pairs(self):
        result = build_h3_result_from_headers(
            [(":status", "404")], stream_id=2, direction="read",
        )
        assert result.status_code == 404


# --------------------------------------------------------------------------
# Message-router gate: header-only datalog must not be dropped
# --------------------------------------------------------------------------
def _datalog_payload(**extra) -> dict:
    payload = {
        "contentType": "datalog",
        "function": "QuicSpdyStream_OnHeadersDecoded",
        "src_addr": "10.0.0.1", "src_port": 5000,
        "dst_addr": "93.184.216.34", "dst_port": 443,
        "ss_family": "AF_INET",
    }
    payload.update(extra)
    return payload


class TestRouterHeaderOnlyGate:
    def test_header_only_message_is_not_dropped(self):
        bus = EventBus()
        seen: list[DatalogEvent] = []
        bus.subscribe(DatalogEvent, seen.append)
        router = MessageRouter(bus)

        # No body bytes, but decoded headers present.
        router.route(
            _datalog_payload(http3_headers=[[":status", "200"]], stream_id=0),
            b"",
        )
        assert len(seen) == 1
        assert seen[0].http3_headers == [[":status", "200"]]
        assert seen[0].stream_id == 0

    def test_empty_message_without_headers_is_dropped(self):
        bus = EventBus()
        seen: list[DatalogEvent] = []
        bus.subscribe(DatalogEvent, seen.append)
        router = MessageRouter(bus)

        router.route(_datalog_payload(), b"")  # no data, no headers
        assert seen == []

    def test_normal_data_message_still_routes(self):
        bus = EventBus()
        seen: list[DatalogEvent] = []
        bus.subscribe(DatalogEvent, seen.append)
        router = MessageRouter(bus)

        router.route(_datalog_payload(function="SSL_read"), b"some-bytes")
        assert len(seen) == 1
        assert seen[0].data == b"some-bytes"


# --------------------------------------------------------------------------
# HTTP/3 multiplexing through the collector
# --------------------------------------------------------------------------
def _h3_event(headers, stream_id, direction) -> DatalogEvent:
    return DatalogEvent(
        data=b"",
        function="QuicSpdyStream_OnHeadersDecoded",
        direction=direction,
        src_addr="10.0.0.1", src_port=5000,
        dst_addr="93.184.216.34", dst_port=443,
        ssl_session_id="quic-conn-1",  # shared -> one connection
        client_random="",
        http3_headers=headers,
        stream_id=stream_id,
        transport="udp",
    )


class TestHttp3Multiplexing:
    def test_two_streams_become_two_flows(self):
        bus = EventBus()
        collector = FlowCollector(event_bus=bus)
        bus.subscribe(DatalogEvent, collector.on_data)

        bus.emit(_h3_event([[":method", "GET"], [":path", "/a"]], stream_id=0, direction="write"))
        bus.emit(_h3_event([[":method", "GET"], [":path", "/b"]], stream_id=4, direction="write"))

        flows = collector.get_flows()
        assert len(flows) == 2
        paths = sorted(f.request.url for f in flows if f.request)
        assert paths == ["/a", "/b"]

    def test_real_stream_zero_not_collapsed_as_ghost(self):
        # QUIC's first client bidi stream is 0; the collector's 0-sentinel must
        # not swallow it. Two distinct real streams 0 and 4 -> two flows, both
        # carrying a request (i.e. real-0 was not treated as "no stream").
        bus = EventBus()
        collector = FlowCollector(event_bus=bus)
        bus.subscribe(DatalogEvent, collector.on_data)

        bus.emit(_h3_event([[":method", "GET"], [":path", "/zero"]], stream_id=0, direction="write"))
        bus.emit(_h3_event([[":method", "GET"], [":path", "/four"]], stream_id=4, direction="write"))

        conn = next(iter(collector._connections.values()))
        # real 0 -> synthetic 1, real 4 -> synthetic 2 (both strictly positive)
        assert conn.map_qsid(0) == 1
        assert conn.map_qsid(4) == 2
        flows = collector.get_flows()
        assert len(flows) == 2
        assert all(f.request is not None for f in flows)

    def test_request_and_response_on_same_stream_share_flow(self):
        bus = EventBus()
        collector = FlowCollector(event_bus=bus)
        bus.subscribe(DatalogEvent, collector.on_data)

        bus.emit(_h3_event([[":method", "GET"], [":path", "/x"]], stream_id=0, direction="write"))
        bus.emit(_h3_event([[":status", "200"]], stream_id=0, direction="read"))

        flows = collector.get_flows()
        assert len(flows) == 1
        flow = flows[0]
        assert flow.request is not None and flow.request.url == "/x"
        assert flow.response is not None and flow.response.status_code == 200
