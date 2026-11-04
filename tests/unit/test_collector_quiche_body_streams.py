"""Collector routing of Google QUICHE de-framed body events (Chrome/Cronet).

The agent tags de-framed body records (QuicSpdyStream_OnDataFramePayload /
_WriteOrBufferBody) ``quic_payload="body"`` with the real QUIC stream id and the connection's single (real) 4-tuple. All
streams of one connection therefore share a connection in the collector, and
the bodies must still land in their own stream's flow: request and response of
a stream together, different streams apart.
"""

from friTap.events import DatalogEvent
from friTap.flow.collector import FlowCollector
from friTap.flow.quic_flow import QUIC_PAYLOAD_BODY

DEVICE = ("10.0.2.16", 50221)
SERVER = ("142.251.155.119", 443)


def _event(data: bytes, stream_id: int, direction: str, function: str,
           ts: float = 1.0, headers=None, protocol: str = "quic",
           quic_payload: str = QUIC_PAYLOAD_BODY) -> DatalogEvent:
    src, dst = (DEVICE, SERVER) if direction == "write" else (SERVER, DEVICE)
    event = DatalogEvent(
        timestamp=ts, data=data, function=function, direction=direction,
        src_addr=src[0], src_port=src[1], dst_addr=dst[0], dst_port=dst[1],
        ssl_session_id="0x7200138000", protocol=protocol, transport="udp",
        stream_id=stream_id, quic_payload=quic_payload,
    )
    if headers is not None:
        event.http3_headers = headers
    return event


def _request_body(sid: int, data: bytes, ts: float = 1.0, protocol: str = "quic") -> DatalogEvent:
    return _event(data, sid, "write", "QuicSpdyStream_WriteOrBufferBody", ts, protocol=protocol)


def _response_body(sid: int, data: bytes, ts: float = 1.5, protocol: str = "quic") -> DatalogEvent:
    return _event(data, sid, "read", "QuicSpdyStream_OnDataFramePayload", ts, protocol=protocol)


def _feed(*events) -> FlowCollector:
    collector = FlowCollector()
    for event in events:
        collector.on_data(event)
    return collector


def _flow_bytes(flow, direction: str) -> bytes:
    return b"".join(c.data for c in flow.chunks if c.direction == direction)


def test_request_and_response_body_of_one_stream_share_a_flow():
    collector = _feed(_request_body(0, b"q=1"), _response_body(0, b"{\"ok\":1}"))
    flows = collector.get_flows()
    assert len(flows) == 1
    assert _flow_bytes(flows[0], "write") == b"q=1"
    assert _flow_bytes(flows[0], "read") == b"{\"ok\":1}"


def test_interleaved_streams_of_one_connection_stay_apart():
    collector = _feed(
        _request_body(0, b"A-req", 1.0),
        _request_body(4, b"B-req", 1.1),
        _response_body(4, b"B-resp", 1.2),
        _response_body(0, b"A-resp", 1.3),
    )
    flows = sorted(collector.get_flows(), key=lambda f: _flow_bytes(f, "write"))
    assert len(flows) == 2
    assert [(_flow_bytes(f, "write"), _flow_bytes(f, "read")) for f in flows] == [
        (b"A-req", b"A-resp"), (b"B-req", b"B-resp")]
    # One connection: both flows carry the same real 4-tuple, device -> server.
    assert {(f.src_addr, f.src_port, f.dst_addr, f.dst_port) for f in flows} == {DEVICE + SERVER}


def test_body_joins_the_decoded_headers_flow_of_its_stream():
    request = _event(b"", 8, "write", "QuicSpdyStream_WriteHeaders", 1.0, quic_payload="", headers=[
        (":method", "GET"), (":scheme", "https"),
        (":authority", "www.google.com"), (":path", "/search?q=x"),
    ])
    collector = _feed(request, _response_body(8, b"<html>", 1.5))
    flows = collector.get_flows()
    assert len(flows) == 1
    assert flows[0].request is not None and flows[0].request.method == "GET"
    assert _flow_bytes(flows[0], "read") == b"<html>"


def test_body_without_stream_id_keeps_the_legacy_connection_path():
    collector = _feed(_request_body(-1, b"a"), _response_body(-1, b"b"))
    flows = collector.get_flows()
    assert len(flows) == 1
    assert _flow_bytes(flows[0], "write") == b"a"
    assert _flow_bytes(flows[0], "read") == b"b"


def test_tls_labelled_quiche_bodies_still_route_per_stream_and_complete():
    # Default --protocol tls stamps Chrome's QUIC records "tls"; the explicit
    # quic_payload tag alone identifies de-framed bodies.
    collector = _feed(
        _response_body(0, b"A1", 1.0, protocol="tls"),
        _response_body(4, b"B1", 1.1, protocol="tls"),
        _response_body(0, b"A2", 1.2, protocol="tls"),
    )
    flows = collector.get_flows()
    assert sorted(_flow_bytes(f, "read") for f in flows) == [b"A1A2", b"B1"]
    collector.flush()
    assert all(f.state.value == "complete" for f in collector.get_flows())


def test_body_tag_routes_per_stream_whatever_the_function_label():
    collector = _feed(
        _event(b"A", 0, "read", "some_future_body_hook", 1.0, protocol="tls"),
        _event(b"B", 4, "read", "some_future_body_hook", 1.1, protocol="tls"),
    )
    assert sorted(_flow_bytes(f, "read") for f in collector.get_flows()) == [b"A", b"B"]


def test_untagged_neqo_body_keeps_the_legacy_connection_path():
    collector = _feed(
        _event(b"x", 0, "read", "neqo_read_response_data", 1.0, quic_payload=""),
        _event(b"y", 4, "read", "neqo_read_response_data", 1.1, quic_payload=""),
    )
    flows = collector.get_flows()
    assert len(flows) == 1 and _flow_bytes(flows[0], "read") == b"xy"
