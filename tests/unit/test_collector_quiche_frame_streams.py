"""Collector routing of Google QUICHE raw STREAM-frame events (Chrome/Cronet).

The agent's STREAM-frame hooks deliver raw, in-order HTTP/3 stream bytes per
real QUIC stream id, tagged ``quic_payload="stream"`` with an explicit
``direction``: control streams (SETTINGS), QPACK encoder/decoder streams and
request streams (HEADERS with QPACK field sections referencing the dynamic
table, DATA). Under the default ``--protocol tls`` these records are tagged
``tls``; they must still be decoded as HTTP/3 so each request stream becomes
one flow carrying the request line, the response status and all header fields.
"""

from friTap.events import DatalogEvent
from friTap.flow.collector import FlowCollector
from friTap.flow.quic_flow import QUIC_PAYLOAD_STREAM
from friTap.parsers.varint import encode_varint
from tests.unit._h3_helpers import (
    FRAME_DATA,
    FRAME_HEADERS,
    UNI_QPACK_ENCODER,
    h3_frame,
    qpack_encoder,
    settings_stream,
)

DEVICE = ("10.0.2.16", 50221)
SERVER = ("142.251.152.119", 443)
TABLE_CAPACITY = 4096
BLOCKED_STREAMS = 16
LIBRARY = "libmonochrome_64.so"


def _event(data: bytes, stream_id: int, direction: str, ts: float, protocol: str = "tls",
           quic_payload: str = QUIC_PAYLOAD_STREAM) -> DatalogEvent:
    src, dst = (DEVICE, SERVER) if direction == "write" else (SERVER, DEVICE)
    # Labels deliberately unknown to SSL_READ/SSL_WRITE: direction is explicit.
    function = "QuicSession_WriteStreamData" if direction == "write" else "QuicConnection_OnStreamFrame"
    return DatalogEvent(
        timestamp=ts, data=data, function=function, direction=direction,
        src_addr=src[0], src_port=src[1], dst_addr=dst[0], dst_port=dst[1],
        ssl_session_id="0x72004e7c00", protocol=protocol, transport="udp", stream_id=stream_id,
        quic_payload=quic_payload, library=LIBRARY,
    )


REQUESTS = {
    0: [(b":method", b"GET"), (b":scheme", b"https"), (b":authority", b"www.google.com"),
        (b":path", b"/"), (b"user-agent", b"Mozilla/5.0 (Linux; Android 16)"),
        (b"accept-language", b"en-US,en;q=0.9")],
    4: [(b":method", b"POST"), (b":scheme", b"https"), (b":authority", b"www.google.com"),
        (b":path", b"/gen_204?atyp=csi"), (b"user-agent", b"Mozilla/5.0 (Linux; Android 16)"),
        (b"accept-language", b"en-US,en;q=0.9")],
}
RESPONSES = {
    0: ([(b":status", b"200"), (b"content-type", b"text/html; charset=UTF-8"),
         (b"server", b"gws")], b"<!doctype html>"),
    4: ([(b":status", b"204"), (b"content-type", b"text/html; charset=UTF-8"),
         (b"server", b"gws")], b""),
}


def _chrome_like_session(protocol: str = "tls", quic_payload: str = QUIC_PAYLOAD_STREAM) -> list:
    """Events in hook order: both control streams, then requests whose HEADERS
    reference dynamic-table entries the encoder streams insert."""
    client, client_enc = qpack_encoder(TABLE_CAPACITY, BLOCKED_STREAMS)
    server, server_enc = qpack_encoder(TABLE_CAPACITY, BLOCKED_STREAMS)
    client_enc = encode_varint(UNI_QPACK_ENCODER) + client_enc
    server_enc = encode_varint(UNI_QPACK_ENCODER) + server_enc
    settings = settings_stream(TABLE_CAPACITY, BLOCKED_STREAMS)
    tagged = {"protocol": protocol, "quic_payload": quic_payload}
    events = [_event(settings, 2, "write", 1.0, **tagged), _event(settings, 3, "read", 1.1, **tagged)]
    ts = 1.2
    for sid, headers in REQUESTS.items():
        enc, block = client.encode(sid, headers)
        events += [_event(client_enc + enc, 6, "write", ts, **tagged),
                   _event(h3_frame(FRAME_HEADERS, block), sid, "write", ts + 0.01, **tagged)]
        client_enc = b""
        status, body = RESPONSES[sid]
        enc, block = server.encode(sid, status)
        payload = h3_frame(FRAME_HEADERS, block) + (h3_frame(FRAME_DATA, body) if body else b"")
        events += [_event(server_enc + enc, 7, "read", ts + 0.02, **tagged),
                   _event(payload, sid, "read", ts + 0.03, **tagged)]
        server_enc = b""
        ts += 0.1
    return events


def _request_flows(collector: FlowCollector) -> dict:
    return {f.request.url: f for f in collector.get_flows()
            if f.request is not None and f.request.method in ("GET", "POST")}


def _collect(events) -> FlowCollector:
    collector = FlowCollector()
    for event in events:
        collector.on_data(event)
    return collector


def test_tls_tagged_raw_frames_decode_request_and_response_into_one_flow():
    flows = _request_flows(_collect(_chrome_like_session()))
    assert len(flows) == 2
    by_method = {f.request.method: f for f in flows.values()}
    get, post = by_method["GET"], by_method["POST"]
    assert get.request.headers.get("user-agent") == "Mozilla/5.0 (Linux; Android 16)"
    assert get.response is not None and get.response.status_code == 200
    assert get.response.headers.get("server") == "gws"
    assert post.response is not None and post.response.status_code == 204


def test_second_request_decodes_through_dynamic_table_references():
    # The second request repeats user-agent / accept-language: the encoder
    # references the dynamic-table entries inserted for the first request.
    flows = _request_flows(_collect(_chrome_like_session()))
    post = {f.request.method: f for f in flows.values()}["POST"]
    assert post.request.headers.get("accept-language") == "en-US,en;q=0.9"


def test_quic_tagged_raw_frames_take_the_same_path():
    flows = _request_flows(_collect(_chrome_like_session(protocol="quic")))
    assert {f.request.method for f in flows.values()} == {"GET", "POST"}


def test_untagged_quic_transport_records_keep_the_legacy_rule():
    # Offline / older records carry no quic_payload: the quic transport plus a
    # real stream id still makes them per-stream HTTP/3 events.
    flows = _request_flows(_collect(_chrome_like_session(protocol="quic", quic_payload="")))
    assert {f.request.method for f in flows.values()} == {"GET", "POST"}


def test_untagged_tls_records_are_not_stream_events():
    flows = _request_flows(_collect(_chrome_like_session(protocol="tls", quic_payload="")))
    assert len(flows) < 2


def test_flow_carries_the_records_own_library():
    flows = _request_flows(_collect(_chrome_like_session()))
    assert {f.tls.library for f in flows.values()} == {LIBRARY}
