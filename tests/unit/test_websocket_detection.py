"""WebSocket blind detection + per-direction trailing data (Phase 7c).

* ``_is_websocket_data`` no longer accepts ANY buffer that merely starts with a
  2-byte control header (``89 17`` ...): a leading PING/PONG/CLOSE must span the
  whole buffer or be followed by a valid, non-CONTINUATION frame, and a CLOSE
  must carry a sane status code. Data-frame detection and feed-time parsing are
  unchanged; an HTTP 101-upgraded connection never goes through detection.
* ``WebSocketParser`` records ``trailing_direction``; the collector routes
  read-direction leftovers into ``Flow.response_trailing_*`` (persisted as
  additive ``resp_trailing_*`` tap meta), rendered on the Response tab only.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from friTap.flow.collector import FlowCollector
from friTap.flow.models import Flow
from friTap.flow.reparse import clear_trailing_data
from friTap.flow.tap_format import decode_flow, encode_flow
from friTap.parsers.base import ParseResult
from friTap.parsers.registry import get_default_registry
from friTap.parsers.websocket import WebSocketParser, _is_websocket_data
from tests.unit._render_helpers import RenderingFakeLog as _FakeLog

_TELEGRAM_LAYER_BLOB = bytes.fromhex(
    "8917e31b0fc1a2e4f91e39178d0905d8cb6391229700000014000000390000007446cc91"
    "0000000036f216008c205efc000000000b486920696e666563746564"
)


def _frame(first: int, payload: bytes = b"") -> bytes:
    """Unmasked frame with a 7-bit length (payload <= 125)."""
    return bytes([first, len(payload)]) + payload


def _ping(payload: bytes = b"hi") -> bytes:
    return _frame(0x89, payload)


def _close(code: int | None = None, reason: bytes = b"") -> bytes:
    body = b"" if code is None else code.to_bytes(2, "big") + reason
    return _frame(0x88, body)


# --------------------------------------------------------------------------- #
# Detection: leading control frames
# --------------------------------------------------------------------------- #

def test_lone_ping_spanning_buffer_is_detected():
    assert _is_websocket_data(_ping())


def test_ping_followed_by_garbage_is_rejected():
    assert not _is_websocket_data(_ping() + b"\xff\xff garbage")


def test_ping_followed_by_single_byte_is_rejected():
    assert not _is_websocket_data(_ping() + b"\x81")


def test_ping_followed_by_valid_text_frame_is_detected():
    assert _is_websocket_data(_ping() + _frame(0x81, b"hello"))


def test_ping_followed_by_orphan_continuation_is_rejected():
    assert not _is_websocket_data(_ping() + b"\x00\x00\x00\x39")


def test_pong_followed_by_pong_is_detected():
    assert _is_websocket_data(_frame(0x8A, b"x") + _frame(0x8A))


def test_telegram_layer_blob_is_not_detected_as_websocket():
    assert not _is_websocket_data(_TELEGRAM_LAYER_BLOB)
    assert not isinstance(get_default_registry().detect(_TELEGRAM_LAYER_BLOB),
                          WebSocketParser)


@pytest.mark.parametrize("code, expected", [
    (1000, True), (1001, True), (4999, True), (999, False), (5000, False),
])
def test_close_status_code_range(code, expected):
    assert _is_websocket_data(_close(code, b"bye")) is expected


def test_close_without_body_is_detected():
    assert _is_websocket_data(_close())


def test_close_with_one_byte_body_is_rejected():
    assert not _is_websocket_data(_frame(0x88, b"\x03"))


def test_masked_close_code_is_unmasked_before_validation():
    mask = b"\x11\x22\x33\x44"
    code = (1000).to_bytes(2, "big")
    masked = bytes(b ^ m for b, m in zip(code, mask))
    assert _is_websocket_data(bytes([0x88, 0x80 | 2]) + mask + masked)


# --------------------------------------------------------------------------- #
# Detection: data frames unchanged
# --------------------------------------------------------------------------- #

def test_single_text_frame_is_detected():
    assert _is_websocket_data(_frame(0x81, b"hello"))


def test_text_frame_followed_by_short_tail_is_detected():
    assert _is_websocket_data(_frame(0x82, b"\x01\x02") + b"\xff")


def test_text_frame_followed_by_invalid_header_is_rejected():
    assert not _is_websocket_data(_frame(0x81, b"hello") + b"\xff\xff")


def test_text_frame_followed_by_continuation_header_still_detected():
    assert _is_websocket_data(_frame(0x01, b"part") + _frame(0x80, b"end"))


# --------------------------------------------------------------------------- #
# Feed-time parsing unchanged + trailing_direction
# --------------------------------------------------------------------------- #

def test_feed_still_parses_ping_before_garbage_and_records_direction():
    parser = WebSocketParser()
    results = parser.feed(_ping() + b"\xff\xff garbage", "read")
    assert [r.method for r in results] == ["PING"]
    assert parser.trailing_data == b"\xff\xff garbage"
    assert parser.trailing_direction == "read"


def test_feed_without_trailing_clears_direction():
    parser = WebSocketParser()
    parser.feed(_ping() + b"\xff\xff", "read")
    parser.feed(_ping(), "write")
    assert parser.trailing_data is None
    assert parser.trailing_direction == ""


# --------------------------------------------------------------------------- #
# Collector routing
# --------------------------------------------------------------------------- #

def _fake_parser(direction: str | None, data: bytes = b"leftover"):
    fields = dict(trailing_data=data, trailing_protocol="",
                  trailing_sub_parse=None)
    if direction is not None:
        fields["trailing_direction"] = direction
    return SimpleNamespace(**fields)


def test_read_trailing_routes_to_response_slot():
    flow = Flow(flow_id="r")
    FlowCollector()._propagate_trailing_data(_fake_parser("read"), flow)
    assert flow.response_trailing_bytes == b"leftover"
    assert flow.trailing_bytes is None


def test_write_trailing_routes_to_legacy_slot():
    flow = Flow(flow_id="w")
    FlowCollector()._propagate_trailing_data(_fake_parser("write"), flow)
    assert flow.trailing_bytes == b"leftover"
    assert flow.response_trailing_bytes is None


def test_directionless_parser_keeps_legacy_slot():
    flow = Flow(flow_id="h1")
    FlowCollector()._propagate_trailing_data(_fake_parser(None), flow)
    assert flow.trailing_bytes == b"leftover"
    assert flow.response_trailing_bytes is None


def test_read_trailing_sub_parse_gets_its_own_mirror_layer():
    flow = Flow(flow_id="rl")
    parser = _fake_parser("read")
    parser.trailing_sub_parse = ParseResult(protocol="HTTP/1.1", is_request=False)
    FlowCollector()._propagate_trailing_data(parser, flow)
    layer = flow.layer("response_trailing")
    assert layer is not None
    assert layer.parsed is flow.response_trailing_parse
    assert flow.layer("trailing") is None


def _data_event(data, direction, function, timestamp):
    return SimpleNamespace(
        src_addr="10.0.0.2", src_port=51000, dst_addr="93.184.216.34",
        dst_port=443, data=data, direction=direction, timestamp=timestamp,
        function=function, ssl_session_id="ws-sess")


def test_upgraded_connection_parses_ping_and_routes_response_trailing():
    """HTTP 101 upgrade installs WebSocketParser directly (no detection)."""
    fc = FlowCollector()
    fc.on_data(_data_event(
        b"GET /chat HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n"
        b"Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZQ==\r\n"
        b"Sec-WebSocket-Version: 13\r\n\r\n", "write", "SSL_write", 1000.0))
    fc.on_data(_data_event(
        b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
        b"Connection: Upgrade\r\n\r\n", "read", "SSL_read", 1000.1))
    fc.on_data(_data_event(_ping() + b"\xff\xff tail", "read", "SSL_read", 1000.2))

    conn = next(iter(fc._connections.values()))
    assert isinstance(getattr(conn.parser, "_inner", conn.parser), WebSocketParser)
    flows = list(fc._flows.values())
    assert any(f.response_trailing_bytes == b"\xff\xff tail" for f in flows)
    assert all(f.trailing_bytes != b"\xff\xff tail" for f in flows)


# --------------------------------------------------------------------------- #
# Detection: a leading CONTINUATION frame (length-prefixed binary) is rejected
# --------------------------------------------------------------------------- #

_RC4_LIKE = bytes.fromhex("9f3ac1e27b0d44a8e61f25cc08b3d97a" * 4)


@pytest.mark.parametrize("data", [
    b"\x00\x00\x00\x1a",
    b"\x00\x00\x00\x40" + _RC4_LIKE,
    b"\x00\x00",
], ids=["len-1a", "len-40-plus-ciphertext", "empty-cont"])
def test_length_prefix_is_not_detected_as_websocket(data):
    assert not _is_websocket_data(data)


@pytest.mark.parametrize("first", [
    _frame(0x81, b"hello"), _frame(0x82, b"\x01\x02"), _ping(),
    _close(1000), _frame(0x01, b"part") + _frame(0x80, b"end"),
], ids=["text", "binary", "ping", "close", "fragmented-text"])
def test_real_websocket_streams_still_detected(first):
    assert _is_websocket_data(first)


def test_websocket_parser_recognized_any_tracks_parsed_frames():
    parser = WebSocketParser()
    assert not parser.recognized_any()
    assert parser.feed(b"\x00\x00\x00\x1a", "read") == []
    assert not parser.recognized_any()
    assert parser.feed(_frame(0x81, b"hi"), "read")
    assert parser.recognized_any()


def test_base_parser_recognized_any_defaults_true():
    from friTap.parsers.hexdump import HexdumpParser
    assert HexdumpParser().recognized_any()


def _commit_websocket_parser(fc, data):
    """Force WebSocket detection so the zero-result commit path is exercised."""
    from unittest.mock import patch
    with patch.object(type(get_default_registry()), "detect",
                      lambda self, _data, transport=None: WebSocketParser()):
        fc.on_data(_data_event(data, "read", "SSL_read", 2000.0))
    return next(iter(fc._connections.values()))


def test_zero_result_websocket_misdetection_is_not_stamped():
    fc = FlowCollector()
    _commit_websocket_parser(fc, b"\x00\x00\x00\x40" + _RC4_LIKE)
    assert all(f.detected_protocol != "websocket" for f in fc._flows.values())


def test_later_successful_feed_stamps_detected_protocol():
    fc = FlowCollector()
    conn = _commit_websocket_parser(fc, b"\x00\x00\x00\x1a")
    assert conn.protocol_stamp_pending
    fc.on_data(_data_event(_frame(0x81, b"hi"), "read", "SSL_read", 2000.1))
    assert not conn.protocol_stamp_pending
    active = fc._flows[conn.active_flow_id]
    assert active.detected_protocol == WebSocketParser.PROTOCOL


# --------------------------------------------------------------------------- #
# Model, tap persistence, reparse
# --------------------------------------------------------------------------- #

def _flow_with_both_trailing() -> Flow:
    flow = Flow(flow_id="both")
    flow.request = ParseResult(protocol="WebSocket", method="PING", body=b"req")
    flow.response = ParseResult(protocol="WebSocket", method="PONG",
                                body=b"resp", is_request=False)
    flow.trailing_bytes = b"REQ-TRAIL"
    flow.trailing_protocol = "unknown"
    flow.response_trailing_bytes = b"RESP-TRAIL"
    flow.response_trailing_protocol = "HTTP/1.1"
    flow.response_trailing_parse = ParseResult(protocol="HTTP/1.1", body=b"sub")
    return flow


def test_segments_append_response_trailing_last():
    assert [s["source"] for s in _flow_with_both_trailing().segments] == \
        ["primary", "trailing", "response_trailing"]


def test_pane_segments_are_per_pane():
    flow = _flow_with_both_trailing()
    assert [s["source"] for s in flow.pane_segments("request")] == ["primary", "trailing"]
    assert [s["source"] for s in flow.pane_segments("response")] == \
        ["primary", "response_trailing"]


def test_tap_round_trip_restores_response_trailing():
    decoded = decode_flow(encode_flow(_flow_with_both_trailing()))
    assert decoded.trailing_bytes == b"REQ-TRAIL"
    assert decoded.response_trailing_bytes == b"RESP-TRAIL"
    assert decoded.response_trailing_protocol == "HTTP/1.1"
    assert decoded.response_trailing_parse.body == b"sub"


def test_tap_without_response_trailing_decodes_to_defaults():
    flow = Flow(flow_id="old")
    flow.trailing_bytes = b"legacy"
    decoded = decode_flow(encode_flow(flow))
    assert decoded.trailing_bytes == b"legacy"
    assert decoded.response_trailing_bytes is None
    assert decoded.response_trailing_protocol == ""
    assert decoded.response_trailing_parse is None


def test_clear_trailing_data_clears_both_slots():
    flow = _flow_with_both_trailing()
    clear_trailing_data(flow)
    assert flow.trailing_bytes is None
    assert flow.response_trailing_bytes is None
    assert flow.response_trailing_protocol == ""


# --------------------------------------------------------------------------- #
# TUI rendering
# --------------------------------------------------------------------------- #

def _widget():
    from friTap.tui.widgets.flow_detail import FlowDetailWidget
    w = FlowDetailWidget.__new__(FlowDetailWidget)
    for name in ("_request_log", "_response_log", "_detail_log", "_message_log"):
        setattr(w, name, _FakeLog())
    w._raw_request = w._raw_response = False
    w._active_processing = None
    w._segment_offsets = []
    w._conversation_siblings = []
    return w


def _response_only_trailing_flow() -> Flow:
    flow = _flow_with_both_trailing()
    flow.trailing_bytes = None
    flow.trailing_protocol = ""
    return flow


def test_response_tab_renders_response_trailing():
    w = _widget()
    w._update_response(_response_only_trailing_flow())
    text = "\n".join(w._response_log.lines)
    assert "SEGMENT 2" in text
    assert "HTTP/1.1" in text


def test_request_tab_does_not_render_response_trailing():
    w = _widget()
    w._update_request(_response_only_trailing_flow())
    assert "SEGMENT 2" not in "\n".join(w._request_log.lines)


def test_detail_tab_summarises_both_trailing_slots():
    w = _widget()
    w._update_detail(_flow_with_both_trailing())
    text = "\n".join(w._detail_log.lines)
    assert "Trailing Data (response)" in text
    assert "9 bytes" in text and "10 bytes" in text


def test_flow_list_badge_considers_response_trailing():
    from friTap.tui.widgets.flow_list import FlowListWidget
    flow = _response_only_trailing_flow()
    flow.response_trailing_parse = None
    flow.response_trailing_protocol = ""
    assert FlowListWidget._trailing_badge(flow) == "+data"
    assert FlowListWidget._trailing_badge(Flow(flow_id="none")) == ""
