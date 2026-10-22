"""Tests for the positioned WebSocket de-framer in friTap.parsers.websocket_defray."""

from __future__ import annotations

from friTap.parsers.websocket_defray import (
    WebSocketFrame,
    iter_websocket_frames,
    iter_websocket_frames_with_end,
)

_HANDSHAKE = b"GET /v1/websocket/ HTTP/1.1\r\n\r\nHTTP/1.1 101 OK\r\n\r\n"
_FRAMES = b"\x82\x03abc" + b"\x82\x02de"


def test_frame_ends_are_offsets_into_the_input():
    positioned = list(iter_websocket_frames_with_end(_FRAMES))
    assert positioned == [(WebSocketFrame(2, b"abc"), 5), (WebSocketFrame(2, b"de"), 9)]


def test_frame_ends_count_a_skipped_handshake():
    ends = [end for _f, end in iter_websocket_frames_with_end(_HANDSHAKE + _FRAMES)]
    assert ends == [len(_HANDSHAKE) + 5, len(_HANDSHAKE) + 9]


def test_plain_iterator_yields_the_same_frames():
    stream = _HANDSHAKE + _FRAMES + b"\x82"  # trailing partial frame
    assert list(iter_websocket_frames(stream)) == [
        frame for frame, _end in iter_websocket_frames_with_end(stream)
    ]
