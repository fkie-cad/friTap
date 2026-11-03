"""Tests for the positioned WebSocket de-framer in friTap.parsers.websocket_defray."""

from __future__ import annotations

import logging

import pytest

from friTap.parsers import websocket_defray as defray
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


# --- RFC 6455 validation + fragment reassembly ----------------------------- #


def _frame(opcode: int, payload: bytes, *, fin: bool = True, rsv: int = 0,
           mask_key: bytes = b"") -> bytes:
    """One RFC 6455 frame (7/16/64-bit length chosen by size)."""
    head = bytes([(0x80 if fin else 0) | rsv | opcode])
    mask_bit = 0x80 if mask_key else 0
    n = len(payload)
    if n < 126:
        head += bytes([mask_bit | n])
    elif n < 0x10000:
        head += bytes([mask_bit | 126]) + n.to_bytes(2, "big")
    else:
        head += bytes([mask_bit | 127]) + n.to_bytes(8, "big")
    return head + mask_key + defray.unmask(payload, mask_key)


def _payloads(stream: bytes):
    return [(f.opcode, f.payload) for f in iter_websocket_frames(stream)]


_GOOD = _frame(0x2, b"good")


def test_oversized_control_frame_stops_iteration():
    stream = _GOOD + _frame(0x9, b"p" * 126) + _GOOD
    assert _payloads(stream) == [(0x2, b"good")]


def test_fragmented_control_frame_stops_iteration():
    stream = _GOOD + _frame(0x8, b"bye", fin=False) + _GOOD
    assert _payloads(stream) == [(0x2, b"good")]


def test_max_size_control_frame_is_accepted():
    assert _payloads(_frame(0x9, b"p" * 125)) == [(0x9, b"p" * 125)]


def test_64bit_length_with_msb_set_stops_iteration():
    bogus = bytes([0x82, 127]) + (1 << 63 | 4).to_bytes(8, "big") + b"evil"
    assert _payloads(_GOOD + bogus + _GOOD) == [(0x2, b"good")]


def test_frame_over_the_size_cap_stops_iteration(monkeypatch):
    monkeypatch.setattr(defray, "MAX_FRAME_BYTES", 8)
    assert _payloads(_GOOD + _frame(0x2, b"x" * 9) + _GOOD) == [(0x2, b"good")]


@pytest.mark.parametrize("rsv", [0x40, 0x20, 0x10])
def test_rsv_bits_stop_iteration(rsv):
    assert _payloads(_GOOD + _frame(0x2, b"zz", rsv=rsv) + _GOOD) == [(0x2, b"good")]


def test_reserved_opcode_stops_iteration():
    assert _payloads(_GOOD + _frame(0x3, b"??") + _GOOD) == [(0x2, b"good")]


def test_invalid_frame_is_logged(caplog):
    with caplog.at_level(logging.DEBUG, logger=defray.__name__):
        list(iter_websocket_frames(_frame(0x9, b"p" * 126)))
    assert "control frame payload" in caplog.text


def test_fragmented_message_is_reassembled_with_final_end_offset():
    first = _frame(0x2, b"hel", fin=False)
    middle = _frame(0x0, b"lo ", fin=False, mask_key=b"\x01\x02\x03\x04")
    last = _frame(0x0, b"world")
    stream = first + middle + last + _GOOD
    assert list(iter_websocket_frames_with_end(stream)) == [
        (WebSocketFrame(0x2, b"hello world"), len(first + middle + last)),
        (WebSocketFrame(0x2, b"good"), len(stream)),
    ]


def test_control_frame_inside_a_fragmented_message_is_yielded_first():
    stream = (_frame(0x1, b"a", fin=False) + _frame(0x9, b"ping")
              + _frame(0x0, b"b"))
    assert _payloads(stream) == [(0x9, b"ping"), (0x1, b"ab")]


def test_orphan_continuation_is_skipped():
    stream = _frame(0x0, b"tail-of-earlier-message") + _GOOD
    assert _payloads(stream) == [(0x2, b"good")]


def test_unfinished_message_is_dropped_by_a_new_data_message():
    stream = _frame(0x2, b"lost", fin=False) + _GOOD
    assert _payloads(stream) == [(0x2, b"good")]


def test_unfinished_message_at_stream_end_is_not_yielded():
    assert _payloads(_GOOD + _frame(0x2, b"half", fin=False)) == [(0x2, b"good")]


def test_reassembly_total_size_cap_stops_iteration(monkeypatch):
    monkeypatch.setattr(defray, "MAX_MESSAGE_BYTES", 5)
    stream = (_GOOD + _frame(0x2, b"abc", fin=False) + _frame(0x0, b"def")
              + _GOOD)
    assert _payloads(stream) == [(0x2, b"good")]


def test_reassembly_fragment_count_cap_stops_iteration(monkeypatch):
    monkeypatch.setattr(defray, "MAX_MESSAGE_FRAGMENTS", 3)
    fragments = (_frame(0x2, b"a", fin=False)
                 + _frame(0x0, b"b", fin=False) * 2 + _frame(0x0, b"c"))
    assert _payloads(_GOOD + fragments + _GOOD) == [(0x2, b"good")]
    ok = _frame(0x2, b"a", fin=False) + _frame(0x0, b"b", fin=False) + _frame(0x0, b"c")
    assert _payloads(ok) == [(0x2, b"abc")]


def test_unfragmented_frames_are_unchanged():
    stream = (_frame(0x2, b"x" * 300) + _frame(0x1, b"text")
              + _frame(0x2, b"m", mask_key=b"\xaa\xbb\xcc\xdd") + _frame(0xA, b""))
    assert _payloads(stream) == [(0x2, b"x" * 300), (0x1, b"text"), (0x2, b"m"), (0xA, b"")]
