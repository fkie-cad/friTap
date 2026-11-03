"""Hardening of the WebSocket parser against attacker-controlled frames.

Covers bounded permessage-deflate (per message + per connection budget),
reassembly of frames split across hooked chunks, RFC 6455 length checks,
per-direction fragment state, JSON detection limits and fast unmasking.
"""

from __future__ import annotations

import os
import tracemalloc
import zlib

import pytest

from friTap.parsers import websocket as ws
from friTap.parsers.websocket import WebSocketParser, unmask_payload


def _deflate(data: bytes, compressor=None) -> bytes:
    """permessage-deflate payload: raw deflate, sync flush, trailer stripped."""
    comp = compressor or zlib.compressobj(9, zlib.DEFLATED, -zlib.MAX_WBITS)
    out = comp.compress(data) + comp.flush(zlib.Z_SYNC_FLUSH)
    assert out.endswith(b"\x00\x00\xff\xff")
    return out[:-4]


def _header(first: int, length: int, mask_key: bytes = b"") -> bytes:
    mask_bit = 0x80 if mask_key else 0
    if length <= 125:
        hdr = bytes([first, mask_bit | length])
    elif length <= 0xFFFF:
        hdr = bytes([first, mask_bit | 126]) + length.to_bytes(2, "big")
    else:
        hdr = bytes([first, mask_bit | 127]) + length.to_bytes(8, "big")
    return hdr + mask_key


def _frame(first: int, payload: bytes, mask_key: bytes = b"") -> bytes:
    body = _reference_unmask(payload, mask_key) if mask_key else payload
    return _header(first, len(payload), mask_key) + body


def _reference_unmask(data: bytes, mask_key: bytes) -> bytes:
    """The original per-byte implementation (masking == unmasking)."""
    return bytes(b ^ mask_key[i % 4] for i, b in enumerate(data))


# --------------------------------------------------------------------------- #
# permessage-deflate bounds
# --------------------------------------------------------------------------- #

def test_deflate_bomb_is_rejected_with_bounded_memory():
    bomb = _deflate(b"\x00" * (64 * 1024 * 1024))  # ~64 KiB -> 64 MiB
    parser = WebSocketParser()
    tracemalloc.start()
    try:
        results = parser.feed(_frame(0xC2, bomb), "read")  # FIN|RSV1|BIN
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert len(results) == 1
    assert results[0].content_encoding == ""
    assert "exceeds" in results[0].error
    assert results[0].body == bomb
    assert peak < 2 * ws._MAX_MESSAGE_INFLATE + 4 * 1024 * 1024


def test_context_is_reset_after_bomb_and_next_message_decodes():
    parser = WebSocketParser()
    parser.feed(_frame(0xC2, _deflate(b"\x00" * (32 * 1024 * 1024))), "read")
    results = parser.feed(_frame(0xC1, _deflate(b'{"ok": true}')), "read")
    assert results[0].body == b'{"ok": true}'
    assert results[0].content_encoding == "permessage-deflate"
    assert results[0].content_type == "application/json"


def test_context_takeover_still_works():
    comp = zlib.compressobj(9, zlib.DEFLATED, -zlib.MAX_WBITS)
    parser = WebSocketParser()
    first = parser.feed(_frame(0xC1, _deflate(b"hello hello", comp)), "write")
    second = parser.feed(_frame(0xC1, _deflate(b"hello hello again", comp)), "write")
    assert first[0].body == b"hello hello"
    assert second[0].body == b"hello hello again"


def test_cumulative_budget_disables_inflation_for_connection(monkeypatch):
    parser = WebSocketParser()
    parser._inflate_budget.remaining = 2500
    msg = _frame(0xC2, _deflate(b"A" * 1000))
    ok = [parser.feed(msg, "read")[0], parser.feed(msg, "write")[0]]
    assert all(r.content_encoding == "permessage-deflate" for r in ok)
    over = parser.feed(msg, "read")[0]
    assert over.content_encoding == ""
    assert "disabled" in over.error
    # Disabled for good, both directions, even for small messages.
    tiny = parser.feed(_frame(0xC2, _deflate(b"x")), "write")[0]
    assert tiny.content_encoding == "" and "disabled" in tiny.error


def test_corrupt_deflate_marks_error_without_raising():
    results = WebSocketParser().feed(_frame(0xC1, b"\xff\xff\xff\xff"), "read")
    assert results[0].error == ws._ERR_INFLATE_FAILED


# --------------------------------------------------------------------------- #
# Frames spanning hooked chunks
# --------------------------------------------------------------------------- #

def test_frame_split_across_two_feeds_is_reassembled():
    payload = os.urandom(3000)
    data = _frame(0x82, payload) + _frame(0x89, b"hi")
    parser = WebSocketParser()
    assert parser.feed(data[:1000], "read") == []
    assert parser.trailing_data is None
    results = parser.feed(data[1000:], "read")
    assert [r.method for r in results] == ["BIN", "PING"]
    assert results[0].body == payload
    assert parser.trailing_data is None


def test_split_header_is_reassembled():
    data = _frame(0x81, b"x" * 300, mask_key=b"\x01\x02\x03\x04")
    parser = WebSocketParser()
    assert parser.feed(data[:3], "write") == []
    results = parser.feed(data[3:], "write")
    assert results[0].body == b"x" * 300


def test_pending_buffer_is_per_direction():
    data = _frame(0x82, b"r" * 500)
    parser = WebSocketParser()
    assert parser.feed(data[:100], "read") == []
    assert parser.feed(_frame(0x81, b"w"), "write")[0].body == b"w"
    assert parser.feed(data[100:], "read")[0].body == b"r" * 500


def test_frame_in_many_small_chunks():
    payload = os.urandom(20000)
    data = _frame(0x82, payload)
    parser = WebSocketParser()
    out = []
    for i in range(0, len(data), 97):
        out += parser.feed(data[i:i + 97], "read")
    assert len(out) == 1 and out[0].body == payload


def test_flush_emits_truncated_pending_frame():
    parser = WebSocketParser()
    parser.feed(_frame(0x82, b"z" * 400)[:50], "read")
    flushed = parser.flush()
    assert len(flushed) == 1
    assert flushed[0].error == ws._ERR_TRUNCATED_FRAME
    assert flushed[0].is_complete is False
    assert parser.flush() == []


# --------------------------------------------------------------------------- #
# Length validation
# --------------------------------------------------------------------------- #

def test_64bit_length_with_msb_set_is_rejected():
    bad = bytes([0x82, 127]) + (1 << 63 | 5).to_bytes(8, "big") + b"hello"
    parser = WebSocketParser()
    assert parser.feed(_frame(0x89, b"hi") + bad, "read")[0].method == "PING"
    assert parser.trailing_data == bad
    assert parser.feed(b"more", "read") == []  # nothing was kept pending


def test_oversized_frame_is_rejected():
    bad = _header(0x82, ws._MAX_FRAME_BYTES + 1) + b"abc"
    parser = WebSocketParser()
    parser.feed(_frame(0x89, b"hi") + bad, "read")
    assert parser.trailing_data == bad


# --------------------------------------------------------------------------- #
# Fragmentation
# --------------------------------------------------------------------------- #

def test_compressed_fragments_are_tracked_per_direction():
    read_payload = _deflate(b"read message " * 10)
    write_payload = _deflate(b"write message " * 10)
    parser = WebSocketParser()
    parser.feed(_frame(0x41, read_payload[:5]), "read")       # RSV1|TEXT, no FIN
    parser.feed(_frame(0x41, write_payload[:5]), "write")
    r = parser.feed(_frame(0x80, read_payload[5:]), "read")[0]   # FIN|CONT
    w = parser.feed(_frame(0x80, write_payload[5:]), "write")[0]
    assert r.body == b"read message " * 10
    assert w.body == b"write message " * 10


def test_orphan_continuation_is_per_direction():
    parser = WebSocketParser()
    parser.feed(_frame(0x01, b"part"), "write")  # opens a fragment on write
    assert parser.feed(_frame(0x80, b"end"), "read") == []
    assert parser.feed(_frame(0x80, b"end"), "write")[0].method == "CONT"


def test_fragment_count_is_capped(monkeypatch):
    monkeypatch.setattr(ws, "_MAX_FRAGMENT_COUNT", 3)
    parser = WebSocketParser()
    parser.feed(_frame(0x42, b"a"), "read")
    errors = [parser.feed(_frame(0x00, b"b"), "read")[0].error for _ in range(3)]
    assert errors[:2] == ["", ""]
    assert errors[2] == ws._ERR_FRAGMENT_TOO_LARGE


def test_fragment_bytes_use_running_total(monkeypatch):
    monkeypatch.setattr(ws, "_MAX_FRAGMENT_BYTES", 10)
    parser = WebSocketParser()
    parser.feed(_frame(0x42, b"12345"), "read")
    assert parser.feed(_frame(0x00, b"12345"), "read")[0].error == ""
    assert parser.feed(_frame(0x00, b"1"), "read")[0].error == ws._ERR_FRAGMENT_TOO_LARGE


# --------------------------------------------------------------------------- #
# JSON detection + unmasking
# --------------------------------------------------------------------------- #

def test_deeply_nested_json_does_not_raise():
    assert ws._detect_json(b"[" * 100000 + b"]" * 100000) == ""


def test_large_json_is_not_parsed(monkeypatch):
    monkeypatch.setattr(ws, "_MAX_JSON_DETECT_BYTES", 8)
    assert ws._detect_json(b'{"a": 1}') == "application/json"
    assert ws._detect_json(b'{"a": 12}') == ""


@pytest.mark.parametrize("size", [0, 1, 3, 4, 5, 127, 4096, 65537])
def test_unmask_matches_reference(size):
    data = os.urandom(size)
    key = os.urandom(4)
    assert unmask_payload(data, key) == _reference_unmask(data, key)
    assert unmask_payload(memoryview(data), key) == _reference_unmask(data, key)


def test_unmask_keeps_leading_zero_bytes():
    assert unmask_payload(b"\x00\x00\x01", b"\x00\x00\x00\x00") == b"\x00\x00\x01"


def test_unmask_with_bad_key_returns_input():
    assert unmask_payload(b"abc", b"\x01") == b"abc"
