"""Http2Parser frame log (per-frame byte attribution) and oversize-frame skip."""

from __future__ import annotations

import struct
import tracemalloc

import pytest

from friTap.parsers import http2 as h2mod
from friTap.parsers.http2 import Http2Parser, _hpack_available

pytestmark = pytest.mark.skipif(not _hpack_available, reason="hpack library not installed")

_DATA, _HEADERS, _SETTINGS, _CONTINUATION = 0x0, 0x1, 0x4, 0x9
_END_STREAM, _END_HEADERS = 0x1, 0x4
_PREFACE = h2mod._CONNECTION_PREFACE
_CHUNK = 64 * 1024


def _frame(ftype: int, flags: int, stream_id: int, payload: bytes = b"") -> bytes:
    return (struct.pack("!I", len(payload))[1:] + bytes([ftype, flags])
            + struct.pack("!I", stream_id) + payload)


def _header_only(ftype: int, flags: int, stream_id: int, length: int) -> bytes:
    return struct.pack("!I", length)[1:] + bytes([ftype, flags]) + struct.pack("!I", stream_id)


def _status_block(status: str = "200") -> bytes:
    from hpack import Encoder
    return Encoder().encode([(":status", status)])


def _logging_parser() -> Http2Parser:
    parser = Http2Parser()
    parser.enable_frame_log()
    return parser


def _after_preface(parser: Http2Parser) -> Http2Parser:
    """Client preface + SETTINGS seen: server frames are capped at 16 KiB."""
    parser.feed(_PREFACE + _frame(_SETTINGS, 0, 0), "write")
    parser.take_frame_log()
    return parser


# --- frame log ---------------------------------------------------------------

def test_frame_log_disabled_by_default_retains_nothing():
    parser = Http2Parser()
    parser.feed(_PREFACE + _frame(_SETTINGS, 0, 0), "write")
    assert parser._frame_log is None
    assert parser.take_frame_log() == []


def test_frame_log_reports_preface_and_frames_in_wire_order():
    parser = _logging_parser()
    settings = _frame(_SETTINGS, 0, 0)
    headers = _frame(_HEADERS, _END_HEADERS | _END_STREAM, 1, _status_block())
    parser.feed(_PREFACE + settings + headers, "write")
    assert parser.take_frame_log() == [
        ("write", 0, _PREFACE), ("write", 0, settings), ("write", 1, headers)]
    assert parser.take_frame_log() == []


def test_partial_frame_is_logged_once_complete():
    parser = _logging_parser()
    frame = _frame(_DATA, _END_STREAM, 3, b"x" * 100)
    parser.feed(frame[:4], "read")
    assert parser.take_frame_log() == []
    parser.feed(frame[4:60], "read")
    assert parser.take_frame_log() == []
    parser.feed(frame[60:], "read")
    assert parser.take_frame_log() == [("read", 3, frame)]


def test_header_block_is_logged_with_its_result():
    parser = _logging_parser()
    block = _status_block()
    headers = _frame(_HEADERS, 0, 1, block[:1])
    continuation = _frame(_CONTINUATION, _END_HEADERS, 1, block[1:])
    assert parser.feed(headers, "read") == []
    assert parser.take_frame_log() == []
    results = parser.feed(continuation, "read")
    assert [r.stream_id for r in results] == [1]
    assert parser.take_frame_log() == [("read", 1, headers), ("read", 1, continuation)]


def test_held_header_block_is_capped():
    """A CONTINUATION flood never accumulates in the log's hold area."""
    parser = _logging_parser()
    parser.feed(_frame(_HEADERS, 0, 1, b"\x00"), "read")
    fragment = _frame(_CONTINUATION, 0, 1, b"\x00" * 16000)
    for _ in range(20):  # ~320 KB > _MAX_HEADER_BLOCK_SIZE
        parser.feed(fragment, "read")
    assert parser._held_block_bytes["read"] <= h2mod._MAX_HEADER_BLOCK_SIZE
    assert parser.take_frame_log()  # released, not held forever


def test_flush_logs_partial_frame_and_open_header_block():
    parser = _logging_parser()
    headers = _frame(_HEADERS, 0, 5, b"\x00")
    partial = _frame(_DATA, 0, 7, b"y" * 50)[:30]
    parser.feed(headers, "read")
    parser.feed(partial, "write")
    parser.flush()
    assert sorted(parser.take_frame_log()) == sorted(
        [("read", 5, headers), ("write", 7, partial)])


# --- oversize frames: skipped by counting, never buffered --------------------

def test_oversize_frame_is_skipped_without_buffering():
    parser = _after_preface(Http2Parser())
    parser.feed(_frame(_HEADERS, _END_HEADERS, 1, _status_block()), "read")
    size = 8 * 1024 * 1024
    chunk = b"\x00" * _CHUNK
    tracemalloc.start()
    try:
        parser.feed(_header_only(_DATA, 0, 1, size), "read")
        for _ in range(size // _CHUNK):
            parser.feed(chunk, "read")
            assert len(parser._buffers["read"]) == 0
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 1024 * 1024  # buffering the frame would need > 8 MiB
    done = [r for r in parser.feed(_frame(_DATA, _END_STREAM, 1, b"ok"), "read")
            if r.is_complete]
    assert done[0].error == "frame-too-large" and done[0].body_size == 2


def test_oversize_skip_ends_mid_record_and_parsing_resumes():
    parser = _after_preface(Http2Parser())
    parser.feed(_frame(_HEADERS, _END_HEADERS, 1, _status_block()), "read")
    oversize = _header_only(_DATA, 0, 1, 20000) + b"z" * 20000
    tail = _frame(_DATA, _END_STREAM, 1, b"ok")
    wire = oversize + tail
    results = []
    for offset in range(0, len(wire), 7000):
        results += parser.feed(wire[offset:offset + 7000], "read")
    done = [r for r in results if r.is_complete]
    assert done[0].error == "frame-too-large" and done[0].body_size == 2


def test_streamed_oversize_headers_still_poisons():
    parser = _after_preface(Http2Parser())
    parser.feed(_header_only(_HEADERS, _END_HEADERS, 1, 40000), "read")
    parser.feed(b"\x00" * 40000, "read")
    assert parser._decoder_failed["read"] is True


def test_oversize_unknown_type_is_skipped_silently():
    parser = _after_preface(_logging_parser())
    parser.feed(_frame(_HEADERS, _END_HEADERS, 1, _status_block()), "read")
    parser.take_frame_log()
    parser.feed(_header_only(0x20, 0, 1, 30000) + b"u" * 30000, "read")
    tail = _frame(_DATA, _END_STREAM, 1, b"ok")
    done = [r for r in parser.feed(tail, "read") if r.is_complete]
    assert done[0].error == "" and done[0].body_size == 2
    assert parser.take_frame_log() == [("read", 1, tail)]  # oversize never logged


def test_flush_resets_pending_skip():
    parser = _after_preface(Http2Parser())
    parser.feed(_header_only(_DATA, 0, 1, 50000), "read")
    parser.flush()
    assert parser._skip_remaining["read"] == 0
