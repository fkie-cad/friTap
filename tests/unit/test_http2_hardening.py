#!/usr/bin/env python3

"""Hardening tests for friTap's HTTP/2 parser against attacker-controlled input.

Parsed bytes are decrypted traffic (possibly malware), so the parser must not
let a single malformed header byte, a CONTINUATION flood, a stream-id flood or
bogus padding poison state or grow memory without bound.
"""

from __future__ import annotations

import struct

import pytest

from friTap.parsers import http2 as h2mod
from friTap.parsers.http2 import Http2Parser, _hpack_available

pytestmark = pytest.mark.skipif(
    not _hpack_available, reason="hpack library not installed"
)

_DATA, _HEADERS, _PRIORITY_FRAME, _SETTINGS = 0x00, 0x01, 0x02, 0x04
_PUSH_PROMISE, _WINDOW_UPDATE, _CONTINUATION = 0x05, 0x08, 0x09
_END_STREAM, _END_HEADERS, _PADDED = 0x01, 0x04, 0x08


def _frame(ftype: int, flags: int, stream_id: int, payload: bytes) -> bytes:
    """Build a 9-byte-header HTTP/2 frame."""
    return (struct.pack("!I", len(payload))[1:]
            + bytes([ftype, flags])
            + struct.pack("!I", stream_id)
            + payload)


def _settings(*params: tuple[int, int]) -> bytes:
    payload = b"".join(struct.pack("!HI", pid, val) for pid, val in params)
    return _frame(_SETTINGS, 0x00, 0, payload)


def _encoder():
    from hpack import Encoder
    return Encoder()


def _completed(results):
    return [r for r in results if r.is_complete]


def _literal_no_index(name: bytes, value: bytes) -> bytes:
    """HPACK literal-without-indexing with a new (non-Huffman) name."""
    assert len(name) < 127 and len(value) < 127
    return b"\x00" + bytes([len(name)]) + name + bytes([len(value)]) + value


def _literal_with_index(name: bytes, value: bytes) -> bytes:
    """HPACK literal-with-incremental-indexing (mutates the dynamic table)."""
    assert len(name) < 127 and len(value) < 127
    return b"\x40" + bytes([len(name)]) + name + bytes([len(value)]) + value


# --- 1. non-UTF-8 header bytes -------------------------------------------

def test_non_utf8_header_value_decodes_latin1_and_does_not_poison():
    parser = Http2Parser()
    enc = _encoder()
    # Indexed literal with a non-UTF-8 value: the dynamic table is updated
    # during the decode, so a late UTF-8 failure used to poison the direction.
    bad = enc.encode([(":status", "200")]) + _literal_with_index(b"x-bin", b"\xff\xfe")
    res = _completed(parser.feed(
        _frame(_HEADERS, _END_HEADERS | _END_STREAM, 1, bad), "read"))[0]
    assert res.error == ""
    assert res.headers["x-bin"] == "\xff\xfe"  # latin-1 fallback

    # A later block indexes the static :status 404 (0x8D) and the dynamic
    # entry inserted above (index 62 -> 0xBE): the table stayed in sync.
    later = _completed(parser.feed(
        _frame(_HEADERS, _END_HEADERS | _END_STREAM, 3,
               b"\x8d\xbe" + _literal_no_index(b"x-ok", b"fine")), "read"))[0]
    assert later.error == ""
    assert later.status_code == 404
    assert later.headers["x-bin"] == "\xff\xfe"
    assert later.headers["x-ok"] == "fine"


def test_valid_utf8_header_value_unchanged():
    parser = Http2Parser()
    block = _encoder().encode([(":status", "200"), ("x-u", "grüße")])
    res = _completed(parser.feed(
        _frame(_HEADERS, _END_HEADERS | _END_STREAM, 1, block), "read"))[0]
    assert res.headers["x-u"] == "grüße"
    assert all(isinstance(k, str) and isinstance(v, str)
               for k, v in res.headers.items())


def test_non_utf8_header_name_falls_back_per_field():
    parser = Http2Parser()
    block = (_encoder().encode([(":status", "200")])
             + _literal_no_index(b"x-\xe9", b"ok"))
    res = _completed(parser.feed(
        _frame(_HEADERS, _END_HEADERS | _END_STREAM, 1, block), "read"))[0]
    assert res.headers["x-\xe9"] == "ok"
    assert res.status_code == 200


# --- 2. CONTINUATION flood ---------------------------------------------------

def test_continuation_flood_is_capped_and_poisons_direction():
    parser = Http2Parser()
    parser.feed(_frame(_HEADERS, 0x00, 1, b"\x00" * 1024), "read")
    chunk = _frame(_CONTINUATION, 0x00, 1, b"\x00" * 16384)
    for _ in range(40):  # ~640 KiB, well past the 256 KiB cap
        parser.feed(chunk, "read")
    stream = parser._streams["read"][1]
    assert len(stream.header_bytes) == 0
    assert stream.error == "header-block-too-large"
    assert parser._decoder_failed["read"] is True

    # Completing the block keeps the specific error (not "hpack-desync").
    res = _completed(parser.feed(
        _frame(_CONTINUATION, _END_HEADERS | _END_STREAM, 1, b""), "read"))[0]
    assert res.error == "header-block-too-large"


def test_push_promise_continuation_flood_is_capped():
    parser = Http2Parser()
    parser.feed(_frame(_PUSH_PROMISE, 0x00, 1, struct.pack("!I", 2)), "read")
    chunk = _frame(_CONTINUATION, 0x00, 1, b"\x00" * 16384)
    for _ in range(40):
        parser.feed(chunk, "read")
    stream = parser._streams["read"][1]
    assert len(stream.push_header_bytes) == 0
    assert parser._decoder_failed["read"] is True
    assert stream.error == ""  # parent not mislabelled (#16)


def test_header_block_below_cap_still_decodes():
    parser = Http2Parser()
    block = _encoder().encode([(":status", "200"), ("x-big", "a" * 8000)])
    half = len(block) // 2
    parser.feed(_frame(_HEADERS, 0x00, 1, block[:half]), "read")
    res = _completed(parser.feed(
        _frame(_CONTINUATION, _END_HEADERS | _END_STREAM, 1, block[half:]),
        "read"))[0]
    assert res.status_code == 200 and res.error == ""


# --- 4. stream state creation / cap ------------------------------------------

def test_window_update_flood_creates_no_stream_state():
    parser = Http2Parser()
    wu = struct.pack("!I", 1000)
    data = b"".join(_frame(_WINDOW_UPDATE, 0, sid, wu)
                    for sid in range(1, 20001, 2))  # 10,000 stream ids
    prio = b"".join(_frame(_PRIORITY_FRAME, 0, sid, b"\x00" * 5)
                    for sid in range(1, 2001, 2))
    assert parser.feed(data + prio, "write") == []
    assert len(parser._streams["write"]) == 0
    assert parser.flush() == []


def test_stream_cap_evicts_oldest_as_incomplete(monkeypatch):
    monkeypatch.setattr(h2mod, "_MAX_OPEN_STREAMS", 4)
    parser = Http2Parser()
    enc = _encoder()
    results = []
    for sid in (1, 3, 5, 7, 9, 11):
        results += parser.feed(_frame(_HEADERS, _END_HEADERS, sid,
                                      enc.encode([(":method", "GET"),
                                                  (":path", f"/{sid}")])),
                               "write")
    evicted = [r for r in results if r.error == "stream-evicted"]
    assert [r.stream_id for r in evicted] == [1, 3]
    assert all(not r.is_complete for r in evicted)
    assert list(parser._streams["write"]) == [5, 7, 9, 11]
    assert parser._decoder_failed["write"] is False


def test_default_stream_cap_bounds_memory():
    parser = Http2Parser()
    data = b"".join(_frame(_DATA, 0, sid, b"x") for sid in range(1, 6001, 2))
    parser.feed(data, "write")
    assert len(parser._streams["write"]) == h2mod._MAX_OPEN_STREAMS


# --- 5. trailers / repeated HEADERS -----------------------------------------

def test_trailers_kept_separately_and_merged():
    parser = Http2Parser()
    enc = _encoder()
    parser.feed(_frame(_HEADERS, _END_HEADERS, 1,
                       enc.encode([(":status", "200"),
                                   ("content-type", "application/grpc")])),
                "read")
    parser.feed(_frame(_DATA, 0, 1, b"payload"), "read")
    stream = parser._streams["read"][1]
    res = _completed(parser.feed(
        _frame(_HEADERS, _END_HEADERS | _END_STREAM, 1,
               enc.encode([("grpc-status", "0")])), "read"))[0]
    assert stream.trailers == {"grpc-status": "0"}
    assert ":status" not in stream.trailers
    assert res.headers["grpc-status"] == "0"
    assert res.status_code == 200 and res.error == ""


def test_repeated_headers_blocks_are_capped(monkeypatch):
    monkeypatch.setattr(h2mod, "_MAX_STREAM_HEADER_FIELDS", 10)
    parser = Http2Parser()
    enc = _encoder()
    results = []
    for i in range(30):
        results += parser.feed(_frame(_HEADERS, _END_HEADERS, 1,
                                      enc.encode([(f"x-h{i}", "v")])), "read")
    assert max(len(r.headers) for r in results) <= 10
    assert results[-1].error == "header-list-too-large"
    assert parser._decoder_failed["read"] is False


def test_header_bytes_cap(monkeypatch):
    monkeypatch.setattr(h2mod, "_MAX_STREAM_HEADER_BYTES", 2000)
    parser = Http2Parser()
    enc = _encoder()
    results = []
    for _ in range(10):
        results += parser.feed(_frame(_HEADERS, _END_HEADERS, 1,
                                      enc.encode([("x-a", "a" * 500)])), "read")
    stream = parser._streams["read"][1]
    assert stream.header_list_bytes <= 2000
    assert results[-1].error == "header-list-too-large"


# --- 3. SETTINGS_HEADER_TABLE_SIZE ---------------------------------------------

def test_larger_peer_header_table_size_does_not_poison():
    parser = Http2Parser()
    # Client (write) advertises a 64 KiB table -> server (read) encoder may use it.
    parser.feed(h2mod._CONNECTION_PREFACE + _settings((0x1, 65536)), "write")
    assert parser._decoders["read"].max_allowed_table_size == 65536

    from hpack import Encoder
    enc = Encoder()
    enc.header_table_size = 65536  # emits a dynamic table size update
    res = _completed(parser.feed(
        _frame(_HEADERS, _END_HEADERS | _END_STREAM, 1,
               enc.encode([(":status", "200")])), "read"))[0]
    assert res.error == "" and res.status_code == 200
    assert parser._decoder_failed["read"] is False


def test_table_size_update_without_settings_still_poisons():
    parser = Http2Parser()
    from hpack import Encoder
    enc = Encoder()
    enc.header_table_size = 65536
    res = _completed(parser.feed(
        _frame(_HEADERS, _END_HEADERS | _END_STREAM, 1,
               enc.encode([(":status", "200")])), "read"))[0]
    assert res.error == "hpack-desync"


def test_peer_header_table_size_is_capped():
    parser = Http2Parser()
    parser.feed(_settings((0x1, 0xFFFFFFFF)), "read")
    assert parser._decoders["write"].max_allowed_table_size == h2mod._MAX_HEADER_TABLE_SIZE


def test_decoder_has_explicit_header_list_cap():
    parser = Http2Parser()
    parser.feed(_frame(_DATA, 0, 1, b"x"), "read")
    assert parser._decoders["read"].max_header_list_size == 65536


# --- 6. invalid padding ---------------------------------------------------------

def test_invalid_headers_padding_marks_error_and_poisons():
    parser = Http2Parser()
    payload = bytes([0xFF]) + b"\x88"  # pad length 255 > remaining 1 byte
    res = _completed(parser.feed(
        _frame(_HEADERS, _END_HEADERS | _END_STREAM | _PADDED, 1, payload),
        "read"))[0]
    assert res.error == "invalid-padding"
    assert parser._decoder_failed["read"] is True


def test_invalid_push_promise_padding_poisons_without_parent_error():
    parser = Http2Parser()
    payload = bytes([0xFF]) + struct.pack("!I", 2)
    parser.feed(_frame(_PUSH_PROMISE, _END_HEADERS | _PADDED, 1, payload), "read")
    assert parser._decoder_failed["read"] is True
    assert parser._streams["read"][1].error == ""


def test_invalid_data_padding_marks_error_without_poison():
    parser = Http2Parser()
    res = _completed(parser.feed(
        _frame(_DATA, _END_STREAM | _PADDED, 1, bytes([0x10]) + b"ab"), "read"))[0]
    assert res.error == "invalid-padding"
    assert parser._decoder_failed["read"] is False


def test_valid_padding_still_decodes():
    parser = Http2Parser()
    block = _encoder().encode([(":status", "200")])
    payload = bytes([3]) + block + b"\x00" * 3
    res = _completed(parser.feed(
        _frame(_HEADERS, _END_HEADERS | _END_STREAM | _PADDED, 1, payload),
        "read"))[0]
    assert res.status_code == 200 and res.error == ""


# --- 7. SETTINGS_MAX_FRAME_SIZE ------------------------------------------------

def test_oversize_headers_frame_after_preface_poisons():
    parser = Http2Parser()
    parser.feed(h2mod._CONNECTION_PREFACE + _settings(), "write")
    big = _encoder().encode([(":status", "200"), ("x", "a" * 40000)])
    parser.feed(_frame(_HEADERS, _END_HEADERS | _END_STREAM, 1, big), "read")
    assert parser._decoder_failed["read"] is True


def test_advertised_max_frame_size_allows_larger_frames():
    parser = Http2Parser()
    parser.feed(h2mod._CONNECTION_PREFACE + _settings((0x5, 65536)), "write")
    big = _encoder().encode([(":status", "200"), ("x", "a" * 40000)])
    assert len(big) > 16384
    res = _completed(parser.feed(
        _frame(_HEADERS, _END_HEADERS | _END_STREAM, 1, big), "read"))[0]
    assert res.status_code == 200 and res.error == ""


def test_no_frame_size_enforcement_mid_connection():
    """Without an observed preface/SETTINGS the limit is unknown: no false
    poisoning when attaching mid-connection."""
    parser = Http2Parser()
    big = _encoder().encode([(":status", "200"), ("x", "a" * 40000)])
    res = _completed(parser.feed(
        _frame(_HEADERS, _END_HEADERS | _END_STREAM, 1, big), "read"))[0]
    assert res.status_code == 200 and res.error == ""
