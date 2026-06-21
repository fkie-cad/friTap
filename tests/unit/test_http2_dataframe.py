#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Synthetic, hermetic tests for friTap's HPACK-free HTTP/2 DATA harvester.

These tests build HTTP/2 frames by hand and feed them through
:mod:`friTap.parsers.http2_dataframe`. No tshark, no capture, no network and
no ``hpack`` dependency (the module deliberately avoids HPACK and only reads
DATA frames).

They cover:

* ``looks_like_http2`` detection vs. raw WebSocket / HTTP/1.1 / short buffers;
* ``group_http2_data_by_stream`` per-stream concatenation, non-DATA skipping,
  PADDED stripping, preface handling, and ``degraded`` reporting on
  truncation / bad frame types.
"""

from __future__ import annotations

import struct

from friTap.parsers.http2_dataframe import (
    HTTP2_PREFACE,
    group_http2_data_by_stream,
    looks_like_http2,
)

# Frame types (RFC 7540 §6).
_DATA = 0x00
_HEADERS = 0x01
_SETTINGS = 0x04
# Flags.
_FLAG_PADDED = 0x08


def make_frame(ftype: int, flags: int, stream_id: int, payload: bytes) -> bytes:
    """Build a 9-byte-header HTTP/2 frame (24-bit length, type, flags, sid)."""
    return (
        struct.pack(">I", len(payload))[1:]
        + bytes([ftype, flags])
        + struct.pack(">I", stream_id)
        + payload
    )


# --------------------------------------------------------------------------- #
# looks_like_http2
# --------------------------------------------------------------------------- #
def test_looks_like_http2_true_on_settings_frame():
    settings = make_frame(_SETTINGS, 0x00, 0, b"\x00\x03\x00\x00\x00\x64")
    assert looks_like_http2(settings) is True


def test_looks_like_http2_true_with_preface():
    settings = make_frame(_SETTINGS, 0x00, 0, b"\x00\x03\x00\x00\x00\x64")
    assert looks_like_http2(HTTP2_PREFACE + settings) is True


def test_looks_like_http2_false_on_raw_websocket_frame():
    masked_ws = b"\x82\x85" + b"\x01\x02\x03\x04" + b"\x00" * 5
    assert looks_like_http2(masked_ws) is False

    unmasked_ws = b"\x82\x05hello"
    assert looks_like_http2(unmasked_ws) is False


def test_looks_like_http2_false_on_http1_text():
    assert looks_like_http2(b"GET / HTTP/1.1\r\n\r\n") is False
    assert looks_like_http2(b"HTTP/1.1 200 OK\r\n") is False


def test_looks_like_http2_false_on_short_buffer():
    assert looks_like_http2(b"") is False
    assert looks_like_http2(b"\x00\x00\x00\x00") is False  # < 9 bytes


# --------------------------------------------------------------------------- #
# group_http2_data_by_stream
# --------------------------------------------------------------------------- #
def test_group_data_by_stream_basic():
    buf = (
        make_frame(_DATA, 0x00, 1, b"hello")
        + make_frame(_DATA, 0x00, 1, b"world")
        + make_frame(_DATA, 0x00, 3, b"xxx")
    )
    streams, degraded = group_http2_data_by_stream(buf)
    assert streams == {1: b"helloworld", 3: b"xxx"}
    assert degraded is False


def test_group_data_skips_non_data():
    buf = (
        make_frame(_DATA, 0x00, 1, b"aaa")
        + make_frame(_HEADERS, 0x04, 1, b"\x88")  # HPACK-ish bytes, ignored
        + make_frame(_SETTINGS, 0x00, 0, b"\x00\x03\x00\x00\x00\x64")
        + make_frame(_DATA, 0x00, 1, b"bbb")
    )
    streams, degraded = group_http2_data_by_stream(buf)
    assert streams == {1: b"aaabbb"}
    assert degraded is False


def test_group_data_padded_stripping():
    payload = bytes([4]) + b"realdata" + b"\x00\x00\x00\x00"
    buf = make_frame(_DATA, _FLAG_PADDED, 1, payload)
    streams, degraded = group_http2_data_by_stream(buf)
    assert streams == {1: b"realdata"}
    assert degraded is False


def test_group_data_padded_invalid_pad_length_is_degraded():
    # pad length byte (200) exceeds the frame payload -> malformed PADDED frame
    # (RFC 7540 PROTOCOL_ERROR). It must contribute no data and flag degraded,
    # while framing stays aligned (the following frame is still harvested).
    bad = make_frame(_DATA, _FLAG_PADDED, 1, bytes([200]) + b"short")
    good = make_frame(_DATA, 0x00, 1, b"after")
    streams, degraded = group_http2_data_by_stream(bad + good)
    assert degraded is True
    assert streams == {1: b"after"}


def test_group_data_with_preface():
    buf = HTTP2_PREFACE + make_frame(_DATA, 0x00, 1, b"payload")
    streams, degraded = group_http2_data_by_stream(buf)
    assert streams == {1: b"payload"}
    assert degraded is False


def test_group_data_degraded_on_truncation():
    valid = make_frame(_DATA, 0x00, 1, b"complete")
    # Truncated trailing frame: header declares length 100 but no body follows.
    truncated_header = struct.pack(">I", 100)[1:] + bytes([_DATA, 0x00]) + struct.pack(">I", 1)
    streams, degraded = group_http2_data_by_stream(valid + truncated_header)
    assert streams == {1: b"complete"}
    assert degraded is True


def test_group_data_degraded_on_bad_frame_type():
    valid = make_frame(_DATA, 0x00, 1, b"complete")
    bad = make_frame(0xFF, 0x00, 1, b"junk")  # type > 0x09
    streams, degraded = group_http2_data_by_stream(valid + bad)
    assert streams == {1: b"complete"}
    assert degraded is True


def test_group_data_empty_buffer():
    streams, degraded = group_http2_data_by_stream(b"")
    assert streams == {}
    assert degraded is False
