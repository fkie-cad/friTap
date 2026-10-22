#!/usr/bin/env python3

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
    group_http2_data_ends_by_stream,
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


# --------------------------------------------------------------------------- #
# group_http2_data_ends_by_stream
# --------------------------------------------------------------------------- #
def test_data_ends_map_stream_positions_back_to_the_buffer():
    settings = make_frame(_SETTINGS, 0x00, 0, b"")
    first = make_frame(_DATA, 0x00, 1, b"abc")
    other = make_frame(_DATA, 0x00, 3, b"zz")
    second = make_frame(_DATA, 0x00, 1, b"de")
    buf = HTTP2_PREFACE + settings + first + other + second

    streams, ends, degraded = group_http2_data_ends_by_stream(buf)

    assert not degraded
    assert streams == {1: b"abcde", 3: b"zz"}
    first_end = len(HTTP2_PREFACE + settings + first)
    assert ends[1] == [(3, first_end), (5, len(buf))]
    assert ends[3] == [(2, first_end + len(other))]


def test_data_ends_agree_with_plain_grouping():
    buf = make_frame(_DATA, _FLAG_PADDED, 5, b"\x02hi\x00\x00")
    streams, _ends, degraded = group_http2_data_ends_by_stream(buf)
    assert (streams, degraded) == group_http2_data_by_stream(buf)


# --------------------------------------------------------------------------- #
# Unknown frame types (RFC 9113 §5.5: MUST be ignored)
# --------------------------------------------------------------------------- #
_PRIORITY_UPDATE = 0x10
_GREASE = 0x0B


def test_http2_data_for_stream_skips_priority_update_before_data():
    from friTap.parsers.http2_dataframe import http2_data_for_stream

    buf = make_frame(_PRIORITY_UPDATE, 0, 0, b"\x00\x00\x00\x01u=1") + make_frame(_DATA, 0, 1, b"hello")
    assert http2_data_for_stream(buf, 1) == (b"hello", False)


def test_http2_data_for_stream_skips_grease_frame():
    from friTap.parsers.http2_dataframe import http2_data_for_stream

    buf = make_frame(_DATA, 0, 3, b"he") + make_frame(_GREASE, 0xFF, 3, b"junk") + make_frame(_DATA, 0, 3, b"llo")
    assert http2_data_for_stream(HTTP2_PREFACE + buf, 0) == (b"hello", False)


def test_http2_data_for_stream_overflowing_unknown_frame_is_degraded():
    from friTap.parsers.http2_dataframe import http2_data_for_stream

    garbage = make_frame(_DATA, 0, 1, b"ok") + b"\xff\xff\xff\x81" + b"\x00" * 10
    assert http2_data_for_stream(garbage, 1) == (b"ok", True)


def test_group_by_stream_still_stops_at_unknown_type():
    """The Signal mid-stream desync heuristic keeps treating type > 0x09 as a stop."""
    buf = make_frame(_GREASE, 0, 0, b"x") + make_frame(_DATA, 0, 1, b"hello")
    assert group_http2_data_by_stream(buf) == ({}, True)
