"""Tests for the shared HTTP/2 frame-header helpers.

``describe_frame_header`` replaces the TUI's private-name frame decoding, which
read the connection preface ``PRI * HTTP/2.0`` as a frame of type 0x20 (32).
"""

from __future__ import annotations

import pytest

from friTap.parsers import http2
from friTap.parsers.http2_constants import (
    HTTP2_EXTENSION_FRAME_TYPE_NAMES,
    HTTP2_FRAME_TYPE_NAMES,
    HTTP2_PREFACE,
    unpack_frame_header,
)
from friTap.parsers.http2_dataframe import (
    H2FrameHeader,
    describe_frame_header,
    looks_like_http2,
)


def header(length: int, frame_type: int, flags: int = 0, stream_id: int = 0) -> bytes:
    return (length.to_bytes(3, "big") + bytes([frame_type, flags])
            + stream_id.to_bytes(4, "big"))


def test_frame_type_names_are_shared_with_http2_parser():
    assert http2._FRAME_TYPE_NAMES is HTTP2_FRAME_TYPE_NAMES
    assert HTTP2_FRAME_TYPE_NAMES[http2._FRAME_SETTINGS] == "SETTINGS"
    assert HTTP2_FRAME_TYPE_NAMES[http2._FRAME_CONTINUATION] == "CONTINUATION"
    assert sorted(HTTP2_FRAME_TYPE_NAMES) == list(range(10))


def test_complete_frame():
    raw = header(6, 0x04) + b"\x00" * 6
    assert describe_frame_header(raw) == H2FrameHeader(
        length=6, frame_type=4, type_name="SETTINGS", flags=0, stream_id=0,
        available=6, preface_skipped=False,
    )
    assert not describe_frame_header(raw).truncated


def test_preface_is_skipped_not_read_as_type_32():
    described = describe_frame_header(HTTP2_PREFACE + header(6, 0x04) + b"\x00" * 6)
    assert described.type_name == "SETTINGS" and described.preface_skipped


def test_truncated_frame_reports_available_bytes():
    described = describe_frame_header(header(100, 0x00, stream_id=3) + b"abc")
    assert (described.type_name, described.length, described.available) == ("DATA", 100, 3)
    assert described.truncated


def test_reserved_stream_bit_is_masked():
    described = describe_frame_header(header(0, 0x01, flags=0x04, stream_id=0x80000005))
    assert described.stream_id == 5 and described.flags == 0x04


def test_short_buffer_returns_none():
    assert describe_frame_header(header(0, 0x04)[:8]) is None
    assert describe_frame_header(b"") is None


def test_preface_alone_returns_none():
    assert describe_frame_header(HTTP2_PREFACE) is None


def test_partial_preface_is_not_a_frame():
    assert describe_frame_header(HTTP2_PREFACE[:20]) is None


def test_unknown_frame_type_returns_none():
    for frame_type in (0x0B, 0x0D, 0x0F, 0x11, 0x20, 0xFF):
        assert describe_frame_header(header(0, frame_type)) is None


@pytest.mark.parametrize("frame_type,name", [
    (0x0A, "ALTSVC"), (0x0C, "ORIGIN"), (0x10, "PRIORITY_UPDATE"),
])
def test_registered_extension_frames_are_described(frame_type, name):
    described = describe_frame_header(header(4, frame_type, stream_id=0) + b"\x00" * 4)
    assert (described.frame_type, described.type_name) == (frame_type, name)
    assert HTTP2_EXTENSION_FRAME_TYPE_NAMES[frame_type] == name


def test_extension_frame_after_preface_is_described():
    described = describe_frame_header(HTTP2_PREFACE + header(0, 0x10, stream_id=3))
    assert described.type_name == "PRIORITY_UPDATE" and described.preface_skipped


def test_looks_like_http2_still_rejects_extension_types():
    for frame_type in HTTP2_EXTENSION_FRAME_TYPE_NAMES:
        assert not looks_like_http2(header(0, frame_type))


# ── unpack_frame_header ──────────────────────────────────────────


def test_unpack_frame_header_fields_and_reserved_bit():
    raw = header(0x123456, 0x01, flags=0x25, stream_id=0x80000007)
    assert unpack_frame_header(raw) == (0x123456, 0x01, 0x25, 7)


def test_unpack_frame_header_at_offset_and_buffer_types():
    raw = b"junk" + header(9, 0x00, flags=0x01, stream_id=5)
    expected = (9, 0x00, 0x01, 5)
    for buf in (raw, bytearray(raw), memoryview(raw)):
        assert unpack_frame_header(buf, 4) == expected


def test_http2_parser_helpers_use_shared_decoder():
    from friTap.parsers.http2 import Http2Parser

    raw = header(16384, 0x00, flags=0x01, stream_id=0x80000003)
    assert Http2Parser._parse_frame_header(raw) == unpack_frame_header(raw)
    assert Http2Parser._is_valid_frame_header(header(0, 0x09))
    assert not Http2Parser._is_valid_frame_header(header(0, 0x0A))
    assert not Http2Parser._is_valid_frame_header(header(0, 0x00)[:8])
