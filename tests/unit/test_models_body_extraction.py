#!/usr/bin/env python3

"""Tests for ``Flow`` HTTP/2 and HTTP/3 body reconstruction.

``Flow._extract_h2_body`` / ``_extract_h3_body`` delegate to the canonical
parser-package walkers (:func:`friTap.parsers.http2_dataframe.http2_data_for_stream`
and :func:`friTap.parsers.http3.iter_h3_data_frames`). Frames are built by hand;
no capture, no network.
"""

from __future__ import annotations

import struct

from friTap.flow.models import Flow, FlowChunk
from friTap.parsers.base import ParseResult
from friTap.parsers.http2_dataframe import HTTP2_PREFACE, http2_data_for_stream
from friTap.parsers.http3 import iter_h3_data_frames
from friTap.parsers.varint import encode_varint

_DATA, _HEADERS, _SETTINGS, _WINDOW_UPDATE = 0x00, 0x01, 0x04, 0x08
_FLAG_PADDED = 0x08


def h2_frame(ftype: int, flags: int, stream_id: int, payload: bytes) -> bytes:
    """Build a 9-byte-header HTTP/2 frame."""
    return (
        struct.pack(">I", len(payload))[1:]
        + bytes([ftype, flags])
        + struct.pack(">I", stream_id)
        + payload
    )


def h3_frame(ftype: int, payload: bytes) -> bytes:
    """Build a varint-framed HTTP/3 frame."""
    return encode_varint(ftype) + encode_varint(len(payload)) + payload


def make_flow(data: bytes, direction: str = "write", stream_id: int = 0) -> Flow:
    """A Flow whose *direction* bytes are *data*, split over two chunks."""
    msg = ParseResult(stream_id=stream_id)
    half = len(data) // 2
    chunks = [
        FlowChunk(data=data[:half], direction=direction, timestamp=0.0),
        FlowChunk(data=b"ignored-other-direction", direction="other", timestamp=0.0),
        FlowChunk(data=data[half:], direction=direction, timestamp=0.0),
    ]
    flow = Flow(chunks=chunks)
    if direction == "write":
        flow.request = msg
    else:
        flow.response = msg
    return flow


# --------------------------------------------------------------------------- #
# HTTP/2
# --------------------------------------------------------------------------- #
class TestH2Body:
    def test_plain_data_frames_concatenate(self):
        raw = h2_frame(_DATA, 0, 1, b"hello ") + h2_frame(_DATA, 0x01, 1, b"world")
        assert make_flow(raw, "read", 1)._extract_h2_body("read") == b"hello world"

    def test_padded_data_frame_strips_pad_length_and_padding(self):
        payload = bytes([3]) + b"body" + b"\x00" * 3
        raw = h2_frame(_DATA, _FLAG_PADDED, 1, payload)
        assert make_flow(raw, "read", 1)._extract_h2_body("read") == b"body"

    def test_padded_frame_with_oversized_pad_contributes_nothing(self):
        bad = h2_frame(_DATA, _FLAG_PADDED, 1, bytes([9]) + b"ab")
        good = h2_frame(_DATA, 0, 1, b"next")
        flow = make_flow(bad + good, "read", 1)
        assert flow._extract_h2_body("read") == b"next"

    def test_interleaved_streams_filtered_by_stream_id(self):
        raw = (
            h2_frame(_DATA, 0, 1, b"A1")
            + h2_frame(_DATA, 0, 3, b"B1")
            + h2_frame(_DATA, 0, 1, b"A2")
            + h2_frame(_DATA, 0, 3, b"B2")
        )
        assert make_flow(raw, "read", 3)._extract_h2_body("read") == b"B1B2"

    def test_stream_id_zero_keeps_all_streams_in_arrival_order(self):
        raw = (
            h2_frame(_DATA, 0, 1, b"A1")
            + h2_frame(_DATA, 0, 3, b"B1")
            + h2_frame(_DATA, 0, 1, b"A2")
        )
        assert make_flow(raw, "read", 0)._extract_h2_body("read") == b"A1B1A2"

    def test_connection_preface_is_skipped(self):
        raw = (
            HTTP2_PREFACE
            + h2_frame(_SETTINGS, 0, 0, b"")
            + h2_frame(_DATA, 0, 1, b"request-body")
        )
        assert make_flow(raw, "write", 1)._extract_h2_body("write") == b"request-body"

    def test_non_data_frames_between_are_skipped(self):
        raw = (
            h2_frame(_HEADERS, 0x04, 1, b"\x82\x84")
            + h2_frame(_DATA, 0, 1, b"one")
            + h2_frame(_WINDOW_UPDATE, 0, 0, b"\x00\x00\x10\x00")
            + h2_frame(_DATA, 0, 1, b"two")
        )
        assert make_flow(raw, "read", 1)._extract_h2_body("read") == b"onetwo"

    def test_truncated_last_frame_keeps_complete_frames(self):
        raw = h2_frame(_DATA, 0, 1, b"full") + h2_frame(_DATA, 0, 1, b"partial")[:-3]
        assert make_flow(raw, "read", 1)._extract_h2_body("read") == b"full"

    def test_unknown_frame_type_is_skipped(self):
        # RFC 9113 §5.5: frames of unknown type MUST be ignored, not end the walk.
        unknown = h2_frame(0xEE, 0, 1, b"xx")
        raw = h2_frame(_DATA, 0, 1, b"ok") + unknown + h2_frame(_DATA, 0, 1, b"more")
        assert make_flow(raw, "read", 1)._extract_h2_body("read") == b"okmore"


class TestHttp2DataForStream:
    def test_reports_degraded_on_truncation(self):
        raw = h2_frame(_DATA, 0, 1, b"full") + h2_frame(_DATA, 0, 1, b"x")[:-1]
        assert http2_data_for_stream(raw, 1) == (b"full", True)

    def test_clean_buffer_not_degraded(self):
        raw = h2_frame(_DATA, 0, 5, b"x") + h2_frame(_DATA, 0, 7, b"y")
        assert http2_data_for_stream(raw, 7) == (b"y", False)


# --------------------------------------------------------------------------- #
# HTTP/3
# --------------------------------------------------------------------------- #
class TestH3Body:
    def test_data_frames_between_headers_and_unknown_types(self):
        raw = (
            h3_frame(0x01, b"\x00\x00\xd1")       # HEADERS
            + h3_frame(0x00, b"part1-")            # DATA
            + h3_frame(0x21, b"grease-reserved")   # unknown / reserved type
            + h3_frame(0x00, b"part2")             # DATA
        )
        assert make_flow(raw, "read")._extract_h3_body("read") == b"part1-part2"

    def test_multibyte_varint_lengths(self):
        body = b"z" * 300  # length needs a 2-byte varint
        raw = h3_frame(0x00, body) + h3_frame(0x4142, b"big-type-varint")
        assert make_flow(raw, "read")._extract_h3_body("read") == body

    def test_truncated_last_frame_keeps_complete_frames(self):
        raw = h3_frame(0x00, b"done") + h3_frame(0x00, b"cut-short")[:-2]
        assert make_flow(raw, "read")._extract_h3_body("read") == b"done"

    def test_iter_h3_data_frames_does_not_mutate_input(self):
        raw = bytearray(h3_frame(0x00, b"a") + h3_frame(0x01, b"h"))
        before = bytes(raw)
        assert list(iter_h3_data_frames(raw)) == [b"a"]
        assert bytes(raw) == before
