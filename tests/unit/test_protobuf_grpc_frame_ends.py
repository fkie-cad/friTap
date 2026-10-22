"""Tests for friTap.parsers.protobuf.grpc.strip_grpc_frame_with_end."""

from __future__ import annotations

import pytest

from friTap.parsers.protobuf.grpc import strip_grpc_frame, strip_grpc_frame_with_end


def _frame(payload: bytes, flag: int = 0) -> bytes:
    return bytes([flag]) + len(payload).to_bytes(4, "big") + payload


def test_frames_pair_with_exclusive_end_offsets():
    data = _frame(b"abc") + _frame(b"", 1) + _frame(b"de")
    pairs = strip_grpc_frame_with_end(data)
    assert [end for _, end in pairs] == [8, 13, 20]
    assert [frame for frame, _ in pairs] == strip_grpc_frame(data)


def test_malformed_framing_raises_like_strip_grpc_frame():
    for bad in (b"\x00\x00", b"\x02" + b"\x00" * 4, _frame(b"abc")[:-1]):
        with pytest.raises(ValueError):
            strip_grpc_frame_with_end(bad)
