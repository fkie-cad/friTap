"""Tests for gRPC framing helpers: lenient splitting and payload decompression."""

from __future__ import annotations

import gzip
import struct
import zlib

import pytest

from friTap.parsers.decompress import MAX_INFLATE
from friTap.parsers.protobuf import (
    GrpcFrame,
    decompress_grpc_payload,
    is_grpc_frame,
    split_grpc_frames_lenient,
    strip_grpc_frame,
)
from friTap.parsers.protobuf.grpc import strip_grpc_frame_with_end
from friTap.parsers.websocket import _detect_grpc

MSG = b"\x08\x96\x01"


def frame(payload: bytes, compressed: int = 0) -> bytes:
    return bytes([compressed]) + struct.pack(">I", len(payload)) + payload


# ── split_grpc_frames_lenient ────────────────────────────────────


def test_split_clean_frames_matches_strict():
    data = frame(MSG) + frame(b"\x10\x01", 1)
    frames, error = split_grpc_frames_lenient(data)
    assert error == ""
    assert frames == strip_grpc_frame(data)
    assert [f.truncated for f in frames] == [False, False]


def test_split_keeps_truncated_final_frame():
    data = frame(MSG) + frame(b"0123456789")[:8]
    frames, error = split_grpc_frames_lenient(data)
    assert frames[0] == GrpcFrame(False, MSG)
    assert frames[1].payload == b"012" and frames[1].truncated
    assert "truncated gRPC payload" in error and "need 10 bytes but only 3 remain" in error


def test_split_invalid_first_header_yields_no_frames():
    frames, error = split_grpc_frames_lenient(b"\x08\x96\x01\x00\x00")
    assert frames == []
    assert error == "invalid gRPC compressed flag 8 at offset 0"


def test_split_trailing_short_header_keeps_earlier_frames():
    frames, error = split_grpc_frames_lenient(frame(MSG) + b"\x00\x00")
    assert frames == [GrpcFrame(False, MSG)]
    assert "truncated gRPC frame header at offset 8" in error


def test_split_empty_input():
    assert split_grpc_frames_lenient(b"") == ([], "")


def test_strict_split_error_messages_unchanged():
    with pytest.raises(ValueError, match="invalid gRPC compressed flag 2 at offset 0"):
        strip_grpc_frame(b"\x02\x00\x00\x00\x00")
    with pytest.raises(ValueError, match="truncated gRPC payload at offset 5"):
        strip_grpc_frame(b"\x00\x00\x00\x00\x09ab")


# ── decompress_grpc_payload ──────────────────────────────────────


def test_decompress_gzip():
    assert decompress_grpc_payload(gzip.compress(MSG), "gzip") == (MSG, "")


def test_decompress_deflate_is_zlib_framed():
    assert decompress_grpc_payload(zlib.compress(MSG), "deflate") == (MSG, "")


def test_decompress_encoding_is_case_insensitive():
    assert decompress_grpc_payload(gzip.compress(MSG), " GZIP ") == (MSG, "")


def test_decompress_zstd():
    zstandard = pytest.importorskip("zstandard")
    packed = zstandard.ZstdCompressor().compress(MSG)
    assert decompress_grpc_payload(packed, "zstd") == (MSG, "")


def test_decompress_without_encoding_is_best_effort():
    data, note = decompress_grpc_payload(gzip.compress(MSG), "")
    assert data == MSG and "without grpc-encoding" in note


def test_decompress_identity_with_compressed_flag_is_best_effort():
    data, note = decompress_grpc_payload(zlib.compress(MSG), "identity")
    assert data == MSG and note


def test_decompress_corrupt_gzip_reports_failure():
    data, note = decompress_grpc_payload(b"not gzip", "gzip")
    assert data is None and note.startswith("gzip decompression failed")


def test_decompress_corrupt_without_encoding_reports_failure():
    data, note = decompress_grpc_payload(b"not gzip", "")
    assert data is None and "without a usable grpc-encoding" in note


def test_decompress_unsupported_encoding():
    data, note = decompress_grpc_payload(b"xx", "snappy")
    assert data is None and "unsupported grpc-encoding 'snappy'" in note


# ── decompression bombs ──────────────────────────────────────────


def test_decompress_zstd_bomb_is_rejected():
    zstandard = pytest.importorskip("zstandard")
    bomb = zstandard.ZstdCompressor(level=19).compress(b"\0" * (MAX_INFLATE * 4))
    assert len(bomb) < 64 * 1024
    data, note = decompress_grpc_payload(bomb, "zstd")
    assert data is None and "decompressed size exceeds limit" in note


def test_decompress_brotli_bomb_is_rejected():
    brotli = pytest.importorskip("brotli")
    # quality=1 keeps the test fast; output (4x limit) still exceeds MAX_INFLATE.
    bomb = brotli.compress(b"\0" * (MAX_INFLATE * 4), quality=1)
    data, note = decompress_grpc_payload(bomb, "br")
    assert data is None and "decompressed size exceeds limit" in note


def test_decompress_gzip_bomb_is_rejected():
    bomb = gzip.compress(b"\0" * (MAX_INFLATE + 1))
    data, note = decompress_grpc_payload(bomb, "gzip")
    assert data is None and note.startswith("gzip decompression failed")


def test_decompress_zstd_at_limit_is_accepted():
    zstandard = pytest.importorskip("zstandard")
    packed = zstandard.ZstdCompressor().compress(b"\x01" * MAX_INFLATE)
    data, note = decompress_grpc_payload(packed, "zstd")
    assert note == "" and len(data) == MAX_INFLATE


def test_decompress_brotli():
    brotli = pytest.importorskip("brotli")
    assert decompress_grpc_payload(brotli.compress(MSG), "br") == (MSG, "")


# ── shared frame walker ──────────────────────────────────────────


def test_strict_and_lenient_agree_on_frames_and_ends():
    body = frame(MSG) + frame(b"", 1) + frame(b"\x08\x01")
    with_end = strip_grpc_frame_with_end(body)
    assert [end for _, end in with_end] == [8, 13, 20]
    assert split_grpc_frames_lenient(body) == ([f for f, _ in with_end], "")


def test_strict_raises_the_lenient_error_text():
    body = frame(MSG) + frame(b"abcdef")[:-2]
    frames, error = split_grpc_frames_lenient(body)
    assert frames[-1].truncated and error
    with pytest.raises(ValueError) as info:
        strip_grpc_frame_with_end(body)
    assert str(info.value) == error


@pytest.mark.parametrize("data", [
    b"", b"\x00\x00\x00", frame(MSG), frame(MSG) + b"tail", frame(MSG)[:-1],
    b"\x02" + frame(MSG)[1:], frame(b"", 1), bytearray(frame(MSG)),
])
def test_websocket_grpc_detection_matches_is_grpc_frame(data):
    expected = len(data) >= 5 and data[0] in (0, 1) and \
        5 + int.from_bytes(data[1:5], "big") <= len(data)
    assert is_grpc_frame(data) is expected
    assert _detect_grpc(data) == ("application/grpc" if expected else "")
