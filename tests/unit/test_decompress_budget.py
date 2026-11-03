"""Bounded decompression helpers and the Flow decompressed-body cache."""

from __future__ import annotations

import gzip
import zlib

import pytest

from friTap.flow.models import Flow, FlowChunk
from friTap.parsers import decompress
from friTap.parsers.base import ParseResult
from friTap.parsers.decompress import (
    MAX_AUTO_DECOMPRESS,
    MAX_DECOMPRESSED_BODY,
    InflateLimitError,
    find_embedded_gzip,
    inflate_bounded,
    inflate_stream_bounded,
)


def _raw_deflate_sync(data: bytes, comp) -> bytes:
    return comp.compress(data) + comp.flush(zlib.Z_SYNC_FLUSH)


# --------------------------------------------------------------------------- #
# inflate_stream_bounded
# --------------------------------------------------------------------------- #

def test_auto_cap_is_smaller_than_save_cap():
    assert MAX_AUTO_DECOMPRESS == 16 * 1024 * 1024
    assert MAX_DECOMPRESSED_BODY == 256 * 1024 * 1024


def test_inflate_stream_bounded_keeps_context_across_messages():
    comp = zlib.compressobj(9, zlib.DEFLATED, -zlib.MAX_WBITS)
    dec = zlib.decompressobj(-zlib.MAX_WBITS)
    assert inflate_stream_bounded(dec, _raw_deflate_sync(b"abcabc", comp), 100) == b"abcabc"
    assert inflate_stream_bounded(dec, _raw_deflate_sync(b"abcabcabc", comp), 100) == b"abcabcabc"


def test_inflate_stream_bounded_exact_limit_ok():
    comp = zlib.compressobj(9, zlib.DEFLATED, -zlib.MAX_WBITS)
    dec = zlib.decompressobj(-zlib.MAX_WBITS)
    assert inflate_stream_bounded(dec, _raw_deflate_sync(b"A" * 1000, comp), 1000) == b"A" * 1000


def test_inflate_stream_bounded_over_limit_raises():
    comp = zlib.compressobj(9, zlib.DEFLATED, -zlib.MAX_WBITS)
    dec = zlib.decompressobj(-zlib.MAX_WBITS)
    with pytest.raises(InflateLimitError):
        inflate_stream_bounded(dec, _raw_deflate_sync(b"A" * 1001, comp), 1000)


def test_inflate_stream_bounded_corrupt_raises_zlib_error():
    with pytest.raises(zlib.error):
        inflate_stream_bounded(zlib.decompressobj(-zlib.MAX_WBITS), b"\xff\xff\xff", 100)


# --------------------------------------------------------------------------- #
# inflate_bounded(require_eof=...)
# --------------------------------------------------------------------------- #

def test_inflate_bounded_truncated_default_returns_partial():
    packed = gzip.compress(b"hello world" * 100)
    out = inflate_bounded(packed[:-12])
    assert (b"hello world" * 100).startswith(out)


def test_inflate_bounded_truncated_require_eof_raises():
    packed = gzip.compress(b"hello world" * 100)
    with pytest.raises(zlib.error):
        inflate_bounded(packed[:-12], require_eof=True)


def test_inflate_bounded_require_eof_complete_ok():
    packed = zlib.compress(b"data" * 50)
    assert inflate_bounded(packed, require_eof=True) == b"data" * 50


# --------------------------------------------------------------------------- #
# find_embedded_gzip shared budget
# --------------------------------------------------------------------------- #

def test_find_embedded_gzip_still_finds_member_after_prefix():
    member = gzip.compress(b"payload")
    assert find_embedded_gzip(b"\x1f\x8b\x08junk" + b"PREFIX" + member) == (
        len(b"\x1f\x8b\x08junk" + b"PREFIX"), b"payload")


def test_find_embedded_gzip_shared_budget_stops_after_bombs():
    # Members without trailer, each inflating more than max_out bytes.
    bomb = gzip.compress(b"\x00" * 10000)[:-8]
    good = gzip.compress(b"ok")
    body = bomb * 4 + good
    assert find_embedded_gzip(body, max_out=1000) is None  # budget exhausted
    assert find_embedded_gzip(bomb * 2 + good, max_out=1000)[1] == b"ok"


# --------------------------------------------------------------------------- #
# Flow: decompressed-body cache + h11 robustness
# --------------------------------------------------------------------------- #

def _flow_with_gzip_response(body: bytes) -> Flow:
    flow = Flow(flow_id="f")
    flow.response = ParseResult(
        protocol="HTTP/1.1", is_request=False, body=gzip.compress(body),
        headers={"Content-Encoding": "gzip"})
    return flow


def test_decompressed_body_is_cached(monkeypatch):
    flow = _flow_with_gzip_response(b"hello")
    calls = []
    real = decompress.decompress_body

    def counting(body, enc, max_out=MAX_DECOMPRESSED_BODY):
        calls.append(max_out)
        return real(body, enc, max_out)

    monkeypatch.setattr(decompress, "decompress_body", counting)
    assert flow.get_decompressed_response_body() == b"hello"
    assert flow.get_decompressed_response_body() == b"hello"
    assert calls == [MAX_AUTO_DECOMPRESS]


def test_cache_invalidated_with_body_cache(monkeypatch):
    flow = _flow_with_gzip_response(b"hello")
    flow.get_decompressed_response_body()
    flow.invalidate_body_cache()
    calls = []
    monkeypatch.setattr(decompress, "decompress_body",
                        lambda b, e, m=0: (calls.append(1), (b"x", ""))[1])
    assert flow.get_decompressed_response_body() == b"x"
    assert calls == [1]


def test_cache_follows_message_replacement():
    flow = _flow_with_gzip_response(b"first")
    assert flow.get_decompressed_response_body() == b"first"
    flow.response = ParseResult(
        protocol="HTTP/1.1", is_request=False, body=gzip.compress(b"second"),
        headers={"Content-Encoding": "gzip"})
    assert flow.get_decompressed_response_body() == b"second"


def test_auto_path_rejects_bodies_over_auto_cap(monkeypatch):
    monkeypatch.setattr(decompress, "MAX_AUTO_DECOMPRESS", 10)
    flow = _flow_with_gzip_response(b"A" * 100)
    compressed = flow.response.body
    assert flow.get_decompressed_response_body() == compressed  # rejected, unchanged
    # The explicit (save) path keeps the large default cap.
    assert flow._get_decompressed_body(flow.response, "read") == b"A" * 100


def test_h1_malformed_chunked_body_does_not_raise():
    raw = (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
           b"5\r\nhello\r\nZZZ\r\n")
    flow = Flow(flow_id="h1")
    flow.response = ParseResult(protocol="HTTP/1.1", is_request=False)
    flow.chunks.append(FlowChunk(data=raw, direction="read", timestamp=0.0))
    flow._total_bytes = len(raw)
    assert flow._extract_h1_body("read") == b"hello"
