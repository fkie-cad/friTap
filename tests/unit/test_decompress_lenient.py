#!/usr/bin/env python3

"""Tests for encoding aliases, embedded-gzip search and lenient decompression."""

from __future__ import annotations

import gzip

import pytest

from friTap.parsers.decompress import (
    decompress_body,
    decompress_lenient,
    find_embedded_gzip,
)

PAYLOAD = b"hello telegram " * 40
PREFIX = b"\x01\x6d\x5c\xf3" + b"\x00" * 24  # 0x1C bytes of framing


def test_find_embedded_gzip_at_offset():
    body = PREFIX + gzip.compress(PAYLOAD) + b"trailer"
    assert find_embedded_gzip(body) == (0x1C, PAYLOAD)


def test_find_embedded_gzip_at_start():
    assert find_embedded_gzip(gzip.compress(PAYLOAD)) == (0, PAYLOAD)


def test_find_embedded_gzip_none_without_member():
    assert find_embedded_gzip(b"no gzip here at all") is None
    assert find_embedded_gzip(b"") is None


def test_find_embedded_gzip_skips_false_magic():
    body = b"\x1f\x8b\x08garbage" + PREFIX + gzip.compress(PAYLOAD)
    offset, data = find_embedded_gzip(body)
    assert data == PAYLOAD and offset == 10 + len(PREFIX)


def test_find_embedded_gzip_respects_max_out():
    assert find_embedded_gzip(PREFIX + gzip.compress(PAYLOAD), max_out=10) is None


def test_brotli_alias_maps_to_br():
    brotli = pytest.importorskip("brotli")
    assert decompress_body(brotli.compress(PAYLOAD), "brotli") == (PAYLOAD, "")


def test_x_gzip_alias_maps_to_gzip():
    assert decompress_body(gzip.compress(PAYLOAD), "x-gzip") == (PAYLOAD, "")


def test_lenient_strict_success_has_no_notes():
    assert decompress_lenient(gzip.compress(PAYLOAD), "gzip") == (PAYLOAD, [], None)


def test_lenient_embedded_gzip_note():
    member = gzip.compress(PAYLOAD)
    data, notes, error = decompress_lenient(PREFIX + member, "gzip")
    assert data == PAYLOAD and error is None
    assert notes == [f"gzip member at offset 0x1C ({len(member)}→{len(PAYLOAD)} bytes)"]


def test_lenient_gzip_without_member_is_error():
    data, notes, error = decompress_lenient(b"plain bytes", "gzip")
    assert data == b"plain bytes" and notes == []
    assert error and "no gzip member" in error


def test_lenient_unknown_encoding_is_explicit_error():
    data, notes, error = decompress_lenient(b"abc", "lzma")
    assert data == b"abc" and notes == []
    assert error == "unknown encoding: 'lzma'"


def test_lenient_brotli_alias_is_known():
    brotli = pytest.importorskip("brotli")
    assert decompress_lenient(brotli.compress(PAYLOAD), "brotli") == (PAYLOAD, [], None)


def test_http_content_encoding_path_stays_strict():
    body = PREFIX + gzip.compress(PAYLOAD)
    data, err = decompress_body(body, "gzip")
    assert data == body and err.startswith("decompress failed")
