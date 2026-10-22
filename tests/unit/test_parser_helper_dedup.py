"""Shared parser helpers: one HTTP/2 preface, unambiguous varint names, and the
generic bounded inflater. Old names must stay bound to the SAME objects."""

from __future__ import annotations

import gzip
import zlib

import pytest

import friTap.parsers as parsers
from friTap.offline.mtproto import content as mtproto_content
from friTap.offline.mtproto.tl import decoder as tl_decoder
from friTap.parsers import boundary_scan, decompress, http2, http2_dataframe, varint
from friTap.parsers.http2_constants import HTTP2_PREFACE
from friTap.parsers.protobuf import wire


def test_http2_preface_is_one_canonical_object():
    assert HTTP2_PREFACE == b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    assert len(HTTP2_PREFACE) == 24
    assert http2_dataframe.HTTP2_PREFACE is HTTP2_PREFACE
    assert http2._CONNECTION_PREFACE is HTTP2_PREFACE
    assert boundary_scan._H2_PREFACE is HTTP2_PREFACE
    assert parsers.HTTP2_PREFACE is HTTP2_PREFACE


def test_varint_aliases_are_the_same_functions():
    assert varint.decode_quic_varint is varint.decode_varint
    assert wire.decode_protobuf_varint is wire.decode_varint
    assert parsers.decode_quic_varint is varint.decode_varint
    assert parsers.decode_varint is varint.decode_varint  # legacy name = QUIC
    assert parsers.decode_protobuf_varint is wire.decode_varint
    from friTap.parsers import protobuf
    assert protobuf.decode_protobuf_varint is wire.decode_varint
    assert protobuf.decode_varint is wire.decode_varint


def test_varint_semantics_differ():
    # 0x40 0x25: QUIC 2-byte varint 37; protobuf reads one byte (0x40 = 64).
    assert varint.decode_quic_varint(b"\x40\x25") == (37, 2)
    assert wire.decode_protobuf_varint(b"\xac\x02", 0) == (300, 2)


def test_inflate_bounded_reexported_from_tl_decoder():
    assert tl_decoder.inflate_bounded is decompress.inflate_bounded
    assert tl_decoder.InflateLimitError is decompress.InflateLimitError
    assert mtproto_content.inflate_bounded is decompress.inflate_bounded
    assert tl_decoder.MAX_INFLATE == decompress.MAX_INFLATE == 16 * 1024 * 1024
    assert issubclass(decompress.InflateLimitError, ValueError)


@pytest.mark.parametrize("compress", [gzip.compress, zlib.compress])
def test_inflate_bounded_round_trip_and_limit(compress):
    packed = compress(b"A" * 1000)
    assert decompress.inflate_bounded(packed) == b"A" * 1000
    assert decompress.inflate_bounded(packed, 1000) == b"A" * 1000
    with pytest.raises(decompress.InflateLimitError, match="^inflate exceeds 999 B limit$"):
        decompress.inflate_bounded(packed, 999)


def test_inflate_bounded_corrupt_raises_zlib_error():
    with pytest.raises(zlib.error):
        decompress.inflate_bounded(b"\x1f\x8b\x08garbage")
