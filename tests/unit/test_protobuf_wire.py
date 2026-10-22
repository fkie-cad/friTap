"""Tests for the schema-less protobuf wire decoder (``friTap.parsers.protobuf.wire``).

Covers the per-field helper extracted from ``_decode_raw_impl`` (behaviour must
be unchanged) and the new lenient decoder used by the TUI previews.
"""

from __future__ import annotations

import random

import pytest

from friTap.parsers.protobuf import decode_raw, decode_raw_lenient, format_message
from friTap.parsers.protobuf.wire import WireType, _decode_field_at

# field 1 varint 150, field 2 "abc", field 3 sub-message {1: 1, 2: 2}
SAMPLE = b"\x08\x96\x01\x12\x03abc\x1a\x04\x08\x01\x10\x02"


# ── decode_raw / format_message (characterization) ───────────────


def test_decode_raw_formats_nested_message():
    assert format_message(decode_raw(SAMPLE)) == (
        '1: 150\n2: "abc"\n3 {\n  1: 1 (signed: -1)\n  2: 2\n}'
    )


def test_decode_raw_packed_varints_marker():
    packed = b"\x0a\x03\x81\x01\x02"  # field 1: packed [129, 2]
    assert format_message(decode_raw(packed)) == "1: [packed] [129, 2]"


@pytest.mark.parametrize("data, message", [
    (b"\x08", "truncated varint"),
    (b"\x12\x05ab", "truncated length-delimited"),
    (b"\x00\x01", "invalid field number 0"),
    (b"\x0e\x01", "unknown wire type 6"),
    (b"\x09\x01\x02", "truncated fixed64"),
    (b"\x0d\x01", "truncated fixed32"),
])
def test_decode_raw_raises_on_malformed(data, message):
    with pytest.raises(ValueError, match=message):
        decode_raw(data)


def test_decode_raw_depth_limit_propagates():
    nested = b"\x08\x01"
    for _ in range(5):
        nested = b"\x0a" + bytes([len(nested)]) + nested
    with pytest.raises(ValueError, match="nesting depth"):
        decode_raw(nested, max_depth=3)


def test_decode_raw_skips_groups():
    # field 1 START_GROUP, inner field 2 varint 5, field 1 END_GROUP, field 3 varint 7
    data = b"\x0b\x10\x05\x0c\x18\x07"
    msg = decode_raw(data)
    assert [f.field_number for f in msg.fields] == [3]


# ── _decode_field_at ─────────────────────────────────────────────


def test_decode_field_at_returns_field_and_next_offset():
    field, offset = _decode_field_at(SAMPLE, 0, 16)
    assert (field.field_number, field.wire_type, field.varint) == (1, WireType.VARINT, 150)
    assert offset == 3
    field, offset = _decode_field_at(SAMPLE, offset, 16)
    assert field.length_delimited == b"abc" and offset == 8


def test_decode_field_at_returns_none_for_group():
    field, offset = _decode_field_at(b"\x0b\x10\x05\x0c", 0, 16)
    assert field is None and offset == 4


def test_decode_field_at_returns_none_for_stray_end_group():
    field, offset = _decode_field_at(b"\x0c", 0, 16)
    assert field is None and offset == 1


# ── decode_raw_lenient ───────────────────────────────────────────


def test_lenient_matches_strict_on_valid_input():
    msg, error = decode_raw_lenient(SAMPLE)
    assert error == ""
    assert format_message(msg) == format_message(decode_raw(SAMPLE))


def test_lenient_keeps_prefix_before_truncated_tail():
    msg, error = decode_raw_lenient(SAMPLE + b"\x22\x10partial")
    assert format_message(msg) == format_message(decode_raw(SAMPLE))
    assert error.startswith(f"decoding stopped at offset {len(SAMPLE)}:")
    assert "truncated length-delimited" in error


def test_lenient_empty_input():
    msg, error = decode_raw_lenient(b"")
    assert msg.fields == [] and error == ""


def test_lenient_garbage_reports_error_without_fields():
    msg, error = decode_raw_lenient(b"\x00\xff")
    assert msg.fields == [] and "invalid field number 0" in error


def test_lenient_depth_exceeded_is_an_error_not_an_exception():
    msg, error = decode_raw_lenient(SAMPLE, max_depth=0)
    assert msg.fields == [] and "nesting depth" in error


def test_lenient_never_raises_on_random_bytes():
    rng = random.Random(7)
    for _ in range(2000):
        data = bytes(rng.randrange(256) for _ in range(rng.randrange(40)))
        decode_raw_lenient(data)
