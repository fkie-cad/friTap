"""Characterization tests for the flat, schema-less protobuf reader.

The expectations below were generated against the ORIGINAL implementation
before it moved to ``friTap.parsers.protobuf.flat``; they pin its exact
semantics (varint limit, error messages, group wire types, ``{}`` on any
decode error).
"""

from __future__ import annotations

import pytest

from friTap.parsers.protobuf import flat

MODULES = [flat]

_MAX_U64 = 18446744073709551615

# (input, expected iter_proto_fields tuples OR error message, expected proto_to_dict)
CASES = {
    "empty": (b"", [], {}),
    "truncated_tag_varint": (b"\x80", "truncated varint", {}),
    "ten_byte_value": (b"\x08" + b"\xff" * 9 + b"\x01", [(1, 0, _MAX_U64)], {1: [_MAX_U64]}),
    "eleven_byte_value": (b"\x08" + b"\xff" * 10 + b"\x01", "varint too long", {}),
    "ten_byte_tag_is_wire_type_7": (b"\xff" * 9 + b"\x01", "unsupported protobuf wire type 7", {}),
    "wire_type_3": (b"\x0b", "unsupported protobuf wire type 3", {}),
    "wire_type_4": (b"\x0c", "unsupported protobuf wire type 4", {}),
    "wire_type_6": (b"\x0e", "unsupported protobuf wire type 6", {}),
    "wire_type_7": (b"\x0f", "unsupported protobuf wire type 7", {}),
    "length_overflow": (b"\n\x05ab", "truncated length-delimited field", {}),
    "length_varint_overflow": (b"\n" + b"\xff" * 9 + b"\x01", "truncated length-delimited field", {}),
    "length_exact": (b"\n\x02ab", [(1, 2, b"ab")], {1: [b"ab"]}),
    "fixed64_truncated": (b"\t" + b"\x01" * 7, "truncated fixed64", {}),
    "fixed64": (b"\t" + bytes(range(1, 9)), [(1, 1, 578437695752307201)], {1: [578437695752307201]}),
    "fixed32_truncated": (b"\r\x01\x01\x01", "truncated fixed32", {}),
    "fixed32": (b"\r\x01\x02\x03\x04", [(1, 5, 67305985)], {1: [67305985]}),
    "field_number_zero": (b"\x00\x05", [(0, 0, 5)], {0: [5]}),
    "nested_left_opaque": (
        b"\n\x03\x08\x96\x01\x10\x07",
        [(1, 2, b"\x08\x96\x01"), (2, 0, 7)],
        {1: [b"\x08\x96\x01"], 2: [7]},
    ),
    "repeated_mixed": (
        b"\x08\x01\x08\x02\x12\x01x",
        [(1, 0, 1), (1, 0, 2), (2, 2, b"x")],
        {1: [1, 2], 2: [b"x"]},
    ),
    "bad_tail_discards_all": (b"\x08\x01\x0f", "unsupported protobuf wire type 7", {}),
}


@pytest.mark.parametrize("mod", MODULES, ids=lambda m: m.__name__)
@pytest.mark.parametrize("name", sorted(CASES))
def test_iter_proto_fields_and_proto_to_dict(mod, name):
    data, expected_iter, expected_dict = CASES[name]
    if isinstance(expected_iter, str):
        with pytest.raises(ValueError, match=f"^{expected_iter}$"):
            list(mod.iter_proto_fields(data))
    else:
        assert [tuple(f) for f in mod.iter_proto_fields(data)] == expected_iter
    assert mod.proto_to_dict(data) == expected_dict


@pytest.mark.parametrize("mod", MODULES, ids=lambda m: m.__name__)
def test_iter_yields_fields_before_the_error(mod):
    gen = mod.iter_proto_fields(b"\x08\x01\x0b")
    assert tuple(next(gen)) == (1, 0, 1)
    with pytest.raises(ValueError, match="unsupported protobuf wire type 3"):
        next(gen)


@pytest.mark.parametrize(
    "data, expected",
    [
        (b"\xac\x02", (300, 2)),
        (b"\xff" * 9 + b"\x01", (_MAX_U64, 10)),
        (b"\xff" * 9 + b"\x7f", (1180591620717411303423, 10)),  # no value clamp
        (b"\x80", "truncated varint"),
        (b"\xff" * 10 + b"\x01", "varint too long"),
    ],
)
def test_read_varint(data, expected):
    if isinstance(expected, str):
        with pytest.raises(ValueError, match=f"^{expected}$"):
            flat.read_varint(data, 0)
    else:
        assert flat.read_varint(data, 0) == expected


def test_nested_decode_and_first_bytes():
    outer = flat.proto_to_dict(b"\n\x03\x08\x96\x01")
    assert flat.proto_to_dict(flat.first_bytes(outer, 1)) == {1: [150]}
    assert flat.first_bytes({1: [bytearray(b"x")]}, 1) == bytearray(b"x")
    assert flat.first_bytes({1: []}, 1) is None
    assert flat.first_bytes({1: [5, b"a"]}, 1) is None  # first value only


def test_first_int_and_first_str():
    fields = {1: [7, 8], 2: [b"hi", b"x"], 3: [b"\xff"], 4: [b"raw"], 5: []}
    assert flat.first_int(fields, 1) == 7
    assert flat.first_int(fields, 4) == 0  # bytes, not a varint
    assert flat.first_int(fields, 5) == 0 and flat.first_int(fields, 9) == 0
    assert flat.first_str(fields, 2) == "hi"
    assert flat.first_str(fields, 3) == "�"
    assert flat.first_str(fields, 1) == "" and flat.first_str(fields, 9) == ""
