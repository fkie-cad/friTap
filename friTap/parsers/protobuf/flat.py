"""Flat, schema-less protobuf field reader (top-level fields only).

A small self-contained reader (varint, length-delimited, fixed32/64) with no
protobuf dependency. Deliberately separate from :mod:`friTap.parsers.protobuf.wire`:

* flat: only the top level; length-delimited values stay opaque ``bytes``.
  ``wire`` builds a tree, guessing sub-messages, strings and packed varints.
* varint errors: :func:`read_varint` accepts the same inputs as ``wire.decode_varint``
  but raises the bare ``"truncated varint"`` / ``"varint too long"`` that callers
  and tests match on, so it is not aliased.
* groups: wire types 3/4 (and invalid 6/7) raise ``ValueError``; ``wire`` parses groups.
* errors: :func:`proto_to_dict` returns ``{}`` on ANY decode error;
  :func:`iter_proto_fields` yields fields until the malformed one, then raises.
"""

from __future__ import annotations

from typing import Dict, Iterator, List, NamedTuple, Optional, Tuple

# Protobuf wire types.
WIRE_VARINT = 0
WIRE_FIXED64 = 1
WIRE_LEN = 2
WIRE_FIXED32 = 5


class ProtoField(NamedTuple):
    """One decoded protobuf field on the wire."""

    number: int
    wire_type: int
    value: object  # int (varint/fixed) or bytes (length-delimited)


def read_varint(buf: bytes, pos: int) -> Tuple[int, int]:
    """Read a base-128 varint starting at *pos*; return ``(value, new_pos)``."""
    # Same 10-byte limit as wire.decode_varint, but tests pin these bare error messages.
    result = 0
    shift = 0
    while True:
        if pos >= len(buf):
            raise ValueError("truncated varint")
        byte = buf[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            break
        shift += 7
        if shift > 63:
            raise ValueError("varint too long")
    return result, pos


def iter_proto_fields(buf: bytes) -> Iterator[ProtoField]:
    """Yield every top-level field in *buf*; a malformed tail or a group wire type raises ``ValueError`` (guard when scanning optimistically)."""
    pos = 0
    n = len(buf)
    while pos < n:
        tag, pos = read_varint(buf, pos)
        field_number = tag >> 3
        wire_type = tag & 0x07
        if wire_type == WIRE_VARINT:
            value, pos = read_varint(buf, pos)
            yield ProtoField(field_number, wire_type, value)
        elif wire_type == WIRE_FIXED64:
            if pos + 8 > n:
                raise ValueError("truncated fixed64")
            yield ProtoField(field_number, wire_type, int.from_bytes(buf[pos:pos + 8], "little"))
            pos += 8
        elif wire_type == WIRE_LEN:
            length, pos = read_varint(buf, pos)
            if pos + length > n:
                raise ValueError("truncated length-delimited field")
            yield ProtoField(field_number, wire_type, buf[pos:pos + length])
            pos += length
        elif wire_type == WIRE_FIXED32:
            if pos + 4 > n:
                raise ValueError("truncated fixed32")
            yield ProtoField(field_number, wire_type, int.from_bytes(buf[pos:pos + 4], "little"))
            pos += 4
        else:
            raise ValueError(f"unsupported protobuf wire type {wire_type}")


def proto_to_dict(buf: bytes) -> Dict[int, List[object]]:
    """Parse *buf* into ``{field_number: [values...]}``; ``{}`` on any decode failure so optimistic scans skip bad blobs."""
    out: Dict[int, List[object]] = {}
    try:
        for field in iter_proto_fields(buf):
            out.setdefault(field.number, []).append(field.value)
    except ValueError:
        return {}
    return out


def first_bytes(fields: Dict[int, List[object]], number: int) -> Optional[bytes]:
    """Return the first ``bytes`` value for *number*, or ``None``."""
    values = fields.get(number)
    if not values:
        return None
    value = values[0]
    return value if isinstance(value, (bytes, bytearray)) else None


def first_int(fields: Dict[int, List[object]], number: int) -> int:
    """First varint value for *number* as int, or 0."""
    values = fields.get(number)
    if not values:
        return 0
    value = values[0]
    return value if isinstance(value, int) else 0


def first_str(fields: Dict[int, List[object]], number: int) -> str:
    """First length-delimited value for *number* decoded as UTF-8, or ""."""
    raw = first_bytes(fields, number)
    if raw is None:
        return ""
    try:
        return raw.decode("utf-8", errors="replace")
    except Exception:
        return ""
