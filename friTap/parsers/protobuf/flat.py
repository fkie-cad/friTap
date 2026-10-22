"""Flat, schema-less protobuf field reader (top-level fields only).

A SMALL self-contained reader (varint + length-delimited + fixed32/64) with no
protobuf dependency, originally written for an offline protocol decryptor
(which still re-exports it from its transport module).

How it differs from :mod:`friTap.parsers.protobuf.wire` (deliberately kept
separate -- the two must NOT be merged):

* **flat**: only the top level of *buf* is walked; length-delimited values stay
  opaque ``bytes`` (callers re-parse nested messages themselves). ``wire``
  builds a :class:`~.wire.ProtobufMessage` tree, guessing sub-messages,
  strings and packed varints.
* **varint errors**: :func:`read_varint` accepts and rejects exactly the same
  inputs as ``wire.decode_varint`` (at most 10 bytes, no 64-bit value clamp),
  but raises with the bare messages ``"truncated varint"`` / ``"varint too
  long"`` (no offset), which callers and tests match on -- so it is kept as
  its own function rather than aliased.
* **groups**: wire types 3/4 (and the invalid 6/7) raise ``ValueError``;
  ``wire`` parses groups.
* **errors**: :func:`proto_to_dict` returns ``{}`` on ANY decode error, dropping
  the fields decoded before it; :func:`iter_proto_fields` yields fields until
  the malformed one, then raises.
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
    """Yield every top-level protobuf field in *buf*.

    Tolerant of trailing garbage only in the sense that a malformed tail raises
    ``ValueError``; callers that scan optimistically should guard for it. Group
    wire types (3/4, deprecated) are not supported and raise.
    """
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
    """Parse *buf* into ``{field_number: [values...]}`` (repeated-safe).

    Returns an empty dict on any decode failure (defensive — optimistically
    scanned data with a malformed blob should be skipped, not crash).
    """
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
