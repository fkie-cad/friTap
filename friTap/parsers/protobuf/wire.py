"""Schema-less protobuf wire format decoder.

Pure Python implementation with zero external dependencies.
Equivalent to ``protoc --decode_raw``.

Usage::

    from friTap.parsers.protobuf.wire import decode_raw, format_message

    msg = decode_raw(b"\\x08\\x96\\x01")
    print(format_message(msg))
    # 1: 150
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional


_TEXT_PREFIXES = (
    b"HTTP/", b"GET ", b"POST ", b"PUT ", b"DELETE ", b"PATCH ", b"HEAD ",
    b"OPTIONS ", b"CONNECT ", b"{", b"[", b"<", b"<!DOCTYPE", b"<?XML",
)
_TEXT_PREFIXES_UPPER = tuple(p.upper() for p in _TEXT_PREFIXES)


class WireType(IntEnum):
    """Protobuf wire types (3-bit tag suffix)."""
    VARINT = 0
    FIXED64 = 1
    LENGTH_DELIMITED = 2
    START_GROUP = 3
    END_GROUP = 4
    FIXED32 = 5


@dataclass
class ProtobufField:
    """A single decoded protobuf field."""
    field_number: int
    wire_type: WireType
    raw_value: bytes
    varint: Optional[int] = None
    fixed32: Optional[bytes] = None
    fixed64: Optional[bytes] = None
    length_delimited: Optional[bytes] = None
    sub_message: Optional[ProtobufMessage] = None
    packed_varints: Optional[list[int]] = None


@dataclass
class ProtobufMessage:
    """A decoded protobuf message (tree of fields)."""
    fields: list[ProtobufField] = field(default_factory=list)


def decode_varint(data: bytes, offset: int) -> tuple[int, int]:
    """Decode a base-128 varint starting at *offset*.

    Returns ``(value, new_offset)``.
    Raises :class:`ValueError` on truncation or >10 bytes.
    """
    result = 0
    shift = 0
    start = offset
    while True:
        if offset >= len(data):
            raise ValueError(f"truncated varint at offset {start}")
        byte = data[offset]
        offset += 1
        result |= (byte & 0x7F) << shift
        shift += 7
        if not (byte & 0x80):
            break
        if shift >= 70:  # 10 bytes max
            raise ValueError(f"varint exceeds 10-byte limit at offset {start}")
    return result, offset


def _zigzag_decode(value: int) -> int:
    """Decode a ZigZag-encoded signed integer."""
    return (value >> 1) ^ -(value & 1)


def _try_decode_submessage(data: bytes, max_depth: int) -> Optional[ProtobufMessage]:
    """Attempt to parse *data* as a nested protobuf message.

    Returns ``None`` if the data does not look like valid protobuf.
    Raises ``ValueError`` if *max_depth* is exceeded (propagated to caller).
    """
    if not data:
        return None
    if max_depth <= 0:
        raise ValueError("maximum nesting depth exceeded")
    try:
        msg = _decode_raw_impl(data, max_depth)
        if not msg.fields:
            return None
        return msg
    except ValueError as exc:
        if "nesting depth" in str(exc):
            raise  # propagate depth limit errors
        return None
    except IndexError:
        return None


def _looks_like_utf8_string(data: bytes) -> bool:
    """Check if *data* is likely a UTF-8 string (printable or common whitespace)."""
    if not data:
        return False
    try:
        text = data.decode("utf-8")
        return all(c.isprintable() or c in "\n\r\t " for c in text)
    except (UnicodeDecodeError, ValueError):
        return False


def _try_decode_packed_varints(data: bytes) -> Optional[list[int]]:
    """Attempt to parse *data* as packed repeated varints.

    Returns a list of integers if the entire buffer is consumed,
    otherwise ``None``.  Rejects data that looks like a UTF-8 string
    since printable ASCII bytes are also valid single-byte varints.
    """
    if not data:
        return None
    # Prefer string interpretation for printable text
    if _looks_like_utf8_string(data):
        return None
    values: list[int] = []
    offset = 0
    try:
        while offset < len(data):
            val, offset = decode_varint(data, offset)
            values.append(val)
    except ValueError:
        return None
    if offset != len(data):
        return None
    if len(values) < 2:
        return None
    return values


def _decode_raw_impl(data: bytes, max_depth: int) -> ProtobufMessage:
    """Internal recursive decoder."""
    if max_depth <= 0:
        raise ValueError("maximum nesting depth exceeded")

    fields: list[ProtobufField] = []
    offset = 0
    length = len(data)

    while offset < length:
        tag, offset = decode_varint(data, offset)
        wire_type_val = tag & 0x07
        field_number = tag >> 3

        if field_number == 0:
            raise ValueError(f"invalid field number 0 at offset {offset}")

        try:
            wire_type = WireType(wire_type_val)
        except ValueError:
            raise ValueError(
                f"unknown wire type {wire_type_val} at offset {offset}"
            )

        pf = ProtobufField(
            field_number=field_number,
            wire_type=wire_type,
            raw_value=b"",
        )

        if wire_type == WireType.VARINT:
            value_start = offset
            value, offset = decode_varint(data, offset)
            pf.varint = value
            pf.raw_value = data[value_start:offset]

        elif wire_type == WireType.FIXED64:
            if offset + 8 > length:
                raise ValueError(f"truncated fixed64 at offset {offset}")
            pf.fixed64 = data[offset:offset + 8]
            pf.raw_value = pf.fixed64
            offset += 8

        elif wire_type == WireType.FIXED32:
            if offset + 4 > length:
                raise ValueError(f"truncated fixed32 at offset {offset}")
            pf.fixed32 = data[offset:offset + 4]
            pf.raw_value = pf.fixed32
            offset += 4

        elif wire_type == WireType.LENGTH_DELIMITED:
            payload_len, offset = decode_varint(data, offset)
            if offset + payload_len > length:
                raise ValueError(
                    f"truncated length-delimited field at offset {offset}, "
                    f"need {payload_len} bytes but only {length - offset} remain"
                )
            payload = data[offset:offset + payload_len]
            pf.length_delimited = payload
            pf.raw_value = payload
            offset += payload_len

            sub = _try_decode_submessage(payload, max_depth - 1)
            if sub is not None:
                pf.sub_message = sub
            else:
                packed = _try_decode_packed_varints(payload)
                if packed is not None:
                    pf.packed_varints = packed

        elif wire_type == WireType.START_GROUP:
            # Deprecated: skip until matching END_GROUP
            depth = 1
            group_start = offset
            while depth > 0 and offset < length:
                inner_tag, offset = decode_varint(data, offset)
                inner_wt = inner_tag & 0x07
                if inner_wt == WireType.START_GROUP:
                    depth += 1
                elif inner_wt == WireType.END_GROUP:
                    depth -= 1
                elif inner_wt == WireType.VARINT:
                    _, offset = decode_varint(data, offset)
                elif inner_wt == WireType.FIXED64:
                    offset += 8
                elif inner_wt == WireType.FIXED32:
                    offset += 4
                elif inner_wt == WireType.LENGTH_DELIMITED:
                    plen, offset = decode_varint(data, offset)
                    offset += plen
            pf.raw_value = data[group_start:offset]
            continue  # skip adding to fields

        elif wire_type == WireType.END_GROUP:
            # Should only appear inside group processing
            continue

        fields.append(pf)

    return ProtobufMessage(fields=fields)


def _varint_byte_len(value: int) -> int:
    """Return the number of bytes a varint occupies."""
    if value == 0:
        return 1
    length = 0
    while value > 0:
        value >>= 7
        length += 1
    return length


def decode_raw(data: bytes, max_depth: int = 16) -> ProtobufMessage:
    """Decode raw protobuf wire format without a schema.

    Recursively attempts sub-message parsing for ``LENGTH_DELIMITED`` fields.

    Args:
        data: Raw protobuf bytes.
        max_depth: Maximum nesting depth (default 16).

    Returns:
        A :class:`ProtobufMessage` tree.

    Raises:
        ValueError: If the data is malformed.
    """
    if not data:
        return ProtobufMessage()
    return _decode_raw_impl(data, max_depth)


def _format_bytes_as_string_or_hex(data: bytes) -> str:
    """Try UTF-8 decode; fall back to hex representation."""
    try:
        text = data.decode("utf-8")
        if all(c.isprintable() or c in "\n\r\t" for c in text):
            return f'"{text}"'
    except (UnicodeDecodeError, ValueError):
        pass
    if len(data) <= 64:
        return data.hex()
    return f"{data[:32].hex()}...({len(data)} bytes)"


def format_message(msg: ProtobufMessage, indent: int = 0) -> str:
    """Format a :class:`ProtobufMessage` as human-readable indented text.

    Output resembles ``protoc --decode_raw``.
    """
    lines: list[str] = []
    prefix = "  " * indent

    for f in msg.fields:
        if f.wire_type == WireType.VARINT and f.varint is not None:
            zigzag = _zigzag_decode(f.varint)
            if zigzag != f.varint and zigzag < 0:
                lines.append(f"{prefix}{f.field_number}: {f.varint} (signed: {zigzag})")
            else:
                lines.append(f"{prefix}{f.field_number}: {f.varint}")

        elif f.wire_type == WireType.FIXED64 and f.fixed64 is not None:
            as_double = struct.unpack("<d", f.fixed64)[0]
            as_uint64 = struct.unpack("<Q", f.fixed64)[0]
            as_int64 = struct.unpack("<q", f.fixed64)[0]
            lines.append(
                f"{prefix}{f.field_number}: 0x{f.fixed64.hex()} "
                f"(uint64: {as_uint64}, int64: {as_int64}, double: {as_double})"
            )

        elif f.wire_type == WireType.FIXED32 and f.fixed32 is not None:
            as_float = struct.unpack("<f", f.fixed32)[0]
            as_uint32 = struct.unpack("<I", f.fixed32)[0]
            as_int32 = struct.unpack("<i", f.fixed32)[0]
            lines.append(
                f"{prefix}{f.field_number}: 0x{f.fixed32.hex()} "
                f"(uint32: {as_uint32}, int32: {as_int32}, float: {as_float})"
            )

        elif f.wire_type == WireType.LENGTH_DELIMITED:
            if f.sub_message is not None:
                lines.append(f"{prefix}{f.field_number} {{")
                lines.append(format_message(f.sub_message, indent + 1))
                lines.append(f"{prefix}}}")
            elif f.packed_varints is not None:
                vals = ", ".join(str(v) for v in f.packed_varints)
                lines.append(f"{prefix}{f.field_number}: [packed] [{vals}]")
            elif f.length_delimited is not None:
                lines.append(
                    f"{prefix}{f.field_number}: "
                    f"{_format_bytes_as_string_or_hex(f.length_delimited)}"
                )

    return "\n".join(lines)


def is_likely_protobuf(data: bytes) -> bool:
    """Heuristic check whether *data* looks like protobuf wire format.

    Checks that the first byte forms a valid tag with a reasonable
    field number and known wire type, and that the message can be
    partially parsed without error.  Rejects data that starts with
    common text protocol signatures (HTTP, JSON, XML, HTML).
    """
    if not data or len(data) < 2:
        return False

    # Reject common text protocols early
    for prefix in _TEXT_PREFIXES_UPPER:
        if data[:len(prefix)].upper() == prefix:
            return False

    # Reject if the majority of bytes are printable ASCII
    if len(data) >= 8:
        printable_count = sum(1 for b in data[:64] if 0x20 <= b <= 0x7E)
        if printable_count / min(len(data), 64) > 0.85:
            return False

    try:
        tag, offset = decode_varint(data, 0)
        wire_type_val = tag & 0x07
        field_number = tag >> 3
        if field_number == 0 or field_number > 536870911:  # max 29-bit field number
            return False
        if wire_type_val > 5:
            return False
        # Try parsing at least the first few fields
        msg = _decode_raw_impl(data[:min(len(data), 512)], max_depth=4)
        return len(msg.fields) >= 1
    except (ValueError, IndexError):
        return False
