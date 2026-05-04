"""RFC 9000 variable-length integer encoding/decoding."""


def decode_varint(data: bytes, offset: int = 0) -> tuple[int, int]:
    """Decode a QUIC variable-length integer (RFC 9000 Section 16).

    Returns (value, bytes_consumed).
    Raises ValueError if insufficient data.
    """
    if offset >= len(data):
        raise ValueError("insufficient data for varint")
    first = data[offset]
    prefix = first >> 6  # top 2 bits
    length = 1 << prefix  # 1, 2, 4, or 8 bytes
    if offset + length > len(data):
        raise ValueError(f"need {length} bytes for varint, have {len(data) - offset}")
    value = first & 0x3F
    for i in range(1, length):
        value = (value << 8) | data[offset + i]
    return value, length


def encode_varint(value: int) -> bytes:
    """Encode an integer as a QUIC variable-length integer.

    Used primarily for testing round-trips.
    """
    if value < 0x40:
        return bytes([value])
    elif value < 0x4000:
        return bytes([0x40 | (value >> 8), value & 0xFF])
    elif value < 0x40000000:
        b = value.to_bytes(4, 'big')
        return bytes([0x80 | b[0], b[1], b[2], b[3]])
    elif value < 0x4000000000000000:
        b = value.to_bytes(8, 'big')
        return bytes([0xC0 | b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
    else:
        raise ValueError(f"value {value} too large for varint encoding")
