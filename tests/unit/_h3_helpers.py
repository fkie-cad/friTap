"""Shared HTTP/3 + QPACK byte builders for parser/collector tests.

All QPACK blocks are produced by the real pylsqpack Encoder, so tests exercise
exactly what a peer would put on the wire.
"""

from friTap.parsers.varint import encode_varint

# RFC 9114 / RFC 9204 unidirectional stream types
UNI_CONTROL = 0x00
UNI_PUSH = 0x01
UNI_QPACK_ENCODER = 0x02
UNI_QPACK_DECODER = 0x03

FRAME_DATA = 0x00
FRAME_HEADERS = 0x01
FRAME_SETTINGS = 0x04

SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0x01
SETTINGS_MAX_FIELD_SECTION_SIZE = 0x06
SETTINGS_QPACK_BLOCKED_STREAMS = 0x07


def h3_frame(frame_type: int, payload: bytes) -> bytes:
    """One HTTP/3 frame: varint type, varint length, payload."""
    return encode_varint(frame_type) + encode_varint(len(payload)) + payload


def settings_payload(settings: dict[int, int]) -> bytes:
    """SETTINGS frame payload: (varint id, varint value) pairs."""
    return b"".join(encode_varint(k) + encode_varint(v) for k, v in settings.items())


def uni_stream(stream_type: int, *frames: bytes) -> bytes:
    """A unidirectional stream: varint stream type followed by *frames*."""
    return encode_varint(stream_type) + b"".join(frames)


def control_stream_bytes() -> bytes:
    """A realistic client control stream (type 0x00 + SETTINGS)."""
    return uni_stream(UNI_CONTROL, h3_frame(FRAME_SETTINGS, settings_payload({
        SETTINGS_QPACK_MAX_TABLE_CAPACITY: 65536,
        SETTINGS_MAX_FIELD_SECTION_SIZE: 262144,
        SETTINGS_QPACK_BLOCKED_STREAMS: 100,
    })))


def qpack_encoder(capacity: int = 0, blocked: int = 0):
    """Return (encoder, preamble). capacity=0 keeps it static-table only.

    The preamble is the encoder-stream bytes produced by apply_settings (empty
    when no dynamic table is configured).
    """
    import pylsqpack

    encoder = pylsqpack.Encoder()
    preamble = encoder.apply_settings(capacity, blocked) if capacity else b""
    return encoder, preamble


def headers_frame(encoder, stream_id: int, headers) -> tuple[bytes, bytes]:
    """Encode *headers* ([(bytes, bytes)]) -> (encoder_stream_bytes, HEADERS frame)."""
    encoder_bytes, block = encoder.encode(stream_id, list(headers))
    return encoder_bytes, h3_frame(FRAME_HEADERS, block)


def settings_stream(capacity: int, blocked: int = 16) -> bytes:
    """A control stream whose SETTINGS size the peer's QPACK dynamic table."""
    return uni_stream(UNI_CONTROL, h3_frame(FRAME_SETTINGS, settings_payload({
        SETTINGS_QPACK_MAX_TABLE_CAPACITY: capacity,
        SETTINGS_QPACK_BLOCKED_STREAMS: blocked,
    })))


def dynamic_exchange(stream_ids, headers, capacity: int = 4096, blocked: int = 16):
    """Encode *headers* on every stream with a dynamic table.

    Repeating the same fields makes pylsqpack insert them and reference the
    dynamic table from the second/third stream on. *headers* is one list for
    every stream or a ``{stream_id: list}`` dict. Returns
    ``(encoder_stream_bytes, {stream_id: raw header block})``; the encoder
    bytes start with the Set Dynamic Table Capacity preamble.
    """
    encoder, encoder_bytes = qpack_encoder(capacity, blocked)
    blocks = {}
    for stream_id in stream_ids:
        fields = headers[stream_id] if isinstance(headers, dict) else headers
        inserts, block = encoder.encode(stream_id, list(fields))
        encoder_bytes += inserts
        blocks[stream_id] = block
    return encoder_bytes, blocks
