"""HTTP/3 stream model helpers (RFC 9000 2.1, RFC 9114 6.2, RFC 9204 4.2).

QUIC stream ids encode who opened a stream and whether it is bidirectional:

* bit 0x1 set   -> server-initiated, clear -> client-initiated;
* bit 0x2 set   -> unidirectional,   clear -> bidirectional.

HTTP/3 request/response exchanges live on client-initiated bidirectional
streams. Every unidirectional stream starts with a stream-type varint that
says what it carries (control, server push, QPACK encoder/decoder, or a
reserved "grease" type that must be ignored).
"""

from dataclasses import dataclass, field
from typing import Optional

from .varint import decode_varint

# Stream id bits (RFC 9000 Section 2.1)
_SERVER_INITIATED_BIT = 0x1
_UNIDIRECTIONAL_BIT = 0x2

# Unidirectional stream types (RFC 9114 6.2, RFC 9204 4.2)
UNI_STREAM_CONTROL = 0x00
UNI_STREAM_PUSH = 0x01
UNI_STREAM_QPACK_ENCODER = 0x02
UNI_STREAM_QPACK_DECODER = 0x03

# Stream kinds reported by Http3Parser.stream_kind()
KIND_REQUEST = "request"
KIND_CONTROL = "control"
KIND_QPACK_ENCODER = "qpack_encoder"
KIND_QPACK_DECODER = "qpack_decoder"
KIND_PUSH = "push"
KIND_UNKNOWN = "unknown"

_KIND_BY_UNI_TYPE = {
    UNI_STREAM_CONTROL: KIND_CONTROL,
    UNI_STREAM_PUSH: KIND_PUSH,
    UNI_STREAM_QPACK_ENCODER: KIND_QPACK_ENCODER,
    UNI_STREAM_QPACK_DECODER: KIND_QPACK_DECODER,
}

# Endpoint sides
SIDE_CLIENT = "client"
SIDE_SERVER = "server"

# SETTINGS identifiers (RFC 9114 7.2.4.1, RFC 9204 5, RFC 9220, RFC 9297)
_SETTINGS_NAMES: dict[int, str] = {
    0x01: "QPACK_MAX_TABLE_CAPACITY",
    0x06: "MAX_FIELD_SECTION_SIZE",
    0x07: "QPACK_BLOCKED_STREAMS",
    0x08: "ENABLE_CONNECT_PROTOCOL",
    0x33: "H3_DATAGRAM",
}


def is_uni(stream_id: int) -> bool:
    """True for a unidirectional QUIC stream."""
    return bool(stream_id & _UNIDIRECTIONAL_BIT)


def is_client_initiated(stream_id: int) -> bool:
    """True for a stream opened by the client."""
    return not stream_id & _SERVER_INITIATED_BIT


def initiator_side(stream_id: int) -> str:
    """``"client"`` or ``"server"``: the endpoint that opened *stream_id*."""
    return SIDE_CLIENT if is_client_initiated(stream_id) else SIDE_SERVER


def kind_for_uni_type(stream_type: Optional[int]) -> str:
    """Stream kind for a unidirectional stream type (grease/unknown -> unknown)."""
    if stream_type is None:
        return KIND_UNKNOWN
    return _KIND_BY_UNI_TYPE.get(stream_type, KIND_UNKNOWN)


@dataclass
class UniStreamState:
    """Per unidirectional stream state.

    ``stype`` is None until the stream-type varint has fully arrived; ``buf``
    holds bytes not consumed yet (type/push-id prefix or partial frames).
    ``push_id`` is set once a push stream's push id has been read.
    """

    stype: Optional[int] = None
    buf: bytearray = field(default_factory=bytearray)
    push_id: Optional[int] = None
    settings_seen: bool = False


def parse_settings(payload: bytes) -> dict[int, int]:
    """Decode a SETTINGS frame payload into ``{identifier: value}``.

    A truncated trailing pair is ignored rather than raising.
    """
    settings: dict[int, int] = {}
    offset = 0
    while offset < len(payload):
        try:
            identifier, id_len = decode_varint(payload, offset)
            value, value_len = decode_varint(payload, offset + id_len)
        except (ValueError, IndexError):
            break
        settings[identifier] = value
        offset += id_len + value_len
    return settings


def setting_name(identifier: int) -> str:
    """Registered SETTINGS name, or the hex identifier for unknown/grease ones."""
    return _SETTINGS_NAMES.get(identifier, f"0x{identifier:x}")


def settings_to_headers(settings: dict[int, int]) -> dict[str, str]:
    """Render decoded SETTINGS as a name -> value string dict for display."""
    return {setting_name(identifier): str(value)
            for identifier, value in settings.items()}
