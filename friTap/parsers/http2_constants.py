"""Dependency-free HTTP/2 wire constants (and the frame-header decoder)
shared by the HTTP/2 parsers.

Kept as a leaf module (no HPACK, no friTap imports) so the stateless DATA
harvester and the boundary scanner can share it without importing the
HPACK-dependent :mod:`friTap.parsers.http2`.
"""

# RFC 7540 §3.5 connection preface: the 24 bytes a client sends before its
# first SETTINGS frame.
HTTP2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

# RFC 7540 §6 / RFC 9113 §6 standard frame types, by wire type byte.
HTTP2_FRAME_TYPE_NAMES: dict[int, str] = {
    0x00: "DATA",
    0x01: "HEADERS",
    0x02: "PRIORITY",
    0x03: "RST_STREAM",
    0x04: "SETTINGS",
    0x05: "PUSH_PROMISE",
    0x06: "PING",
    0x07: "GOAWAY",
    0x08: "WINDOW_UPDATE",
    0x09: "CONTINUATION",
}

# Registered extension frame types (IANA "HTTP/2 Frame Type" registry) that a
# real connection carries: RFC 7838 ALTSVC, RFC 8336 ORIGIN, RFC 9218
# PRIORITY_UPDATE. Kept apart from the standard table, whose ``<= 0x09``
# range several detectors rely on.
HTTP2_EXTENSION_FRAME_TYPE_NAMES: dict[int, str] = {
    0x0A: "ALTSVC",
    0x0C: "ORIGIN",
    0x10: "PRIORITY_UPDATE",
}

# Size of the fixed HTTP/2 frame header (RFC 9113 §4.1).
HTTP2_FRAME_HEADER_LEN = 9


def unpack_frame_header(buf, offset: int = 0) -> tuple[int, int, int, int]:
    """Decode the 9-byte frame header at *offset* in *buf*.

    Returns ``(length, frame_type, flags, stream_id)`` with the reserved
    stream-id bit masked off. *buf* may be ``bytes``, ``bytearray`` or a
    ``memoryview``; the caller guarantees ``HTTP2_FRAME_HEADER_LEN`` bytes are
    available. No validation is done.
    """
    length = int.from_bytes(buf[offset:offset + 3], "big")
    stream_id = int.from_bytes(buf[offset + 5:offset + 9], "big") & 0x7FFFFFFF
    return length, buf[offset + 3], buf[offset + 4], stream_id
