"""Stateless RFC 6455 WebSocket de-framing utilities (plugin-facing).

These are the low-level, dependency-free building blocks used by the offline
Signal decryptor (and reusable by any protocol that rides WebSocket): a frame
de-framer that walks a contiguous decrypted byte stream and yields each
complete frame's ``(opcode, payload)`` with masking honored.

Moved here from ``friTap.offline.signal.transport`` so the de-framer is a
shared, plugin-usable utility rather than Signal-locked. ``transport.py``
re-imports these names for backwards compatibility.

The companion stateful flow-level parser is
``friTap.parsers.websocket.WebSocketParser``; this module is the stateless
streaming primitive (no per-direction deflate context, no flow attachment).
"""

from __future__ import annotations

from typing import Iterator, NamedTuple


class WebSocketFrame(NamedTuple):
    """One de-framed WebSocket message (opcode + already-unmasked payload)."""

    opcode: int
    payload: bytes


def unmask(payload: bytes, mask_key: bytes) -> bytes:
    """XOR-unmask *payload* with the 4-byte *mask_key* (RFC 6455 §5.3).

    Returns *payload* unchanged when *mask_key* is empty (server->client
    frames are never masked).
    """
    if not mask_key:
        return payload
    return bytes(c ^ mask_key[i % 4] for i, c in enumerate(payload))


def looks_like_websocket_frame(buf: bytes) -> bool:
    """Cheap O(1) check that *buf* starts with a plausible WebSocket frame.

    Verifies the 2-byte minimum header: reserved bits (RSV1-3) clear and a
    known opcode. Used to distinguish DATA-derived WebSocket bytes from an
    HTTP/1.1 handshake or HTTP/2 framing at a stream's head.
    """
    if len(buf) < 2:
        return False
    b0 = buf[0]
    # RSV1-3 must be 0 (no extensions negotiated on Signal's chat socket).
    if b0 & 0x70:
        return False
    opcode = b0 & 0x0F
    # Continuation(0), text(1), binary(2), close(8), ping(9), pong(10).
    return opcode in (0x0, 0x1, 0x2, 0x8, 0x9, 0xA)


def _skip_http_handshake(stream: bytes) -> bytes:
    """Strip a leading HTTP/1.1 WebSocket upgrade handshake, if present.

    A TLS-decrypted Signal stream begins with the WebSocket HTTP handshake
    (``GET /v1/websocket/ … \\r\\n\\r\\n`` then ``HTTP/1.1 101 …\\r\\n\\r\\n``);
    the binary WebSocket framing only starts AFTER the final ``101`` response
    headers. We skip past the last handshake header block so framing aligns.
    Returns *stream* unchanged when no handshake prefix is detected.
    """
    if not stream[:8].upper().startswith((b"GET ", b"HTTP/", b"PUT ", b"POST ")):
        return stream
    # Skip every back-to-back HTTP header block (request line + 101 response).
    pos = 0
    while True:
        sep = stream.find(b"\r\n\r\n", pos)
        if sep < 0:
            return stream[pos:]
        nxt = sep + 4
        # Stop once the bytes after the header block no longer look like HTTP.
        if not stream[nxt:nxt + 5].upper().startswith((b"HTTP/", b"GET ", b"PUT ", b"POST")):
            return stream[nxt:]
        pos = nxt


def iter_websocket_frames(stream: bytes) -> Iterator[WebSocketFrame]:
    """De-frame a contiguous WebSocket byte stream (RFC 6455) into frames.

    Yields each complete frame's ``(opcode, payload)``. A leading HTTP upgrade
    handshake (the ``GET /v1/websocket`` / ``101 Switching Protocols`` exchange)
    is stripped first. FIN/continuation handling is minimal: each frame is
    yielded with its own opcode (Signal sends each ``WebSocketMessage`` as a
    single un-fragmented binary frame, so this is sufficient in practice). A
    partial trailing frame stops iteration. Masking is honored (client->server
    frames are masked).
    """
    stream = _skip_http_handshake(stream)
    pos = 0
    n = len(stream)
    while pos + 2 <= n:
        b0 = stream[pos]
        b1 = stream[pos + 1]
        opcode = b0 & 0x0F
        masked = bool(b1 & 0x80)
        length = b1 & 0x7F
        header = pos + 2
        if length == 126:
            if header + 2 > n:
                return
            length = int.from_bytes(stream[header:header + 2], "big")
            header += 2
        elif length == 127:
            if header + 8 > n:
                return
            length = int.from_bytes(stream[header:header + 8], "big")
            header += 8
        mask_key = b""
        if masked:
            if header + 4 > n:
                return
            mask_key = stream[header:header + 4]
            header += 4
        if header + length > n:
            return  # partial trailing frame
        payload = unmask(stream[header:header + length], mask_key)
        yield WebSocketFrame(opcode, payload)
        pos = header + length
