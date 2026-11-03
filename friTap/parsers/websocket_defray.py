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

Frames are validated per RFC 6455 section 5 before they are trusted: RSV bits
clear, a defined opcode, control frames unfragmented and at most 125 bytes, a
64-bit length with its most significant bit clear, and a payload of at most
:data:`MAX_FRAME_BYTES`. The first invalid frame ends iteration, exactly like
a partial trailing frame always has. RSV1 is rejected too: no caller of this
module negotiates permessage-deflate (Signal's chat socket uses no extension),
so a set RSV bit means misaligned or hostile bytes. Compressed WebSocket
traffic is handled by the stateful ``WebSocketParser`` instead.
"""

from __future__ import annotations

import logging
from typing import Iterator, List, NamedTuple, Optional, Tuple

logger = logging.getLogger(__name__)

#: Largest single frame payload accepted (same cap as
#: ``friTap.parsers.websocket``); a larger declared length is invalid.
MAX_FRAME_BYTES = 16 * 1024 * 1024

#: Largest reassembled fragmented message, and the most fragments it may span.
MAX_MESSAGE_BYTES = 16 * 1024 * 1024
MAX_MESSAGE_FRAGMENTS = 4096

_OPCODE_CONTINUATION = 0x0
_DATA_OPCODES = frozenset({0x1, 0x2})          # text, binary
_CONTROL_OPCODES = frozenset({0x8, 0x9, 0xA})  # close, ping, pong
_MAX_CONTROL_PAYLOAD = 125
_RSV_BITS = 0x70
_PAYLOAD_LEN_MSB = 1 << 63


class WebSocketFrame(NamedTuple):
    """One de-framed WebSocket message (opcode + already-unmasked payload)."""

    opcode: int
    payload: bytes


class _FrameHeader(NamedTuple):
    """A parsed RFC 6455 frame header; ``payload_start`` is a stream offset."""

    fin: bool
    rsv: int
    opcode: int
    length: int
    mask_key: bytes
    payload_start: int


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
    """De-frame a contiguous WebSocket byte stream (RFC 6455) into messages.

    Yields each complete message's ``(opcode, payload)``. A leading HTTP
    upgrade handshake (the ``GET /v1/websocket`` / ``101 Switching Protocols``
    exchange) is stripped first. Masking is honored (client->server frames are
    masked).

    A fragmented data message (a text/binary frame with FIN=0, then
    continuation frames up to the one with FIN=1) is reassembled and yielded
    ONCE, under the first frame's opcode; control frames interleaved in it are
    yielded as they arrive. Reassembly is bounded by
    :data:`MAX_MESSAGE_BYTES` and :data:`MAX_MESSAGE_FRAGMENTS`. A continuation
    frame with no message to continue (a capture that starts mid-message) is
    skipped; an unfinished message is dropped when a new data message starts
    or the stream ends. A partial trailing frame, an invalid frame (see the
    module docstring) or an over-cap message stops iteration.
    """
    for frame, _end in iter_websocket_frames_with_end(stream):
        yield frame


def iter_websocket_frames_with_end(stream: bytes) -> Iterator[Tuple[WebSocketFrame, int]]:
    """Like :func:`iter_websocket_frames`, also yielding each message's end offset.

    The offset is exclusive and relative to *stream* as passed in (a skipped
    HTTP upgrade handshake is counted), so a caller can map a message back to
    the capture bytes that completed it (for a reassembled message: the end of
    its final fragment).
    """
    stripped = _skip_http_handshake(stream)
    skipped = len(stream) - len(stripped)
    assembler = _MessageAssembler()
    for header, payload, end in _iter_valid_frames(stripped):
        message, violation = assembler.feed(header, payload)
        if violation:
            logger.debug("WebSocket de-framing stopped at offset %d: %s",
                         skipped + end, violation)
            return
        if message is not None:
            yield message, skipped + end


def _read_frame_header(stream: bytes, pos: int = 0) -> Optional[_FrameHeader]:
    """The header of the frame starting at *pos*, or ``None`` when incomplete.

    Only the header has to be present; the payload is not checked or copied.
    """
    if pos + 2 > len(stream):
        return None
    b0, b1 = stream[pos], stream[pos + 1]
    length = b1 & 0x7F
    offset = pos + 2
    if length >= 126:
        width = 2 if length == 126 else 8
        if offset + width > len(stream):
            return None
        length = int.from_bytes(stream[offset:offset + width], "big")
        offset += width
    mask_key = b""
    if b1 & 0x80:
        if offset + 4 > len(stream):
            return None
        mask_key = bytes(stream[offset:offset + 4])
        offset += 4
    return _FrameHeader(bool(b0 & 0x80), b0 & _RSV_BITS, b0 & 0x0F, length, mask_key, offset)


def _frame_violation(header: _FrameHeader) -> str:
    """Why *header* breaks RFC 6455 section 5 or the size cap; ``""`` if valid."""
    if header.rsv:
        return "RSV bits set without a negotiated extension"
    if header.length & _PAYLOAD_LEN_MSB:
        return "64-bit payload length has its most significant bit set"
    if header.length > MAX_FRAME_BYTES:
        return f"frame payload of {header.length} B exceeds {MAX_FRAME_BYTES} B"
    if header.opcode in _CONTROL_OPCODES:
        return _control_frame_violation(header)
    if header.opcode != _OPCODE_CONTINUATION and header.opcode not in _DATA_OPCODES:
        return f"reserved opcode 0x{header.opcode:X}"
    return ""


def _control_frame_violation(header: _FrameHeader) -> str:
    """RFC 6455 section 5.5: control frames are unfragmented, <= 125 bytes."""
    if header.length > _MAX_CONTROL_PAYLOAD:
        return f"control frame payload of {header.length} B exceeds {_MAX_CONTROL_PAYLOAD} B"
    if not header.fin:
        return "fragmented control frame (FIN=0)"
    return ""


def _iter_valid_frames(stream: bytes) -> Iterator[Tuple[_FrameHeader, bytes, int]]:
    """Yield ``(header, unmasked_payload, end_offset)`` per complete valid frame.

    Stops at a partial trailing frame or at the first invalid header (checked
    BEFORE its payload is sliced, so a bogus length never allocates).
    """
    pos = 0
    while True:
        header = _read_frame_header(stream, pos)
        if header is None:
            return
        violation = _frame_violation(header)
        if violation:
            logger.debug("WebSocket de-framing stopped at offset %d: %s", pos, violation)
            return
        end = header.payload_start + header.length
        if end > len(stream):
            return  # partial trailing frame
        yield header, unmask(stream[header.payload_start:end], header.mask_key), end
        pos = end


class _MessageAssembler:
    """Reassembles fragmented data messages (RFC 6455 section 5.4), bounded."""

    def __init__(self) -> None:
        self._opcode: Optional[int] = None
        self._parts: List[bytes] = []
        self._size = 0

    def feed(self, header: _FrameHeader,
             payload: bytes) -> Tuple[Optional[WebSocketFrame], str]:
        """Feed one valid frame: ``(completed message or None, violation)``."""
        if header.opcode in _CONTROL_OPCODES:
            return WebSocketFrame(header.opcode, payload), ""
        if header.opcode == _OPCODE_CONTINUATION:
            return self._continue(payload, header.fin)
        if self._opcode is not None:
            logger.debug("WebSocket: unfinished fragmented message dropped")
        self._start(header.opcode, payload)
        return (self._finish(), "") if header.fin else (None, "")

    def _start(self, opcode: int, payload: bytes) -> None:
        self._opcode, self._parts, self._size = opcode, [payload], len(payload)

    def _continue(self, payload: bytes,
                  fin: bool) -> Tuple[Optional[WebSocketFrame], str]:
        if self._opcode is None:
            return None, ""  # orphan continuation: the capture began mid-message
        self._parts.append(payload)
        self._size += len(payload)
        violation = self._cap_violation()
        if violation or not fin:
            return None, violation
        return self._finish(), ""

    def _cap_violation(self) -> str:
        if self._size > MAX_MESSAGE_BYTES:
            return f"fragmented message exceeds {MAX_MESSAGE_BYTES} B"
        if len(self._parts) > MAX_MESSAGE_FRAGMENTS:
            return f"fragmented message spans more than {MAX_MESSAGE_FRAGMENTS} frames"
        return ""

    def _finish(self) -> WebSocketFrame:
        parts = self._parts
        frame = WebSocketFrame(self._opcode, parts[0] if len(parts) == 1 else b"".join(parts))
        self._opcode, self._parts, self._size = None, [], 0
        return frame
