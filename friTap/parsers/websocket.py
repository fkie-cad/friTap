"""Lightweight WebSocket frame parser (RFC 6455).

Detection is O(1) — only the first 2 bytes are checked.
``feed()`` extracts the frame header (opcode, payload length) and sets
*protocol* / *method* on the ParseResult so the flow list shows
``WS  PING``, ``WS  TEXT``, etc.  Masked payloads (client→server per
RFC 6455) are unmasked eagerly so the body is always readable.

Trailing data detection: when valid frames don't consume the entire buffer,
the parser detects unconsumed bytes, identifies their protocol (e.g. HTTP),
and optionally sub-parses them.  Results are stored on the parser instance
and propagated to the Flow by the collector.
"""

from __future__ import annotations

import zlib
from typing import Optional

from friTap.constants import PROTOCOL_WEBSOCKET
from .base import BaseParser, ParseResult


# RFC 6455 § 11.8 — opcode names
_OPCODE_NAMES: dict[int, str] = {
    0x0: "CONT",
    0x1: "TEXT",
    0x2: "BIN",
    0x8: "CLOSE",
    0x9: "PING",
    0xA: "PONG",
}

_VALID_OPCODES = frozenset(_OPCODE_NAMES)

# RFC 7692 — permessage-deflate sync flush trailer appended before decompression
_DEFLATE_TAIL = b"\x00\x00\xff\xff"

# Maximum accumulated fragment size before discarding (prevents memory exhaustion)
_MAX_FRAGMENT_BYTES = 16 * 1024 * 1024  # 16 MB


class _DeflateContext:
    """Per-direction permessage-deflate decompression state (RFC 7692).

    Optimistically reuses the zlib decompressor across messages (context-takeover).
    Falls back to a fresh decompressor if reuse fails (no_context_takeover).
    """

    def __init__(self) -> None:
        self._dec: zlib.decompressobj | None = None

    def decompress(self, payload: bytes) -> tuple[bytes, bool]:
        """Decompress a permessage-deflate payload.

        Returns ``(data, was_decompressed)``.  On failure returns
        ``(original_payload, False)`` so the caller can display raw data.
        """
        raw = payload + _DEFLATE_TAIL

        # Try persistent context first (context-takeover mode)
        if self._dec is not None:
            try:
                return self._dec.decompress(raw), True
            except zlib.error:
                self._dec = None

        # Try fresh decompressor
        try:
            dec = zlib.decompressobj(-zlib.MAX_WBITS)
            result = dec.decompress(raw)
            self._dec = dec  # save for reuse
            return result, True
        except zlib.error:
            return payload, False


def _is_websocket_frame(data: bytes) -> bool:
    """Check if *data* starts with a plausible WebSocket frame header.

    Only inspects the first 2 bytes — O(1).

    Validation rules (RFC 6455):
    * Opcode must be a known value (0x0–0x2, 0x8–0xA).
    * RSV2 and RSV3 must be 0 (RSV1 is allowed for per-message compression,
      RFC 7692).  This rejects ASCII bytes like ``P`` (0x50) that happen to
      have opcode 0x0 but set reserved bits.
    * Control frames (opcode ≥ 0x8) must have FIN set and payload ≤ 125.
    """
    if len(data) < 2:
        return False

    first = data[0]
    opcode = first & 0x0F

    if opcode not in _VALID_OPCODES:
        return False

    # RSV2 (0x20) and RSV3 (0x10) must be zero
    if first & 0x30:
        return False

    # Control frames (opcode >= 0x8) MUST have FIN set and payload ≤ 125
    if opcode >= 0x8:
        if not (first & 0x80):       # FIN bit required
            return False
        payload_len = data[1] & 0x7F
        if payload_len > 125:        # control frame max
            return False

    return True


def _parse_frame_header(data: bytes) -> tuple[int, bool, bool, bool, int, int, bytes] | None:
    """Parse the WebSocket frame header.

    Returns ``(opcode, fin, rsv1, masked, payload_length, header_size, mask_key)``
    or ``None`` if *data* is too short.  *rsv1* indicates per-message
    compression (RFC 7692).  *mask_key* is ``b""`` for unmasked frames
    and 4 bytes for masked frames.
    """
    if len(data) < 2:
        return None

    first = data[0]
    second = data[1]

    fin = bool(first & 0x80)
    rsv1 = bool(first & 0x40)
    opcode = first & 0x0F
    masked = bool(second & 0x80)
    payload_len = second & 0x7F
    header_size = 2

    if payload_len == 126:
        if len(data) < 4:
            return None
        payload_len = int.from_bytes(data[2:4], "big")
        header_size = 4
    elif payload_len == 127:
        if len(data) < 10:
            return None
        payload_len = int.from_bytes(data[2:10], "big")
        header_size = 10

    mask_key = b""
    if masked:
        mask_start = header_size
        if len(data) < mask_start + 4:
            return None
        mask_key = data[mask_start:mask_start + 4]
        header_size += 4

    return opcode, fin, rsv1, masked, payload_len, header_size, mask_key


def unmask_payload(data: bytes, mask_key: bytes) -> bytes:
    """XOR-unmask a WebSocket payload.  Cheap O(n) operation."""
    if len(mask_key) != 4:
        return data
    n = len(data)
    mask = mask_key * ((n + 3) // 4)
    return bytes(a ^ b for a, b in zip(data, mask))


def _is_websocket_data(data: bytes) -> bool:
    """Stricter WebSocket detection for standalone protocol identification.

    Requires at least one complete frame fitting in the buffer.
    If enough data exists for a second frame, requires it to also be valid
    (only for data frames — control frames commonly have trailing non-WS data).
    """
    if not _is_websocket_frame(data):
        return False

    hdr = _parse_frame_header(data)
    if hdr is None:
        return False

    opcode, _fin, _rsv1, _masked, payload_len, header_size, _mask_key = hdr
    frame_end = header_size + payload_len

    # Complete frame must fit in the buffer
    if frame_end > len(data):
        return False

    # For data frames (TEXT/BIN/CONT), if enough data for a second frame
    # header, require it to also be valid. Control frames (PING/PONG/CLOSE)
    # commonly appear with trailing non-WebSocket data, so skip this check.
    if opcode < 0x8 and frame_end + 2 <= len(data):
        if not _is_websocket_frame(data[frame_end:]):
            return False

    return True


def _detect_json(payload: bytes) -> str:
    """Return ``"application/json"`` if *payload* is valid JSON, else ``""``."""
    stripped = payload.lstrip()
    if not stripped or stripped[0:1] not in (b'{', b'['):
        return ""
    try:
        import json
        json.loads(payload)
        return "application/json"
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
        return ""


def _detect_grpc(payload: bytes) -> str:
    """Return ``"application/grpc"`` if *payload* starts with a valid gRPC frame header."""
    if len(payload) < 5:
        return ""
    comp_flag = payload[0]
    if comp_flag not in (0, 1):
        return ""
    msg_len = int.from_bytes(payload[1:5], "big")
    if 5 + msg_len <= len(payload):
        return "application/grpc"
    return ""


# Trailing data detection — shared with Http1Parser via trailing.py
from .trailing import detect_trailing_protocol, try_sub_parse  # noqa: E402


class WebSocketParser(BaseParser):
    """Lightweight WebSocket parser with trailing data detection.

    * **can_parse()** — O(1), checks first 2 bytes for a valid frame header.
    * **feed()** — extracts frame opcode and sets ``protocol="WebSocket"``,
      ``method="TEXT"`` / ``"PING"`` / etc.  Masked payloads are unmasked
      eagerly so the body is always readable.

    When valid frames don't consume the entire buffer, trailing data
    info is stored on the parser instance (``trailing_data``,
    ``trailing_protocol``, ``trailing_sub_parse``) and propagated to
    the Flow by the collector.
    """

    PROTOCOL = PROTOCOL_WEBSOCKET

    def __init__(self) -> None:
        self._in_fragment: bool = False
        self._has_parsed: bool = False
        # Per-direction permessage-deflate contexts (RFC 7692)
        self._deflate_read = _DeflateContext()
        self._deflate_write = _DeflateContext()
        # Fragment accumulation for compressed messages
        self._fragment_compressed: bool = False
        self._fragment_parts: list[bytes] = []
        self._fragment_direction: str = ""
        # Trailing data from the last feed() call
        self.trailing_data: Optional[bytes] = None
        self.trailing_protocol: str = ""
        self.trailing_sub_parse: Optional[ParseResult] = None

    def can_parse(self, data: bytes) -> bool:
        return _is_websocket_data(data)

    def feed(self, data: bytes, direction: str,
             stream_id: int | None = None) -> list[ParseResult]:
        """Parse WebSocket frame header, return one ParseResult per frame.

        After parsing, check ``self.trailing_data`` for any unconsumed bytes.
        """
        results: list[ParseResult] = []
        offset = 0
        # Clear trailing state from previous call
        self.trailing_data = None
        self.trailing_protocol = ""
        self.trailing_sub_parse = None

        while offset < len(data):
            remaining = data[offset:]

            # Validate frame header before parsing (stops phantom frames)
            if not _is_websocket_frame(remaining):
                break

            hdr = _parse_frame_header(remaining)
            if hdr is None:
                break

            opcode, fin, rsv1, masked, payload_len, header_size, mask_key = hdr

            # Reject orphan CONT frames (CONT without preceding fragmented data frame)
            if opcode == 0x0 and not self._in_fragment:
                break

            frame_end = offset + header_size + payload_len

            payload_start = offset + header_size
            payload = data[payload_start:frame_end] if frame_end <= len(data) else data[payload_start:]

            if mask_key:
                payload = unmask_payload(payload, mask_key)

            # --- Per-message deflate decompression (RFC 7692) ---
            error = ""
            was_decompressed = False
            raw_payload = b""  # pre-decompression bytes for explorer

            # Control frames (opcode >= 0x8) are never compressed
            if opcode < 0x8:
                if rsv1 and opcode in (0x1, 0x2) and fin:
                    # Unfragmented compressed message
                    ctx = self._deflate_read if direction == "read" else self._deflate_write
                    raw_payload = payload
                    payload, was_decompressed = ctx.decompress(payload)
                    if rsv1 and not was_decompressed:
                        error = "permessage-deflate decompression failed"

                elif rsv1 and opcode in (0x1, 0x2) and not fin:
                    # First fragment of a compressed message
                    self._fragment_compressed = True
                    self._fragment_parts = [payload]
                    self._fragment_direction = direction

                elif opcode == 0x0 and self._fragment_compressed:
                    # Continuation of a compressed message
                    self._fragment_parts.append(payload)
                    total = sum(len(p) for p in self._fragment_parts)
                    if total > _MAX_FRAGMENT_BYTES:
                        error = "permessage-deflate fragment too large, discarded"
                        self._fragment_compressed = False
                        self._fragment_parts = []
                    elif fin:
                        combined = b"".join(self._fragment_parts)
                        ctx = self._deflate_read if self._fragment_direction == "read" else self._deflate_write
                        raw_payload = combined
                        payload, was_decompressed = ctx.decompress(combined)
                        if not was_decompressed:
                            error = "permessage-deflate decompression failed"
                        self._fragment_compressed = False
                        self._fragment_parts = []

            method = _OPCODE_NAMES.get(opcode, f"OP{opcode}")

            # --- Body content detection ---
            content_type = ""
            if opcode == 0x1 and payload and fin:
                # TEXT frame: try JSON detection
                content_type = _detect_json(payload)
            elif opcode == 0x2 and payload and fin and len(payload) >= 5:
                # BIN frame: try gRPC detection
                content_type = _detect_grpc(payload)

            # Build metadata headers for control frames
            ws_headers: dict[str, str] = {}
            if opcode >= 0x8:
                ws_headers["frame-type"] = method
                ws_headers["masked"] = "yes" if masked else "no"
                ws_headers["payload-length"] = str(payload_len)
                if opcode == 0x8 and len(payload) >= 2:
                    close_code = int.from_bytes(payload[:2], "big")
                    ws_headers["close-code"] = str(close_code)
                    if len(payload) > 2:
                        try:
                            ws_headers["close-reason"] = payload[2:].decode("utf-8", errors="replace")
                        except Exception:
                            pass

            results.append(ParseResult(
                protocol=PROTOCOL_WEBSOCKET,
                method=method,
                body=payload,
                body_size=len(payload),
                is_request=(direction == "write"),
                is_complete=fin,
                error=error,
                content_type=content_type,
                content_encoding="permessage-deflate" if was_decompressed else "",
                headers=ws_headers if opcode >= 0x8 else {},
                raw=raw_payload,
            ))

            # Track fragmentation state (control frames don't affect it)
            if opcode in (0x1, 0x2) and not fin:
                self._in_fragment = True
            elif opcode == 0x0 and fin:
                self._in_fragment = False

            if frame_end > len(data):
                break
            offset = frame_end

        if results:
            self._has_parsed = True

        # Detect unconsumed trailing data (also when parser has history from prior feed() calls)
        if offset < len(data) and (results or self._has_parsed):
            unconsumed = data[offset:]
            protocol, cleaned, detected_parser = detect_trailing_protocol(unconsumed)
            sub = try_sub_parse(cleaned, detected_parser, direction) if protocol else None
            self.trailing_data = unconsumed
            self.trailing_protocol = protocol
            self.trailing_sub_parse = sub

        return results

    def flush(self) -> list[ParseResult]:
        return []
