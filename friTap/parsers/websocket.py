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

from friTap.analysis._json_walk import exceeds_depth
from friTap.constants import PROTOCOL_WEBSOCKET
from friTap.decoder_isolation import (
    DecoderContextLost,
    close_isolated_decoder,
    isolated_inflater,
)

from .base import BaseParser, ParseResult
from .decompress import MAX_AUTO_DECOMPRESS, InflateLimitError, inflate_stream_bounded
from .protobuf.grpc import is_grpc_frame

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

# Maximum number of fragments of one compressed message before discarding.
_MAX_FRAGMENT_COUNT = 4096

# Largest single frame payload accepted; a bigger declared length is treated
# as an invalid header (input is attacker-controlled decrypted traffic).
_MAX_FRAME_BYTES = _MAX_FRAGMENT_BYTES

# Longest frame header: 2 + 8 (64-bit length) + 4 (mask key).
_MAX_FRAME_HEADER = 14

# Cap on the bytes kept per direction for a frame spanning hooked chunks.
_MAX_PENDING_BYTES = _MAX_FRAME_BYTES + _MAX_FRAME_HEADER

# RFC 6455 section 5.2: the most significant bit of a 64-bit length MUST be 0.
_PAYLOAD_LEN_MSB = 1 << 63

# Inflated size cap per permessage-deflate message.
_MAX_MESSAGE_INFLATE = MAX_AUTO_DECOMPRESS

# Cumulative inflated output per connection before inflation is disabled.
_MAX_CONNECTION_INFLATE = 1024 * 1024 * 1024  # 1 GiB

# TEXT payloads above this size are not parsed for JSON content detection.
_MAX_JSON_DETECT_BYTES = 1024 * 1024

_ERR_INFLATE_FAILED = "permessage-deflate decompression failed"
_ERR_INFLATE_TOO_LARGE = (
    f"permessage-deflate message exceeds {_MAX_MESSAGE_INFLATE} B inflated, not decompressed"
)
_ERR_INFLATE_BUDGET = (
    f"permessage-deflate output exceeds {_MAX_CONNECTION_INFLATE} B for this "
    "connection; decompression disabled"
)
_ERR_FRAGMENT_TOO_LARGE = "permessage-deflate fragment too large, discarded"
# Decoder isolation: the worker-side inflater (and its history) is gone.
_ERR_CONTEXT_LOST = "permessage-deflate decoder context lost; decompression disabled"
_ERR_TRUNCATED_FRAME = "incomplete WebSocket frame (truncated)"


class _InflateBudget:
    """Cumulative inflated-output allowance shared by a connection's directions."""

    def __init__(self, total: int = _MAX_CONNECTION_INFLATE) -> None:
        self.remaining = total
        self.exhausted = False

    def consume(self, produced: int) -> bool:
        """Charge *produced* bytes; False (and exhausted for good) when over."""
        if self.exhausted or produced > self.remaining:
            self.exhausted = True
            self.remaining = 0
            return False
        self.remaining -= produced
        return True


class _DeflateContext:
    """Per-direction permessage-deflate decompression state (RFC 7692).

    Optimistically reuses the zlib decompressor across messages (context-takeover).
    Falls back to a fresh decompressor if reuse fails (no_context_takeover).
    Every message is inflated to at most *max_message* bytes and charged to
    the connection's *budget*; any failure drops the shared inflater and is
    reported via :attr:`last_error` instead of raising.

    With decoder isolation on the inflater lives in the worker process (the
    budgets stay here). If the worker loses it, the context-takeover history
    is gone, so this direction's decompression is disabled for good.
    """

    def __init__(self, budget: _InflateBudget | None = None,
                 max_message: int = _MAX_MESSAGE_INFLATE) -> None:
        self._dec: zlib.decompressobj | None = None
        self._budget = budget if budget is not None else _InflateBudget()
        self._max_message = max_message
        self._disabled = False  # isolated inflater lost: history unrecoverable
        self.last_error = ""

    def decompress(self, payload: bytes) -> tuple[bytes, bool]:
        """Decompress a permessage-deflate payload.

        Returns ``(data, was_decompressed)``.  On failure returns
        ``(original_payload, False)`` so the caller can display raw data;
        :attr:`last_error` then says why.
        """
        self.last_error = ""
        if self._budget.exhausted:
            return self._fail(payload, _ERR_INFLATE_BUDGET)
        if self._disabled:
            return self._fail(payload, _ERR_CONTEXT_LOST)
        try:
            out = self._inflate(payload + _DEFLATE_TAIL)
        except InflateLimitError:
            return self._fail(payload, _ERR_INFLATE_TOO_LARGE)
        except (zlib.error, ValueError, MemoryError):
            return self._fail(payload, _ERR_INFLATE_FAILED)
        except DecoderContextLost:
            self._disabled = True
            return self._fail(payload, _ERR_CONTEXT_LOST)
        if not self._budget.consume(len(out)):
            return self._fail(payload, _ERR_INFLATE_BUDGET)
        return out, True

    def _inflate(self, raw: bytes) -> bytes:
        """Inflate with the persistent context, else a fresh one (kept on success)."""
        if self._dec is not None:
            try:
                return _feed_inflater(self._dec, raw, self._max_message)
            except zlib.error:
                self._drop_inflater()
        dec = _new_inflater()
        out = _feed_inflater(dec, raw, self._max_message)
        self._dec = dec  # save for reuse
        return out

    def release(self) -> None:
        """Free an isolated inflater (stream end); its history is then gone.

        In-process inflaters are kept untouched.
        """
        if close_isolated_decoder(self._dec):
            self._dec = None
            self._disabled = True

    def _drop_inflater(self) -> None:
        """Forget the inflater (an isolated one frees its worker context)."""
        close_isolated_decoder(self._dec)
        self._dec = None

    def _fail(self, payload: bytes, error: str) -> tuple[bytes, bool]:
        """Drop the (possibly mid-stream) inflater and report *error*."""
        self._drop_inflater()
        self.last_error = error
        return payload, False


def _new_inflater():
    """A fresh raw-deflate inflater: worker-side when decoder isolation is on."""
    isolated = isolated_inflater(-zlib.MAX_WBITS)
    return isolated if isolated is not None else zlib.decompressobj(-zlib.MAX_WBITS)


def _feed_inflater(dec, raw: bytes, max_out: int) -> bytes:
    """``inflate_stream_bounded`` on an in-process or isolated inflater."""
    if getattr(dec, "isolated", False):
        return dec.inflate_bounded(raw, max_out)
    return inflate_stream_bounded(dec, raw, max_out)


class _DirectionState:
    """Parser state kept separately for each direction ("read" / "write").

    Holds the permessage-deflate context, fragmentation state and the bounded
    pending buffer for a frame that spans hooked chunks.
    """

    def __init__(self, budget: _InflateBudget) -> None:
        self.deflate = _DeflateContext(budget)
        self.in_fragment = False
        self.fragment_compressed = False
        self.fragment_parts: list[bytes] = []
        self.fragment_bytes = 0
        self._pending_parts: list[bytes] = []
        self._pending_len = 0
        self._pending_need = 0  # full frame size once the header is known

    # --- compressed-message fragments --------------------------------------

    def start_compressed_fragment(self, payload: bytes) -> None:
        self.fragment_compressed = True
        self.fragment_parts = [payload]
        self.fragment_bytes = len(payload)

    def add_compressed_fragment(self, payload: bytes) -> bool:
        """Append a CONT payload; False (state reset) when over the caps."""
        self.fragment_parts.append(payload)
        self.fragment_bytes += len(payload)
        if (self.fragment_bytes > _MAX_FRAGMENT_BYTES
                or len(self.fragment_parts) > _MAX_FRAGMENT_COUNT):
            self.reset_compressed_fragment()
            return False
        return True

    def take_compressed_message(self) -> bytes:
        combined = b"".join(self.fragment_parts)
        self.reset_compressed_fragment()
        return combined

    def reset_compressed_fragment(self) -> None:
        self.fragment_compressed = False
        self.fragment_parts = []
        self.fragment_bytes = 0

    # --- frames spanning chunks --------------------------------------------

    def absorb(self, data: bytes) -> bytes | None:
        """*data* prefixed with the pending tail, or None while still short.

        Linear in the frame size: chunks are only joined once the pending
        frame can be complete.
        """
        if not self._pending_parts:
            return data
        self._pending_parts.append(data)
        self._pending_len += len(data)
        if self._pending_need and self._pending_len < self._pending_need:
            return None
        return self.take_pending()

    def keep_pending(self, tail: bytes, need: int) -> None:
        """Hold an incomplete frame *tail* (*need* = full size, 0 if unknown)."""
        self._pending_parts = [tail]
        self._pending_len = len(tail)
        self._pending_need = need

    def take_pending(self) -> bytes:
        buf = b"".join(self._pending_parts)
        self._pending_parts = []
        self._pending_len = 0
        self._pending_need = 0
        return buf


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
    """XOR-unmask a WebSocket payload.  Cheap O(n) operation.

    XORs the whole payload as one big integer against the repeated mask
    (C speed, no per-byte Python loop).
    """
    if len(mask_key) != 4:
        return data
    n = len(data)
    if n == 0:
        return b""
    mask = (bytes(mask_key) * ((n + 3) // 4))[:n]
    unmasked = int.from_bytes(data, "big") ^ int.from_bytes(mask, "big")
    return unmasked.to_bytes(n, "big")


def _payload_length_allowed(payload_len: int) -> bool:
    """RFC 6455 64-bit length MSB clear, and within :data:`_MAX_FRAME_BYTES`."""
    return not payload_len & _PAYLOAD_LEN_MSB and payload_len <= _MAX_FRAME_BYTES


_OPCODE_CLOSE = 0x8
_CLOSE_CODE_MIN = 1000
_CLOSE_CODE_MAX = 4999


def _is_valid_close_payload(payload: bytes, mask_key: bytes) -> bool:
    """RFC 6455 §5.5.1: a CLOSE body is empty or starts with a 2-byte status code.

    A 1-byte body is invalid; a status code outside 1000-4999 is not a code
    a real endpoint sends, so it disqualifies the frame for *detection*.
    """
    if not payload:
        return True
    if len(payload) < 2:
        return False
    raw_code = unmask_payload(payload[:2], mask_key) if mask_key else payload[:2]
    code = int.from_bytes(raw_code, "big")
    return _CLOSE_CODE_MIN <= code <= _CLOSE_CODE_MAX


def _is_plausible_leading_control_frame(data: bytes, opcode: int, frame_end: int,
                                        header_size: int, mask_key: bytes) -> bool:
    """Detection-only check for a buffer that STARTS with a control frame.

    A 2-byte control header (e.g. ``0x89 0x17``) is common in arbitrary binary
    data, so it is accepted only when the frame spans the whole buffer or the
    bytes after it start another valid, non-CONTINUATION frame; a CLOSE must
    also carry a sane status code. Feed-time parsing is unaffected.
    """
    if opcode == _OPCODE_CLOSE and not _is_valid_close_payload(
            data[header_size:frame_end], mask_key):
        return False
    remainder = len(data) - frame_end
    if remainder == 0:
        return True
    return remainder >= 2 and _starts_unfragmented_frame(data[frame_end:])


def _starts_unfragmented_frame(data: bytes) -> bool:
    """A valid frame header that a FRESH parser would parse (no orphan CONT).

    Mirrors feed()'s orphan-CONT rejection: detection runs on a stream start,
    where a CONTINUATION (opcode 0x0) cannot follow — ``00 00`` after a
    2-byte control header is just zero padding in arbitrary binary data.
    """
    return _is_websocket_frame(data) and (data[0] & 0x0F) != 0x0


def _is_websocket_data(data: bytes) -> bool:
    """Stricter WebSocket detection for standalone protocol identification.

    Requires at least one complete frame fitting in the buffer.
    If enough data exists for a second frame, requires it to also be valid.
    A leading control frame (PING/PONG/CLOSE) must span the whole buffer or be
    followed by a valid frame (see ``_is_plausible_leading_control_frame``).
    """
    if not _is_websocket_frame(data):
        return False

    hdr = _parse_frame_header(data)
    if hdr is None:
        return False

    opcode, _fin, _rsv1, _masked, payload_len, header_size, mask_key = hdr
    frame_end = header_size + payload_len

    # A stream cannot START with a CONTINUATION frame (feed() rejects orphan
    # CONT too); ``00 00 00 1a`` is a 4-byte big-endian length prefix.
    if opcode == 0x0:
        return False

    # Complete frame must fit in the buffer
    if frame_end > len(data):
        return False

    if opcode >= 0x8:
        return _is_plausible_leading_control_frame(
            data, opcode, frame_end, header_size, mask_key)

    # For data frames (TEXT/BIN/CONT), if enough data for a second frame
    # header, require it to also be valid.
    if frame_end + 2 <= len(data):
        if not _is_websocket_frame(data[frame_end:]):
            return False

    return True


def _detect_json(payload: bytes) -> str:
    """Return ``"application/json"`` if *payload* is valid JSON, else ``""``.

    Payloads over :data:`_MAX_JSON_DETECT_BYTES` are not parsed, and nesting
    beyond ``MAX_JSON_DEPTH`` counts as not-JSON (checked explicitly: since
    CPython 3.14 ``json.loads`` no longer raises ``RecursionError`` on it).
    """
    if len(payload) > _MAX_JSON_DETECT_BYTES:
        return ""
    stripped = payload.lstrip()
    if not stripped or stripped[0:1] not in (b'{', b'['):
        return ""
    try:
        import json
        return "" if exceeds_depth(json.loads(payload)) else "application/json"
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError, RecursionError):
        return ""


def _detect_grpc(payload: bytes) -> str:
    """Return ``"application/grpc"`` if *payload* starts with a valid gRPC frame header."""
    return "application/grpc" if is_grpc_frame(payload) else ""


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
        self._has_parsed: bool = False
        # Per-direction state: permessage-deflate contexts (RFC 7692),
        # fragmentation and pending partial frames. Both directions share
        # one cumulative inflate budget (per connection).
        self._inflate_budget = _InflateBudget()
        self._directions: dict[str, _DirectionState] = {
            "read": _DirectionState(self._inflate_budget),
            "write": _DirectionState(self._inflate_budget),
        }
        self._deflate_read = self._directions["read"].deflate
        self._deflate_write = self._directions["write"].deflate
        # Trailing data from the last feed() call
        self.trailing_data: Optional[bytes] = None
        self.trailing_protocol: str = ""
        self.trailing_sub_parse: Optional[ParseResult] = None
        # Direction ("read"/"write") of the feed() that left trailing_data
        self.trailing_direction: str = ""

    def can_parse(self, data: bytes) -> bool:
        return _is_websocket_data(data)

    def recognized_any(self) -> bool:
        """True once at least one frame was parsed (detection alone is weak)."""
        return self._has_parsed

    def _state(self, direction: str) -> _DirectionState:
        return self._directions["read" if direction == "read" else "write"]

    def _clear_trailing(self) -> None:
        self.trailing_data = None
        self.trailing_protocol = ""
        self.trailing_sub_parse = None
        self.trailing_direction = ""

    def feed(self, data: bytes, direction: str,
             stream_id: int | None = None) -> list[ParseResult]:
        """Parse WebSocket frame header, return one ParseResult per frame.

        Only complete frames are emitted: an incomplete frame at the end of
        *data* is kept (bounded, per direction) and completed by the next
        feed() for that direction. After parsing, check ``self.trailing_data``
        for any unconsumed bytes.
        """
        self._clear_trailing()
        state = self._state(direction)
        buf = state.absorb(bytes(data))
        if buf is None:
            return []
        results, offset = self._parse_frames(buf, direction, state)
        if results:
            self._has_parsed = True
        if offset < len(buf) and (results or self._has_parsed):
            self._record_trailing(buf[offset:], direction)
        return results

    def _parse_frames(self, buf: bytes, direction: str,
                      state: _DirectionState) -> tuple[list[ParseResult], int]:
        """Parse complete frames from *buf*: ``(results, consumed_offset)``.

        An incomplete last frame is moved to the pending buffer and counted
        as consumed; an invalid header stops parsing (trailing data).
        """
        results: list[ParseResult] = []
        view = memoryview(buf)
        offset = 0
        while offset < len(buf):
            status, hdr = self._classify_frame(view[offset:], state)
            if status == _FRAME_INCOMPLETE and len(buf) - offset <= _MAX_PENDING_BYTES:
                state.keep_pending(buf[offset:], _frame_size(hdr))
                return results, len(buf)
            if status == _FRAME_INCOMPLETE:
                break
            if status == _FRAME_INVALID:
                break
            frame_end = offset + hdr[5] + hdr[4]
            payload = bytes(view[offset + hdr[5]:frame_end])
            results.append(self._frame_result(hdr, payload, direction, state))
            offset = frame_end
        return results, offset

    @staticmethod
    def _classify_frame(view, state: _DirectionState) -> tuple[str, tuple | None]:
        """``(status, header)`` for the frame starting at *view*."""
        # Validate frame header before parsing (stops phantom frames)
        if not _is_websocket_frame(view):
            return _FRAME_INVALID, None
        hdr = _parse_frame_header(view)
        if hdr is None:
            return _FRAME_INCOMPLETE, None
        opcode, payload_len, header_size = hdr[0], hdr[4], hdr[5]
        # Reject orphan CONT frames (CONT without preceding fragmented data frame)
        if opcode == 0x0 and not state.in_fragment:
            return _FRAME_INVALID, None
        if not _payload_length_allowed(payload_len):
            return _FRAME_INVALID, None
        if header_size + payload_len > len(view):
            return _FRAME_INCOMPLETE, hdr
        return _FRAME_COMPLETE, hdr

    def _frame_result(self, hdr: tuple, payload: bytes, direction: str,
                      state: _DirectionState) -> ParseResult:
        """Build the ParseResult for one complete frame and update *state*."""
        opcode, fin, rsv1, masked, payload_len, _header_size, mask_key = hdr
        if mask_key:
            payload = unmask_payload(payload, bytes(mask_key))
        payload, raw_payload, was_decompressed, error = _decode_message_payload(
            state, opcode, fin, rsv1, payload)
        method = _OPCODE_NAMES.get(opcode, f"OP{opcode}")
        _track_fragmentation(state, opcode, fin)
        return ParseResult(
            protocol=PROTOCOL_WEBSOCKET,
            method=method,
            body=payload,
            body_size=len(payload),
            is_request=(direction == "write"),
            is_complete=fin,
            error=error,
            content_type=_detect_content_type(opcode, fin, payload),
            content_encoding="permessage-deflate" if was_decompressed else "",
            headers=_control_frame_headers(opcode, method, masked, payload_len, payload),
            raw=raw_payload,
        )

    def _record_trailing(self, unconsumed: bytes, direction: str) -> None:
        """Detect the protocol of unconsumed bytes and store trailing info."""
        protocol, cleaned, detected_parser = detect_trailing_protocol(
            unconsumed, transport=self.flow_transport)
        sub = try_sub_parse(cleaned, detected_parser, direction) if protocol else None
        self.trailing_data = unconsumed
        self.trailing_protocol = protocol
        self.trailing_sub_parse = sub
        self.trailing_direction = direction

    def flush(self) -> list[ParseResult]:
        """Emit frames still pending at stream end, marked truncated.

        Also frees isolated (worker-side) inflaters; in-process ones are kept.
        """
        results: list[ParseResult] = []
        for direction, state in self._directions.items():
            tail = state.take_pending()
            result = _truncated_frame_result(tail, direction) if tail else None
            if result is not None:
                results.append(result)
            state.deflate.release()
        return results


# Frame classification results used by WebSocketParser._classify_frame().
_FRAME_COMPLETE = "complete"
_FRAME_INCOMPLETE = "incomplete"
_FRAME_INVALID = "invalid"


def _frame_size(hdr: tuple | None) -> int:
    """Full frame size from a parsed header, 0 when the header is incomplete."""
    return 0 if hdr is None else hdr[5] + hdr[4]


def _decode_message_payload(state: _DirectionState, opcode: int, fin: bool,
                            rsv1: bool, payload: bytes
                            ) -> tuple[bytes, bytes, bool, str]:
    """Per-message deflate (RFC 7692): ``(payload, raw, decompressed, error)``.

    Control frames (opcode >= 0x8) are never compressed. Compressed
    fragments are accumulated per direction (bounded) until the final CONT.
    """
    if opcode >= 0x8:
        return payload, b"", False, ""
    if rsv1 and opcode in (0x1, 0x2) and fin:
        return _inflate_message(state, payload)
    if rsv1 and opcode in (0x1, 0x2):
        state.start_compressed_fragment(payload)
    elif opcode == 0x0 and state.fragment_compressed:
        if not state.add_compressed_fragment(payload):
            return payload, b"", False, _ERR_FRAGMENT_TOO_LARGE
        if fin:
            return _inflate_message(state, state.take_compressed_message())
    return payload, b"", False, ""


def _inflate_message(state: _DirectionState, compressed: bytes
                     ) -> tuple[bytes, bytes, bool, str]:
    """Inflate one complete compressed message with the direction's context."""
    payload, was_decompressed = state.deflate.decompress(compressed)
    error = "" if was_decompressed else (state.deflate.last_error or _ERR_INFLATE_FAILED)
    return payload, compressed, was_decompressed, error


def _track_fragmentation(state: _DirectionState, opcode: int, fin: bool) -> None:
    """Update fragmentation state (control frames don't affect it)."""
    if opcode in (0x1, 0x2) and not fin:
        state.in_fragment = True
    elif opcode == 0x0 and fin:
        state.in_fragment = False


def _detect_content_type(opcode: int, fin: bool, payload: bytes) -> str:
    """Body content detection: JSON for TEXT, gRPC for BIN frames."""
    if opcode == 0x1 and payload and fin:
        return _detect_json(payload)
    if opcode == 0x2 and payload and fin and len(payload) >= 5:
        return _detect_grpc(payload)
    return ""


def _control_frame_headers(opcode: int, method: str, masked: bool,
                           payload_len: int, payload: bytes) -> dict[str, str]:
    """Metadata headers for control frames (empty for data frames)."""
    if opcode < 0x8:
        return {}
    ws_headers = {
        "frame-type": method,
        "masked": "yes" if masked else "no",
        "payload-length": str(payload_len),
    }
    if opcode == 0x8 and len(payload) >= 2:
        ws_headers["close-code"] = str(int.from_bytes(payload[:2], "big"))
        if len(payload) > 2:
            ws_headers["close-reason"] = payload[2:].decode("utf-8", errors="replace")
    return ws_headers


def _truncated_frame_result(tail: bytes, direction: str) -> ParseResult | None:
    """ParseResult for a frame cut off at stream end (payload as received)."""
    hdr = _parse_frame_header(tail)
    if hdr is None:
        return None
    opcode, _fin, _rsv1, _masked, _payload_len, header_size, mask_key = hdr
    payload = tail[header_size:]
    if mask_key:
        payload = unmask_payload(payload, bytes(mask_key))
    return ParseResult(
        protocol=PROTOCOL_WEBSOCKET,
        method=_OPCODE_NAMES.get(opcode, f"OP{opcode}"),
        body=payload,
        body_size=len(payload),
        is_request=(direction == "write"),
        is_complete=False,
        error=_ERR_TRUNCATED_FRAME,
    )
