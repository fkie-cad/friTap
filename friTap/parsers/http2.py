"""HTTP/2 frame-level parser with HPACK decompression via hpack library."""

import logging
import struct

_log = logging.getLogger(__name__)

# Try to import hpack for HPACK header decompression
_hpack_available = False
try:
    from hpack import Decoder as HpackDecoder, HPACKDecodingError
    _hpack_available = True
except ImportError:
    HpackDecoder = None  # type: ignore[assignment,misc]

    class HPACKDecodingError(Exception):  # type: ignore[no-redef]
        """Stub raised when hpack is not installed."""

    _log.warning(
        "hpack library not available — HTTP/2 frame parsing will work, "
        "but HPACK header decompression is disabled. Install with: pip install hpack"
    )

from friTap.constants import PROTOCOL_HTTP2  # noqa: E402
from .base import BaseParser, ParseResult, apply_http2_headers  # noqa: E402


# HTTP/2 connection preface
_CONNECTION_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

# Frame types
_FRAME_DATA = 0x00
_FRAME_HEADERS = 0x01
_FRAME_PRIORITY = 0x02
_FRAME_RST_STREAM = 0x03
_FRAME_SETTINGS = 0x04
_FRAME_PUSH_PROMISE = 0x05
_FRAME_PING = 0x06
_FRAME_GOAWAY = 0x07
_FRAME_WINDOW_UPDATE = 0x08
_FRAME_CONTINUATION = 0x09

# Flags
_FLAG_END_STREAM = 0x01
_FLAG_END_HEADERS = 0x04
_FLAG_PADDED = 0x08
_FLAG_PRIORITY = 0x20

_FRAME_HEADER_SIZE = 9
_MAX_VALID_FRAME_TYPE = 0x09

# Fixed pre-fragment field sizes (RFC 7540 §6.2 / §6.6) that precede the HPACK
# header-block fragment inside a PADDED-capable frame.
_HEADERS_PRIORITY_LEN = 5      # 4-byte stream dependency + 1-byte weight
_PUSH_PROMISE_PREFIX_LEN = 4   # R bit + 31-bit promised stream id

# Sentinel URLs for control-frame ParseResults (shared with TUI rendering)
H2_URL_CONNECTION_SETUP = "connection-setup"
H2_URL_CONNECTION_CONTROL = "connection-control"

# RFC 7540 Section 6.5.2 — SETTINGS parameter identifiers
_SETTINGS_PARAMS: dict[int, str] = {
    0x1: "HEADER_TABLE_SIZE",
    0x2: "ENABLE_PUSH",
    0x3: "MAX_CONCURRENT_STREAMS",
    0x4: "INITIAL_WINDOW_SIZE",
    0x5: "MAX_FRAME_SIZE",
    0x6: "MAX_HEADER_LIST_SIZE",
}

# Frame type display names
_FRAME_TYPE_NAMES: dict[int, str] = {
    _FRAME_DATA: "DATA",
    _FRAME_HEADERS: "HEADERS",
    _FRAME_PRIORITY: "PRIORITY",
    _FRAME_RST_STREAM: "RST_STREAM",
    _FRAME_SETTINGS: "SETTINGS",
    _FRAME_PUSH_PROMISE: "PUSH_PROMISE",
    _FRAME_PING: "PING",
    _FRAME_GOAWAY: "GOAWAY",
    _FRAME_WINDOW_UPDATE: "WINDOW_UPDATE",
    _FRAME_CONTINUATION: "CONTINUATION",
}

# GOAWAY error codes (RFC 7540 Section 7)
_GOAWAY_ERRORS: dict[int, str] = {
    0x0: "NO_ERROR",
    0x1: "PROTOCOL_ERROR",
    0x2: "INTERNAL_ERROR",
    0x3: "FLOW_CONTROL_ERROR",
    0x4: "SETTINGS_TIMEOUT",
    0x5: "STREAM_CLOSED",
    0x6: "FRAME_SIZE_ERROR",
    0x7: "REFUSED_STREAM",
    0x8: "CANCEL",
    0x9: "COMPRESSION_ERROR",
    0xa: "CONNECT_ERROR",
    0xb: "ENHANCE_YOUR_CALM",
    0xc: "INADEQUATE_SECURITY",
    0xd: "HTTP_1_1_REQUIRED",
}


def is_h2_control_frame_data(data: bytes) -> bool:
    """Check if data consists entirely of HTTP/2 connection-level frames (stream_id == 0).

    Per RFC 7540 Section 4.1, each frame has a 9-byte header:
    Length (3 octets) + Type (1) + Flags (1) + Reserved (1 bit) + Stream ID (31 bits).
    Connection-level frames use stream_id == 0 and include SETTINGS, PING,
    WINDOW_UPDATE, and GOAWAY (Sections 6.5, 6.7, 6.8, 6.9).
    """
    if not data or len(data) < _FRAME_HEADER_SIZE:
        return False
    offset = 0
    preface_len = len(_CONNECTION_PREFACE)
    if data[offset:offset + preface_len] == _CONNECTION_PREFACE:
        offset += preface_len
    frame_count = 0
    while offset + _FRAME_HEADER_SIZE <= len(data):
        length, frame_type, _, stream_id = Http2Parser._parse_frame_header(
            data[offset:offset + _FRAME_HEADER_SIZE]
        )
        if frame_type > _MAX_VALID_FRAME_TYPE or stream_id != 0:
            return False
        total = _FRAME_HEADER_SIZE + length
        if offset + total > len(data):
            break
        offset += total
        frame_count += 1
    return frame_count > 0


class _StreamState:
    """Per-stream state tracking."""

    __slots__ = (
        "stream_id", "headers", "trailers", "header_bytes", "body_size",
        "is_request", "method", "url", "host", "status_code", "status_text",
        "content_encoding", "content_type", "end_stream_seen",
        "awaiting_continuation", "pending_push_promise", "error",
        "push_header_bytes", "headers_awaiting_continuation",
        "push_awaiting_continuation", "pending_end_stream",
    )

    def __init__(self, stream_id: int) -> None:
        self.stream_id = stream_id
        self.headers: dict[str, str] = {}
        self.trailers: dict[str, str] = {}
        self.header_bytes: bytearray = bytearray()
        self.body_size: int = 0
        self.is_request: bool = True
        self.method: str = ""
        self.url: str = ""
        self.host: str = ""
        self.status_code: int = 0
        self.status_text: str = ""
        self.content_encoding: str = ""
        self.content_type: str = ""
        self.end_stream_seen: bool = False
        # Kept as the union "is ANY header block awaiting a CONTINUATION on this
        # stream" (read in flush() / preserved for external consumers). The two
        # fields below disambiguate WHICH block (#39).
        self.awaiting_continuation: bool = False
        # True while accumulating a PUSH_PROMISE header block (possibly across
        # CONTINUATION frames); the block advances the HPACK table but is not
        # applied to this stream's own headers.
        self.pending_push_promise: bool = False
        # SEPARATE accumulation buffer for PUSH_PROMISE header-block fragments
        # (#45). PUSH_PROMISE describes a *server-pushed* stream and must never
        # share ``header_bytes`` with a possibly half-buffered real HEADERS
        # block on the same stream — mixing them corrupts both.
        self.push_header_bytes: bytearray = bytearray()
        # Independent "awaiting CONTINUATION" flags for the two block kinds
        # (#39). A CONTINUATION is routed to whichever block is open; finalizing
        # one kind must never clear the other's pending state. A CONTINUATION
        # with neither flag set is a protocol error.
        self.headers_awaiting_continuation: bool = False
        self.push_awaiting_continuation: bool = False
        # RFC 7540 §6.2: a HEADERS frame may carry END_STREAM even when its
        # header block is continued in CONTINUATION frames (which can NOT carry
        # END_STREAM). When END_HEADERS is deferred we remember the END_STREAM
        # intent here so the stream still finalizes once the block completes,
        # instead of being silently lost and the request/response only ever
        # surfacing as incomplete (#62).
        self.pending_end_stream: bool = False
        # Set to "hpack-desync" when this stream's headers could not be
        # decoded; consumers use it to tell "undecodable" from a real status.
        self.error: str = ""


class Http2Parser(BaseParser):
    """HTTP/2 frame-level parser.

    Parses 9-byte frame headers, decompresses HPACK headers using the hpack
    library, accumulates DATA frame payloads per stream, and returns
    ParseResults when END_STREAM is encountered.

    Maintains separate HPACK decoders and buffers per direction to handle
    independent header compression contexts for requests vs responses.
    """

    PROTOCOL = PROTOCOL_HTTP2

    def __init__(self) -> None:
        # Per-direction state: separate HPACK contexts, buffers, and streams
        self._decoders: dict[str, HpackDecoder] = {}
        self._buffers: dict[str, bytearray] = {}
        self._streams: dict[str, dict[int, _StreamState]] = {}
        self._preface_seen: dict[str, bool] = {}
        # Once a direction's HPACK decoder hits an unrecoverable desync it is
        # poisoned: HPACK is stateful and cannot resync after a missed dynamic-
        # table insertion, so every later decode on that direction would fail.
        self._decoder_failed: dict[str, bool] = {}

    def _ensure_direction(self, direction: str) -> None:
        """Lazily initialize per-direction state."""
        if direction not in self._decoders:
            self._decoders[direction] = HpackDecoder() if _hpack_available else None
            self._buffers[direction] = bytearray()
            self._streams[direction] = {}
            self._preface_seen[direction] = False
            self._decoder_failed[direction] = False

    def can_parse(self, data: bytes) -> bool:
        """Detect HTTP/2 connection preface or valid frame header.

        Without the connection preface, requires stricter validation:
        frame length <= 16384 (RFC 7540 initial max), frame-type-specific
        length constraints, and a second consecutive frame header when
        enough data is available.
        """
        if not data:
            return False
        if data.startswith(_CONNECTION_PREFACE):
            return True
        if len(data) < _FRAME_HEADER_SIZE:
            return False
        length, frame_type, flags, stream_id = self._parse_frame_header(
            data[:_FRAME_HEADER_SIZE]
        )
        if frame_type > _MAX_VALID_FRAME_TYPE:
            return False
        # Without the preface, apply strict initial-window constraints
        if length > 16384:  # RFC 7540 default SETTINGS_MAX_FRAME_SIZE
            return False
        # Frame-type-specific length constraints (RFC 7540 Section 6)
        if frame_type == _FRAME_SETTINGS and stream_id == 0 and length % 6 != 0:
            return False
        if frame_type == _FRAME_PING and length != 8:
            return False
        if frame_type == _FRAME_WINDOW_UPDATE and length != 4:
            return False
        if frame_type == _FRAME_RST_STREAM and length != 4:
            return False
        if frame_type == _FRAME_PRIORITY and length != 5:
            return False
        # If we have enough data, require a second valid frame header
        total = _FRAME_HEADER_SIZE + length
        if len(data) >= total + _FRAME_HEADER_SIZE:
            if not self._is_valid_frame_header(data[total:total + _FRAME_HEADER_SIZE]):
                return False
        return True

    def feed(self, data: bytes, direction: str,
             stream_id: int | None = None) -> list[ParseResult]:
        """Parse HTTP/2 frames and return completed stream results.

        ``stream_id`` is ignored: HTTP/2 derives the stream id from the
        frame header on the wire.
        """
        self._ensure_direction(direction)
        buf = self._buffers[direction]
        buf += data
        streams = self._streams[direction]
        decoder = self._decoders[direction]
        results: list[ParseResult] = []
        control_frames: list[tuple[int, int, bytes]] = []

        # Strip connection preface if present
        if not self._preface_seen[direction]:
            if buf.startswith(_CONNECTION_PREFACE):
                del buf[:len(_CONNECTION_PREFACE)]
                self._preface_seen[direction] = True
            elif _CONNECTION_PREFACE[:len(buf)] == buf:
                # Buffer is a prefix of the connection preface — wait for more data
                return results

        while len(buf) >= _FRAME_HEADER_SIZE:
            length, frame_type, flags, stream_id = self._parse_frame_header(
                buf[:_FRAME_HEADER_SIZE]
            )

            total_frame_size = _FRAME_HEADER_SIZE + length
            if len(buf) < total_frame_size:
                break

            payload = bytes(buf[_FRAME_HEADER_SIZE:total_frame_size])
            del buf[:total_frame_size]

            if frame_type > _MAX_VALID_FRAME_TYPE:
                continue

            # Collect connection-level frames (stream_id == 0)
            if stream_id == 0:
                control_frames.append((frame_type, flags, payload))
                continue

            if frame_type == _FRAME_RST_STREAM:
                streams.pop(stream_id, None)
                continue

            stream = self._get_stream(streams, stream_id, direction)

            # Whether this frame is allowed to honor an END_STREAM flag and
            # finalize the parent request/response stream (#15). A PUSH_PROMISE
            # block — or a CONTINUATION completing one — describes a *pushed*
            # stream and must NEVER close the parent it arrived on.
            finalizes_parent = False

            if frame_type == _FRAME_HEADERS:
                header_payload = self._strip_padded_frame(
                    payload, flags, self._headers_prefix_len(flags)
                )
                stream.header_bytes += header_payload
                if flags & _FLAG_END_HEADERS:
                    self._finalize_headers(stream, decoder, flags, direction, results)
                    finalizes_parent = True
                else:
                    # Await a CONTINUATION that completes this real HEADERS block.
                    # Carry the HEADERS frame's END_STREAM intent forward (#62):
                    # the completing CONTINUATION cannot repeat it, so without
                    # this the stream would never finalize.
                    stream.headers_awaiting_continuation = True
                    if flags & _FLAG_END_STREAM:
                        stream.pending_end_stream = True
                    self._sync_awaiting(stream)

            elif frame_type == _FRAME_PUSH_PROMISE:
                # A PUSH_PROMISE block mutates the read-direction HPACK dynamic
                # table just like HEADERS does. It must be fed to the decoder in
                # wire order or later responses desync ("Invalid table index").
                # It is accumulated in a SEPARATE buffer (#45) so it can never
                # corrupt a concurrently half-buffered real HEADERS block, and
                # it never finalizes the parent stream (#15).
                stream.push_header_bytes += self._strip_padded_frame(
                    payload, flags, _PUSH_PROMISE_PREFIX_LEN
                )
                stream.pending_push_promise = True
                if flags & _FLAG_END_HEADERS:
                    self._finalize_push_promise(stream, decoder, direction)
                else:
                    stream.push_awaiting_continuation = True
                    self._sync_awaiting(stream)

            elif frame_type == _FRAME_CONTINUATION:
                # A CONTINUATION is only valid for a stream with an open header
                # block (#39). It completes whichever block is still awaiting
                # one; per RFC 7540 §6.10 only one can be open at a time. A
                # CONTINUATION with neither block open is a protocol error —
                # surface it instead of silently appending into a buffer.
                if stream.push_awaiting_continuation:
                    stream.push_header_bytes += payload
                    if flags & _FLAG_END_HEADERS:
                        self._finalize_push_promise(stream, decoder, direction)
                elif stream.headers_awaiting_continuation:
                    stream.header_bytes += payload
                    if flags & _FLAG_END_HEADERS:
                        self._finalize_headers(stream, decoder, flags, direction, results)
                        finalizes_parent = True
                else:
                    stream.error = "protocol-error"
                    _log.warning(
                        "Unexpected CONTINUATION on stream %d (%s) with no "
                        "block awaiting continuation — protocol error",
                        stream_id, direction,
                    )

            elif frame_type == _FRAME_DATA:
                actual_data = self._strip_padding(payload, flags)
                stream.body_size += len(actual_data)
                finalizes_parent = True

            # Only HEADERS / DATA / a CONTINUATION that completes a real HEADERS
            # block may finalize the parent on END_STREAM. PUSH_PROMISE frames
            # (and CONTINUATIONs of them) carry their own END_HEADERS semantics
            # and never legitimately set END_STREAM for the parent (#15).
            # ``pending_end_stream`` covers the split-headers case (#62) where
            # END_STREAM rode the HEADERS frame but END_HEADERS was deferred to
            # the CONTINUATION that now finalizes the block.
            if (flags & _FLAG_END_STREAM or stream.pending_end_stream) and finalizes_parent:
                stream.end_stream_seen = True
                result = self._build_result(stream)
                results.append(result)
                streams.pop(stream_id, None)

        # Produce a synthetic result when only control frames were seen
        if control_frames and not results:
            results.append(self._build_control_result(
                control_frames, direction,
                self._preface_seen.get(direction, False),
            ))

        return results

    def flush(self) -> list[ParseResult]:
        """Return partial streams as incomplete results."""
        results: list[ParseResult] = []
        for direction, streams in self._streams.items():
            for stream in streams.values():
                # #51: a stream still awaiting a CONTINUATION (or with a
                # pending PUSH_PROMISE block) at flush time never completed its
                # header block. Surface that as an error so a poisoned/partial
                # block is not reported as a clean status-0 result. Don't clobber
                # an error already recorded for this stream.
                if not stream.error and (
                    stream.awaiting_continuation or stream.pending_push_promise
                ):
                    stream.error = "incomplete-headers"
                result = self._build_result(stream, is_complete=False)
                results.append(result)
            streams.clear()
        for buf in self._buffers.values():
            buf.clear()
        return results

    @staticmethod
    def _sync_awaiting(stream: _StreamState) -> None:
        """Keep ``awaiting_continuation`` as the union of the two per-kind flags
        so flush() (#51) and external consumers see a single meaningful signal.
        """
        stream.awaiting_continuation = (
            stream.headers_awaiting_continuation
            or stream.push_awaiting_continuation
        )

    @staticmethod
    def _get_stream(
        streams: dict[int, _StreamState], stream_id: int, direction: str
    ) -> _StreamState:
        if stream_id not in streams:
            stream = _StreamState(stream_id)
            stream.is_request = (direction == "write")
            streams[stream_id] = stream
        return streams[stream_id]

    @staticmethod
    def _parse_frame_header(header: bytes) -> tuple[int, int, int, int]:
        """Parse 9-byte frame header into (length, type, flags, stream_id)."""
        length = (header[0] << 16) | (header[1] << 8) | header[2]
        frame_type = header[3]
        flags = header[4]
        stream_id = struct.unpack("!I", header[5:9])[0] & 0x7FFFFFFF
        return length, frame_type, flags, stream_id

    @staticmethod
    def _is_valid_frame_header(header: bytes) -> bool:
        """Check if 9 bytes look like a valid HTTP/2 frame header."""
        if len(header) < _FRAME_HEADER_SIZE:
            return False
        length = (header[0] << 16) | (header[1] << 8) | header[2]
        frame_type = header[3]
        if frame_type > _MAX_VALID_FRAME_TYPE:
            return False
        if length > 16777215:
            return False
        return True

    @staticmethod
    def _headers_prefix_len(flags: int) -> int:
        """Pre-fragment field length for a HEADERS frame: the PRIORITY block
        (5 bytes) is present only when the PRIORITY flag is set (RFC 7540 §6.2).
        """
        return _HEADERS_PRIORITY_LEN if (flags & _FLAG_PRIORITY) else 0

    @staticmethod
    def _strip_padded_frame(payload: bytes, flags: int, prefix_len: int) -> bytes:
        """Return the HPACK header-block fragment from a PADDED-capable frame.

        Shared by HEADERS and PUSH_PROMISE (#57). Layout is::

            [Pad Length (1, if PADDED)] [fixed prefix (prefix_len)]
            Header Block Fragment [Padding (pad_length, if PADDED)]

        ``prefix_len`` is the frame-specific fixed field preceding the fragment:
        the PRIORITY block for HEADERS, the 4-byte promised stream id for
        PUSH_PROMISE. A SINGLE consistent boundary is applied: per RFC 7540
        §6.1, if the padding length is >= the bytes remaining after the
        pad-length octet, the frame is invalid and an empty fragment is returned.
        """
        offset = 0
        pad_length = 0

        if flags & _FLAG_PADDED:
            if len(payload) < 1:
                return b""
            pad_length = payload[0]
            offset += 1
            # RFC 7540 §6.1: the Pad Length must be strictly less than the
            # payload remaining after the Pad Length octet. If padding is >=
            # that remainder the frame is invalid — reject consistently for
            # both HEADERS and PUSH_PROMISE (#57).
            if pad_length >= len(payload) - 1:
                return b""

        offset += prefix_len
        end = len(payload) - pad_length
        if end <= offset:
            return b""

        return payload[offset:end]

    @staticmethod
    def _strip_padding(payload: bytes, flags: int) -> bytes:
        """Strip PADDED field from DATA payload."""
        if flags & _FLAG_PADDED:
            if len(payload) < 1:
                return b""
            pad_length = payload[0]
            end = len(payload) - pad_length
            if end <= 1:
                return b""
            return payload[1:end]
        return payload

    @classmethod
    def _strip_push_promise(cls, payload: bytes, flags: int) -> bytes:
        """Return the header-block fragment of a PUSH_PROMISE payload.

        Thin backward-compatible wrapper around the shared
        :meth:`_strip_padded_frame` (#57). PUSH_PROMISE (RFC 7540 §6.6) is
        PADDED-capable, never carries PRIORITY, and prefixes its fragment with a
        4-byte promised stream id; the id is skipped — we only keep the HPACK
        table in sync, not emit the pushed request as its own flow.
        """
        return cls._strip_padded_frame(payload, flags, _PUSH_PROMISE_PREFIX_LEN)

    def _finalize_headers(
        self, stream: _StreamState, decoder: HpackDecoder,
        flags: int, direction: str, results: list[ParseResult],
    ) -> None:
        """Decode headers and emit an intermediate result if END_STREAM not yet seen."""
        self._decode_headers(stream, decoder, direction)
        # Clear only the real-HEADERS continuation state; a pending PUSH_PROMISE
        # block (if any) keeps its own flag (#39).
        stream.headers_awaiting_continuation = False
        self._sync_awaiting(stream)
        # END_STREAM may never arrive for long-lived connections. Treat a
        # carried-forward END_STREAM (split-headers, #62) the same as one on the
        # current frame so the caller's finalize check emits a COMPLETE result
        # rather than this intermediate incomplete one.
        if not (flags & _FLAG_END_STREAM or stream.pending_end_stream):
            results.append(self._build_result(stream, is_complete=False))

    def _finalize_push_promise(
        self, stream: _StreamState, decoder: HpackDecoder, direction: str,
    ) -> None:
        """Run a completed PUSH_PROMISE block through the decoder to keep the
        dynamic table in sync, then discard the decoded headers.

        Decodes from the SEPARATE ``push_header_bytes`` buffer (#45) so the
        parent's own ``header_bytes`` is untouched, and with ``stamp_error=False``
        so a PUSH_PROMISE HPACK failure never writes ``error`` onto the parent
        request/response stream (#16). A failure still poisons the direction,
        because the dynamic table is genuinely desynced for later frames.

        Emitting the promised request as its own flow is out of scope; the only
        requirement is that the read-direction HPACK table stays consistent so
        subsequent response :status references decode correctly.
        """
        block = bytes(stream.push_header_bytes)
        stream.push_header_bytes = bytearray()
        self._run_hpack(stream, decoder, direction, block, stamp_error=False)
        # Clear only push-promise state; a half-buffered real HEADERS block on
        # the same stream keeps awaiting its own CONTINUATION (#39/#45).
        stream.push_awaiting_continuation = False
        stream.pending_push_promise = False
        self._sync_awaiting(stream)

    def _decode_headers(
        self, stream: _StreamState, decoder: HpackDecoder, direction: str,
    ) -> None:
        """Decode HPACK-encoded headers and apply them to the stream."""
        block = bytes(stream.header_bytes)
        stream.header_bytes = bytearray()
        headers = self._run_hpack(stream, decoder, direction, block,
                                  stamp_error=True)
        if headers is None:
            return
        apply_http2_headers(stream, headers)

    def _run_hpack(
        self, stream: _StreamState, decoder: HpackDecoder, direction: str,
        block: bytes, stamp_error: bool = True,
    ) -> list[tuple[str, str]] | None:
        """Decode ``block`` against the direction's HPACK decoder, advancing its
        dynamic table.

        Returns the decoded (name, value) pairs, or ``None`` when decoding is
        unavailable or failed. A genuine HPACKDecodingError poisons the
        direction (HPACK cannot resync after a desync). Only when
        ``stamp_error`` is True is ``error = "hpack-desync"`` written onto
        ``stream`` — push-promise decodes pass False so a pushed block's failure
        never mislabels the parent request/response (#16).
        """
        if decoder is None:
            # hpack library not installed — skip decoding; not an error.
            return None

        if self._decoder_failed.get(direction):
            # Decoder already desynced earlier on this direction.
            if stamp_error:
                stream.error = "hpack-desync"
            return None

        try:
            decoded = decoder.decode(block)
        except HPACKDecodingError as e:
            _log.warning(
                "HPACK decoding failed for stream %d on %s: %s — decoder "
                "poisoned (HPACK cannot resync after a missed table insertion)",
                stream.stream_id, direction, e,
            )
            self._decoder_failed[direction] = True
            if stamp_error:
                stream.error = "hpack-desync"
            return None

        headers = []
        for name, value in decoded:
            if isinstance(name, bytes):
                name = name.decode("latin-1", errors="replace")
            if isinstance(value, bytes):
                value = value.decode("latin-1", errors="replace")
            headers.append((name, value))
        return headers

    @staticmethod
    def _build_result(
        stream: _StreamState, is_complete: bool = True
    ) -> ParseResult:
        """Build ParseResult from stream state."""
        return ParseResult(
            protocol="HTTP/2",
            method=stream.method,
            url=stream.url,
            host=stream.host,
            status_code=stream.status_code,
            headers=dict(stream.headers),
            body=b"",
            body_size=stream.body_size,
            is_complete=is_complete,
            is_request=stream.is_request,
            content_encoding=stream.content_encoding,
            content_type=stream.content_type,
            error=stream.error,
            stream_id=stream.stream_id,
        )

    @staticmethod
    def _build_control_result(
        frames: list[tuple[int, int, bytes]], direction: str,
        preface_seen: bool,
    ) -> ParseResult:
        """Build a synthetic ParseResult for connection-level control frames."""
        headers: dict[str, str] = {}
        primary_type = "SETTINGS"

        for frame_type, flags, payload in frames:
            if frame_type == _FRAME_SETTINGS:
                is_ack = bool(flags & 0x01)
                if is_ack:
                    headers["SETTINGS"] = "ACK"
                else:
                    for i in range(0, len(payload) - 5, 6):
                        param_id = int.from_bytes(payload[i:i + 2], "big")
                        param_val = int.from_bytes(payload[i + 2:i + 6], "big")
                        name = _SETTINGS_PARAMS.get(param_id, f"0x{param_id:x}")
                        headers[name] = str(param_val)

            elif frame_type == _FRAME_WINDOW_UPDATE and len(payload) >= 4:
                increment = int.from_bytes(payload[:4], "big") & 0x7FFFFFFF
                headers["WINDOW_UPDATE"] = str(increment)

            elif frame_type == _FRAME_GOAWAY and len(payload) >= 8:
                primary_type = "GOAWAY"
                last_stream = int.from_bytes(payload[:4], "big") & 0x7FFFFFFF
                error_code = int.from_bytes(payload[4:8], "big")
                error_name = _GOAWAY_ERRORS.get(error_code, f"0x{error_code:x}")
                headers["last_stream_id"] = str(last_stream)
                headers["error_code"] = error_name

            elif frame_type == _FRAME_PING:
                is_ack = bool(flags & 0x01)
                headers["PING"] = "ACK" if is_ack else "request"
                primary_type = "PING"

        url = H2_URL_CONNECTION_SETUP if preface_seen else H2_URL_CONNECTION_CONTROL

        return ParseResult(
            protocol="HTTP/2",
            method=primary_type,
            url=url,
            is_request=(direction == "write"),
            is_complete=True,
            headers=headers,
            stream_id=0,
            is_control_frame=True,
        )
