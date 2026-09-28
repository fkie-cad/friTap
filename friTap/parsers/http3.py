"""HTTP/3 frame parser (RFC 9114).

HTTP/3 runs over QUIC. This parser handles HTTP/3 frame-level parsing
when QUIC hooks are active. It parses:
- DATA frames (0x00): body data
- HEADERS frames (0x01): QPACK-compressed headers
- SETTINGS frames (0x04): connection settings
- GOAWAY frames (0x07): graceful shutdown
- Other frame types are skipped
"""

from friTap.constants import PROTOCOL_HTTP3

from .base import BaseParser, ParseResult, accumulate_body, apply_http2_headers
from .h3_streams import (
    KIND_CONTROL,
    KIND_PUSH,
    KIND_QPACK_ENCODER,
    KIND_REQUEST,
    SIDE_CLIENT,
    SIDE_SERVER,
    UNI_STREAM_PUSH,
    UniStreamState,
    is_client_initiated,
    is_uni,
    kind_for_uni_type,
    parse_settings,
    settings_to_headers,
)
from .http2 import H2_URL_CONNECTION_CONTROL
from .qpack_context import QpackDecoderContext
from .varint import decode_varint

# Try to import pylsqpack for QPACK header decompression
_qpack_available = False
try:
    import pylsqpack
    _qpack_available = True
except ImportError:
    pass

# HTTP/3 frame types (RFC 9114 Section 7.2)
_FRAME_DATA = 0x00
_FRAME_HEADERS = 0x01
_FRAME_CANCEL_PUSH = 0x03
_FRAME_SETTINGS = 0x04
_FRAME_PUSH_PROMISE = 0x05
_FRAME_GOAWAY = 0x07
_FRAME_MAX_PUSH_ID = 0x0D

# Known frame types for detection
_KNOWN_FRAME_TYPES = frozenset({
    _FRAME_DATA, _FRAME_HEADERS, _FRAME_CANCEL_PUSH,
    _FRAME_SETTINGS, _FRAME_PUSH_PROMISE, _FRAME_GOAWAY,
    _FRAME_MAX_PUSH_ID,
})

# Maximum reasonable frame length for detection (16MB)
_MAX_FRAME_LENGTH = 16 * 1024 * 1024

# Direction labels and their opposite (client-direction inference)
_OPPOSITE_DIRECTION = {"write": "read", "read": "write"}
_DEFAULT_CLIENT_DIRECTION = "write"

# Responses that never carry a body (RFC 9110 6.4.1)
_BODYLESS_STATUSES = frozenset({204, 304})

# Cap on buffered QPACK encoder-stream bytes per side (consumed by Phase Q5)
_MAX_ENCODER_BUFFER = 1024 * 1024

# SETTINGS identifiers that size a QPACK dynamic table (RFC 9204 5)
_SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0x01
_SETTINGS_QPACK_BLOCKED_STREAMS = 0x07

_OTHER_SIDE = {SIDE_CLIENT: SIDE_SERVER, SIDE_SERVER: SIDE_CLIENT}


class _H3StreamState:
    """Per-stream state for HTTP/3."""
    __slots__ = (
        "stream_id", "headers", "body_size", "is_request",
        "method", "url", "host", "status_code", "status_text",
        "content_encoding", "content_type", "headers_received",
    )

    def __init__(self, stream_id: int = 0) -> None:
        self.stream_id = stream_id
        self.headers: dict[str, str] = {}
        self.body_size: int = 0
        self.is_request: bool = True
        self.method: str = ""
        self.url: str = ""
        self.host: str = ""
        self.status_code: int = 0
        self.status_text: str = ""
        self.content_encoding: str = ""
        self.content_type: str = ""
        self.headers_received: bool = False


class Http3Parser(BaseParser):
    """HTTP/3 frame parser.

    Parses HTTP/3 frames from QUIC stream data. Uses pylsqpack for
    QPACK header decompression when available, falls back to raw
    pseudo-header scanning otherwise.
    """

    PROTOCOL = PROTOCOL_HTTP3

    def __init__(self) -> None:
        self._buffers: dict[str, bytearray] = {}  # per-direction buffers
        self._active_streams: dict[str, dict[int, _H3StreamState]] = {}  # direction -> {stream_id: state}
        self._current_stream: dict[str, int] = {}  # direction -> current active stream_id (for non-muxed mode)
        self._stream_counter: int = 0
        # Muxed (real QUIC stream id) mode state
        self._uni_streams: dict[int, UniStreamState] = {}
        self._client_direction: str | None = None
        self._client_direction_certain: bool = False
        self._peer_settings: dict[str, dict[int, int]] = {}
        self._encoder_bytes: dict[str, bytearray] = {}
        self._finished_streams: set[int] = set()
        # Muxed mode QPACK: one decoding context per ENCODER side, and the
        # direction of every header block waiting in a context.
        self._qpack_ctx = self._new_qpack_contexts()
        self._waiting_blocks: dict[tuple[str, int], str] = {}
        if _qpack_available:
            self._qpack_decoder = pylsqpack.Decoder(4096, 16)
        else:
            self._qpack_decoder = None

    @classmethod
    def _new_qpack_contexts(cls) -> dict[str, QpackDecoderContext] | None:
        """Per encoder side QPACK contexts, or None without pylsqpack."""
        if not _qpack_available:
            return None
        return {side: QpackDecoderContext(fallback=cls._scan_raw_headers)
                for side in (SIDE_CLIENT, SIDE_SERVER)}

    def can_parse(self, data: bytes) -> bool:
        """Detect HTTP/3 framing patterns.

        Tries to decode a varint frame type + length and checks if the
        frame type is a known HTTP/3 type with a reasonable length.
        """
        if not data or len(data) < 2:
            return False
        try:
            frame_type, type_len = decode_varint(data, 0)
            if type_len + 1 > len(data):
                return False
            frame_length, _ = decode_varint(data, type_len)
            # Must be a known HTTP/3 frame type with reasonable length
            if frame_type in _KNOWN_FRAME_TYPES and frame_length <= _MAX_FRAME_LENGTH:
                return True
        except (ValueError, IndexError):
            pass
        return False

    def feed(self, data: bytes, direction: str,
             stream_id: int | None = None) -> list[ParseResult]:
        """Parse HTTP/3 frames and return completed results.

        When ``stream_id`` is provided (QUIC stream multiplexing), frames are
        reassembled and bucketed per stream so interleaved streams do not get
        concatenated. When it is ``None`` the parser keeps its legacy
        non-muxed behavior (a single current stream per direction).
        """
        if stream_id is not None:
            return self._feed_muxed(data, direction, stream_id)
        buf_key = direction if stream_id is None else f"{direction}:{stream_id}"
        if buf_key not in self._buffers:
            self._buffers[buf_key] = bytearray()
        buf = self._buffers[buf_key]
        buf.extend(data)
        results: list[ParseResult] = []

        # Complete frames only; a trailing partial frame waits for more data.
        for frame_type, payload in self._drain_frames(buf):
            self._process_frame(frame_type, payload, direction, results, stream_id)

        return results

    def flush(self) -> list[ParseResult]:
        """Return partial streams as incomplete results."""
        self._apply_blocked_fallbacks()
        results: list[ParseResult] = []
        for streams in self._active_streams.values():
            for stream in streams.values():
                if stream.headers_received or stream.body_size:
                    result = self._build_result(stream, is_complete=False)
                    results.append(result)
        self._active_streams.clear()
        self._current_stream.clear()
        self._buffers.clear()
        return results

    # ------------------------------------------------------------------
    # Muxed mode: real QUIC stream ids (RFC 9114 stream model)
    # ------------------------------------------------------------------

    def stream_kind(self, stream_id: int) -> str:
        """What *stream_id* carries: request, control, qpack_encoder,
        qpack_decoder, push or unknown (unidirectional type not seen yet,
        reserved/grease type)."""
        if not is_uni(stream_id):
            return KIND_REQUEST
        state = self._uni_streams.get(stream_id)
        return kind_for_uni_type(state.stype if state else None)

    def _feed_muxed(self, data: bytes, direction: str,
                    stream_id: int) -> list[ParseResult]:
        """Route one real-stream-id chunk to the uni or bidi stream handler."""
        self._learn_client_direction(stream_id, direction)
        if is_uni(stream_id):
            return self._feed_uni(stream_id, data, direction)
        return self._feed_bidi(stream_id, data, direction)

    def _learn_client_direction(self, stream_id: int, direction: str) -> None:
        """Infer which direction label is the client's from stream ownership.

        A unidirectional stream only carries its initiator's bytes, so it is
        conclusive. The first data seen on a client-initiated bidirectional
        stream is normally the request and is used until something
        conclusive arrives. Defaults to ``"write"`` while nothing is known.
        """
        opposite = _OPPOSITE_DIRECTION.get(direction)
        if opposite is None or self._client_direction_certain:
            return
        if is_uni(stream_id):
            self._client_direction = (direction if is_client_initiated(stream_id)
                                      else opposite)
            self._client_direction_certain = True
        elif self._client_direction is None and is_client_initiated(stream_id):
            self._client_direction = direction

    @property
    def client_direction(self) -> str:
        """The direction label ("write"/"read") carrying client bytes."""
        return self._client_direction or _DEFAULT_CLIENT_DIRECTION

    def _side_of(self, direction: str) -> str:
        """``"client"`` or ``"server"`` for a direction label."""
        return SIDE_CLIENT if direction == self.client_direction else SIDE_SERVER

    @staticmethod
    def _drain_frames(buf: bytearray):
        """Yield ``(frame_type, payload)`` for every complete frame in *buf*,
        removing it; a trailing partial frame stays buffered."""
        while buf:
            try:
                frame_type, type_len = decode_varint(buf, 0)
                frame_length, len_len = decode_varint(buf, type_len)
            except (ValueError, IndexError):
                return
            total = type_len + len_len + frame_length
            if len(buf) < total:
                return
            payload = bytes(buf[type_len + len_len:total])
            del buf[:total]
            yield frame_type, payload

    # -- unidirectional streams ------------------------------------------

    def _feed_uni(self, stream_id: int, data: bytes,
                  direction: str) -> list[ParseResult]:
        """Consume a unidirectional stream chunk according to its type."""
        state = self._uni_streams.setdefault(stream_id, UniStreamState())
        state.buf.extend(data)
        if not self._read_uni_prefix(state):
            return []
        kind = kind_for_uni_type(state.stype)
        if kind == KIND_CONTROL:
            return self._feed_control(stream_id, state, self._side_of(direction))
        if kind == KIND_QPACK_ENCODER:
            data = bytes(state.buf)
            state.buf.clear()
            return self._on_encoder_bytes(self._side_of(direction), data)
        if kind == KIND_PUSH:
            return self._feed_push(stream_id, state, direction)
        state.buf.clear()  # decoder/grease streams are ignored
        return []

    @staticmethod
    def _read_uni_prefix(state: UniStreamState) -> bool:
        """Read the stream-type varint (and a push stream's push id) once.

        Returns False while the prefix is still incomplete.
        """
        try:
            if state.stype is None:
                state.stype, used = decode_varint(state.buf, 0)
                del state.buf[:used]
            if state.stype == UNI_STREAM_PUSH and state.push_id is None:
                state.push_id, used = decode_varint(state.buf, 0)
                del state.buf[:used]
        except (ValueError, IndexError):
            return False
        return True

    def _feed_control(self, stream_id: int, state: UniStreamState,
                      side: str) -> list[ParseResult]:
        """Parse control-stream frames; the first SETTINGS yields one result.

        GOAWAY, MAX_PUSH_ID, CANCEL_PUSH and unknown frames are consumed.
        """
        results: list[ParseResult] = []
        for frame_type, payload in self._drain_frames(state.buf):
            if frame_type != _FRAME_SETTINGS or state.settings_seen:
                continue
            state.settings_seen = True
            settings = parse_settings(payload)
            self._peer_settings[side] = settings
            results.append(self._control_result(
                stream_id, side, "SETTINGS", settings_to_headers(settings)))
            results.extend(self._configure_qpack(side, settings))
        return results

    def _on_encoder_bytes(self, side: str, data: bytes) -> list[ParseResult]:
        """Feed QPACK encoder-stream bytes sent by *side* to its context.

        Returns results of request/response streams the inserts unblocked.
        """
        buffered = self._encoder_bytes.setdefault(side, bytearray())
        accumulate_body(buffered, data, _MAX_ENCODER_BUFFER)
        if self._qpack_ctx is None:
            return []
        return self._resume_blocks(side, self._qpack_ctx[side].feed_encoder(data))

    def _configure_qpack(self, settings_side: str,
                         settings: dict[int, int]) -> list[ParseResult]:
        """Size the table of the OTHER side's encoder from *settings_side*'s
        SETTINGS (the decoder advertises its limits, RFC 9204 3.2.3).

        An absent capacity means the dynamic table is disabled (0).
        """
        if self._qpack_ctx is None:
            return []
        encoder_side = _OTHER_SIDE[settings_side]
        unblocked = self._qpack_ctx[encoder_side].configure(
            settings.get(_SETTINGS_QPACK_MAX_TABLE_CAPACITY, 0),
            settings.get(_SETTINGS_QPACK_BLOCKED_STREAMS, 0))
        return self._resume_blocks(encoder_side, unblocked)

    def _resume_blocks(self, side: str, stream_ids: list[int]) -> list[ParseResult]:
        """Apply the headers of now-decodable waiting blocks -> one result each."""
        results: list[ParseResult] = []
        for stream_id in stream_ids:
            direction = self._waiting_blocks.pop((side, stream_id), None)
            headers = self._qpack_ctx[side].resume(stream_id)
            if direction is None or stream_id in self._finished_streams:
                continue
            stream = self._get_stream(direction, stream_id)
            self._apply_header_pairs(stream, self._to_str_pairs(headers), direction)
            results.append(self._message_result(stream_id, direction))
            if side == SIDE_CLIENT:
                results.extend(self._held_response_result(stream_id))
        return results

    def _apply_blocked_fallbacks(self) -> None:
        """At flush: raw-scan header blocks that never became decodable."""
        if self._qpack_ctx is None:
            return
        for side, ctx in self._qpack_ctx.items():
            for stream_id, block in ctx.drain_fallback().items():
                direction = self._waiting_blocks.pop((side, stream_id), None)
                if direction is None or stream_id in self._finished_streams:
                    continue
                stream = self._get_stream(direction, stream_id)
                self._apply_header_pairs(stream, self._scan_raw_headers(block), direction)

    def _feed_push(self, stream_id: int, state: UniStreamState,
                   direction: str) -> list[ParseResult]:
        """A push stream carries a response after its push id."""
        data = bytes(state.buf)
        state.buf.clear()
        return self._feed_bidi(stream_id, data, direction)

    @staticmethod
    def _control_result(stream_id: int, side: str, frame_name: str,
                        headers: dict[str, str]) -> ParseResult:
        """A connection-level control-frame result (mirrors HTTP/2's)."""
        return ParseResult(
            protocol="HTTP/3",
            method=frame_name,
            url=H2_URL_CONNECTION_CONTROL,
            is_request=(side == SIDE_CLIENT),
            is_complete=True,
            headers=headers,
            stream_id=stream_id,
            is_control_frame=True,
        )

    # -- request streams (and push responses) ----------------------------

    def _feed_bidi(self, stream_id: int, data: bytes,
                   direction: str) -> list[ParseResult]:
        """Parse a request-stream chunk -> at most one result for the stream."""
        buf_key = f"{direction}:{stream_id}"
        if stream_id in self._finished_streams:
            self._buffers.pop(buf_key, None)
            return []  # late bytes of a completed exchange
        buf = self._buffers.setdefault(buf_key, bytearray())
        buf.extend(data)
        dirty = False
        for frame_type, payload in self._drain_frames(buf):
            dirty |= self._apply_message_frame(stream_id, direction, frame_type, payload)
        if not dirty:
            return []
        return [self._message_result(stream_id, direction)]

    def _apply_message_frame(self, stream_id: int, direction: str,
                             frame_type: int, payload: bytes) -> bool:
        """Apply a HEADERS/DATA frame; True when the message state changed."""
        if frame_type == _FRAME_HEADERS:
            stream = self._get_stream(direction, stream_id)
            self._start_header_block(stream)
            if self._qpack_ctx is None:
                self._decode_headers(stream, payload, direction, self.client_direction)
                stream.headers_received = True
                return True
            return self._decode_muxed_block(stream, payload, direction)
        if frame_type == _FRAME_DATA:
            stream = self._get_stream(direction, stream_id)
            stream.body_size += len(payload)
            return stream.headers_received
        return False  # PUSH_PROMISE, reserved and unknown frames

    def _decode_muxed_block(self, stream: _H3StreamState, payload: bytes,
                            direction: str) -> bool:
        """Decode a header block in the encoder side's context.

        Returns False while the block waits for SETTINGS or table inserts;
        its headers are applied later by _resume_blocks or at flush.
        """
        side = self._side_of(direction)
        decoded = self._qpack_ctx[side].decode(stream.stream_id, payload)
        if decoded is None:
            self._waiting_blocks[(side, stream.stream_id)] = direction
            return False
        self._apply_header_pairs(stream, self._to_str_pairs(decoded), direction)
        return True

    def _apply_header_pairs(self, stream: _H3StreamState, headers: list,
                            direction: str) -> None:
        """Apply decoded (name, value) pairs; infer the role if no pseudo-header."""
        apply_http2_headers(stream, headers)
        if not stream.method and not stream.status_code:
            stream.is_request = (direction == self.client_direction)
        stream.headers_received = True

    @staticmethod
    def _start_header_block(stream: _H3StreamState) -> None:
        """A HEADERS block after a 1xx interim response starts the final one."""
        if 100 <= stream.status_code < 200:
            stream.headers.clear()
            stream.status_code = 0

    def _message_result(self, stream_id: int, direction: str) -> ParseResult:
        """Build the stream's current result; retire the stream once its
        response is complete."""
        stream = self._get_stream(direction, stream_id)
        is_complete = (self._is_message_complete(stream)
                       and not self._request_headers_waiting(stream))
        result = self._build_result(stream, is_complete=is_complete)
        if is_complete and not stream.is_request:
            self._finish_stream(stream_id)
        return result

    def _request_headers_waiting(self, stream: _H3StreamState) -> bool:
        """True for a response whose request's header block still waits.

        Completing (and retiring) the exchange now would drop the request's
        headers when they resume, so the response stays open until then.
        """
        return (not stream.is_request
                and (SIDE_CLIENT, stream.stream_id) in self._waiting_blocks)

    def _held_response_result(self, stream_id: int) -> list[ParseResult]:
        """Re-emit a response held open by _request_headers_waiting."""
        direction = _OPPOSITE_DIRECTION.get(self.client_direction, "read")
        response = self._active_streams.get(direction, {}).get(stream_id)
        if response is None or response.is_request or not response.headers_received:
            return []
        if not self._is_message_complete(response):
            return []
        return [self._message_result(stream_id, direction)]

    def _is_message_complete(self, stream: _H3StreamState) -> bool:
        """Request: headers plus any announced body. Response: see below."""
        if stream.is_request:
            content_length = self._content_length(stream)
            return not content_length or stream.body_size >= content_length
        return self._is_response_complete(stream)

    def _is_response_complete(self, stream: _H3StreamState) -> bool:
        """Complete on 204/304, a HEAD request or content-length reached.

        1xx interim responses never complete; anything else is completed by
        the collector at finalize/flush time (the stream FIN is not visible).
        """
        status = stream.status_code
        if 100 <= status < 200:
            return False
        if status in _BODYLESS_STATUSES or self._is_head_request(stream.stream_id):
            return True
        content_length = self._content_length(stream)
        return content_length is not None and stream.body_size >= content_length

    def _is_head_request(self, stream_id: int) -> bool:
        """True if the client sent a HEAD request on *stream_id*."""
        streams = self._active_streams.get(self.client_direction, {})
        request = streams.get(stream_id)
        return request is not None and request.method == "HEAD"

    @staticmethod
    def _content_length(stream: _H3StreamState) -> int | None:
        """The message's content-length header, or None when absent/invalid."""
        value = stream.headers.get("content-length")
        try:
            return int(value) if value is not None else None
        except ValueError:
            return None

    def _finish_stream(self, stream_id: int) -> None:
        """Forget a completed exchange; later bytes of it are ignored."""
        self._finished_streams.add(stream_id)
        for streams in self._active_streams.values():
            streams.pop(stream_id, None)
        for direction in _OPPOSITE_DIRECTION:
            self._buffers.pop(f"{direction}:{stream_id}", None)

    def _get_stream(self, direction: str, stream_id: int | None = None) -> _H3StreamState:
        """Get or create stream for a direction.

        Uses stream_id if provided (future QUIC hooks). Otherwise uses
        the current active stream for the direction (non-muxed mode).
        """
        if direction not in self._active_streams:
            self._active_streams[direction] = {}
        streams = self._active_streams[direction]

        if stream_id is not None:
            if stream_id not in streams:
                streams[stream_id] = _H3StreamState(stream_id)
            return streams[stream_id]

        # Non-muxed mode: use current active stream for this direction
        sid = self._current_stream.get(direction)
        if sid is not None and sid in streams:
            return streams[sid]

        # Create new stream
        self._stream_counter += 1
        sid = self._stream_counter
        self._current_stream[direction] = sid
        streams[sid] = _H3StreamState(sid)
        return streams[sid]

    def _process_frame(self, frame_type: int, payload: bytes,
                       direction: str, results: list[ParseResult],
                       stream_id: int | None = None) -> None:
        """Process a single HTTP/3 frame."""
        if frame_type == _FRAME_HEADERS:
            stream = self._get_stream(direction, stream_id)
            # Non-muxed mode: a second HEADERS frame means a new message —
            # emit the previous one and start fresh on a new synthetic stream.
            if (stream_id is None
                    and stream.headers_received
                    and (stream.method or stream.status_code)):
                result = self._build_result(stream)
                results.append(result)
                # Remove old stream, create new
                streams = self._active_streams.get(direction, {})
                streams.pop(stream.stream_id, None)
                self._stream_counter += 1
                sid = self._stream_counter
                self._current_stream[direction] = sid
                stream = _H3StreamState(sid)
                if direction not in self._active_streams:
                    self._active_streams[direction] = {}
                self._active_streams[direction][sid] = stream

            self._decode_headers(stream, payload, direction)
            stream.headers_received = True
            # Muxed mode: the collector correlates by stream_id, so emit the
            # result as soon as headers are known for this stream.
            if stream_id is not None:
                results.append(self._build_result(stream))

        elif frame_type == _FRAME_DATA:
            stream = self._get_stream(direction, stream_id)
            stream.body_size += len(payload)

        elif frame_type == _FRAME_GOAWAY:
            # Flush all active streams
            for streams in list(self._active_streams.values()):
                for stream in streams.values():
                    if stream.headers_received:
                        result = self._build_result(stream, is_complete=False)
                        results.append(result)
            self._active_streams.clear()
            self._current_stream.clear()

        # Other frame types (SETTINGS, CANCEL_PUSH, etc.) are silently skipped

    def _decode_headers(self, stream: _H3StreamState, payload: bytes, direction: str,
                        client_direction: str = _DEFAULT_CLIENT_DIRECTION) -> None:
        """Decode QPACK-compressed headers."""
        headers = []
        if self._qpack_decoder is not None:
            try:
                # pylsqpack returns (decoder_stream_bytes, headers)
                _control, decoded = self._qpack_decoder.feed_header(stream.stream_id, payload)
                headers = self._to_str_pairs(decoded)
            except pylsqpack.StreamBlocked:
                # Needs dynamic-table inserts we have not seen: raw-scan for now
                headers = self._scan_raw_headers(payload)
            except Exception:
                # QPACK decoding failed, try raw scanning
                headers = self._scan_raw_headers(payload)
        else:
            headers = self._scan_raw_headers(payload)

        apply_http2_headers(stream, headers)

        # If no pseudo-headers found, infer from direction
        if not stream.method and not stream.status_code:
            stream.is_request = (direction == client_direction)

    @staticmethod
    def _to_str_pairs(decoded) -> list[tuple[str, str]]:
        """Convert QPACK (name, value) pairs, bytes or str, to latin-1 strings."""
        return [(Http3Parser._to_str(name), Http3Parser._to_str(value))
                for name, value in decoded]

    @staticmethod
    def _to_str(value) -> str:
        """Decode a bytes header field as latin-1; pass str through."""
        if isinstance(value, str):
            return value
        return bytes(value).decode("latin-1", errors="replace")

    @staticmethod
    def _scan_raw_headers(payload: bytes) -> list[tuple[str, str]]:
        """Scan raw bytes for HTTP pseudo-header patterns."""
        headers = []
        pseudo_headers = [b":method", b":path", b":status", b":authority", b":scheme"]
        for pseudo in pseudo_headers:
            idx = payload.find(pseudo)
            if idx == -1:
                continue
            value_start = idx + len(pseudo)
            while value_start < len(payload) and payload[value_start:value_start + 1] in (b"\x00", b"\x01", b"\x02", b"\x03"):
                value_start += 1
            value_end = value_start
            while value_end < len(payload) and 0x20 <= payload[value_end] <= 0x7E:
                value_end += 1
            if value_end > value_start:
                name = pseudo.decode("ascii")
                value = payload[value_start:value_end].decode("ascii", errors="replace")
                headers.append((name, value))
        return headers

    @staticmethod
    def _build_result(stream: _H3StreamState, is_complete: bool = True) -> ParseResult:
        """Build ParseResult from stream state."""
        return ParseResult(
            protocol="HTTP/3",
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
            stream_id=stream.stream_id,
        )


def build_h3_result_from_headers(
    headers: list,
    stream_id: int,
    direction: str,
    body_size: int = 0,
) -> ParseResult:
    """Build a ParseResult from already-decoded HTTP/3 headers.

    Used by the "app-api" (Boundary 4) capture mode where the application's
    own QPACK decoder already produced the header name/value pairs, so no
    QPACK decoding or frame parsing is needed. ``headers`` is an iterable of
    ``(name, value)`` pairs (or ``[name, value]`` lists). ``stream_id`` is the
    (synthetic, positive) stream identifier used for flow multiplexing.
    """
    stream = _H3StreamState(stream_id)
    stream.body_size = body_size
    apply_http2_headers(stream, [(n, v) for n, v in headers])
    if not stream.method and not stream.status_code:
        # No pseudo-headers present — infer direction ("write" == request).
        stream.is_request = (direction == "write")
    stream.headers_received = True
    return Http3Parser._build_result(stream)
