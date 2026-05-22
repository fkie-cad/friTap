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
from .base import BaseParser, ParseResult, apply_http2_headers
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
        if _qpack_available:
            self._qpack_decoder = pylsqpack.Decoder(4096, 16)
        else:
            self._qpack_decoder = None

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
        buf_key = direction if stream_id is None else f"{direction}:{stream_id}"
        if buf_key not in self._buffers:
            self._buffers[buf_key] = bytearray()
        buf = self._buffers[buf_key]
        buf.extend(data)
        results: list[ParseResult] = []

        while buf:
            # Try to parse frame header (type + length varints)
            try:
                frame_type, type_len = decode_varint(buf, 0)
                frame_length, len_len = decode_varint(buf, type_len)
            except (ValueError, IndexError):
                break  # Need more data

            total = type_len + len_len + frame_length
            if len(buf) < total:
                break  # Need more data

            payload = bytes(buf[type_len + len_len:total])
            del buf[:total]

            self._process_frame(frame_type, payload, direction, results, stream_id)

        return results

    def flush(self) -> list[ParseResult]:
        """Return partial streams as incomplete results."""
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

    def _decode_headers(self, stream: _H3StreamState, payload: bytes, direction: str) -> None:
        """Decode QPACK-compressed headers."""
        headers = []
        if self._qpack_decoder is not None:
            try:
                decoded = self._qpack_decoder.feed_header(stream.stream_id, payload)
                headers = [(name if isinstance(name, str) else name.decode("latin-1", errors="replace"),
                           value if isinstance(value, str) else value.decode("latin-1", errors="replace"))
                          for name, value in decoded]
            except Exception:
                # QPACK decoding failed, try raw scanning
                headers = self._scan_raw_headers(payload)
        else:
            headers = self._scan_raw_headers(payload)

        apply_http2_headers(stream, headers)

        # If no pseudo-headers found, infer from direction
        if not stream.method and not stream.status_code:
            stream.is_request = (direction == "write")

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
