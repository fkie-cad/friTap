"""HTTP/2 frame-level parser with HPACK decompression via hpack library."""

import logging
from collections import OrderedDict

_log = logging.getLogger(__name__)

# Try to import hpack for HPACK header decompression
_hpack_available = False
try:
    from hpack import Decoder as HpackDecoder
    from hpack import HPACKDecodingError
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
from .http2_constants import (  # noqa: E402
    HTTP2_FRAME_TYPE_NAMES,
    HTTP2_PREFACE,
    unpack_frame_header,
)

# HTTP/2 connection preface (legacy private alias of the shared constant)
_CONNECTION_PREFACE = HTTP2_PREFACE

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

# --- Hardening limits (parsed bytes are attacker-controlled) ---
# Cap on an accumulated (HEADERS/PUSH_PROMISE + CONTINUATION) header block. A
# CONTINUATION flood beyond this poisons the direction (the HPACK table cannot
# stay in sync without decoding the block) and frees the buffer.
_MAX_HEADER_BLOCK_SIZE = 256 * 1024
# Explicit decompressed-size cap for a single header list (hpack Decoder).
_MAX_HEADER_LIST_SIZE = 65536
# Upper bound on a peer-advertised SETTINGS_HEADER_TABLE_SIZE we honor.
_MAX_HEADER_TABLE_SIZE = 1024 * 1024
# Cap on concurrently-open stream states per direction; the oldest is evicted.
_MAX_OPEN_STREAMS = 1024
# Caps on the merged header fields of one stream across repeated HEADERS
# blocks (initial headers + trailers), so intermediate copies stay bounded.
_MAX_STREAM_HEADER_FIELDS = 512
_MAX_STREAM_HEADER_BYTES = 256 * 1024
# RFC 7541 §4.1 per-entry overhead used when sizing header fields.
_HEADER_FIELD_OVERHEAD = 32
# RFC 7540 §6.5.2 SETTINGS_MAX_FRAME_SIZE bounds.
_DEFAULT_MAX_FRAME_SIZE = 16384
_MAX_ALLOWED_FRAME_SIZE = 16777215

# SETTINGS parameter ids we act on (RFC 7540 §6.5.2).
_SETTINGS_HEADER_TABLE_SIZE = 0x1
_SETTINGS_MAX_FRAME_SIZE = 0x5
_FLAG_ACK = 0x01

# Frame types that may create per-stream state for a new stream id. Other
# stream-level frames (PRIORITY, WINDOW_UPDATE, RST_STREAM, ...) never do, so a
# flood of them on fresh ids allocates nothing. CONTINUATION is kept so a stray
# one is still surfaced as a protocol error (#39).
_STREAM_CREATING_FRAMES = frozenset({
    _FRAME_HEADERS, _FRAME_DATA, _FRAME_PUSH_PROMISE, _FRAME_CONTINUATION,
})

# Frames whose payload carries an HPACK header-block fragment.
_HEADER_BLOCK_FRAMES = frozenset({
    _FRAME_HEADERS, _FRAME_PUSH_PROMISE, _FRAME_CONTINUATION,
})

# The peer direction whose encoder a direction's SETTINGS constrain.
_OPPOSITE_DIRECTION = {"read": "write", "write": "read"}

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

# Frame type display names (shared table; legacy private alias)
_FRAME_TYPE_NAMES = HTTP2_FRAME_TYPE_NAMES

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


def decode_header_text(raw) -> str:
    """Decode a raw header name/value to text.

    UTF-8 (identical to hpack's own decoding) with a per-field latin-1
    fallback for non-UTF-8 bytes; a ``str`` is returned unchanged. Shared by
    every parser that must render header fields exactly as HTTP/2 does.
    """
    if isinstance(raw, str):
        return raw
    data = bytes(raw)
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1")


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
        "header_block_invalid", "header_blocks_decoded", "header_list_bytes",
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
        # True once the real-HEADERS block currently being accumulated was
        # rejected (oversize / invalid padding); its decode is skipped so the
        # specific error is not overwritten by "hpack-desync".
        self.header_block_invalid: bool = False
        # Number of real HEADERS blocks decoded so far; a block after the first
        # one (typically END_STREAM trailers) is also kept in ``trailers``.
        self.header_blocks_decoded: int = 0
        # Running size of the fields merged into ``headers`` (capped).
        self.header_list_bytes: int = 0


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
        # Insertion-ordered so the oldest open stream can be evicted once a
        # direction exceeds ``_MAX_OPEN_STREAMS``.
        self._streams: dict[str, OrderedDict[int, _StreamState]] = {}
        self._preface_seen: dict[str, bool] = {}
        # Once a direction's HPACK decoder hits an unrecoverable desync it is
        # poisoned: HPACK is stateful and cannot resync after a missed dynamic-
        # table insertion, so every later decode on that direction would fail.
        self._decoder_failed: dict[str, bool] = {}
        # Peer-advertised SETTINGS_MAX_FRAME_SIZE bounding the frames *sent by*
        # each direction; absent until observed.
        self._max_frame_size: dict[str, int] = {}
        # Payload bytes of an oversize frame still to be skipped, per
        # direction. They are counted off as they arrive, never buffered.
        self._skip_remaining: dict[str, int] = {}
        # Opt-in ``(direction, stream_id, raw_frame)`` log of every consumed
        # frame (see enable_frame_log); None while disabled.
        self._frame_log: list[tuple[str, int, bytes]] | None = None
        # Per direction: frames of a header block still awaiting END_HEADERS,
        # logged together once the block closes (see _log_frame).
        self._held_block: dict[str, list[tuple[str, int, bytes]]] = {}
        self._held_block_bytes: dict[str, int] = {}

    @staticmethod
    def _new_decoder():
        """Create an HPACK decoder with an explicit header-list size cap."""
        if not _hpack_available:
            return None
        return HpackDecoder(max_header_list_size=_MAX_HEADER_LIST_SIZE)

    def _ensure_direction(self, direction: str) -> None:
        """Lazily initialize per-direction state."""
        if direction not in self._decoders:
            self._decoders[direction] = self._new_decoder()
            self._buffers[direction] = bytearray()
            self._streams[direction] = OrderedDict()
            self._preface_seen[direction] = False
            self._decoder_failed[direction] = False
            self._skip_remaining[direction] = 0
            self._held_block[direction] = []
            self._held_block_bytes[direction] = 0

    # --- Frame log (per-frame byte attribution for the flow collector) -----

    def enable_frame_log(self) -> None:
        """Start recording the raw bytes of every frame this parser consumes.

        The flow collector uses it to hand each HTTP/2 stream's flow exactly
        its own frames. Off by default, so other users retain nothing extra.
        """
        if self._frame_log is None:
            self._frame_log = []

    def take_frame_log(self) -> list[tuple[str, int, bytes]]:
        """Return and clear the ``(direction, stream_id, raw_frame)`` log.

        Entries are complete frames (9-byte header included) in wire order;
        the connection preface is reported on stream 0. A header block
        (HEADERS/PUSH_PROMISE plus CONTINUATIONs) is reported as a whole once
        END_HEADERS arrives, i.e. in the same feed as the result it produces.
        Oversize frames are skipped unbuffered and so never reported.
        :meth:`flush` adds whatever was still held or partially buffered.
        """
        log = self._frame_log
        if not log:
            return []
        self._frame_log = []
        return log

    @staticmethod
    def _opens_header_block(frame_type: int, flags: int) -> bool:
        """True for a header-block frame that is not the block's last one."""
        return frame_type in _HEADER_BLOCK_FRAMES and not flags & _FLAG_END_HEADERS

    def _log_frame(self, direction: str, stream_id: int, raw: bytes,
                   holds_block: bool = False) -> None:
        """Append *raw* to the frame log; no-op while the log is disabled.

        Frames of a still-open header block (*holds_block*) are held back
        and released together with the frame that closes the block. The
        hold is capped at ``_MAX_HEADER_BLOCK_SIZE`` (the parser rejects such
        a block anyway), so a CONTINUATION flood cannot grow it unbounded.
        """
        if self._frame_log is None:
            return
        held = self._held_block[direction]
        held.append((direction, stream_id, raw))
        self._held_block_bytes[direction] += len(raw)
        if holds_block and self._held_block_bytes[direction] <= _MAX_HEADER_BLOCK_SIZE:
            return
        self._release_held_block(direction)

    def _release_held_block(self, direction: str) -> None:
        """Move *direction*'s held header-block frames into the frame log."""
        self._frame_log.extend(self._held_block[direction])
        self._held_block[direction].clear()
        self._held_block_bytes[direction] = 0

    def _log_unframed(self) -> None:
        """At flush: log held header blocks and partially buffered frames."""
        if self._frame_log is None:
            return
        for direction, buf in self._buffers.items():
            self._release_held_block(direction)
            if buf:
                self._frame_log.append(
                    (direction, self._leftover_stream_id(buf), bytes(buf)))

    @staticmethod
    def _leftover_stream_id(buf: bytearray) -> int:
        """Stream id of a partially buffered frame (0 without a full header)."""
        if len(buf) < _FRAME_HEADER_SIZE:
            return 0
        return unpack_frame_header(buf)[3]

    def _pop_frame(self, buf: bytearray, total: int, direction: str,
                   stream_id: int, frame_type: int, flags: int) -> bytes:
        """Remove one complete frame from *buf*, log it, return its payload."""
        if self._frame_log is None:
            payload = bytes(buf[_FRAME_HEADER_SIZE:total])
        else:
            raw = bytes(buf[:total])
            payload = raw[_FRAME_HEADER_SIZE:]
            self._log_frame(direction, stream_id, raw,
                            self._opens_header_block(frame_type, flags))
        del buf[:total]
        return payload

    # --- Oversize-frame skipping (counted, never buffered) -----------------

    def _skip_incoming(self, direction: str, data: bytes):
        """Drop the still-to-skip oversize payload from the head of *data*.

        Returns the remainder as a zero-copy view. Only reached while the
        direction's buffer is empty: a pending skip drains it completely.
        """
        remaining = self._skip_remaining[direction]
        if not remaining:
            return data
        skipped = min(remaining, len(data))
        self._skip_remaining[direction] = remaining - skipped
        return memoryview(data)[skipped:]

    def _skip_buffered(self, direction: str, buf: bytearray) -> bool:
        """Drop still-to-skip oversize payload bytes from *buf*.

        Returns True once nothing is left to skip (parsing may continue).
        """
        remaining = self._skip_remaining[direction]
        if remaining:
            skipped = min(remaining, len(buf))
            del buf[:skipped]
            remaining -= skipped
            self._skip_remaining[direction] = remaining
        return remaining == 0

    def _begin_oversize_skip(
        self, streams: OrderedDict, buf: bytearray, header: tuple[int, int, int, int],
        direction: str,
    ) -> None:
        """Start skipping an oversize frame: drop its header, count its payload.

        A known frame type keeps the ``frame-too-large`` / poisoning handling;
        an unknown type is skipped silently, as unknown types always were.
        """
        length, frame_type, _flags, stream_id = header
        if frame_type <= _MAX_VALID_FRAME_TYPE:
            self._handle_oversize_frame(streams, stream_id, frame_type, length, direction)
        del buf[:_FRAME_HEADER_SIZE]
        self._skip_remaining[direction] = length

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
        # A DATA frame (type 0x0) MUST be associated with a non-zero stream
        # (RFC 7540 Sec 6.1); DATA on stream 0 is a connection error and never
        # valid HTTP/2. Plaintext mDNS/DNS-over-UDP messages start with a zero
        # transaction id + flags (e.g. a response "00 00 84 00 ...") which decode
        # as a zero-stream DATA frame, so without this guard they are mislabelled
        # HTTP/2. A genuine mid-connection DATA frame rides a non-zero stream and
        # is unaffected.
        if frame_type == _FRAME_DATA and stream_id == 0:
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
        buf += self._skip_incoming(direction, data)
        streams = self._streams[direction]
        decoder = self._decoders[direction]
        results: list[ParseResult] = []
        control_frames: list[tuple[int, int, bytes]] = []

        # Strip connection preface if present
        if not self._preface_seen[direction]:
            if buf.startswith(_CONNECTION_PREFACE):
                del buf[:len(_CONNECTION_PREFACE)]
                self._preface_seen[direction] = True
                self._log_frame(direction, 0, _CONNECTION_PREFACE)
            elif _CONNECTION_PREFACE[:len(buf)] == buf:
                # Buffer is a prefix of the connection preface — wait for more data
                return results

        while self._skip_buffered(direction, buf) and len(buf) >= _FRAME_HEADER_SIZE:
            header = self._parse_frame_header(buf[:_FRAME_HEADER_SIZE])
            length, frame_type, flags, stream_id = header

            # A frame above the peer's SETTINGS_MAX_FRAME_SIZE is skipped by
            # counting its payload off as it arrives — never buffered (it may
            # announce up to 16 MiB).
            if self._is_oversize_frame(direction, length):
                self._begin_oversize_skip(streams, buf, header, direction)
                continue

            total_frame_size = _FRAME_HEADER_SIZE + length
            if len(buf) < total_frame_size:
                break

            payload = self._pop_frame(
                buf, total_frame_size, direction, stream_id, frame_type, flags)

            if frame_type > _MAX_VALID_FRAME_TYPE:
                continue

            # Collect connection-level frames (stream_id == 0)
            if stream_id == 0:
                control_frames.append((frame_type, flags, payload))
                if frame_type == _FRAME_SETTINGS:
                    self._apply_peer_settings(direction, flags, payload)
                continue

            if frame_type == _FRAME_RST_STREAM:
                streams.pop(stream_id, None)
                continue

            # PRIORITY / WINDOW_UPDATE / ... carry nothing we track per stream;
            # never allocate state for them (flood on fresh ids, #4).
            if frame_type not in _STREAM_CREATING_FRAMES:
                continue

            stream = self._get_or_create_stream(
                streams, stream_id, direction, results
            )

            # Whether this frame is allowed to honor an END_STREAM flag and
            # finalize the parent request/response stream (#15). A PUSH_PROMISE
            # block — or a CONTINUATION completing one — describes a *pushed*
            # stream and must NEVER close the parent it arrived on.
            finalizes_parent = False

            if frame_type == _FRAME_HEADERS:
                prefix_len = self._headers_prefix_len(flags)
                if self._padded_frame_is_valid(payload, flags, prefix_len):
                    self._append_header_fragment(
                        stream,
                        self._strip_padded_frame(payload, flags, prefix_len),
                        direction,
                    )
                else:
                    self._reject_header_block(stream, direction, "invalid-padding")
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
                if self._padded_frame_is_valid(
                    payload, flags, _PUSH_PROMISE_PREFIX_LEN
                ):
                    self._append_push_fragment(
                        stream,
                        self._strip_padded_frame(
                            payload, flags, _PUSH_PROMISE_PREFIX_LEN
                        ),
                        direction,
                    )
                else:
                    self._reject_push_block(stream, direction, "invalid-padding")
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
                    self._append_push_fragment(stream, payload, direction)
                    if flags & _FLAG_END_HEADERS:
                        self._finalize_push_promise(stream, decoder, direction)
                elif stream.headers_awaiting_continuation:
                    self._append_header_fragment(stream, payload, direction)
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
                if not self._data_padding_is_valid(payload, flags):
                    # Body accounting only; the HPACK table is unaffected.
                    stream.error = stream.error or "invalid-padding"
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
        self._log_unframed()
        for buf in self._buffers.values():
            buf.clear()
        for direction in self._skip_remaining:
            self._skip_remaining[direction] = 0
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

    def _get_or_create_stream(
        self, streams: OrderedDict, stream_id: int, direction: str,
        results: list[ParseResult],
    ) -> _StreamState:
        """``_get_stream`` that first evicts the oldest streams when creating
        a new one would exceed ``_MAX_OPEN_STREAMS`` (#4)."""
        if stream_id not in streams:
            self._evict_oldest_streams(streams, direction, results)
        return self._get_stream(streams, stream_id, direction)

    def _evict_oldest_streams(
        self, streams: OrderedDict, direction: str, results: list[ParseResult],
    ) -> None:
        """Evict the oldest open streams, surfacing each as an incomplete result
        (same shape as flush()). Evicting a stream mid header block loses that
        block, so the direction's HPACK context is poisoned."""
        while len(streams) >= _MAX_OPEN_STREAMS:
            _, evicted = streams.popitem(last=False)
            if evicted.awaiting_continuation:
                self._poison_direction(
                    direction, evicted.stream_id, "stream evicted mid header block"
                )
            if not evicted.error:
                evicted.error = "stream-evicted"
            results.append(self._build_result(evicted, is_complete=False))

    # --- Hardening helpers -------------------------------------------------

    def _poison_direction(self, direction: str, stream_id: int, reason: str) -> None:
        """Mark ``direction``'s HPACK context as unrecoverably desynced."""
        if not self._decoder_failed.get(direction):
            _log.warning(
                "HTTP/2 %s on stream %d (%s) — HPACK decoder poisoned",
                reason, stream_id, direction,
            )
        self._decoder_failed[direction] = True

    @staticmethod
    def _exceeds_block_cap(buffer: bytearray, fragment: bytes) -> bool:
        return len(buffer) + len(fragment) > _MAX_HEADER_BLOCK_SIZE

    def _reject_header_block(
        self, stream: _StreamState, direction: str, error: str,
    ) -> None:
        """Drop the real-HEADERS block being accumulated, stamp ``error`` and
        poison the direction (the block can never reach the decoder)."""
        stream.header_bytes = bytearray()
        stream.header_block_invalid = True
        stream.error = error
        self._poison_direction(direction, stream.stream_id, error)

    def _reject_push_block(
        self, stream: _StreamState, direction: str, reason: str,
    ) -> None:
        """Drop a PUSH_PROMISE block and poison the direction. The parent
        stream's ``error`` is left untouched (#16)."""
        stream.push_header_bytes = bytearray()
        self._poison_direction(direction, stream.stream_id, f"PUSH_PROMISE {reason}")

    def _append_header_fragment(
        self, stream: _StreamState, fragment: bytes, direction: str,
    ) -> None:
        """Append a real-HEADERS fragment, enforcing ``_MAX_HEADER_BLOCK_SIZE``.
        Nothing is buffered once the block or the direction is unusable."""
        if stream.header_block_invalid or self._decoder_failed.get(direction):
            return
        if self._exceeds_block_cap(stream.header_bytes, fragment):
            self._reject_header_block(stream, direction, "header-block-too-large")
            return
        stream.header_bytes += fragment

    def _append_push_fragment(
        self, stream: _StreamState, fragment: bytes, direction: str,
    ) -> None:
        """Append a PUSH_PROMISE fragment, enforcing ``_MAX_HEADER_BLOCK_SIZE``."""
        if self._decoder_failed.get(direction):
            return
        if self._exceeds_block_cap(stream.push_header_bytes, fragment):
            self._reject_push_block(stream, direction, "header-block-too-large")
            return
        stream.push_header_bytes += fragment

    def _apply_peer_settings(self, direction: str, flags: int, payload: bytes) -> None:
        """Track SETTINGS sent by ``direction``. They constrain the *opposite*
        direction's encoder/frames, so they are applied to that direction."""
        peer = _OPPOSITE_DIRECTION.get(direction)
        if peer is None or flags & _FLAG_ACK:
            return
        self._ensure_direction(peer)
        for i in range(0, len(payload) - 5, 6):
            param_id = int.from_bytes(payload[i:i + 2], "big")
            value = int.from_bytes(payload[i + 2:i + 6], "big")
            if param_id == _SETTINGS_HEADER_TABLE_SIZE:
                self._set_peer_table_size(peer, value)
            elif param_id == _SETTINGS_MAX_FRAME_SIZE:
                self._set_peer_max_frame_size(peer, value)

    def _set_peer_table_size(self, peer: str, value: int) -> None:
        """Allow ``peer``'s encoder a dynamic table up to ``value`` (capped).

        As a passive observer we never drop the limit below the table size
        currently in use: the encoder only has to shrink after the SETTINGS
        ACK, so lowering it eagerly would falsely poison the direction.
        """
        decoder = self._decoders.get(peer)
        if decoder is None:
            return
        allowed = min(value, _MAX_HEADER_TABLE_SIZE)
        decoder.max_allowed_table_size = max(allowed, decoder.header_table_size)

    def _set_peer_max_frame_size(self, peer: str, value: int) -> None:
        if _DEFAULT_MAX_FRAME_SIZE <= value <= _MAX_ALLOWED_FRAME_SIZE:
            self._max_frame_size[peer] = value

    def _frame_size_limit(self, direction: str) -> int | None:
        """Max frame size ``direction`` may send, or None when unknown.

        The RFC default (16384) is only assumed for server->client frames once
        the client connection preface was seen (we then observe its SETTINGS).
        """
        limit = self._max_frame_size.get(direction)
        if limit is None and direction == "read" and self._preface_seen.get("write"):
            limit = _DEFAULT_MAX_FRAME_SIZE
        return limit

    def _is_oversize_frame(self, direction: str, length: int) -> bool:
        limit = self._frame_size_limit(direction)
        return limit is not None and length > limit

    def _handle_oversize_frame(
        self, streams: OrderedDict, stream_id: int, frame_type: int,
        length: int, direction: str,
    ) -> None:
        """Skip a frame larger than the peer's SETTINGS_MAX_FRAME_SIZE. A
        header-carrying one desyncs HPACK, so the direction is poisoned."""
        stream = streams.get(stream_id)
        if stream is not None:
            stream.error = "frame-too-large"
        if frame_type in _HEADER_BLOCK_FRAMES:
            self._poison_direction(
                direction, stream_id,
                f"frame of {length} bytes exceeds SETTINGS_MAX_FRAME_SIZE",
            )

    @staticmethod
    def _parse_frame_header(header: bytes) -> tuple[int, int, int, int]:
        """Parse 9-byte frame header into (length, type, flags, stream_id)."""
        return unpack_frame_header(header)

    @staticmethod
    def _is_valid_frame_header(header: bytes) -> bool:
        """Check if 9 bytes look like a valid HTTP/2 frame header."""
        if len(header) < _FRAME_HEADER_SIZE:
            return False
        length, frame_type, _flags, _stream_id = unpack_frame_header(header)
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
    def _padded_frame_is_valid(payload: bytes, flags: int, prefix_len: int) -> bool:
        """True when a HEADERS/PUSH_PROMISE payload can hold its pad-length
        octet, fixed prefix and padding (RFC 7540 §6.1/§6.2/§6.6)."""
        pad_field = 1 if flags & _FLAG_PADDED else 0
        if len(payload) < pad_field + prefix_len:
            return False
        pad_length = payload[0] if pad_field else 0
        return pad_length <= len(payload) - pad_field - prefix_len

    @staticmethod
    def _data_padding_is_valid(payload: bytes, flags: int) -> bool:
        """RFC 7540 §6.1: padding must be shorter than the frame payload."""
        if not flags & _FLAG_PADDED:
            return True
        return len(payload) >= 1 and payload[0] < len(payload)

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
        if stream.header_block_invalid:
            # Block was rejected (oversize / invalid padding): its specific
            # error is already recorded and the direction poisoned.
            stream.header_block_invalid = False
            return
        headers = self._run_hpack(stream, decoder, direction, block,
                                  stamp_error=True)
        if headers is None:
            return
        self._apply_decoded_headers(stream, headers)

    def _apply_decoded_headers(
        self, stream: _StreamState, headers: list[tuple[str, str]],
    ) -> None:
        """Merge a decoded block into the stream (as before), within the
        per-stream field caps. Blocks after the first are also kept in
        ``trailers`` (#5)."""
        admitted = self._admit_header_fields(stream, headers)
        if stream.header_blocks_decoded > 0:
            stream.trailers.update(admitted)
        stream.header_blocks_decoded += 1
        apply_http2_headers(stream, admitted)

    @staticmethod
    def _admit_header_fields(
        stream: _StreamState, headers: list[tuple[str, str]],
    ) -> list[tuple[str, str]]:
        """Return the fields that fit the stream's header count/byte caps;
        flag the stream ``header-list-too-large`` when any are dropped."""
        admitted: list[tuple[str, str]] = []
        new_names: set[str] = set()
        truncated = False
        for name, value in headers:
            size = len(name) + len(value) + _HEADER_FIELD_OVERHEAD
            is_new = name not in stream.headers and name not in new_names
            too_many = is_new and len(stream.headers) + len(new_names) >= _MAX_STREAM_HEADER_FIELDS
            if too_many or stream.header_list_bytes + size > _MAX_STREAM_HEADER_BYTES:
                truncated = True
                continue
            if is_new:
                new_names.add(name)
            stream.header_list_bytes += size
            admitted.append((name, value))
        if truncated and not stream.error:
            stream.error = "header-list-too-large"
        return admitted

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
            # raw=True: a non-UTF-8 byte must not raise *after* the dynamic
            # table was updated (that poisoned the direction for good).
            decoded = decoder.decode(block, raw=True)
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
            headers.append((self._header_text(name), self._header_text(value)))
        return headers

    @staticmethod
    def _header_text(field) -> str:
        """Decode a raw header name/value; see :func:`decode_header_text`."""
        return decode_header_text(field)

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
