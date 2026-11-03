"""QPACK decoding state for ONE encoder side of an HTTP/3 connection (RFC 9204).

Each endpoint runs its own QPACK encoder, so a connection has two independent
dynamic tables:

* the client's encoder compresses request header blocks and sends its table
  inserts on the client's type-0x02 unidirectional stream;
* the server's encoder does the same for response header blocks.

The size of a table is chosen by its DECODER: the endpoint that decodes
advertises ``SETTINGS_QPACK_MAX_TABLE_CAPACITY`` (0x01) and
``SETTINGS_QPACK_BLOCKED_STREAMS`` (0x07). The context decoding client-encoded
blocks is therefore configured from the SERVER's SETTINGS and vice versa. The
capacity must be the exact advertised value: the Required Insert Count of
every header block is encoded modulo a value derived from it.

A passive observer sees the three inputs (SETTINGS, encoder stream, header
blocks) in any order, possibly with gaps, so this class queues until it can
decode and never raises:

* encoder bytes are buffered until the capacity is known;
* header blocks that reference entries not inserted yet are kept "blocked"
  and handed back through :meth:`resume` once inserts arrive;
* blocks with a Required Insert Count of 0 only use the static table and are
  decoded right away by a static-only decoder;
* after an encoder-stream error or a buffer overflow the context is
  "poisoned": dynamic references can no longer be trusted, so blocks are
  decoded with the injected fallback (a raw pseudo-header scan).

The peer is untrusted, so decoding is bounded (header-bomb defence):

* an advertised table capacity above :data:`MAX_QPACK_TABLE_CAPACITY` poisons
  the context instead of sizing a huge decoder table;
* a header block is only handed to pylsqpack when its worst-case expansion
  (every byte referencing a capacity-sized entry) fits
  :data:`MAX_DECODE_EXPANSION`;
* a decoded header list above :data:`MAX_HEADER_LIST_COUNT` fields or
  :data:`MAX_HEADER_LIST_BYTES` bytes is replaced by the fallback.

Rejections are recorded per stream and handed out by :meth:`take_error`.

With decoder isolation on (``--isolate-decoders``) every pylsqpack decoder is
a worker-side context (:func:`new_qpack_decoder`); all bounds above stay
here. A lost worker context poisons the QPACK context like an encoder-stream
error; :meth:`QpackDecoderContext.release` frees the worker contexts.
"""

import logging
from typing import Callable, Optional

from friTap.decoder_isolation import (
    DecoderContextLost,
    HeaderListTooLarge,
    close_isolated_decoder,
    isolated_qpack_decoder,
)

logger = logging.getLogger(__name__)

try:
    import pylsqpack
except ImportError:  # pragma: no cover - exercised via the availability flag
    pylsqpack = None

HeaderPairs = list[tuple]
Fallback = Callable[[bytes], HeaderPairs]

# Caps on data buffered while decoding is not possible yet
MAX_PENDING_ENCODER_BYTES = 256 * 1024
MAX_BLOCKED_BLOCKS = 128
# Lower bound for the decoder's own blocked-stream limit: an observer must not
# fail blocks just because the peer advertised a small limit.
_MIN_DECODER_BLOCKED_STREAMS = 128

# Header-bomb bounds (the peer's SETTINGS and header blocks are untrusted)
MAX_QPACK_TABLE_CAPACITY = 64 * 1024
# Absolute header block cap (matches the HTTP/3 HEADERS frame cap)
MAX_HEADER_BLOCK_SIZE = 256 * 1024
MAX_DECODE_EXPANSION = 64 * 1024 * 1024
# Formerly the per-byte expansion factor of the coarse bound; still the
# ceiling used for a static-table reference (longest static entry < 128 B).
_MIN_EXPANSION_FACTOR = 128
_MAX_STATIC_ENTRY = _MIN_EXPANSION_FACTOR
# Huffman decoding expands at most 8/5 (shortest code is 5 bits): use 2
_HUFFMAN_EXPANSION = 2
MAX_HEADER_LIST_COUNT = 512
# Decoded header list cap. 256 KiB matches the common
# SETTINGS_MAX_FIELD_SECTION_SIZE of browsers/servers, far above real cookie
# headers (browsers cap a cookie at ~4 KB, a header line at a few tens of KB).
MAX_HEADER_LIST_BYTES = 256 * 1024
# Bound on per-stream rejection reasons kept until take_error()
_MAX_RECORDED_ERRORS = 1024

ERROR_HEADER_BLOCK_TOO_LARGE = "qpack-header-block-too-large"
ERROR_HEADER_LIST_TOO_LARGE = "qpack-header-list-too-large"
ERROR_HEADER_BLOCK_MALFORMED = "qpack-header-block-malformed"

# First byte of a header block prefix with Required Insert Count 0
_STATIC_ONLY_PREFIX = 0x00


def _no_fallback(_block: bytes) -> HeaderPairs:
    return []


class _MalformedBlock(ValueError):
    """The field section could not be pre-scanned."""


# Longest prefix integer accepted by the pre-scan (62-bit values)
_MAX_INT_CONTINUATION = 9


def _read_prefix_int(block: bytes, offset: int, prefix_bits: int) -> tuple[int, int]:
    """RFC 7541 5.1 prefix integer at *offset* -> (value, next offset)."""
    if offset >= len(block):
        raise _MalformedBlock("truncated integer")
    limit = (1 << prefix_bits) - 1
    value = block[offset] & limit
    offset += 1
    if value < limit:
        return value, offset
    for shift in range(0, 7 * _MAX_INT_CONTINUATION, 7):
        if offset >= len(block):
            raise _MalformedBlock("truncated integer")
        byte = block[offset]
        offset += 1
        value += (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, offset
    raise _MalformedBlock("integer too long")


def _skip_string(block: bytes, offset: int, prefix_bits: int) -> tuple[int, int]:
    """Skip a string literal (H bit + length) -> (decoded size bound, next offset)."""
    huffman = block[offset] & (1 << prefix_bits) if offset < len(block) else 0
    length, offset = _read_prefix_int(block, offset, prefix_bits)
    if offset + length > len(block):
        raise _MalformedBlock("truncated string")
    return length * (_HUFFMAN_EXPANSION if huffman else 1), offset + length


def _scan_field_line(block: bytes, offset: int) -> tuple[str, int, int]:
    """Pre-scan one field line (RFC 9204 4.5.2-4.5.6).

    Returns ``(reference, literal_bound, next offset)`` where reference is
    "dynamic", "static" or "" (literal name).
    """
    first = block[offset]
    if first & 0x80:                       # 1Txxxxxx indexed
        _index, offset = _read_prefix_int(block, offset, 6)
        return ("static" if first & 0x40 else "dynamic"), 0, offset
    if first & 0x40:                       # 01NTxxxx literal, name reference
        _index, offset = _read_prefix_int(block, offset, 4)
        size, offset = _skip_string(block, offset, 7)
        return ("static" if first & 0x10 else "dynamic"), size, offset
    if first & 0x20:                       # 001NHxxx literal name
        name_size, offset = _skip_string(block, offset, 3)
        value_size, offset = _skip_string(block, offset, 7)
        return "", name_size + value_size, offset
    if first & 0x10:                       # 0001xxxx indexed post-base
        _index, offset = _read_prefix_int(block, offset, 4)
        return "dynamic", 0, offset
    _index, offset = _read_prefix_int(block, offset, 3)  # 0000Nxxx post-base name
    size, offset = _skip_string(block, offset, 7)
    return "dynamic", size, offset


def decoded_size_bound(block: bytes, capacity: Optional[int]) -> int:
    """Upper bound on the decoded size of field section *block*.

    Scans the Required Insert Count / Base prefix and every field line
    without Huffman-decoding: a dynamic reference may expand to a whole
    *capacity*-sized entry, a static one to the longest static entry, and a
    literal to twice its encoded length. Raises _MalformedBlock.
    """
    _ric, offset = _read_prefix_int(block, 0, 8)
    _delta_base, offset = _read_prefix_int(block, offset, 7)
    bound = 0
    while offset < len(block):
        reference, literal_size, offset = _scan_field_line(block, offset)
        bound += literal_size
        if reference == "dynamic":
            bound += capacity or 0
        elif reference == "static":
            bound += _MAX_STATIC_ENTRY
    return bound


def check_block(block: bytes, capacity: Optional[int]) -> str:
    """"" when *block* may be decoded, else the rejection reason."""
    if len(block) > MAX_HEADER_BLOCK_SIZE:
        return ERROR_HEADER_BLOCK_TOO_LARGE
    try:
        bound = decoded_size_bound(block, capacity)
    except _MalformedBlock:
        return ERROR_HEADER_BLOCK_MALFORMED
    return "" if bound <= MAX_DECODE_EXPANSION else ERROR_HEADER_BLOCK_TOO_LARGE


def block_within_budget(block: bytes, capacity: Optional[int]) -> bool:
    """True if decoding *block* cannot expand beyond MAX_DECODE_EXPANSION
    (see :func:`decoded_size_bound`); False also for a malformed block."""
    return not check_block(block, capacity)


def header_list_too_large(headers: HeaderPairs) -> bool:
    """True if a decoded header list exceeds the field-count or byte caps."""
    if len(headers) > MAX_HEADER_LIST_COUNT:
        return True
    total = 0
    for name, value in headers:
        total += len(name) + len(value)
        if total > MAX_HEADER_LIST_BYTES:
            return True
    return False


def decoder_blocked_streams(advertised: int) -> int:
    """The decoder's blocked-stream limit: never below the observer minimum,
    never above MAX_BLOCKED_BLOCKS (the advertised value is untrusted)."""
    return min(max(advertised, _MIN_DECODER_BLOCKED_STREAMS), MAX_BLOCKED_BLOCKS)


def new_qpack_decoder(capacity: int, blocked_streams: int):
    """``pylsqpack.Decoder(capacity, blocked_streams)``, or its worker-side
    stand-in (same API and exceptions) when decoder isolation is on."""
    isolated = isolated_qpack_decoder(capacity, blocked_streams,
                                      max_count=MAX_HEADER_LIST_COUNT,
                                      max_bytes=MAX_HEADER_LIST_BYTES)
    return isolated if isolated is not None else pylsqpack.Decoder(capacity, blocked_streams)


def is_static_only_block(block: bytes) -> bool:
    """True if *block* has Required Insert Count 0 (no dynamic references)."""
    return bool(block) and block[0] == _STATIC_ONLY_PREFIX


class QpackDecoderContext:
    """Decodes header blocks produced by one endpoint's QPACK encoder."""

    def __init__(self, fallback: Optional[Fallback] = None) -> None:
        self.decoder = None
        self.static_decoder = None
        self.capacity: Optional[int] = None
        self.pending_encoder = bytearray()
        self.blocked: dict[int, bytes] = {}   # fed to self.decoder, waiting
        self.queued: dict[int, bytes] = {}    # not fed yet (not configured)
        self.ready: dict[int, HeaderPairs] = {}  # decoded, awaiting resume()
        self.poisoned = False
        self.errors: dict[int, str] = {}  # stream id -> rejection reason
        self._fallback = fallback or _no_fallback

    # ------------------------------------------------------------------
    # State
    # ------------------------------------------------------------------

    @property
    def configured(self) -> bool:
        """True once the decoding endpoint's table capacity is known."""
        return self.decoder is not None

    def waiting_stream_ids(self) -> list[int]:
        """Streams whose header block is queued or blocked."""
        return [*self.queued, *self.blocked]

    def poison(self, reason: str) -> list[int]:
        """Stop trusting the dynamic table; waiting blocks become fallbacks.

        Returns the stream ids that :meth:`resume` can now answer.
        """
        if not self.poisoned:
            logger.debug("QPACK context poisoned: %s", reason)
        self.poisoned = True
        self.pending_encoder.clear()
        close_isolated_decoder(self.decoder)  # its dynamic table is unused now
        waiting = self.waiting_stream_ids()
        for sid in waiting:
            self.ready[sid] = self._fallback(self._take_block(sid))
        return waiting

    # ------------------------------------------------------------------
    # Inputs
    # ------------------------------------------------------------------

    def configure(self, capacity: int, blocked_streams: int) -> list[int]:
        """Create the decoder with the EXACT advertised capacity.

        Buffered encoder bytes and queued blocks are fed afterwards. Returns
        the stream ids that :meth:`resume` can now answer. A second call is
        ignored (SETTINGS are sent once per connection).
        """
        if self.configured or self.poisoned or pylsqpack is None:
            return []
        if capacity > MAX_QPACK_TABLE_CAPACITY:
            return self.poison(f"table capacity {capacity} exceeds "
                               f"{MAX_QPACK_TABLE_CAPACITY}")
        self.capacity = max(0, capacity)
        self.decoder = new_qpack_decoder(
            self.capacity, decoder_blocked_streams(blocked_streams))
        unblocked = self._feed_decoder(bytes(self.pending_encoder))
        self.pending_encoder.clear()
        return unblocked + self._feed_queued()

    def feed_encoder(self, data: bytes) -> list[int]:
        """Consume encoder-stream bytes -> stream ids now resumable."""
        if self.poisoned or not data:
            return []
        if self.configured:
            return self._feed_decoder(data)
        if len(self.pending_encoder) + len(data) > MAX_PENDING_ENCODER_BYTES:
            return self.poison("encoder buffer overflow")
        self.pending_encoder.extend(data)
        return []

    def decode(self, stream_id: int, block: bytes) -> Optional[HeaderPairs]:
        """Decode a header block, or return None when it has to wait."""
        if is_static_only_block(block) and not self._main_decoder_usable():
            return self._decode_static(stream_id, block)
        if self.poisoned or stream_id in self.ready or self._is_waiting(stream_id):
            return self._fallback(block)
        if len(self.queued) + len(self.blocked) >= MAX_BLOCKED_BLOCKS:
            return self._fallback(block)
        if not self.configured:
            self.queued[stream_id] = block
            return None
        return self._decode_main(stream_id, block)

    def resume(self, stream_id: int) -> HeaderPairs:
        """Headers of a stream reported as resumable (empty when unknown)."""
        if stream_id in self.ready:
            return self.ready.pop(stream_id)
        block = self.blocked.pop(stream_id, None)
        if block is None:
            return []
        try:
            _control, headers = self.decoder.resume_header(stream_id)
        except HeaderListTooLarge:
            return self._reject_block(stream_id, block, ERROR_HEADER_LIST_TOO_LARGE)
        except DecoderContextLost as exc:
            return self._context_lost(exc, block)
        except Exception:
            logger.debug("QPACK resume failed for stream %s", stream_id, exc_info=True)
            return self._fallback(block)
        return self._bounded(stream_id, headers, block)

    def take_error(self, stream_id: int) -> str:
        """Pop the reason a block of *stream_id* was rejected ("" if none)."""
        return self.errors.pop(stream_id, "")

    def drain_fallback(self) -> dict[int, bytes]:
        """Hand back every still-waiting block (raw bytes) and forget it."""
        drained = {sid: self._take_block(sid) for sid in self.waiting_stream_ids()}
        return drained

    def release(self) -> None:
        """Free isolated (worker-side) decoders at stream end.

        A released dynamic table cannot be rebuilt, so the context is then
        poisoned; the static decoder is simply re-created on demand.
        In-process decoders are left untouched.
        """
        if close_isolated_decoder(self.static_decoder):
            self.static_decoder = None
        if getattr(self.decoder, "isolated", False) and not self.poisoned:
            self.poison("decoder context released")

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _main_decoder_usable(self) -> bool:
        return self.configured and not self.poisoned

    def _is_waiting(self, stream_id: int) -> bool:
        return stream_id in self.queued or stream_id in self.blocked

    def _take_block(self, stream_id: int) -> bytes:
        block = self.queued.pop(stream_id, None)
        if block is None:
            block = self.blocked.pop(stream_id, b"")
        return block

    def _record_error(self, stream_id: int, reason: str) -> None:
        """Remember why *stream_id*'s block was rejected (bounded)."""
        if len(self.errors) >= _MAX_RECORDED_ERRORS:
            self.errors.pop(next(iter(self.errors)))
        self.errors[stream_id] = reason

    def _context_lost(self, exc: Exception, block: bytes) -> HeaderPairs:
        """The worker lost the dynamic table: poison, answer with the fallback."""
        self.poison(f"decoder context lost ({exc})")
        return self._fallback(block)

    def _reject_block(self, stream_id: int, block: bytes, reason: str) -> HeaderPairs:
        """Record *reason* and answer *block* with the fallback."""
        logger.debug("QPACK block of stream %s rejected: %s", stream_id, reason)
        self._record_error(stream_id, reason)
        return self._fallback(block)

    def _bounded(self, stream_id: int, headers: HeaderPairs,
                 block: bytes) -> HeaderPairs:
        """Decoded *headers*, or the fallback when the list is too large."""
        if header_list_too_large(headers):
            return self._reject_block(stream_id, block, ERROR_HEADER_LIST_TOO_LARGE)
        return headers

    def _decode_static(self, stream_id: int, block: bytes) -> HeaderPairs:
        """Decode a Required-Insert-Count-0 block without a dynamic table."""
        if pylsqpack is None:
            return self._fallback(block)
        rejection = check_block(block, 0)
        if rejection:
            return self._reject_block(stream_id, block, rejection)
        if self.static_decoder is None:
            self.static_decoder = new_qpack_decoder(0, 0)
        try:
            _control, headers = self.static_decoder.feed_header(stream_id, block)
        except HeaderListTooLarge:
            return self._reject_block(stream_id, block, ERROR_HEADER_LIST_TOO_LARGE)
        except Exception:
            logger.debug("QPACK static decode failed", exc_info=True)
            self.static_decoder = None  # a failed block may leave state behind
            return self._fallback(block)
        return self._bounded(stream_id, headers, block)

    def _decode_main(self, stream_id: int, block: bytes) -> Optional[HeaderPairs]:
        """Decode with the dynamic-table decoder; None when blocked."""
        rejection = check_block(block, self.capacity)
        if rejection:
            return self._reject_block(stream_id, block, rejection)
        try:
            _control, headers = self.decoder.feed_header(stream_id, block)
            return self._bounded(stream_id, headers, block)
        except pylsqpack.StreamBlocked:
            self.blocked[stream_id] = block
            return None
        except HeaderListTooLarge:
            return self._reject_block(stream_id, block, ERROR_HEADER_LIST_TOO_LARGE)
        except DecoderContextLost as exc:
            return self._context_lost(exc, block)
        except Exception:
            logger.debug("QPACK decode failed for stream %s", stream_id, exc_info=True)
            return self._fallback(block)

    def _feed_decoder(self, data: bytes) -> list[int]:
        """Feed encoder bytes to the configured decoder; poison on error."""
        if not data:
            return []
        try:
            unblocked = self.decoder.feed_encoder(data)
        except DecoderContextLost as exc:
            return self.poison(f"decoder context lost ({exc})")
        except Exception:
            return self.poison("encoder stream error")
        return [sid for sid in unblocked if sid in self.blocked]

    def _feed_queued(self) -> list[int]:
        """Feed blocks that arrived before configure(); decoded ones -> ready."""
        resumable = []
        queued, self.queued = self.queued, {}
        for sid, block in queued.items():
            headers = self._decode_main(sid, block)
            if headers is not None:
                self.ready[sid] = headers
                resumable.append(sid)
        return resumable
