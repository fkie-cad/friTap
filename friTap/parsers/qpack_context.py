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
"""

import logging
from typing import Callable, Optional

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

# First byte of a header block prefix with Required Insert Count 0
_STATIC_ONLY_PREFIX = 0x00


def _no_fallback(_block: bytes) -> HeaderPairs:
    return []


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
        self.capacity = max(0, capacity)
        self.decoder = pylsqpack.Decoder(
            self.capacity, max(blocked_streams, _MIN_DECODER_BLOCKED_STREAMS))
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
            return headers
        except Exception:
            logger.debug("QPACK resume failed for stream %s", stream_id, exc_info=True)
            return self._fallback(block)

    def drain_fallback(self) -> dict[int, bytes]:
        """Hand back every still-waiting block (raw bytes) and forget it."""
        drained = {sid: self._take_block(sid) for sid in self.waiting_stream_ids()}
        return drained

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

    def _decode_static(self, stream_id: int, block: bytes) -> HeaderPairs:
        """Decode a Required-Insert-Count-0 block without a dynamic table."""
        if pylsqpack is None:
            return self._fallback(block)
        if self.static_decoder is None:
            self.static_decoder = pylsqpack.Decoder(0, 0)
        try:
            _control, headers = self.static_decoder.feed_header(stream_id, block)
            return headers
        except Exception:
            logger.debug("QPACK static decode failed", exc_info=True)
            self.static_decoder = None  # a failed block may leave state behind
            return self._fallback(block)

    def _decode_main(self, stream_id: int, block: bytes) -> Optional[HeaderPairs]:
        """Decode with the dynamic-table decoder; None when blocked."""
        try:
            _control, headers = self.decoder.feed_header(stream_id, block)
            return headers
        except pylsqpack.StreamBlocked:
            self.blocked[stream_id] = block
            return None
        except Exception:
            logger.debug("QPACK decode failed for stream %s", stream_id, exc_info=True)
            return self._fallback(block)

    def _feed_decoder(self, data: bytes) -> list[int]:
        """Feed encoder bytes to the configured decoder; poison on error."""
        if not data:
            return []
        try:
            unblocked = self.decoder.feed_encoder(data)
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
