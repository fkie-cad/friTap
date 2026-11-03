"""``qpack_decoder`` context kind. Runs only inside the decoder worker.

Loaded by file path (never via the ``friTap`` package) and imports only the
stdlib and ``pylsqpack``. It wraps one ``pylsqpack.Decoder`` and answers the
three QPACK context ops with compact binary lists from the wire protocol
module. The parent keeps every policy decision (table capacity and
blocked-stream clamps, pre-decode size bound, post-decode caps); the caps it
passes in the create parameters only stop this side from sending a header
list the parent would reject as a protocol violation.

pylsqpack exceptions travel as statuses / reply flags:

* ``StreamBlocked``        -> ``Status.BLOCKED``
* ``DecompressionFailed``  -> ``CONTEXT_ERROR`` + ``REPLY_QPACK_DECOMPRESSION_FAILED``
* ``EncoderStreamError``   -> ``CONTEXT_ERROR`` + ``REPLY_QPACK_ENCODER_STREAM_ERROR``
* anything else            -> ``CONTEXT_ERROR`` without flags
* header list over the caps -> ``LIMIT_ERROR`` (the context stays usable)
"""

import struct

try:
    import pylsqpack
except ImportError:  # the kind is then simply not registered
    pylsqpack = None

KIND = "qpack_decoder"
# create params: capacity, blocked streams, max header fields, max header bytes
PARAMS = struct.Struct("!qqqq")
# Most stream ids one feed_encoder reply may list (pylsqpack blocks <= 128).
MAX_UNBLOCKED_IDS = 1024


def available():
    """True when pylsqpack could be imported in the worker."""
    return pylsqpack is not None


def warm_up():
    """Exercise pylsqpack once before the sandbox closes (no late imports)."""
    if pylsqpack is None:
        return
    _control, block = pylsqpack.Encoder().encode(0, [(b":method", b"GET")])
    pylsqpack.Decoder(0, 0).feed_header(0, block)
    try:
        pylsqpack.Decoder(0, 0).feed_header(0, b"\xff\xff\xff")
    except Exception:
        pass


class QpackDecoderContext:
    """One pylsqpack decoder (a dynamic table) living in the worker."""

    def __init__(self, engine, protocol, params):
        if pylsqpack is None:
            raise ValueError("pylsqpack is not available in the decoder worker")
        if len(params) != PARAMS.size:
            raise ValueError("qpack_decoder needs 4 x i64 parameters")
        capacity, blocked, self._max_count, self._max_bytes = PARAMS.unpack(params)
        if min(capacity, blocked, self._max_count, self._max_bytes) < 0:
            raise ValueError("negative qpack_decoder parameter")
        self._decoder = pylsqpack.Decoder(capacity, blocked)

    def call(self, op, data, max_out, protocol):
        """Dispatch one context op -> ``(status, flags, data, text)``."""
        C = protocol.CtxOp
        if op == C.QPACK_FEED_ENCODER:
            return self._feed_encoder(data, protocol)
        if op == C.QPACK_FEED_HEADER:
            return self._header_op(data, protocol, with_block=True)
        if op == C.QPACK_RESUME_HEADER:
            return self._header_op(data, protocol, with_block=False)
        return protocol.Status.UNSUPPORTED, 0, b"", b"unknown qpack_decoder op"

    def _feed_encoder(self, data, protocol):
        S = protocol.Status
        try:
            unblocked = self._decoder.feed_encoder(data)
        except Exception as exc:
            return self._error(exc, protocol)
        if len(unblocked) > MAX_UNBLOCKED_IDS:
            return S.CONTEXT_ERROR, 0, b"", b"too many unblocked streams"
        return S.OK, 0, protocol.encode_u64_list(unblocked), b""

    def _header_op(self, data, protocol, with_block):
        S = protocol.Status
        parsed = protocol.unpack_u64_prefix(data)
        if parsed is None or (not with_block and parsed[1]):
            return S.BAD_REQUEST, 0, b"", b"malformed qpack_decoder request"
        stream_id, block = parsed
        try:
            if with_block:
                _control, headers = self._decoder.feed_header(stream_id, block)
            else:
                _control, headers = self._decoder.resume_header(stream_id)
        except pylsqpack.StreamBlocked:
            return S.BLOCKED, 0, b"", b""
        except Exception as exc:
            return self._error(exc, protocol)
        if self._too_large(headers):
            return S.LIMIT_ERROR, 0, b"", b"header list exceeds the caps"
        return S.OK, 0, protocol.encode_header_list(headers), b""

    def _too_large(self, headers):
        """Same rule as the parent's header_list_too_large()."""
        if len(headers) > self._max_count:
            return True
        return sum(len(name) + len(value) for name, value in headers) > self._max_bytes

    @staticmethod
    def _error(exc, protocol):
        flags = 0
        if isinstance(exc, pylsqpack.DecompressionFailed):
            flags = protocol.REPLY_QPACK_DECOMPRESSION_FAILED
        elif isinstance(exc, pylsqpack.EncoderStreamError):
            flags = protocol.REPLY_QPACK_ENCODER_STREAM_ERROR
        text = protocol.encode_text(f"{type(exc).__name__}: {exc}")
        return protocol.Status.CONTEXT_ERROR, flags, b"", text
