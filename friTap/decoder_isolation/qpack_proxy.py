"""Isolated stand-in for ``pylsqpack.Decoder`` (``qpack_decoder`` kind).

Same three methods and the same exception types as the in-process decoder,
so :mod:`friTap.parsers.qpack_context` and the non-muxed HTTP/3 path keep
their handling. Only the pylsqpack calls run in the worker; the caller keeps
the capacity / blocked-stream clamps, the pre-decode size bound and the
post-decode caps.

Every reply is validated before use: allowed status and flags per op, empty
data on failure, and a strict decode of the stream-id / header list
(lengths, counts, total size, no trailing bytes). Any violation is a
protocol violation: the supervisor kills the worker and this context is
lost (the caller poisons its QPACK context).

Two outcomes have no pylsqpack equivalent: :class:`DecoderContextLost`
(worker state gone) and :class:`HeaderListTooLarge` (list above the caps,
withheld by the worker).
"""

from __future__ import annotations

import pylsqpack

from . import protocol as P
from .client import ContextOp, ContextReply, ContextStatus
from .contexts import ContextOwner
from .errors import DecoderContextError, HeaderListTooLarge
from .supervisor import DecoderSupervisor

S = P.Status
# Mirrors qpack_kind.MAX_UNBLOCKED_IDS (worker side).
MAX_UNBLOCKED_IDS = 1024
_ID_LIST_WIRE_CAP = 4 + 8 * MAX_UNBLOCKED_IDS

_COMMON = {S.HANDLE_LOST: 0, S.UNSUPPORTED: 0, S.BAD_REQUEST: 0}
# op -> {allowed status: allowed flag bits}
_ALLOWED: dict[int, dict[int, int]] = {
    ContextOp.QPACK_FEED_ENCODER: {
        S.OK: 0, S.CONTEXT_ERROR: P.REPLY_QPACK_ENCODER_STREAM_ERROR, **_COMMON},
    ContextOp.QPACK_FEED_HEADER: {
        S.OK: 0, S.BLOCKED: 0, S.LIMIT_ERROR: 0,
        S.CONTEXT_ERROR: P.REPLY_QPACK_DECOMPRESSION_FAILED, **_COMMON},
    ContextOp.QPACK_RESUME_HEADER: {
        S.OK: 0, S.LIMIT_ERROR: 0,
        S.CONTEXT_ERROR: P.REPLY_QPACK_DECOMPRESSION_FAILED, **_COMMON},
}


def check_reply_shape(op: int, reply: P.Frame) -> str | None:
    """Status / flags / empty-data rules of a qpack_decoder reply to *op*."""
    allowed = _ALLOWED[op]
    if reply.status not in allowed:
        return f"status {reply.status} not allowed for qpack op {op}"
    if reply.flags & ~allowed[reply.status]:
        return f"unexpected flags 0x{reply.flags:x} for qpack op {op}"
    if reply.status != S.OK and reply.data:
        return "data attached to a failed qpack reply"
    return None


class IsolatedQpackDecoder(ContextOwner):
    """``pylsqpack.Decoder(capacity, blocked_streams)`` inside the worker."""

    KIND = "qpack_decoder"

    def __init__(self, capacity: int, blocked_streams: int, *, max_count: int,
                 max_bytes: int, supervisor: DecoderSupervisor | None = None) -> None:
        params = b"".join(P.pack_i64(v) for v in (capacity, blocked_streams,
                                                  max_count, max_bytes))
        super().__init__(params, supervisor=supervisor)
        self._max_count, self._max_bytes = max_count, max_bytes
        self._header_wire_cap = P.header_list_wire_cap(max_count, max_bytes)

    # --- pylsqpack.Decoder API ----------------------------------------------------

    def feed_encoder(self, data: bytes) -> list[int]:
        """Encoder-stream bytes -> stream ids now resumable."""
        decoded: list = []
        reply = self._call(ContextOp.QPACK_FEED_ENCODER, bytes(data), _ID_LIST_WIRE_CAP,
                           validate=self._validator(ContextOp.QPACK_FEED_ENCODER, decoded))
        if reply.status is ContextStatus.OK:
            return decoded[0]
        raise self._failure(reply)

    def feed_header(self, stream_id: int, block: bytes) -> tuple[bytes, list]:
        """``(b"", headers)``; raises StreamBlocked like pylsqpack."""
        payload = P.pack_u64(stream_id) + bytes(block)
        return b"", self._header_call(ContextOp.QPACK_FEED_HEADER, payload)

    def resume_header(self, stream_id: int) -> tuple[bytes, list]:
        """``(b"", headers)`` of a stream unblocked by :meth:`feed_encoder`."""
        return b"", self._header_call(ContextOp.QPACK_RESUME_HEADER, P.pack_u64(stream_id))

    # --- internals ---------------------------------------------------------------

    def _header_call(self, op: int, payload: bytes) -> list:
        decoded: list = []
        reply = self._call(op, payload, self._header_wire_cap,
                           validate=self._validator(op, decoded))
        if reply.status is ContextStatus.OK:
            return decoded[0]
        if reply.status is ContextStatus.BLOCKED:
            raise pylsqpack.StreamBlocked()
        if reply.status is ContextStatus.LIMIT:
            raise HeaderListTooLarge(reply.error)
        raise self._failure(reply)

    def _validator(self, op: int, decoded: list):
        """Validator that also stores the decoded OK payload in *decoded*."""
        def validate(reply: P.Frame) -> str | None:
            problem = check_reply_shape(op, reply)
            if problem or reply.status != S.OK:
                return problem
            try:
                decoded.append(self._decode(op, reply.data))
            except P.ProtocolError as exc:
                return str(exc)
            return None
        return validate

    def _decode(self, op: int, data: bytes) -> list:
        if op == ContextOp.QPACK_FEED_ENCODER:
            return P.decode_u64_list(data, MAX_UNBLOCKED_IDS)
        return P.decode_header_list(data, self._max_count, self._max_bytes)

    @staticmethod
    def _failure(reply: ContextReply) -> Exception:
        """The pylsqpack exception matching a CONTEXT_ERROR/ERROR reply."""
        if reply.flags & P.REPLY_QPACK_DECOMPRESSION_FAILED:
            return pylsqpack.DecompressionFailed(reply.error)
        if reply.flags & P.REPLY_QPACK_ENCODER_STREAM_ERROR:
            return pylsqpack.EncoderStreamError(reply.error)
        return DecoderContextError(reply.error or "qpack decoder call failed")
