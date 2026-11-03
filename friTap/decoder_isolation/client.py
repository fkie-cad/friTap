"""Typed calls into the decoder worker.

Stateless helpers back :mod:`friTap.parsers.decompress` (which keeps the
public return-value and error-string contract); the context API is the
building block for stateful decoders (``zlib_stream``,
``qpack_decoder``; see :mod:`.contexts`). Every reply has already passed the supervisor's frame
validation; the op-specific checks here reject semantically impossible
values (e.g. a gzip member outside the input) as protocol violations.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass
from typing import NamedTuple

from . import protocol as P
from .supervisor import (
    CONTEXT_LOST_MESSAGE,
    DecoderSupervisor,
    WorkerFailure,
    get_supervisor,
)

DECOMPRESS_FAILED_PREFIX = "decompress failed: "

_GZIP_MAGIC = b"\x1f\x8b\x08"


def _supervisor(supervisor: DecoderSupervisor | None) -> DecoderSupervisor:
    return supervisor if supervisor is not None else get_supervisor()


def _clamp_max_out(max_out: int) -> int:
    """*max_out* as a wire value: never negative, never above the frame cap."""
    return max(0, min(int(max_out), P.MAX_REPLY_DATA))


def _no_flags(reply: P.Frame) -> str | None:
    return f"unexpected flags 0x{reply.flags:x}" if reply.flags else None


def _rejected(reply: P.Frame) -> str:
    return f"decoder worker rejected the request: {P.safe_worker_text(reply.text)}"


# --- stateless -----------------------------------------------------------------

def isolated_decompress_body(body: bytes, encoding: str, max_out: int, *,
                             allow_unpatched_brotli: bool = False,
                             supervisor: DecoderSupervisor | None = None) -> tuple[bytes, str]:
    """``decompress_body`` in the worker: ``(data, "")`` or ``(body, error)``."""
    limit = _clamp_max_out(max_out)
    flags = P.REQ_ALLOW_UNPATCHED_BROTLI if allow_unpatched_brotli else 0
    reply = _supervisor(supervisor).request(
        P.Op.DECOMPRESS_BODY, data=body, text=P.encode_text(encoding, P.MAX_KIND_LEN),
        flags=flags, arg0=limit, max_reply=limit, label=encoding, output_hint=limit,
        validate=_no_flags)
    if isinstance(reply, WorkerFailure):
        return body, DECOMPRESS_FAILED_PREFIX + reply.message
    if reply.status == P.Status.OK:
        return reply.data, ""
    if reply.status == P.Status.DECODE_ERROR:
        return body, P.safe_worker_text(reply.text)
    return body, DECOMPRESS_FAILED_PREFIX + _rejected(reply)


def isolated_find_gzip_member(data: bytes, max_out: int, max_candidates: int, *,
                              supervisor: DecoderSupervisor | None = None,
                              ) -> tuple[int, bytes, int] | None:
    """``_find_gzip_member`` in the worker: ``(offset, inflated, member_len)`` or None."""
    limit = _clamp_max_out(max_out)

    def validate(reply: P.Frame) -> str | None:
        if reply.status != P.Status.OK:
            return _no_flags(reply)
        return _no_flags(reply) or _check_member(reply, data)

    reply = _supervisor(supervisor).request(
        P.Op.FIND_GZIP_MEMBER, data=data, arg0=limit, arg1=max(0, int(max_candidates)),
        max_reply=limit, label="gzip-embedded", output_hint=limit, validate=validate)
    if isinstance(reply, WorkerFailure) or reply.status != P.Status.OK:
        return None
    return reply.arg0, reply.data, reply.arg1


def _check_member(reply: P.Frame, data: bytes) -> str | None:
    """A reported member must lie inside *data* and start with the gzip magic."""
    offset, member_len = reply.arg0, reply.arg1
    if offset >= len(data) or member_len == 0 or member_len > len(data) - offset:
        return f"gzip member {offset}+{member_len} outside a {len(data)}-byte input"
    if bytes(data[offset:offset + 3]) != _GZIP_MAGIC:
        return "gzip member does not start with the gzip magic"
    return None


class InflateOutcome(NamedTuple):
    """Result of :func:`isolated_inflate_checked`.

    *error* is None on success, ``"zlib"`` for a corrupt stream or worker
    failure, ``"limit"`` when the output would exceed the limit. *message*
    carries the (filtered) error text.
    """

    data: bytes
    complete: bool
    error: str | None
    message: str


def isolated_inflate_checked(packed: bytes, limit: int, *,
                             supervisor: DecoderSupervisor | None = None) -> InflateOutcome:
    """``inflate_bounded_checked`` in the worker."""
    wire_limit = _clamp_max_out(limit) if limit > 0 else P.MAX_REPLY_DATA

    def validate(reply: P.Frame) -> str | None:
        allowed = P.REPLY_COMPLETE if reply.status == P.Status.OK else 0
        return f"unexpected flags 0x{reply.flags:x}" if reply.flags & ~allowed else None

    reply = _supervisor(supervisor).request(
        P.Op.INFLATE_CHECKED, data=packed, arg0=0 if limit == 0 else wire_limit,
        max_reply=wire_limit, label="gzip-zlib", output_hint=wire_limit, validate=validate)
    if isinstance(reply, WorkerFailure):
        return InflateOutcome(b"", False, "zlib", reply.message)
    if reply.status == P.Status.OK:
        return InflateOutcome(reply.data, bool(reply.flags & P.REPLY_COMPLETE), None, "")
    message = P.safe_worker_text(reply.text)
    if reply.status == P.Status.LIMIT_ERROR:
        return InflateOutcome(b"", False, "limit", message)
    if reply.status == P.Status.ZLIB_ERROR:
        return InflateOutcome(b"", False, "zlib", message)
    return InflateOutcome(b"", False, "zlib", _rejected(reply))


# --- stateful contexts -----------------------------------------------------------

class ContextOp(enum.IntEnum):
    """Per-call operation codes for context kinds."""

    FEED = P.CtxOp.FEED
    QPACK_FEED_ENCODER = P.CtxOp.QPACK_FEED_ENCODER
    QPACK_FEED_HEADER = P.CtxOp.QPACK_FEED_HEADER
    QPACK_RESUME_HEADER = P.CtxOp.QPACK_RESUME_HEADER


class ContextStatus(enum.Enum):
    """Outcome of a context call."""

    OK = "ok"
    LIMIT = "limit"                  # output would exceed max_out (context poisoned)
    ERROR = "error"                  # decoder error (context poisoned)
    UNSUPPORTED = "unsupported"      # unknown kind or op
    LOST = "lost"                    # handle unknown: the worker was restarted
    WORKER_FAILED = "worker_failed"  # crash/timeout/breaker during this call
    BLOCKED = "blocked"              # input waits for more state (qpack_decoder only)


@dataclass(frozen=True)
class ContextHandle:
    """Opaque reference to a context living inside one worker generation."""

    kind: str
    generation: int
    worker_handle: int


class ContextReply(NamedTuple):
    """Result of a context operation; *error* is filtered, safe text."""

    status: ContextStatus
    data: bytes = b""
    error: str = ""
    handle: ContextHandle | None = None
    flags: int = 0  # reply flags (kind-specific, already validated by the caller)

    @property
    def context_lost(self) -> bool:
        """True when the caller must treat the context as gone (poison it)."""
        return self.status in (ContextStatus.LOST, ContextStatus.WORKER_FAILED)


CONTEXT_LOST_ERROR = CONTEXT_LOST_MESSAGE

_STATUS_MAP = {
    P.Status.OK: ContextStatus.OK,
    P.Status.LIMIT_ERROR: ContextStatus.LIMIT,
    P.Status.CONTEXT_ERROR: ContextStatus.ERROR,
    P.Status.HANDLE_LOST: ContextStatus.LOST,
    P.Status.UNSUPPORTED: ContextStatus.UNSUPPORTED,
    P.Status.BAD_REQUEST: ContextStatus.ERROR,
    P.Status.BLOCKED: ContextStatus.BLOCKED,
}


def plain_context_reply(reply: P.Frame) -> str | None:
    """Default CTX_CALL validator: no flags, no BLOCKED (zlib_stream, test kinds)."""
    if reply.status == P.Status.BLOCKED:
        return "BLOCKED status from a context kind that never blocks"
    return _no_flags(reply)


def _context_reply(reply: P.Frame | WorkerFailure, handle: ContextHandle | None = None,
                   ) -> ContextReply:
    if isinstance(reply, WorkerFailure):
        status = ContextStatus.LOST if reply.kind == "lost" else ContextStatus.WORKER_FAILED
        return ContextReply(status, error=reply.message)
    status = _STATUS_MAP[reply.status]
    if status is ContextStatus.LOST:
        return ContextReply(status, error=CONTEXT_LOST_ERROR)
    data = reply.data if status is ContextStatus.OK else b""
    return ContextReply(status, data, P.safe_worker_text(reply.text), handle, reply.flags)


def create_context(kind: str, params: bytes = b"", *,
                   supervisor: DecoderSupervisor | None = None) -> ContextReply:
    """Create a *kind* context in the worker; ``reply.handle`` is set on success."""
    reply, generation = _supervisor(supervisor).request_in_generation(
        P.Op.CTX_CREATE, text=P.encode_text(kind, P.MAX_KIND_LEN), data=params,
        label=kind, validate=_no_flags)
    result = _context_reply(reply)
    if result.status is not ContextStatus.OK:
        return result
    handle = ContextHandle(kind, generation, reply.handle)
    return result._replace(handle=handle, data=b"")


def call_context(handle: ContextHandle, op: int, data: bytes, max_out: int, *,
                 supervisor: DecoderSupervisor | None = None,
                 validate=None) -> ContextReply:
    """Run *op* on *handle* with *data*; output capped at *max_out*.

    *validate* replaces :func:`plain_context_reply` for kinds with richer
    replies (it must check flags, statuses and the data encoding; a non-None
    message is a protocol violation that kills the worker).
    """
    limit = _clamp_max_out(max_out)
    reply = _supervisor(supervisor).request(
        P.Op.CTX_CALL, handle=handle.worker_handle, arg0=limit, arg1=int(op), data=data,
        max_reply=limit, label=handle.kind, output_hint=limit,
        validate=validate or plain_context_reply, expected_generation=handle.generation)
    return _context_reply(reply, handle)


def destroy_context(handle: ContextHandle, *,
                    supervisor: DecoderSupervisor | None = None) -> None:
    """Free *handle* in the worker (no-op when its worker generation is gone)."""
    _supervisor(supervisor).request(
        P.Op.CTX_DESTROY, handle=handle.worker_handle, label=handle.kind,
        validate=_no_flags, expected_generation=handle.generation)
