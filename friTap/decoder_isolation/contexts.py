"""Parent-side owners of worker decoder contexts.

A :class:`ContextOwner` holds one context handle of the decoder worker. It is
created lazily on first use (constructing a parser never starts the worker),
and freed by :meth:`ContextOwner.close` or -- best effort -- when the owner
is garbage collected. Collection can happen at any point, including while
the supervisor lock is held, so the finalizer never talks to the worker: it
only queues the handle, and queued handles are destroyed before the next
context is created (worker restarts free everything anyway).

Any lost / failed / unavailable context raises :class:`DecoderContextLost`;
the owner is then permanently closed (its state cannot be rebuilt).
"""

from __future__ import annotations

import collections
import weakref

from .client import (
    CONTEXT_LOST_ERROR,
    ContextHandle,
    ContextReply,
    ContextStatus,
    call_context,
    create_context,
    destroy_context,
)
from .errors import DecoderContextLost
from .supervisor import DecoderSupervisor, get_supervisor

# (handle, supervisor) pairs of collected owners, destroyed by drain_orphans().
_orphans: collections.deque = collections.deque()


def _orphan(slot: list) -> None:
    """Finalizer: queue the handle (never blocks, never does I/O)."""
    if slot[0] is not None:
        _orphans.append((slot[0], slot[1]))


def drain_orphans() -> int:
    """Destroy the worker contexts of collected owners; returns how many."""
    drained = 0
    while _orphans:
        try:
            handle, supervisor = _orphans.popleft()
        except IndexError:
            break
        destroy_context(handle, supervisor=supervisor)
        drained += 1
    return drained


class ContextOwner:
    """One lazily created worker context of kind :attr:`KIND`."""

    KIND = ""
    isolated = True  # marks isolated stand-ins of in-process decoder objects

    def __init__(self, params: bytes = b"", *,
                 supervisor: DecoderSupervisor | None = None) -> None:
        self._params = params
        self._requested_supervisor = supervisor
        self._closed = False
        # [handle, supervisor]: shared with the finalizer (which must not
        # reference self).
        self._slot: list = [None, None]
        self._finalizer = weakref.finalize(self, _orphan, self._slot)

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def handle(self) -> ContextHandle | None:
        """The live worker handle, or None before first use / after close."""
        return self._slot[0]

    def close(self) -> None:
        """Destroy the worker context now; later use raises DecoderContextLost."""
        handle, supervisor = self._slot
        self._forget()
        if handle is not None:
            destroy_context(handle, supervisor=supervisor)

    # --- for subclasses ----------------------------------------------------------

    def _call(self, op: int, data: bytes, max_out: int, validate=None) -> ContextReply:
        """Run *op*; raise DecoderContextLost when the context is gone."""
        handle = self._ensure_handle()
        reply = call_context(handle, op, data, max_out, supervisor=self._slot[1],
                             validate=validate)
        if reply.context_lost or reply.status is ContextStatus.UNSUPPORTED:
            self._forget()  # the worker no longer has it: nothing to destroy
            raise DecoderContextLost(reply.error or CONTEXT_LOST_ERROR)
        return reply

    # --- internals ---------------------------------------------------------------

    def _ensure_handle(self) -> ContextHandle:
        if self._closed:
            raise DecoderContextLost("decoder context closed")
        if self._slot[0] is None:
            self._create()
        return self._slot[0]

    def _create(self) -> None:
        drain_orphans()
        supervisor = self._requested_supervisor or get_supervisor()
        reply = create_context(self.KIND, self._params, supervisor=supervisor)
        if reply.status is not ContextStatus.OK:
            self._forget()
            reason = reply.error or reply.status.value
            raise DecoderContextLost(f"decoder context unavailable ({reason})")
        self._slot[:] = [reply.handle, supervisor]

    def _forget(self) -> None:
        self._closed = True
        self._slot[:] = [None, None]
        self._finalizer.detach()
