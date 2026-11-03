"""Isolated stand-in for a persistent zlib inflater (``zlib_stream`` kind).

Used for WebSocket permessage-deflate with context takeover: the inflater's
history lives in the worker, the per-message and per-connection budgets stay
with the caller.
"""

from __future__ import annotations

import zlib

from friTap.parsers.decompress import InflateLimitError

from . import protocol as P
from .client import ContextOp, ContextStatus
from .contexts import ContextOwner
from .supervisor import DecoderSupervisor


class IsolatedInflater(ContextOwner):
    """``inflate_stream_bounded`` semantics on a worker-side decompressobj."""

    KIND = "zlib_stream"

    def __init__(self, wbits: int, *, supervisor: DecoderSupervisor | None = None) -> None:
        super().__init__(P.pack_i64(wbits), supervisor=supervisor)

    def inflate_bounded(self, data: bytes, max_out: int) -> bytes:
        """Inflate *data* into at most *max_out* bytes.

        Raises :class:`InflateLimitError` (limit) or ``zlib.error`` (corrupt
        stream) -- the context is then closed, like a discarded in-process
        inflater -- and DecoderContextLost when the worker lost it.
        """
        reply = self._call(ContextOp.FEED, data, max_out)
        if reply.status is ContextStatus.OK:
            return reply.data
        self.close()
        if reply.status is ContextStatus.LIMIT:
            raise InflateLimitError(reply.error or f"inflate exceeds {max_out} B limit")
        raise zlib.error(reply.error or "inflate failed in the decoder worker")
