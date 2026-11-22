"""Offline QUIC stream reassembly.

tshark's ``quic.stream_data`` is one entry per STREAM frame *as captured*:
retransmissions repeat bytes already seen and loss/reordering delivers frames
out of order. Feeding those raw frames to the HTTP/3 parser corrupts its
framing, so when the ``-T ek`` export carries the per-frame OFF/LEN/FIN flags
each stream's byte sequence is rebuilt from the frame offsets first.
"""

from __future__ import annotations

import heapq
import logging
from dataclasses import dataclass, field

# Records keep the converter's logger name, which log config and tests key on.
logger = logging.getLogger("friTap.offline.pcap_to_tap")

# Per-stream cap on out-of-order bytes held while waiting for a gap to fill.
# Past it the gap is declared lost and skipped (debug-logged and counted).
_QUIC_REASSEMBLY_GAP_CAP = 1 << 20  # 1 MiB


@dataclass
class _QuicStreamBuffer:
    """Reassembly state of one directional QUIC stream."""

    next_offset: int = 0
    pending: dict = field(default_factory=dict)  # offset -> bytes (out of order)
    starts: list = field(default_factory=list)  # min-heap of the offsets in pending
    pending_bytes: int = 0
    context: dict | None = None  # DatalogEvent kwargs for drained leftovers


class _QuicStreamReassembler:
    """Rebuild in-order QUIC stream bytes from captured STREAM frames.

    Keyed by an opaque per-direction stream key (the converter uses
    ``(udp_stream_key, direction, stream_id)`` because each QUIC stream carries
    two independent byte sequences). :meth:`push` returns only the bytes that
    became contiguous: duplicates and overlaps are trimmed, gaps are buffered up
    to *gap_cap* bytes per stream and skipped past it. :meth:`drain_all` flushes
    whatever is still buffered at the end of the capture.
    """

    def __init__(self, gap_cap: int = _QUIC_REASSEMBLY_GAP_CAP) -> None:
        self._streams: dict = {}
        self._gap_cap = gap_cap
        self.gap_count = 0          # gaps skipped (cap exceeded or drained)
        self.duplicate_bytes = 0    # retransmitted bytes trimmed

    def push(self, key, offset: int, data: bytes, context: dict | None = None) -> bytes:
        """Add one frame's *data* at *offset*; return newly in-order bytes."""
        buf = self._streams.setdefault(key, _QuicStreamBuffer())
        if context is not None:
            buf.context = context
        offset, data = self._trim_delivered(buf, offset, data)
        if not data:
            return b""
        if offset == buf.next_offset and not buf.pending:
            buf.next_offset += len(data)  # fast path: in order, nothing held
            return data
        self._hold(buf, offset, data)
        released = bytearray(self._release_contiguous(buf))
        while buf.pending_bytes > self._gap_cap:
            released += self._skip_gap(key, buf, "gap cap exceeded")
        return bytes(released)

    def drain(self, key) -> bytes:
        """Flush *key*'s buffered bytes, skipping any remaining gaps."""
        buf = self._streams.get(key)
        released = bytearray()
        while buf is not None and buf.pending:
            released += self._skip_gap(key, buf, "end of capture")
        return bytes(released)

    def drain_all(self) -> list[tuple]:
        """Flush every stream; return ``(key, context, bytes)`` for non-empty ones."""
        leftovers = []
        for key, buf in self._streams.items():
            data = self.drain(key)
            if data:
                leftovers.append((key, buf.context, data))
        return leftovers

    def _trim_delivered(self, buf: _QuicStreamBuffer, offset: int, data: bytes):
        """Cut the prefix of *data* that was already released (retransmission)."""
        overlap = buf.next_offset - offset
        if overlap <= 0:
            return offset, data
        self.duplicate_bytes += min(overlap, len(data))
        return buf.next_offset, data[overlap:]

    @staticmethod
    def _hold(buf: _QuicStreamBuffer, offset: int, data: bytes) -> None:
        """Buffer an out-of-order segment (keeping the longer one per offset)."""
        existing = buf.pending.get(offset)
        if existing is not None and len(existing) >= len(data):
            return
        if existing is None:
            heapq.heappush(buf.starts, offset)
        buf.pending_bytes += len(data) - (len(existing) if existing else 0)
        buf.pending[offset] = data

    @staticmethod
    def _release_contiguous(buf: _QuicStreamBuffer) -> bytes:
        """Pop held segments that now touch ``next_offset`` (trimming overlap)."""
        out = bytearray()
        while buf.starts:
            start = buf.starts[0]
            if start > buf.next_offset:
                break
            heapq.heappop(buf.starts)
            segment = buf.pending.pop(start)
            buf.pending_bytes -= len(segment)
            tail = segment[buf.next_offset - start:]
            out += tail
            buf.next_offset += len(tail)
        return bytes(out)

    def _skip_gap(self, key, buf: _QuicStreamBuffer, reason: str) -> bytes:
        """Declare the gap before the lowest held segment lost and move past it."""
        start = buf.starts[0]
        self.gap_count += 1
        logger.debug("QUIC stream %s: skipping %d-byte gap at offset %d (%s)",
                     key, start - buf.next_offset, buf.next_offset, reason)
        buf.next_offset = start
        return self._release_contiguous(buf)
