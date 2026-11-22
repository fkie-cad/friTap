"""Per-frame provenance of the decrypted TLS plaintext (single-pass side channel).

The TLS single pass (:class:`friTap.offline.pipeline_api.TlsSinglePass`) records
one :class:`TlsPlaintextSpan` per DatalogEvent, so a TLS-riding decryptor (e.g.
nested RC4) can reuse the bytes without another tshark run and map an offset
range of a direction's joined plaintext back to frames and timestamps.

Store layout::

    store[canonical_4tuple(src, sport, dst, dport)]["write" | "read"] -> [span, ...]

``"write"`` is client->server, ``"read"`` server->client. Spans are appended in
capture order, so a direction's joined plaintext is ``b"".join(s.data ...)``.

Port reuse puts several TCP sessions under one 4-tuple, so each span also
records its ``tls.stream`` for consumers whose offsets are per followed stream.
"""

from __future__ import annotations

import bisect
import heapq
from dataclasses import dataclass
from itertools import accumulate
from typing import Dict, List, Optional, Tuple

from friTap.connection_index import canonical_4tuple

SpanStore = Dict[str, Dict[str, List["TlsPlaintextSpan"]]]


@dataclass(frozen=True)
class TlsPlaintextSpan:
    """The decrypted TLS plaintext one pcap frame contributed to one direction.

    Endpoint fields are the packet's own (sender = ``src``).
    """

    frame_no: int
    ts: float
    direction: str  # "write" (client->server) | "read" (server->client)
    data: bytes
    src_addr: str = ""
    src_port: int = 0
    dst_addr: str = ""
    dst_port: int = 0
    stream: Optional[int] = None  # tshark ``tls.stream``; None when unknown


def _frame_number(pkt: dict) -> int:
    """``frame.number`` of a ``-T ek`` packet dict, or 0."""
    from friTap.offline.pipeline_api import coerce_int, ek_field, ek_first

    layers = pkt.get("layers") or {}
    return coerce_int(ek_first(ek_field(layers, "frame.number")))


def _tls_stream(pkt: dict) -> Optional[int]:
    """``tls.stream`` of a ``-T ek`` packet dict, or None."""
    from friTap.offline.pipeline_api import coerce_int, ek_field, ek_first

    layers = pkt.get("layers") or {}
    return coerce_int(ek_first(ek_field(layers, "tls.stream")), default=None)


def record_tls_span(store: SpanStore, pkt: dict, event) -> None:
    """Append *event*'s plaintext as a span (*pkt* supplies ``frame.number``); empty events are ignored."""
    if not event.data:
        return
    key = canonical_4tuple(event.src_addr, event.src_port,
                           event.dst_addr, event.dst_port)
    span = TlsPlaintextSpan(
        frame_no=_frame_number(pkt), ts=event.timestamp,
        direction=event.direction, data=bytes(event.data),
        src_addr=event.src_addr, src_port=event.src_port,
        dst_addr=event.dst_addr, dst_port=event.dst_port,
        stream=_tls_stream(pkt),
    )
    store.setdefault(key, {}).setdefault(event.direction, []).append(span)


def spans_covering(spans: List[TlsPlaintextSpan], lo: int,
                   hi: int) -> List[TlsPlaintextSpan]:
    """The spans holding any byte of ``[lo, hi)`` of the direction's joined plaintext."""
    covering: List[TlsPlaintextSpan] = []
    if hi <= lo:
        return covering
    start = 0
    for span in spans:
        end = start + len(span.data)
        if start < hi and end > lo:
            covering.append(span)
        if end >= hi:
            break
        start = end
    return covering


def capture_time_at(spans: List[TlsPlaintextSpan], end_offset: int) -> float:
    """Capture time of the span delivering the byte before *end_offset* (exclusive, joined plaintext).

    Clamped to the last span; a non-positive offset or empty direction gives ``0.0``.
    """
    return _capture_time_from_ends(spans, span_end_offsets(spans), end_offset)


def span_end_offsets(spans: List[TlsPlaintextSpan]) -> List[int]:
    """Cumulative exclusive end offset of each span in the joined plaintext."""
    return list(accumulate(len(span.data) for span in spans))


def _capture_time_from_ends(spans: List[TlsPlaintextSpan], ends: List[int],
                            end_offset: int) -> float:
    """:func:`capture_time_at` over precomputed *ends* (``span_end_offsets``)."""
    if end_offset <= 0 or not spans:
        return 0.0
    index = bisect.bisect_left(ends, end_offset)
    return spans[min(index, len(spans) - 1)].ts


class SpanCaptureClock:
    """Repeated :func:`capture_time_at` lookups over one span store in O(log S).

    Caches spans and end offsets per (connection, direction[, stream]); spans are
    append-only, so an entry is rebuilt whenever its direction has grown.
    """

    def __init__(self, store: SpanStore) -> None:
        self._store = store
        self._cache: Dict[Tuple[str, str, Optional[int]],
                          Tuple[int, List[TlsPlaintextSpan], List[int]]] = {}

    def capture_time_at(self, key: str, direction: str, end_offset: int,
                        stream: Optional[int] = None) -> float:
        """Capture time for *end_offset*, relative to *stream*'s plaintext or, without it, the whole 4-tuple's."""
        all_spans = (self._store.get(key) or {}).get(direction) or []
        cached = self._cache.get((key, direction, stream))
        if cached is None or cached[0] != len(all_spans):
            spans = spans_of_stream(all_spans, stream)
            cached = (len(all_spans), spans, span_end_offsets(spans))
            self._cache[(key, direction, stream)] = cached
        return _capture_time_from_ends(cached[1], cached[2], end_offset)


def spans_of_stream(spans: List[TlsPlaintextSpan],
                    stream: Optional[int]) -> List[TlsPlaintextSpan]:
    """The spans of TLS stream *stream*; all of them when it is None or no span carries a stream index."""
    if stream is None or all(span.stream is None for span in spans):
        return spans
    return [span for span in spans if span.stream == stream]


# ``(tls.stream, (client_addr, client_port, server_addr, server_port), [(direction, data), ...])``
FollowedStream = Tuple[int, Tuple[str, int, str, int], List[Tuple[str, bytes]]]


def followed_streams_from_spans(store: SpanStore) -> List[FollowedStream]:
    """Rebuild tshark's per-stream follow-TLS results from a span store.

    Saves a ``list_tls_streams`` plus one ``follow_tls_stream`` per stream. Groups
    by ``span.stream`` (port reuse shares 4-tuples) and skips spans without one.
    Streams ascend by id; segments interleave by frame number so per-direction
    joins match the follow output byte for byte. The client is a ``write`` span's
    sender, else a ``read`` span's receiver.
    """
    by_stream: Dict[int, Dict[str, List[TlsPlaintextSpan]]] = {}
    for by_direction in store.values():
        for direction, spans in by_direction.items():
            for span in spans:
                if span.stream is None:
                    continue
                by_stream.setdefault(span.stream, {}).setdefault(direction, []).append(span)
    return [
        (stream_id, _followed_endpoints(by_stream[stream_id]),
         _followed_segments(by_stream[stream_id]))
        for stream_id in sorted(by_stream)
    ]


def _followed_endpoints(
    by_direction: Dict[str, List[TlsPlaintextSpan]],
) -> Tuple[str, int, str, int]:
    """Client and server endpoint of one stream."""
    writes = by_direction.get("write")
    if writes:
        span = writes[0]
        return (span.src_addr, span.src_port, span.dst_addr, span.dst_port)
    span = next(spans[0] for spans in by_direction.values() if spans)
    return (span.dst_addr, span.dst_port, span.src_addr, span.src_port)


def _followed_segments(
    by_direction: Dict[str, List[TlsPlaintextSpan]],
) -> List[Tuple[str, bytes]]:
    """One stream's spans as ``(direction, data)`` in frame order."""
    merged = heapq.merge(*by_direction.values(), key=lambda span: span.frame_no)
    return [(span.direction, span.data) for span in merged]
