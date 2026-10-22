"""Per-frame provenance of the decrypted TLS plaintext (single-pass side channel).

The TLS single pass (:class:`friTap.offline.pipeline_api.TlsSinglePass`)
turns each TLS application-data frame into one DatalogEvent. A TLS-riding
decryptor (e.g. the nested RC4 path) consumes the SAME plaintext but needs to know
which pcap frame each byte came from. This module records one
:class:`TlsPlaintextSpan` per event, so such a decryptor can reuse the single-pass
bytes (no extra tshark run) and map any offset range of a direction's joined
plaintext back to the frames and timestamps that carried it.

Store layout::

    store[canonical_4tuple(src, sport, dst, dport)]["write" | "read"] -> [span, ...]

``"write"`` is client->server and ``"read"`` server->client, exactly as the
direction tracker and the RC4 decrypt path use them. Spans are appended in
capture order, so a direction's joined plaintext is ``b"".join(s.data ...)``.

One 4-tuple can carry several TCP sessions (port reuse), and they all append to
the same entry. Each span therefore also records its tshark ``tls.stream``, so a
consumer whose offsets are relative to ONE followed stream (the Signal emitter's
``follow,tls,raw,<stream>`` buffer) can scope a lookup to that stream's spans.
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

    The endpoint fields are the packet's own (sender = ``src``), so a consumer can
    recover the client/server addressing from any span of a known direction.
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
    """The ``frame.number`` of a ``-T ek`` packet dict, or 0 when absent."""
    from friTap.offline.pipeline_api import coerce_int, ek_field, ek_first

    layers = pkt.get("layers") or {}
    return coerce_int(ek_first(ek_field(layers, "frame.number")))


def _tls_stream(pkt: dict) -> Optional[int]:
    """The ``tls.stream`` of a ``-T ek`` packet dict, or None when absent."""
    from friTap.offline.pipeline_api import coerce_int, ek_field, ek_first

    layers = pkt.get("layers") or {}
    return coerce_int(ek_first(ek_field(layers, "tls.stream")), default=None)


def record_tls_span(store: SpanStore, pkt: dict, event) -> None:
    """Append ``event``'s plaintext as a span under its connection and direction.

    ``pkt`` is the raw ``-T ek`` packet (source of ``frame.number``); ``event`` is
    the DatalogEvent built from it. Empty events are ignored.
    """
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
    """The spans of ONE direction that hold any byte of ``[lo, hi)``.

    Offsets are positions in the direction's joined plaintext (the spans'
    ``data`` concatenated in order). An empty range covers nothing.
    """
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
    """Capture time of the span that delivered the byte just before *end_offset*.

    *end_offset* is an exclusive end in the direction's joined plaintext, so this
    is when a frame ending there was complete on the wire. An offset past the
    joined bytes is clamped to the last span; an unknown (non-positive) offset or
    an empty direction gives ``0.0`` ("no capture time").
    """
    return _capture_time_from_ends(spans, span_end_offsets(spans), end_offset)


def span_end_offsets(spans: List[TlsPlaintextSpan]) -> List[int]:
    """Cumulative exclusive end offset of each span in the joined plaintext."""
    return list(accumulate(len(span.data) for span in spans))


def _capture_time_from_ends(spans: List[TlsPlaintextSpan], ends: List[int],
                            end_offset: int) -> float:
    """:func:`capture_time_at` over precomputed *ends* (``span_end_offsets``).

    The first span whose end reaches *end_offset* holds the byte just before it
    (its start lies below *end_offset*, so it is never an empty span).
    """
    if end_offset <= 0 or not spans:
        return 0.0
    index = bisect.bisect_left(ends, end_offset)
    return spans[min(index, len(spans) - 1)].ts


class SpanCaptureClock:
    """Repeated :func:`capture_time_at` lookups over one span store, by bisection.

    Caches each (connection, direction[, stream])'s spans and cumulative end
    offsets on first use, so a lookup is O(log S) instead of a linear walk.
    Spans are only ever appended, so a cached entry is rebuilt whenever its
    direction has grown.
    """

    def __init__(self, store: SpanStore) -> None:
        self._store = store
        self._cache: Dict[Tuple[str, str, Optional[int]],
                          Tuple[int, List[TlsPlaintextSpan], List[int]]] = {}

    def capture_time_at(self, key: str, direction: str, end_offset: int,
                        stream: Optional[int] = None) -> float:
        """Capture time of *key*/*direction*'s byte just before *end_offset*.

        With *stream*, *end_offset* is relative to that ``tls.stream``'s own
        plaintext (see :func:`spans_of_stream`); without it, to the joined
        plaintext of every session on the 4-tuple.
        """
        all_spans = (self._store.get(key) or {}).get(direction) or []
        cached = self._cache.get((key, direction, stream))
        if cached is None or cached[0] != len(all_spans):
            spans = spans_of_stream(all_spans, stream)
            cached = (len(all_spans), spans, span_end_offsets(spans))
            self._cache[(key, direction, stream)] = cached
        return _capture_time_from_ends(cached[1], cached[2], end_offset)


def spans_of_stream(spans: List[TlsPlaintextSpan],
                    stream: Optional[int]) -> List[TlsPlaintextSpan]:
    """The spans of tshark TLS stream *stream* (all spans when it is None).

    A direction whose spans carry no stream index at all (e.g. the mid-stream
    pipeline's) cannot be scoped, so it is returned whole, as before.
    """
    if stream is None or all(span.stream is None for span in spans):
        return spans
    return [span for span in spans if span.stream == stream]


# ``(tls.stream, (client_addr, client_port, server_addr, server_port),
#   [(direction, data), ...])`` — the shape of one tshark ``follow,tls,raw`` result.
FollowedStream = Tuple[int, Tuple[str, int, str, int], List[Tuple[str, bytes]]]


def followed_streams_from_spans(store: SpanStore) -> List[FollowedStream]:
    """Rebuild tshark's per-stream Follow-TLS-Stream results from a span store.

    The single pass already decrypted every TLS stream into *store*, so a
    TLS-riding decoder can read the same bytes here instead of re-running
    ``list_tls_streams`` + one ``follow_tls_stream`` per stream.

    Grouping is by ``span.stream`` (tshark's ``tls.stream``, the index the follow
    path uses), NOT the 4-tuple: one 4-tuple can carry several TCP sessions (port
    reuse). Spans without a stream index (the mid-stream pipeline's) are skipped,
    as the follow path never sees those flows either. Streams come back in
    ascending id order; segments interleave the two directions by frame number
    while keeping each direction's own capture order, so per-direction joins match
    the follow output byte for byte. The client is a ``write`` span's sender, or
    else a ``read`` span's receiver.
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
    """``(client_addr, client_port, server_addr, server_port)`` of one stream."""
    writes = by_direction.get("write")
    if writes:
        span = writes[0]
        return (span.src_addr, span.src_port, span.dst_addr, span.dst_port)
    span = next(spans[0] for spans in by_direction.values() if spans)
    return (span.dst_addr, span.dst_port, span.src_addr, span.src_port)


def _followed_segments(
    by_direction: Dict[str, List[TlsPlaintextSpan]],
) -> List[Tuple[str, bytes]]:
    """All of one stream's spans as ``(direction, data)``, merged by frame number."""
    merged = heapq.merge(*by_direction.values(), key=lambda span: span.frame_no)
    return [(span.direction, span.data) for span in merged]
