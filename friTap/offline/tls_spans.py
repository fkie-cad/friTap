"""Per-frame provenance of the decrypted TLS plaintext (single-pass side channel).

The TLS single pass (:func:`friTap.offline.pcap_to_tap._emit_tls_streams_singlepass`)
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
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List

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


def _frame_number(pkt: dict) -> int:
    """The ``frame.number`` of a ``-T ek`` packet dict, or 0 when absent."""
    from friTap.offline.pcap_to_tap import _coerce_int, _field, _first

    layers = pkt.get("layers") or {}
    return _coerce_int(_first(_field(layers, "frame.number")))


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
