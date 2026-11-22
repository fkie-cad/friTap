"""QUIC rows of the offline converter: tshark ``-T ek`` packets to friTap events.

Maps QUIC stream-data rows to :class:`~friTap.events.DatalogEvent` objects (via
:class:`~friTap.offline.quic_reassembly._QuicStreamReassembler` when the frame
layout is exported) and QUIC metadata to SESSION_STARTED events.
:class:`_QuicCombinedSink` is the QUIC consumer of the keyed combined pass.
"""

from __future__ import annotations

import logging
from collections import deque

from friTap.connection_index import resolve_connection_key
from friTap.events import SESSION_STARTED, DatalogEvent, EventBus, SessionEvent

from .pipeline_api import (
    ConvertResult,
    StreamDirectionTracker,
    WriterState,
    coerce_float,
    coerce_int,
    ek_as_list,
    ek_field,
    ek_first,
    extract_addrs,
)
from .quic_reassembly import _QuicStreamReassembler
from .tshark import QuicMetadataAccumulator, decode_hex, is_quic_row, is_quic_stream_row

# Records keep the converter's logger name, which log config and tests key on.
logger = logging.getLogger("friTap.offline.pcap_to_tap")

# One STREAM frame's layout: (offset, explicit length or None, fin).
_QuicFrameLayout = tuple[int, "int | None", bool]


def _ek_true(value) -> bool:
    """Interpret one `-T ek` FT_BOOLEAN entry (``"True"``/``"1"``/bool)."""
    return str(value).strip().lower() in ("true", "1")


def _pop_gated_values(flags: list, values: list) -> list | None:
    """Expand a sparse value list to one slot per frame, gated by *flags*.

    ``quic.stream.offset`` / ``quic.stream.length`` only carry entries for the
    frames whose OFF / LEN bit is set. Returns ``None`` when the counts disagree
    (the layout cannot be trusted), else a list with ``None`` for unset frames.
    """
    if sum(1 for flag in flags if _ek_true(flag)) != len(values):
        return None
    remaining = iter(values)
    return [coerce_int(next(remaining), default=None) if _ek_true(flag) else None
            for flag in flags]


def _quic_frame_layout(layers: dict, n_ids: int) -> list[_QuicFrameLayout] | None:
    """Return per-STREAM-frame ``(offset, length|None, fin)`` aligned with the ids.

    Built from the ``quic.stream.off``/``len``/``fin`` flag lists (one entry per
    frame, parallel to ``quic.stream.stream_id``) plus the sparse
    ``quic.stream.offset``/``length`` values. A frame without the OFF bit starts
    at offset 0. Returns ``None`` when the flags are absent (older exports and
    hand-built packets) or inconsistent, so callers fall back to raw frames.
    """
    off_flags = ek_as_list(ek_field(layers, "quic.stream.off"))
    len_flags = ek_as_list(ek_field(layers, "quic.stream.len"))
    fin_flags = ek_as_list(ek_field(layers, "quic.stream.fin"))
    if not n_ids or not (len(off_flags) == len(len_flags) == len(fin_flags) == n_ids):
        return None
    offsets = _pop_gated_values(off_flags, ek_as_list(ek_field(layers, "quic.stream.offset")))
    lengths = _pop_gated_values(len_flags, ek_as_list(ek_field(layers, "quic.stream.length")))
    if offsets is None or lengths is None:
        return None
    return [(offset or 0, length, _ek_true(fin))
            for offset, length, fin in zip(offsets, lengths, fin_flags)]


def _align_payloads(
    ids: list,
    payloads: list,
    layout: list[_QuicFrameLayout] | None,
) -> list[tuple] | None:
    """Pair stream ids with payloads (and layout), or ``None`` if impossible.

    Equal counts zip directly. With more ids than payloads, a zero-length
    (typically FIN-only) STREAM frame contributed an id but no ``stream_data``
    entry; when the layout identifies those frames they are dropped so the
    remaining frames line up. Anything else is unrecoverable -> ``None``.
    """
    frames = layout if layout is not None else [None] * len(ids)
    if len(ids) == len(payloads):
        return list(zip(ids, payloads, frames))
    if layout is None or len(ids) < len(payloads):
        return None
    kept = [(sid, frame) for sid, frame in zip(ids, frames) if frame[1] != 0]
    if len(kept) != len(payloads):
        return None
    return [(sid, payload, frame) for (sid, frame), payload in zip(kept, payloads)]



def _quic_stream_frames(layers: dict, stream_key: str,
                        result: ConvertResult | None) -> list[tuple] | None:
    """Return aligned ``(stream_id, payload, layout|None)`` frames, or ``None``.

    ``None`` means the id/payload lists could not be aligned: the packet is
    skipped (warning + *result* drop counter) rather than mis-attributed.
    """
    stream_ids = ek_as_list(ek_field(layers, "quic.stream.stream_id"))
    stream_payloads = ek_as_list(ek_field(layers, "quic.stream_data"))
    layout = _quic_frame_layout(layers, len(stream_ids))
    frames = _align_payloads(stream_ids, stream_payloads, layout)
    if frames is None:
        logger.warning(
            "QUIC packet on %s has mismatched stream id/payload counts "
            "(%d ids vs %d payloads); skipping packet to avoid misattribution.",
            stream_key, len(stream_ids), len(stream_payloads),
        )
        if result is not None:
            result.dropped_packet_count += 1
    return frames


def _quic_packet_to_events(
    pkt: dict,
    tracker: StreamDirectionTracker,
    result: ConvertResult | None = None,
    reassembler: _QuicStreamReassembler | None = None,
) -> list[DatalogEvent]:
    """Translate one QUIC `-T ek` packet dict into DatalogEvents.

    ``quic.stream.stream_id`` and ``quic.stream_data`` are parallel lists, one
    entry per stream frame; each pair becomes one event. A zero-length or
    FIN-only frame can make the lists differ in length, and ``zip`` would then
    attach payloads to the wrong stream id. With the OFF/LEN/FIN flags exported
    those frames are dropped (see :func:`_align_payloads`); otherwise the whole
    packet is skipped, logged and counted on *result*.

    When *reassembler* is given and the frame layout is known, each event's data
    is only the bytes that became in-order for that directional stream
    (retransmissions trimmed, out-of-order frames held back); frames releasing
    nothing produce no event. Without flags, frames pass through unchanged.
    """
    layers = pkt.get("layers") or {}

    timestamp = coerce_float(ek_first(ek_field(layers, "frame.time_epoch")))

    src_addr, dst_addr, ss_family = extract_addrs(layers)

    src_port = coerce_int(ek_first(ek_field(layers, "udp.srcport")))
    dst_port = coerce_int(ek_first(ek_field(layers, "udp.dstport")))
    stream_key = f"udp:{ek_first(ek_field(layers, 'udp.stream'))}"
    direction = tracker.direction_for(
        stream_key, src_addr, src_port, dst_addr, dst_port)

    frames = _quic_stream_frames(layers, stream_key, result)
    if frames is None:
        return []

    events: list[DatalogEvent] = []
    for stream_id, payload, layout in frames:
        data = decode_hex(str(payload))
        if not data:
            continue
        context = dict(
            function="tshark_offline",
            direction=direction,
            src_addr=src_addr,
            src_port=src_port,
            dst_addr=dst_addr,
            dst_port=dst_port,
            ss_family=ss_family,
            ssl_session_id="",
            transport="udp",
            protocol="quic",  # so the flow is keyed/typed as QUIC (flow.transport)
            stream_id=coerce_int(stream_id, default=None),
        )
        if reassembler is not None and layout is not None:
            data = reassembler.push(
                (stream_key, direction, context["stream_id"]), layout[0], data, context)
            if not data:
                continue
        events.append(DatalogEvent(timestamp=timestamp, data=data, **context))
    return events


def _emit_quic_session_event(bus: EventBus, meta: dict) -> None:
    """Emit a SESSION_STARTED carrying QUIC metadata for one ``udp.stream``.

    Must be emitted on the same bus before the QUIC DatalogEvents, so the
    collector stamps ``flow.quic`` (version, alpn, cipher) when the data events
    create the flow. ``protocol="quic"`` makes the ``connection_id`` match the
    ``net:quic:<canonical 4-tuple>`` key ``on_data`` derives for the data
    events. Skipped when no endpoints.
    """
    c_addr = meta.get("src_addr", "")
    s_addr = meta.get("dst_addr", "")
    if not c_addr and not s_addr:
        return
    conn_id = resolve_connection_key(
        c_addr, meta.get("src_port", 0), s_addr, meta.get("dst_port", 0),
        protocol="quic")
    bus.emit(SessionEvent(
        event_type=SESSION_STARTED,
        connection_id=conn_id,
        quic_version=meta.get("version", ""),
        server_name=meta.get("sni", ""),
        alpn=meta.get("alpn", ""),
        cipher_suite=meta.get("cipher", ""),
        client_random=meta.get("client_random", ""),
        src_addr=c_addr,
        src_port=meta.get("src_port", 0),
        dst_addr=s_addr,
        dst_port=meta.get("dst_port", 0),
        protocol="quic",
    ))


def _emit_quic_events(
    events: list[DatalogEvent],
    udp_stream: int | None,
    bus: EventBus,
    state: WriterState,
    result: ConvertResult,
    quic_stream_ids: set,
) -> None:
    """Emit QUIC data events, tracking distinct (udp.stream, stream_id) pairs."""
    state.ensure_open(events[0].timestamp or 0.0)
    for ev in events:
        result.decrypted_packet_count += 1
        quic_stream_ids.add((udp_stream, ev.stream_id))
        bus.emit(ev)


def _emit_quic_leftovers(
    reassembler: _QuicStreamReassembler,
    last_timestamp: float,
    bus: EventBus,
    state: WriterState,
    result: ConvertResult,
    quic_stream_ids: set,
) -> None:
    """Flush bytes still held by *reassembler*, stamped with the last timestamp.

    Held bytes sit behind a gap that never filled (lost frames the capture
    missed); they are released past the gap so no captured payload is lost.
    """
    for key, context, data in reassembler.drain_all():
        if context is None:
            continue
        udp_stream = coerce_int(str(key[0]).partition(":")[2], default=None)
        event = DatalogEvent(timestamp=last_timestamp, data=data, **context)
        _emit_quic_events([event], udp_stream, bus, state, result, quic_stream_ids)
    if reassembler.gap_count or reassembler.duplicate_bytes:
        logger.debug("QUIC reassembly: %d gap(s) skipped, %d retransmitted "
                     "byte(s) trimmed", reassembler.gap_count,
                     reassembler.duplicate_bytes)


def _fold_metadata_row(accumulator, layers: dict, label: str) -> None:
    """Feed one row to a metadata *accumulator*; a bad row is skipped (debug-logged)."""
    try:
        accumulator.feed_ek(layers)
    except Exception:
        logger.debug("Skipping unparseable %s metadata row", label, exc_info=True)


class _QuicCombinedSink:
    """The QUIC consumer of the combined pass.

    Folds every QUIC row into the metadata and translates every stream-data
    row as it arrives (direction tracking, reassembly and drop counters run
    live), but holds the resulting events back: :meth:`flush` emits the QUIC
    SessionEvents (first-seen ``udp.stream`` order), then the data events,
    then the reassembly leftovers stamped with the last timestamp.
    """

    def __init__(self, bus: EventBus, state: WriterState, result: ConvertResult,
                 tracker: StreamDirectionTracker) -> None:
        self._bus, self._state, self._result, self._tracker = bus, state, result, tracker
        self._meta = QuicMetadataAccumulator()
        self._reassembler = _QuicStreamReassembler()
        self._pending: deque = deque()  # (events, udp_stream) in capture order
        self._last_timestamp = 0.0

    def feed(self, pkt: dict, layers: dict) -> None:
        """Consume one combined-pass row (rows without QUIC are ignored)."""
        if is_quic_row(layers):
            _fold_metadata_row(self._meta, layers, "QUIC")
        if is_quic_stream_row(layers):
            self._translate(pkt, layers)

    def _translate(self, pkt: dict, layers: dict) -> None:
        try:
            events = _quic_packet_to_events(pkt, self._tracker, self._result,
                                            self._reassembler)
        except Exception:
            self._result.dropped_packet_count += 1
            logger.debug("Skipping unparseable QUIC packet", exc_info=True)
            return
        if not events:
            return
        udp_stream = coerce_int(ek_first(ek_field(layers, "udp.stream")), default=None)
        self._last_timestamp = events[-1].timestamp or self._last_timestamp
        self._pending.append((events, udp_stream))

    def flush(self) -> None:
        """Emit the metadata events, the buffered data, then the leftovers."""
        for quic_meta in self._meta.result().values():
            _emit_quic_session_event(self._bus, quic_meta)
        quic_stream_ids: set = set()
        while self._pending:
            events, udp_stream = self._pending.popleft()
            _emit_quic_events(events, udp_stream, self._bus, self._state,
                              self._result, quic_stream_ids)
        _emit_quic_leftovers(self._reassembler, self._last_timestamp, self._bus,
                             self._state, self._result, quic_stream_ids)
        self._result.stream_count += len(quic_stream_ids)
