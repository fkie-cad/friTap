#!/usr/bin/env python3

"""Reconstruct a friTap ``.tap`` from a tshark-decrypted capture.

The conversion is a thin adapter that reuses friTap's parsers. tshark recovers
the decrypted plaintext two ways — Follow-TLS-Stream for TLS/TCP and a
``-T ek`` export of ``quic.stream_data`` for QUIC/HTTP3 — and we translate the
recovered bytes into :class:`~friTap.events.DatalogEvent` objects fed through
the EXISTING :class:`~friTap.flow.collector.FlowCollector` (parsers, flow
correlation) and :class:`~friTap.flow.tap_writer.TapWriter`. No protocol
parsing is duplicated.
"""

from __future__ import annotations

import contextlib
import heapq
import importlib
import inspect
import logging
import os
from collections import deque
from dataclasses import dataclass, field
from typing import Callable, Iterator, Tuple

from friTap.connection_index import resolve_connection_key
from friTap.events import SESSION_STARTED, DatalogEvent, EventBus, SessionEvent
from friTap.flow.collector import FlowCollector
from friTap.flow.layer_pipeline import MESSAGE_TRANSPORTS
from friTap.flow.layers import SshLayer
from friTap.flow.tap_writer import TapWriter

from .pipeline_api import (
    ConvertResult,
    StreamDirectionTracker,
    TlsSinglePass,
    WriterState,
    coerce_float,
    coerce_int,
    ek_as_list,
    ek_field,
    ek_first,
    extract_addrs,
    tls_packet_to_events,
    unique_keylog_paths,
)
from .tshark import (
    ENCRYPTED_RECORD_MARKERS,
    QuicMetadataAccumulator,
    SshConnectionAccumulator,
    build_combined_command,
    build_plaintext_command,
    build_quic_detection_command,
    capture_has_dsb,
    decode_hex,
    extract_ssh_connections,
    find_tshark,
    has_plaintext_payload,
    is_quic_row,
    is_quic_stream_row,
    is_ssh_row,
    stream_packets,
    tls_app_data_marker,
    tshark_version,
    warn_if_outdated,
)

logger = logging.getLogger(__name__)

# Historical private names of the pipeline API (friTap.offline.pipeline_api),
# kept bound here because this module, other callers and tests still use them.
_StreamDirectionTracker = StreamDirectionTracker
_WriterState = WriterState
_field = ek_field
_as_list = ek_as_list
_first = ek_first
_coerce_int = coerce_int
_coerce_float = coerce_float
_extract_addrs = extract_addrs
_tls_packet_to_events = tls_packet_to_events


@contextlib.contextmanager
def _closing_packets(packets):
    """Yield *packets* and close it afterwards, when it can be closed.

    ``stream_packets`` returns a generator whose ``close()`` terminates and reaps
    tshark, so a consumer that stops early (an exception, a ``break``) never
    leaves the process running. Test fakes may return a plain list, which has
    no ``close()``; it is yielded unchanged.
    """
    try:
        yield packets
    finally:
        close = getattr(packets, "close", None)
        if callable(close):
            close()


# Well-known cleartext server ports used to anchor flow direction when ingesting
# an already-plaintext capture (there is no TLS/QUIC handshake to infer the
# server side from). Any --tls-port / --quic-port values are folded in as extra
# hints at the call site, since those are the only server-port signals fritap has.
_PLAINTEXT_SERVER_PORTS = (80, 8080, 8000)


def messaging_buckets(result) -> Iterator[Tuple[str, dict]]:
    """Yield ``(prefix, counters)`` for every messaging prefix, in fixed order.

    *counters* is ``result.per_protocol[prefix]`` (see
    :meth:`ConvertResult.record_protocol`), or ``{}`` when that protocol recorded
    nothing. Duck-typed: any object with (or without) a ``per_protocol`` dict works.
    """
    per_protocol = getattr(result, "per_protocol", None) or {}
    for prefix in MESSAGING_PREFIXES:
        yield prefix, per_protocol.get(prefix) or {}


# ---------------------------------------------------------------------------
# Offline QUIC stream reassembly
# ---------------------------------------------------------------------------
#
# tshark's ``quic.stream_data`` is one entry per STREAM frame *as captured*:
# retransmissions repeat bytes already seen and loss/reordering delivers frames
# out of order. Feeding those raw frames to the HTTP/3 parser corrupts its
# framing, so when the ``-T ek`` export carries the per-frame OFF/LEN/FIN flags
# we rebuild each stream's byte sequence from the frame offsets first.

# Per-stream cap on out-of-order bytes held while waiting for a gap to fill.
# Past it the gap is declared lost and skipped (debug-logged and counted).
_QUIC_REASSEMBLY_GAP_CAP = 1 << 20  # 1 MiB

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
    return [_coerce_int(next(remaining), default=None) if _ek_true(flag) else None
            for flag in flags]


def _quic_frame_layout(layers: dict, n_ids: int) -> list[_QuicFrameLayout] | None:
    """Return per-STREAM-frame ``(offset, length|None, fin)`` aligned with the ids.

    Built from the ``quic.stream.off``/``len``/``fin`` flag lists (one entry per
    frame, parallel to ``quic.stream.stream_id``) plus the sparse
    ``quic.stream.offset``/``length`` values. A frame without the OFF bit starts
    at offset 0. Returns ``None`` when the flags are absent (older exports and
    hand-built packets) or inconsistent, so callers fall back to raw frames.
    """
    off_flags = _as_list(_field(layers, "quic.stream.off"))
    len_flags = _as_list(_field(layers, "quic.stream.len"))
    fin_flags = _as_list(_field(layers, "quic.stream.fin"))
    if not n_ids or not (len(off_flags) == len(len_flags) == len(fin_flags) == n_ids):
        return None
    offsets = _pop_gated_values(off_flags, _as_list(_field(layers, "quic.stream.offset")))
    lengths = _pop_gated_values(len_flags, _as_list(_field(layers, "quic.stream.length")))
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


def _quic_stream_frames(layers: dict, stream_key: str,
                        result: ConvertResult | None) -> list[tuple] | None:
    """Return aligned ``(stream_id, payload, layout|None)`` frames, or ``None``.

    ``None`` means the id/payload lists could not be aligned: the packet is
    skipped (warning + *result* drop counter) rather than mis-attributed.
    """
    stream_ids = _as_list(_field(layers, "quic.stream.stream_id"))
    stream_payloads = _as_list(_field(layers, "quic.stream_data"))
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
    tracker: _StreamDirectionTracker,
    result: ConvertResult | None = None,
    reassembler: _QuicStreamReassembler | None = None,
) -> list[DatalogEvent]:
    """Translate one QUIC `-T ek` packet dict into DatalogEvents.

    ``quic.stream.stream_id`` and ``quic.stream_data`` are PARALLEL lists when
    a single packet carries multiple stream frames — we zip them and emit one
    event per (stream_id, stream_data) pair.

    These two fields are extracted as independent parallel ``-T ek`` lists, so a
    packet carrying a zero-length / FIN-only STREAM frame can make the lists
    differ in length. ``zip`` would silently truncate, attaching payloads to the
    wrong stream id. When the per-frame OFF/LEN/FIN flags are exported the
    zero-length frames are identified and dropped (see :func:`_align_payloads`);
    otherwise we log a warning, increment *result*'s drop counter (when
    supplied), and SKIP the whole packet rather than emit a wrong mapping.

    When *reassembler* is given and the frame layout is known, each event's data
    is only the bytes that became in-order for that directional stream
    (retransmissions trimmed, out-of-order frames held back); frames releasing
    nothing produce no event. Without flags, frames pass through unchanged.
    """
    layers = pkt.get("layers") or {}

    timestamp = _coerce_float(_first(_field(layers, "frame.time_epoch")))

    src_addr, dst_addr, ss_family = _extract_addrs(layers)

    src_port = _coerce_int(_first(_field(layers, "udp.srcport")))
    dst_port = _coerce_int(_first(_field(layers, "udp.dstport")))
    stream_key = f"udp:{_first(_field(layers, 'udp.stream'))}"
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
            stream_id=_coerce_int(stream_id, default=None),
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

    Emitted on the SAME bus and BEFORE the QUIC DatalogEvents so the collector
    caches it and stamps the flow's QUIC layer (``flow.quic`` — version, alpn,
    cipher) when the data events create the flow. ``protocol="quic"`` so the
    ``connection_id`` matches the key ``on_data`` derives for the QUIC data
    events (which now carry ``protocol="quic"``): the protocol-scoped
    ``net:quic:<canonical 4-tuple>``. Skipped when no endpoints.
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
    state: _WriterState,
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
    state: _WriterState,
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
        udp_stream = _coerce_int(str(key[0]).partition(":")[2], default=None)
        event = DatalogEvent(timestamp=last_timestamp, data=data, **context)
        _emit_quic_events([event], udp_stream, bus, state, result, quic_stream_ids)
    if reassembler.gap_count or reassembler.duplicate_bytes:
        logger.debug("QUIC reassembly: %d gap(s) skipped, %d retransmitted "
                     "byte(s) trimmed", reassembler.gap_count,
                     reassembler.duplicate_bytes)


def _is_encrypted_record(layers: dict, proto_layers: list[str]) -> bool:
    """Return True when a keyless packet carries genuine cipher-text.

    tshark's heuristic dissector tags any unparseable TCP/443 (or UDP) payload as
    ``tls``/``quic`` in ``frame.protocols``, so the protocol-stack string alone is
    not proof of encryption — friTap's own decrypted HTTP/2 frames get tagged
    ``tls`` too. A genuinely encrypted stream additionally exposes a parsed record
    marker, because the TLS record header / QUIC packet header is cleartext even
    without keys (``tls.record.content_type`` 22/23/…, ``quic.header_form``). We
    require that marker before skipping a stream. The (protocol, marker) pairs and
    the matching tshark export live in :data:`~friTap.offline.tshark.
    ENCRYPTED_RECORD_MARKERS`.
    """
    return any(
        proto in proto_layers and _first(_field(layers, marker)) is not None
        for proto, marker in ENCRYPTED_RECORD_MARKERS
    )


def _detect_encrypted_quic_streams(
    tshark_bin: str,
    pcap_path: str,
    *,
    quic_ports: tuple[int, ...],
    extra_decode_as: tuple[str, ...],
    heuristic: bool,
) -> frozenset[str]:
    """Return ``udp:<stream>`` keys for genuinely-encrypted QUIC in a keyless capture.

    QUIC header protection encrypts the first header byte, so without keys tshark
    cannot tell real QUIC cipher-text from friTap's decrypted HTTP/3 by header
    fields alone. The one robust, key-free signal is a captured QUIC handshake (see
    :func:`~friTap.offline.tshark.build_quic_detection_command`): a ClientHello or a
    registered-version Initial — neither of which decrypted HTTP/3 can produce. We
    run that detection pass and return the matching streams so the plaintext pass
    skips them instead of ingesting cipher-text. Detection failure is non-fatal
    (returns empty): at worst we fall back to the prior over-ingest behavior.
    """
    cmd = build_quic_detection_command(
        pcap_path, quic_ports=quic_ports,
        extra_decode_as=extra_decode_as, heuristic=heuristic)
    cmd[0] = tshark_bin
    streams: set[str] = set()
    try:
        with _closing_packets(stream_packets(cmd)) as packets:
            for pkt in packets:
                layers = pkt.get("layers") or {}
                stream_id = _first(_field(layers, "udp.stream"))
                if stream_id is not None and str(stream_id) != "":
                    streams.add(f"udp:{stream_id}")
    except Exception:
        logger.debug("QUIC encrypted-stream detection failed; "
                     "treating capture as fully plaintext", exc_info=True)
        return frozenset()
    return frozenset(streams)


def _plaintext_packet_to_events(
    pkt: dict,
    tracker: _StreamDirectionTracker,
    encrypted_streams: set[str],
    encrypted_quic_streams: frozenset[str] = frozenset(),
) -> list[DatalogEvent]:
    """Translate one raw-payload ``-T ek`` packet dict into DatalogEvents.

    For an already-plaintext capture there are no keys: the application bytes are
    the raw transport payload (``tcp.payload`` / ``udp.payload``). Genuinely
    encrypted streams need keys, so we record them in *encrypted_streams* (for a
    later "pass --keylog" hint) and skip them rather than ingesting cipher-text as
    bogus plaintext. Mirrors :func:`_tls_packet_to_events`, but reads the raw
    payload field instead of the decrypted ``data.data``.

    A stream is encrypted when EITHER :func:`_is_encrypted_record` matches a parsed
    TLS/QUIC record marker on this packet, OR its ``udp.stream`` is in
    *encrypted_quic_streams* (genuine QUIC identified by the handshake pre-scan —
    see :func:`_detect_encrypted_quic_streams` for why that pre-scan is needed).
    """
    layers = pkt.get("layers") or {}
    # frame.protocols is the colon-separated dissector stack, e.g.
    # "eth:ethertype:ip:tcp:tls"; split so membership is exact (no substring
    # false-matches against a protocol name that merely contains "tls"/"quic").
    proto_layers = str(_first(_field(layers, "frame.protocols")) or "").lower().split(":")

    timestamp = _coerce_float(_first(_field(layers, "frame.time_epoch")))

    src_addr, dst_addr, ss_family = _extract_addrs(layers)

    tcp_stream = _first(_field(layers, "tcp.stream"))
    if tcp_stream is not None:
        transport = "tcp"
        stream_key = f"tcp:{tcp_stream}"
        src_port = _coerce_int(_first(_field(layers, "tcp.srcport")))
        dst_port = _coerce_int(_first(_field(layers, "tcp.dstport")))
        payload_field = "tcp.payload"
    else:
        udp_stream = _first(_field(layers, "udp.stream"))
        transport = "udp"
        stream_key = f"udp:{udp_stream}"
        src_port = _coerce_int(_first(_field(layers, "udp.srcport")))
        dst_port = _coerce_int(_first(_field(layers, "udp.dstport")))
        payload_field = "udp.payload"

    # Encrypted streams need keys: record once and skip every packet on them.
    # Either this packet exposes a parsed TLS/QUIC record marker, or its stream was
    # confirmed as genuine QUIC by the handshake pre-scan.
    if stream_key in encrypted_quic_streams or _is_encrypted_record(layers, proto_layers):
        encrypted_streams.add(stream_key)
        return []

    payloads = _as_list(_field(layers, payload_field))
    data = b"".join(decode_hex(str(p)) for p in payloads)
    if not data:
        return []

    direction = tracker.direction_for(
        stream_key, src_addr, src_port, dst_addr, dst_port)

    return [DatalogEvent(
        timestamp=timestamp,
        data=data,
        function="tshark_offline",
        direction=direction,
        src_addr=src_addr,
        src_port=src_port,
        dst_addr=dst_addr,
        dst_port=dst_port,
        ss_family=ss_family,
        ssl_session_id="",
        transport=transport,
        stream_id=None,
    )]


def _emit_plaintext_streams_singlepass(
    tshark_bin: str,
    pcap_path: str,
    *,
    extra_decode_as: tuple[str, ...],
    heuristic: bool,
    bus: EventBus,
    state: _WriterState,
    result: ConvertResult,
    tracker: _StreamDirectionTracker,
    encrypted_quic_streams: frozenset[str] = frozenset(),
    ssh_accumulator: SshConnectionAccumulator | None = None,
) -> None:
    """Export raw transport payload via ONE ``-T ek`` pass and emit events.

    The keyless counterpart to the keyed combined pass
    (:func:`_run_keyed_combined_pass`): instead of decrypted ``data.data`` it reads ``tcp.payload`` / ``udp.payload`` for an
    already-plaintext capture. Encrypted streams are detected and skipped — TLS (and
    per-packet-marked QUIC) via :func:`_is_encrypted_record`, and handshake-confirmed
    QUIC via *encrypted_quic_streams* — with their count surfaced on *result* so the
    caller can hint that ``--keylog`` is required. Emitted bytes flow through the
    same EventBus -> FlowCollector -> parser pipeline as every other path.

    With *ssh_accumulator* the same pass also exports the SSH metadata rows and
    folds them into it; only rows carrying a transport payload become events.
    """
    include_ssh = ssh_accumulator is not None
    cmd = build_plaintext_command(
        pcap_path, extra_decode_as=extra_decode_as, heuristic=heuristic,
        include_ssh=include_ssh)
    cmd[0] = tshark_bin  # replace the literal "tshark" with the resolved path

    encrypted_streams: set[str] = set()
    with _closing_packets(stream_packets(cmd)) as packets:
        for pkt in packets:
            if include_ssh:
                layers = pkt.get("layers") or {}
                if is_ssh_row(layers):
                    _fold_metadata_row(ssh_accumulator, layers, "SSH")
                if not has_plaintext_payload(layers):
                    continue
            try:
                events = _plaintext_packet_to_events(
                    pkt, tracker, encrypted_streams, encrypted_quic_streams)
            except Exception:
                result.dropped_packet_count += 1
                logger.debug("Skipping unparseable plaintext packet", exc_info=True)
                continue
            if not events:
                continue

            state.ensure_open()
            for ev in events:
                result.decrypted_packet_count += 1
                bus.emit(ev)

    # The tracker only sees cleartext packets (encrypted ones return before
    # direction_for is called), so its stream_count is the distinct-cleartext
    # count. Encrypted streams are tallied separately for the "needs keys" hint.
    result.stream_count += tracker.stream_count
    result.encrypted_streams_skipped += len(encrypted_streams)


class NoDecryptionKeysError(ValueError):
    """Raised when a capture cannot be decrypted: no keylog and no embedded DSB."""


def _require_decryptable(pcap_path: str, keylog_path: str | None) -> None:
    """Fail loud when *pcap_path* has no path to decryption.

    Without TLS keys, tshark silently emits no plaintext and the pipeline would
    produce an empty/garbage ``.tap`` that looks like success. Decryption needs
    EITHER an explicit keylog file OR a pcapng with an embedded Decryption
    Secrets Block. If neither is present we stop here with a clear message
    instead of depending on hidden state.
    """
    has_keylog = bool(keylog_path) and os.path.isfile(keylog_path)
    if has_keylog or capture_has_dsb(pcap_path):
        return
    if keylog_path:
        detail = f"keylog file not found: {keylog_path}"
    else:
        detail = "no --keylog given and the capture has no embedded DSB"
    raise NoDecryptionKeysError(
        f"Cannot decrypt {pcap_path}: {detail}. "
        "Pass --keylog <SSLKEYLOGFILE>, or use a pcapng with an embedded "
        "Decryption Secrets Block (DSB)."
    )


def _emit_ssh_connections(
    tshark_bin: str,
    pcap_path: str,
    *,
    heuristic: bool,
    collector: FlowCollector,
    state: _WriterState,
) -> None:
    """Add a metadata-only synthetic flow per SSH connection found in *pcap*.

    SSH's handshake (banners + KEXINIT) is PLAINTEXT, so connection metadata is
    recoverable offline even though the payload is not. Each connection becomes
    a synthetic flow carrying an :class:`SshLayer`. Purely additive: any
    extraction failure is logged and swallowed so it never aborts the
    conversion.
    """
    try:
        connections = extract_ssh_connections(
            tshark_bin, pcap_path, heuristic=heuristic)
    except Exception:
        logger.warning("SSH metadata extraction failed; continuing without "
                       "SSH flows", exc_info=True)
        return
    _add_ssh_synthetic_flows(connections, collector, state)


def _add_ssh_synthetic_flows(connections: list[dict], collector: FlowCollector,
                             state: _WriterState) -> None:
    """Add one metadata-only synthetic flow (an :class:`SshLayer`) per SSH connection."""
    for conn in connections:
        layer = SshLayer(
            client_version=conn.get("client_version", ""),
            server_version=conn.get("server_version", ""),
            kex=conn.get("kex", ""),
            cipher=conn.get("cipher", ""),
            mac=conn.get("mac", ""),
        )
        collector.add_synthetic_flow(
            src_addr=conn.get("src_addr", ""),
            src_port=conn.get("src_port", 0),
            dst_addr=conn.get("dst_addr", ""),
            dst_port=conn.get("dst_port", 0),
            layer=layer,
            detected_protocol="SSH",
            transport="tcp",
            protocol="ssh",
        )
        state.ensure_open()


# --------------------------------------------------------------------------- #
# Offline-decryptor registry wiring
# --------------------------------------------------------------------------- #
#
# ``convert_pcap_to_tap`` iterates the offline registry instead of hardcoding
# per-protocol if-blocks (and so plugin protocols join automatically). Every
# in-tree offline decryptor (MTProto/Telegram, Signal, RC4, Schannel) ships as a
# self-registering subpackage discovered via :func:`_discover_offline_decryptor_extensions`.
# The scan imports subpackages in sorted name order (``pkgutil.iter_modules``),
# so registration order is deterministic: mtproto, telegram, rc4, schannel, signal.

def _discover_offline_decryptor_extensions() -> None:
    """Import in-tree offline-decryptor subpackages so they self-register.

    Mirrors ``friTap.protocols.registry._discover_protocol_extensions``: scan the
    subpackages of the :mod:`friTap.offline` package and import every package
    (``info.ispkg``) whose name does not start with ``_``. A package that carries
    the discovery marker (``is_fritap_offline_decryptor``) self-registers its
    :class:`OfflineDecryptorEntry` on import; a package without the marker (e.g.
    the generic ``net`` / ``tls`` subpackages) imports harmlessly and does NOT
    register.

    Names NO protocol — a filtered/public build that omits a private subpackage
    simply has nothing to import here. Idempotent: registration is idempotent in
    the registry, and a broken/optional subpackage is logged at debug and skipped.
    """
    import pkgutil

    try:
        from friTap import offline as _offline_pkg
    except Exception:  # pragma: no cover - the package we live in must import
        return
    for info in pkgutil.iter_modules(_offline_pkg.__path__):
        if not info.ispkg or info.name.startswith("_"):
            continue
        try:
            importlib.import_module(f"{_offline_pkg.__name__}.{info.name}")
        except Exception as exc:  # a broken/optional subpackage must not break core
            logger.debug("skipping offline-decryptor subpackage %r: %s", info.name, exc)


# Make sure every in-tree offline decryptor is registered (idempotent). All of
# them (MTProto/Telegram included) ship as self-registering in-tree subpackages
# picked up by the discovery scan, so the public core never names them.
# ``friTap.offline.mtproto`` sorts first, so its two entries stay first in the
# registry, ahead of the TLS-riding / nested decryptors. Historical name kept
# as an alias.
_register_builtin_offline_decryptors = _discover_offline_decryptor_extensions


_register_builtin_offline_decryptors()


# The messaging protocols whose obfuscated/self-contained transports friTap
# decrypts itself (not via tshark). Their counters all live in
# ``ConvertResult.per_protocol`` under these prefixes. The legacy flat
# ``mtproto_*`` names are not stored separately: they are read-only properties
# over ``per_protocol["mtproto"]`` declared by
# ``friTap.offline.result_schema.V1_FLAT_COUNTERS`` (kept for the frozen v1 JSON
# shape; deprecated aliases). Walking every prefix covers a
# ``telegram``-keylog run's counts too. Registry-derived (``messaging``), in
# registration order: ("mtproto", "telegram", "signal") today.
from friTap.offline.registry import attach_hooks as _attach_hooks  # noqa: E402
from friTap.offline.registry import (  # noqa: E402
    default_resync_search_depth as _default_resync_search_depth,
)
from friTap.offline.registry import entry_family as _entry_family  # noqa: E402
from friTap.offline.registry import (  # noqa: E402
    get_offline_decryptor_registry as _get_offline_decryptor_registry,
)
from friTap.offline.registry import (  # noqa: E402
    messaging_protocol_names as _messaging_protocol_names,
)

MESSAGING_PREFIXES = _messaging_protocol_names(_get_offline_decryptor_registry().list())

# MTProto's default resync search depth (the first registered mid-stream
# decryptor's ``resync_default``), kept for display and back-compat only. The
# ``resync_search_depth`` parameter default is ``None``: each offline decryptor
# then applies its OWN default.
DEFAULT_RESYNC_SEARCH_DEPTH = _default_resync_search_depth(
    _get_offline_decryptor_registry().list())


def _tls_riding_protocol_names() -> set:
    """Names of offline decryptors whose protocol rides inside TLS.

    Registry-driven (``requires_tls_strip``) rather than a hardcoded literal:
    today this is just ``{"signal"}``, but any future TLS-riding plugin protocol
    is picked up automatically.
    """
    return {
        e.protocol_name
        for e in _get_offline_decryptor_registry().list()
        if e.requires_tls_strip
    }


def _tls_nested_protocol_names() -> set:
    """Names of independent decryptors that can nest inside TLS (``nests_in_tls``).

    Registry-driven like :func:`_tls_riding_protocol_names` (today ``{"rc4"}``).
    """
    return {
        e.protocol_name
        for e in _get_offline_decryptor_registry().list()
        if e.nests_in_tls
    }


def _post_attach_transports() -> frozenset:
    """Transports whose flows get metadata folded on AFTER collection.

    TLS-riding decryptors (Signal), TLS-nesting ones (RC4-in-TLS) plus the
    message transports (Telegram MTProto / Secret-Chat): convert_pcap_to_tap
    writes these flows itself once the ``_attach_*`` passes ran, so the
    TapWriter defers them on "completed".
    """
    return frozenset(_tls_riding_protocol_names() | _tls_nested_protocol_names()
                     | MESSAGE_TRANSPORTS)


def _tls_holdback_transports(present_entries) -> frozenset:
    """``{"tls"}`` while a TLS-nesting decryptor runs on this capture, else empty.

    Its TLS flows are then written only after the nested attach, which may
    absorb them; a capture without such a decryptor keeps the early TLS write.
    """
    if any(getattr(e, "nests_in_tls", False) for e in present_entries):
        return frozenset({"tls"})
    return frozenset()


def _run_registered_attaches(collector, state) -> set:
    """Run every registered entry's post-collection attach hook, in order.

    Registry-driven (``attach`` / ``attach_order``): today the RC4-in-TLS fold,
    then the Telegram fold. Each hook gets the LIVE flows and runs whether or
    not its protocol was selected (it is a no-op without its own state).
    Returns the union of the absorbed flow ids.
    """
    absorbed: set = set()
    for hook in _attach_hooks(_get_offline_decryptor_registry().list()):
        absorbed |= hook(collector.live_flows(), state) or set()
    return absorbed


def _run_midstream_tls_stage(
    pcap_path: str,
    sidecar_path: str | None,
    *,
    bus: EventBus,
    state: _WriterState,
    result: ConvertResult,
    tls_ports: tuple[int, ...],
) -> set:
    """Bind mid-stream TLS secret bundles and emit their plaintext; return bound keys.

    No-op (returns an empty set) without a sidecar path or when the file is
    absent (logged as a warning) or empty. Delegates to
    :func:`friTap.offline.tls_midstream.pipeline.run_midstream_tls_stage`, seeding
    it with the capture's first-packet time so the synthetic events order after
    the handshake-anchored flows. Never aborts the conversion.
    """
    if not sidecar_path:
        return set()
    if not os.path.isfile(sidecar_path):
        logger.warning("TLS mid-stream secret-bundle sidecar %s not found; "
                       "skipping mid-stream TLS decryption", sidecar_path)
        return set()
    try:
        from friTap.offline.tls_midstream.pipeline import run_midstream_tls_stage

        server_ports = tls_ports or (443,)
        return run_midstream_tls_stage(
            pcap_path, sidecar_path,
            bus=bus, state=state, result=result,
            base_ts=_first_packet_time(pcap_path),
            server_ports=tuple(server_ports),
        )
    except Exception:  # noqa: BLE001 - the mid-stream stage is additive
        logger.warning("Mid-stream TLS stage failed; continuing without it",
                       exc_info=True)
        return set()


def _possible_raw_tcp_consumers(midstream_sidecar: str | None,
                                independent_plan: list) -> int:
    """Upper bound on the raw-TCP reassemblies one conversion may run.

    The mid-stream TLS stage reassembles only when its sidecar exists (the same
    gate as :func:`_run_midstream_tls_stage`); each independent-decryptor pass
    may reassemble raw TCP. Over-counting only keeps the shared parse cached, so
    no per-protocol knowledge is needed here.
    """
    midstream = 1 if midstream_sidecar and os.path.isfile(midstream_sidecar) else 0
    return midstream + len(independent_plan)


def _bridge_bound_midstream_spans(
    state: _WriterState,
    bound_keys: set,
    proto_keylogs: dict,
    present_entries: list,
    *,
    bus: EventBus,
    result: ConvertResult,
) -> None:
    """Hand mid-stream-recovered TLS plaintext to every entry's ``midstream_spans``.

    Registry-driven: each registered entry carrying the optional hook gets the
    bound connections (the hook picks its own keylog out of *present_entries*).
    Only an import failure of a hook's lazily-imported component is guarded: an
    absent component (a filtered build) is a silent no-op and any other import
    failure is surfaced but never aborts the surrounding conversion. A decode
    failure inside the hook propagates (the hook guards its own decode). A no-op
    as well when nothing bound.
    """
    if not bound_keys:
        return
    for entry in _get_offline_decryptor_registry().list():
        hook = entry.midstream_spans
        if hook is None:
            continue
        try:
            hook(state, bound_keys, proto_keylogs, present_entries,
                 bus=bus, result=result)
        except ImportError as exc:  # the bridge is additive; never break convert
            if not _is_absent_hook_component(exc, hook):
                logger.warning("Mid-stream span bridge unavailable; continuing without it",
                               exc_info=True)


def _is_absent_hook_component(exc: ImportError, hook) -> bool:
    """True when *exc* is a missing module of *hook*'s own package (filtered build)."""
    package = getattr(hook, "__module__", "").rpartition(".")[0]
    return bool(package) and isinstance(exc, ModuleNotFoundError) and (
        exc.name or "").startswith(package)


def _relabel_midstream_flows(flows, bound_keys: set) -> None:
    """Stamp ``TLS(midstream)`` on flows that bound only via a mid-stream secret.

    Only flows whose 4-tuple is in *bound_keys* and that carry no
    ``detected_protocol`` yet are relabelled, so a richer inner decoder (e.g.
    Signal) keeps its own protocol label. Pure mutation of the live flow objects.
    """
    if not bound_keys:
        return
    from friTap.connection_index import canonical_4tuple
    from friTap.offline.tls_midstream.pipeline import MIDSTREAM_PROTOCOL_LABEL

    for flow in flows:
        key = canonical_4tuple(
            flow.src_addr, flow.src_port, flow.dst_addr, flow.dst_port)
        if key in bound_keys and not getattr(flow, "detected_protocol", ""):
            flow.detected_protocol = MIDSTREAM_PROTOCOL_LABEL


def _make_metadata_marker(layer_cls, name: str):
    """Build a metadata-only (no-bytes) layer marker named *name*."""
    from friTap.flow.layers import LayerData
    marker = layer_cls()
    marker._name = name
    marker.metadata_only = True
    marker.data = LayerData(data_source="none")
    return marker


def _apply_inner_meta(layer, meta: dict | None) -> None:
    """Fold a TLS-riding decryptor's accumulated parsed inner metadata onto its
    innermost flow layer.

    No-op when *layer* or *meta* is absent, so a flow with no recovered metadata
    keeps its empty-but-valid layer (degrades, never raises).
    """
    if layer is None or not meta:
        return
    layer.chat_type = meta.get("chat_type", "")
    layer.identifier = meta.get("identifier", "")
    messages = meta.get("messages", []) or []
    layer.messages = messages
    layer.message_count = len(messages)


def _tls_layers_by_endpoint(flows, endpoint_key) -> dict:
    """The TLS layer of each endpoint pair that carries a ``transport="tls"`` flow.

    A TLS flow whose layer stack is not materialized yet (still live, and with no
    captured handshake to stamp it, e.g. a mid-stream recovery) still proves the
    connection rides TLS: it maps to an empty-metadata TLS layer, the same layer
    its own finalize would build. A materialized layer always wins.
    """
    from friTap.flow.layers import TlsLayer

    by_endpoint: dict = {}
    unstamped: set = set()
    for flow in flows:
        if getattr(flow, "transport", "") != "tls":
            continue
        tls_layer = flow.layer("tls")
        if tls_layer is not None:
            by_endpoint.setdefault(endpoint_key(flow), tls_layer)
        else:
            unstamped.add(endpoint_key(flow))
    for key in unstamped - set(by_endpoint):
        by_endpoint[key] = TlsLayer()
    return by_endpoint


def _carries_http2(flow) -> bool:
    """True when the collector recognised *flow*'s decrypted bytes as HTTP/2.

    Evidence is the parser's ``detected_protocol``, a parsed request/response
    protocol, or an already-materialized ``http2`` layer.
    """
    from friTap.constants import PROTOCOL_HTTP2

    if getattr(flow, "detected_protocol", "") == PROTOCOL_HTTP2:
        return True
    messages = (getattr(flow, "request", None), getattr(flow, "response", None))
    if any(getattr(msg, "protocol", "") == PROTOCOL_HTTP2 for msg in messages):
        return True
    return flow.layer("http2") is not None


def _http2_endpoints(flows, endpoint_key) -> set:
    """Endpoint pairs whose ``transport="tls"`` companion flow carries HTTP/2.

    The proof for an HTTP/2 hop when no ALPN is known, e.g. a mid-stream
    recovery whose handshake (and so its ALPN) was never captured.
    """
    return {
        endpoint_key(flow) for flow in flows
        if getattr(flow, "transport", "") == "tls" and _carries_http2(flow)
    }


def _attach_transport_metadata_layers(flows, inner_meta: dict | None = None) -> None:
    """Attach the TLS/HTTP-2/WebSocket encapsulation layers onto TLS-riding flows.

    A TLS-riding offline-decrypted flow carries only its innermost decrypted
    layer, while the TLS handshake metadata (SNI/version/cipher/ALPN) lands on a
    SEPARATE ``protocol="tls"`` flow over the same 4-tuple. This correlates the
    two by endpoint pair (via the spelling-independent :func:`canonical_4tuple`
    key) and rebuilds each such flow's layer stack as::

        TlsLayer(metadata-only) -> [AppLayer("http2")] -> AppLayer("websocket")
            -> <inner protocol layer>(chunks)

    The outer layers are metadata-only markers (no bytes of their own); only the
    innermost layer owns the decrypted plaintext. The HTTP/2 marker is added only
    when the TLS ALPN advertises h2 or the companion TLS flow over the same
    endpoints was recognised as HTTP/2 (a mid-stream recovery has no ALPN);
    the legacy plain-WebSocket transport gets
    just TLS -> WebSocket -> inner. Flows with no correlatable TLS metadata are
    left untouched (payload-only), exactly like live plaintext-hook captures. The
    set of TLS-riding protocols is registry-driven (``requires_tls_strip``), so a
    TLS-riding plugin protocol is handled here automatically.
    """
    from friTap.connection_index import canonical_4tuple, normalize_addr
    from friTap.flow.layers import AppLayer, TlsLayer

    def endpoint_key(flow) -> str:
        # Canonical (spelling-independent) key — must match the key the
        # TLS-riding emitter stored the metadata under.
        return canonical_4tuple(flow.src_addr, flow.src_port,
                                flow.dst_addr, flow.dst_port)

    # Consumed-once tracking so the fallback match can't hand the same parsed
    # messages to two different flows.
    consumed_meta_keys: set = set()

    def lookup_inner_meta(flow):
        """Find this flow's parsed-message metadata, resilient to key drift.

        Primary: exact canonical-key hit. Fallback (safety net for any residual
        address-spelling drift between tshark passes): the single unconsumed
        ``inner_meta`` entry whose canonical endpoint pair equals the flow's.
        """
        if not inner_meta:
            return None
        key = endpoint_key(flow)
        if key in inner_meta and key not in consumed_meta_keys:
            consumed_meta_keys.add(key)
            return inner_meta[key]
        flow_eps = {
            f"{normalize_addr(flow.src_addr)}:{flow.src_port}",
            f"{normalize_addr(flow.dst_addr)}:{flow.dst_port}",
        }
        candidates = [
            k for k in inner_meta
            if k not in consumed_meta_keys and "-" in k
            and set(k.split("-", 1)) == flow_eps
        ]
        if len(candidates) == 1:
            chosen = candidates[0]
            consumed_meta_keys.add(chosen)
            logger.debug(
                "inner meta fallback-matched flow %s to key %s",
                getattr(flow, "flow_id", "?"), chosen,
            )
            return inner_meta[chosen]
        return None

    tls_riding = _tls_riding_protocol_names()
    if not tls_riding:
        return

    tls_layer_by_endpoint = _tls_layers_by_endpoint(flows, endpoint_key)
    http2_endpoints = _http2_endpoints(flows, endpoint_key)

    for flow in flows:
        inner_name = getattr(flow, "transport", "")
        if inner_name not in tls_riding:
            continue
        # Parsed inner metadata accumulated by the TLS-riding emitter (DatalogEvent
        # cannot carry it). Looked up by the same canonical 4-tuple key, with a
        # consumed-once fallback so message-bearing flows are never orphaned.
        meta = lookup_inner_meta(flow)

        source = tls_layer_by_endpoint.get(endpoint_key(flow))
        if source is None:
            # No correlatable TLS metadata (e.g. the handshake wasn't captured /
            # the capture started mid-connection) -> leave the flow payload-only,
            # but STILL fold any decrypted messages onto the inner layer so they
            # surface independently of whether the TLS handshake was recovered.
            if meta:
                inner = flow.layer(inner_name)
                if inner is None:
                    getattr(flow, inner_name)  # lazily materialize the chunks layer
                    inner = flow.layer(inner_name)
                _apply_inner_meta(inner, meta)
            continue

        inner_layer = flow.layer(inner_name)

        tls_marker = _make_metadata_marker(TlsLayer, "tls")
        tls_marker.version = source.version
        tls_marker.sni = source.sni
        tls_marker.cipher = source.cipher
        tls_marker.alpn = source.alpn

        rebuilt = [tls_marker]
        # TLS-riding protocols ride a WebSocket-over-HTTP/2 transport (HTTP/2 only
        # when ALPN advertises h2 or the companion TLS flow parsed as HTTP/2;
        # legacy transport is plain TLS -> WebSocket).
        # An observed ALPN is authoritative; the companion-flow HTTP/2 detection
        # is only the fallback when no ALPN was captured (e.g. mid-stream).
        alpn = (source.alpn or "").lower()
        if "h2" in alpn or (not alpn and endpoint_key(flow) in http2_endpoints):
            rebuilt.append(_make_metadata_marker(AppLayer, "http2"))
        rebuilt.append(_make_metadata_marker(AppLayer, "websocket"))

        # Rebuild the stack with the markers first, then the innermost decrypted
        # layer (the chunks-owning layer with the bytes) last.
        flow.layers = []
        for marker in rebuilt:
            flow.add_layer(marker)
        if inner_layer is not None:
            # Preserve the existing inner layer (chat_type/identifier/count, etc.).
            inner_layer.metadata_only = False
            _apply_inner_meta(inner_layer, meta)
            flow.add_layer(inner_layer)
        else:
            # No materialized inner layer yet (offline flows build it lazily at
            # finalize). ``getattr`` triggers _create_layer, which ALREADY appends
            # the chunks-view layer — do NOT add_layer it again.
            getattr(flow, inner_name)
            _apply_inner_meta(flow.layer(inner_name), meta)


def _family_representative(members: list, family: str):
    """Pick the entry that runs a family: the one named after it, else the first."""
    for entry in members:
        if entry.protocol_name == family:
            return entry
    return members[0]


def _dedupe_independent_entries(entries, proto_keylogs: dict) -> list:
    """Collapse offline entries that would run the same decoder twice.

    Entries are grouped by :func:`_entry_family` (e.g. ``mtproto`` and
    ``telegram`` both run the Telegram decoder). Each family runs ONCE, via
    the entry named after the family when present. Returns ``(entry, keylogs)``
    pairs, *keylogs* being the family's distinct keylog paths (by real path):
    one path is the plain case, several mean the pass must load their union.
    Order follows the first appearance of each family.
    """
    families: dict = {}
    for entry in entries:
        families.setdefault(_entry_family(entry), []).append(entry)
    plan = []
    for family, members in families.items():
        chosen = _family_representative(members, family)
        paths = unique_keylog_paths(
            proto_keylogs[chosen.protocol_name],
            [proto_keylogs[m.protocol_name] for m in members],
        )
        for dropped in (m for m in members if m is not chosen):
            logger.debug(
                "offline decryptor %r shares decoder family %r with %r; "
                "running it once", dropped.protocol_name, family,
                chosen.protocol_name,
            )
        plan.append((chosen, paths))
    return plan


def _emitter_accepts(emitter, name: str) -> bool:
    """True if *emitter* declares keyword *name* (or a ``**kwargs`` catch-all).

    Lets the dispatch forward a protocol-specific kwarg only to the emitters that
    understand it, so a plugin decryptor with a fixed signature is never handed an
    argument it cannot take. Fails open (assume accepted) if introspection fails.
    """
    try:
        params = inspect.signature(emitter).parameters.values()
    except (TypeError, ValueError):
        return True
    if any(p.kind is inspect.Parameter.VAR_KEYWORD for p in params):
        return True
    return any(p.name == name for p in params)


def _resync_kwargs(entry, depth: int | None) -> dict:
    """Map the generic resync *depth* onto *entry*'s own emitter keyword.

    Returns ``{entry.resync_param: depth}``, or ``{}`` when *depth* is ``None``
    (each emitter keeps its own default), when the entry declares no
    ``resync_param``, or when its emitter does not accept that keyword. An
    explicit ``0`` (no lag search) is forwarded like any other depth.
    """
    param = getattr(entry, "resync_param", None)
    if depth is None or not param or not _emitter_accepts(entry.emitter, param):
        return {}
    return {param: depth}


def _run_independent_entry(entry, keylogs: list, **emitter_kwargs) -> None:
    """Run one self-contained offline entry over its (possibly merged) keylogs.

    ``extra_keylogs`` is only passed when a family brought several distinct
    files, so single-keylog (plugin) emitters keep their plain signature.
    """
    if len(keylogs) > 1:
        emitter_kwargs["extra_keylogs"] = tuple(keylogs[1:])
    entry.emitter(proto_keylog=keylogs[0], **emitter_kwargs)


def _emit_progress(progress: "Callable[[str], None] | None", message: str) -> None:
    """Report a coarse decrypt milestone to *progress*, if supplied.

    Total: a raising or missing callback must never break the conversion.
    """
    if progress is None:
        return
    try:
        progress(message)
    except Exception:  # noqa: BLE001 - progress reporting is best-effort
        logger.debug("progress callback raised", exc_info=True)


@dataclass
class _ConversionContext:
    """Everything one :func:`convert_pcap_to_tap` run threads through its stages.

    Built in three steps: the caller's inputs, the derived plan
    (:func:`_prepare_conversion`), then the event pipeline
    (:func:`_wire_pipeline`). The cross-stage fields carry results one stage
    hands to a later one.
    """

    # Inputs (the caller's arguments).
    pcap_path: str
    keylog_path: str | None
    tap_path: str
    tls_ports: tuple[int, ...]
    quic_ports: tuple[int, ...]
    extra_decode_as: tuple[str, ...]
    heuristic: bool
    capture_target: str
    resync_search_depth: int | None
    tls_midstream_secrets: str | None
    progress: "Callable[[str], None] | None"
    # Derived plan.
    has_keys: bool = False
    proto_keylogs: dict = field(default_factory=dict)
    present_entries: list = field(default_factory=list)
    tls_strip_entries: list = field(default_factory=list)
    independent_entries: list = field(default_factory=list)
    independent_plan: list = field(default_factory=list)
    tshark_bin: str = ""
    tshark_release: tuple = ()
    target: str = ""
    # Event pipeline.
    bus: EventBus | None = None
    collector: FlowCollector | None = None
    writer: TapWriter | None = None
    post_attach_transports: frozenset = frozenset()
    tracker: StreamDirectionTracker | None = None
    tls_tracker: StreamDirectionTracker | None = None
    result: ConvertResult | None = None
    state: WriterState | None = None
    # Cross-stage results.
    midstream_bound_keys: set = field(default_factory=set)
    absorbed_flow_ids: set = field(default_factory=set)


def _fold_protocol_keylogs(protocol_keylogs: dict | None,
                           legacy_protocol_keylogs: dict) -> dict:
    """Merge back-compat ``<protocol>_keylog`` kwargs into the generic keylog map.

    The protocol is the token before ``_keylog`` (``mtproto_keylog`` ->
    ``mtproto``), so the core names no protocol. Entries already in
    *protocol_keylogs* win; empty values are ignored. Returns a new dict.
    """
    proto_keylogs: dict[str, str] = dict(protocol_keylogs or {})
    for kwarg_name, kwarg_value in legacy_protocol_keylogs.items():
        if kwarg_value and kwarg_name.endswith("_keylog"):
            proto_keylogs.setdefault(kwarg_name[: -len("_keylog")], kwarg_value)
    return proto_keylogs


def _present_offline_entries(proto_keylogs: dict) -> list:
    """Registered offline entries whose keylog was supplied and exists.

    Looks the registry up on every call. A supplied but missing keylog is
    logged and its entry skipped.
    """
    present = []
    for entry in _get_offline_decryptor_registry().list():
        keylog = proto_keylogs.get(entry.protocol_name)
        if not keylog:
            continue
        if not os.path.isfile(keylog):
            logger.warning(
                "%s keylog %s not found; skipping %s decryption",
                entry.protocol_name, keylog, entry.protocol_name,
            )
            continue
        present.append(entry)
    return present


def _prepare_conversion(ctx: _ConversionContext, protocol_keylogs: dict | None,
                        legacy_protocol_keylogs: dict, tshark_path: str | None) -> None:
    """Fill *ctx*'s derived plan: keys, offline entries, tshark binary, target.

    Decryption uses an explicit keylog file OR a pcapng with an embedded
    Decryption Secrets Block (DSB). Without either the capture is ingested as
    already-plaintext, but a ``--keylog`` that was given and is missing fails
    loud (:class:`NoDecryptionKeysError`), so a typo is not mistaken for
    plaintext. Offline entries split into TLS-riding ones (consume tshark's
    plaintext, run only with keys) and independent ones (decrypt raw TCP), the
    latter collapsed to one pass per decoder family.
    """
    keylog_path = ctx.keylog_path
    keylog_present = bool(keylog_path) and os.path.isfile(keylog_path)
    ctx.has_keys = keylog_present or capture_has_dsb(ctx.pcap_path)
    if keylog_path and not ctx.has_keys:
        _require_decryptable(ctx.pcap_path, keylog_path)  # raises NoDecryptionKeysError

    ctx.proto_keylogs = _fold_protocol_keylogs(protocol_keylogs, legacy_protocol_keylogs)
    ctx.present_entries = _present_offline_entries(ctx.proto_keylogs)
    ctx.tls_strip_entries = [e for e in ctx.present_entries if e.requires_tls_strip]
    ctx.independent_entries = [e for e in ctx.present_entries if not e.requires_tls_strip]
    ctx.independent_plan = _dedupe_independent_entries(
        ctx.independent_entries, ctx.proto_keylogs)

    ctx.tshark_bin = find_tshark(tshark_path)
    ctx.tshark_release = tshark_version(ctx.tshark_bin) or ()
    warn_if_outdated(ctx.tshark_release)
    ctx.target = ctx.capture_target or os.path.basename(ctx.pcap_path)


def _wire_pipeline(ctx: _ConversionContext) -> None:
    """Build the bus -> collector -> writer pipeline and the direction trackers.

    Offline events carry pcap capture times, so the collector measures idle time
    by them. Flows of the post-attach transports are written once, after the
    post-collection attach, so the writer defers their early write. Each
    tracker is seeded with its protocol's server ports (TLS keyed on
    ``tcp.stream``, QUIC on ``udp.stream``) so direction does not depend on
    first-packet order. The ``.tap`` itself opens lazily on the first event.
    """
    ctx.bus = EventBus()
    ctx.collector = FlowCollector(event_bus=ctx.bus)
    ctx.collector.use_event_clock(True)
    post_attach = (_post_attach_transports()
                   | _tls_holdback_transports(ctx.present_entries))
    ctx.post_attach_transports = post_attach
    ctx.writer = TapWriter(
        defer_flow=lambda flow: getattr(flow, "transport", "") in post_attach,
    )
    ctx.collector.set_capture_target(ctx.target)
    ctx.bus.subscribe(DatalogEvent, ctx.collector.on_data)
    ctx.bus.subscribe(SessionEvent, ctx.collector.on_session_event)
    ctx.collector.subscribe(ctx.writer.on_flow_event)

    ctx.tracker = _StreamDirectionTracker(server_ports=ctx.quic_ports)
    ctx.tls_tracker = _StreamDirectionTracker(server_ports=ctx.tls_ports)
    ctx.result = ConvertResult(tap_path=ctx.tap_path)
    ctx.state = _WriterState(ctx.writer, ctx.tap_path, ctx.target, ctx.keylog_path)


def _run_midstream_stage(ctx: _ConversionContext) -> None:
    """Bind mid-stream TLS secret bundles, then bridge their plaintext.

    Flows captured with no ClientHello never surface in the tshark passes; with
    a secret-bundle sidecar their plaintext is recovered here first, so a
    span-consuming decoder sees it. Runs regardless of ``has_keys`` (a
    mid-stream-only capture has no NSS keys). The bridge then hands the bound
    connections to every entry's ``midstream_spans`` hook (e.g. Signal decoded
    straight from the recovered spans); both are no-ops without bindings.
    """
    ctx.midstream_bound_keys = _run_midstream_tls_stage(
        ctx.pcap_path, ctx.tls_midstream_secrets,
        bus=ctx.bus, state=ctx.state, result=ctx.result, tls_ports=ctx.tls_ports,
    )
    _bridge_bound_midstream_spans(
        ctx.state, ctx.midstream_bound_keys, ctx.proto_keylogs, ctx.present_entries,
        bus=ctx.bus, result=ctx.result,
    )


def _run_tshark_stage(ctx: _ConversionContext) -> None:
    """Run the tshark passes over the capture.

    With keys: ONE combined ``-T ek`` pass (:func:`_run_keyed_combined_pass`)
    yields the TLS handshake metadata and decrypted data, the QUIC metadata
    and data and the SSH metadata. Without keys, and with no independent
    offline decryptor present (its obfuscated bytes are not plaintext), the
    capture is ingested as already-plaintext (:func:`_run_keyless_passes`): a
    handshake pre-scan first finds the genuinely encrypted QUIC streams so
    they are skipped, then one pass reads the plaintext and the SSH metadata.
    Otherwise only the SSH metadata pass runs. SSH banners/KEXINIT need no
    keys and only add synthetic flows, last (a failure never aborts the
    conversion).
    """
    if ctx.has_keys:
        _emit_progress(ctx.progress, "Decrypting TLS/QUIC streams…")
        ssh_connections = _run_keyed_combined_pass(ctx)
    elif not ctx.independent_entries:
        ssh_connections = _run_keyless_passes(ctx)
    else:
        _emit_ssh_connections(ctx.tshark_bin, ctx.pcap_path, heuristic=ctx.heuristic,
                              collector=ctx.collector, state=ctx.state)
        return
    _add_ssh_synthetic_flows(ssh_connections, ctx.collector, ctx.state)


def _run_keyed_combined_pass(ctx: _ConversionContext) -> list[dict]:
    """Decrypt TLS and QUIC and read every metadata with ONE tshark run.

    Each row goes to its consumers (:mod:`friTap.offline.tshark` row
    predicates): TLS handshake and app-data rows to the live
    :class:`TlsSinglePass`, QUIC rows to :class:`_QuicCombinedSink`, SSH rows to
    the SSH accumulator. The event order is that of the former separate passes
    (recorded in ``tests/fixtures/combined_pass/``): the TLS events stream live, then the QUIC SessionEvents, the QUIC data and
    the reassembly leftovers (buffered until the end). Metadata failures are
    non-fatal. Returns the SSH connections.
    """
    marker = tls_app_data_marker(ctx.tshark_release)
    cmd = build_combined_command(
        ctx.pcap_path, ctx.keylog_path,
        tls_ports=ctx.tls_ports, quic_ports=ctx.quic_ports,
        extra_decode_as=ctx.extra_decode_as, heuristic=ctx.heuristic,
        app_data_marker=marker)
    cmd[0] = ctx.tshark_bin  # replace the literal "tshark" with the resolved path

    tls = TlsSinglePass(bus=ctx.bus, state=ctx.state, result=ctx.result,
                        tracker=ctx.tls_tracker, app_data_marker=marker,
                        packet_to_events=_tls_packet_to_events)
    quic = _QuicCombinedSink(ctx.bus, ctx.state, ctx.result, ctx.tracker)
    ssh = SshConnectionAccumulator()
    with _closing_packets(stream_packets(cmd)) as packets:
        for pkt in packets:
            tls.feed(pkt)
            layers = pkt.get("layers") or {}
            quic.feed(pkt, layers)
            if is_ssh_row(layers):
                _fold_metadata_row(ssh, layers, "SSH")
    tls.finish()
    quic.flush()
    return ssh.result()


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
    then the reassembly leftovers stamped with the last timestamp, exactly as
    the separate QUIC metadata + data passes did after the TLS pass.
    """

    def __init__(self, bus: EventBus, state: _WriterState, result: ConvertResult,
                 tracker: _StreamDirectionTracker) -> None:
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
        udp_stream = _coerce_int(_first(_field(layers, "udp.stream")), default=None)
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


def _capture_may_carry_udp(pcap_path: str) -> bool:
    """Conservatively tell whether *pcap_path* may hold any UDP datagram.

    Delegates to :func:`friTap.offline.net.pcap_fast.capture_may_carry_udp`
    (imported lazily: it pulls in scapy's pcap reader).
    """
    from friTap.offline.net.pcap_fast import capture_may_carry_udp

    return capture_may_carry_udp(pcap_path)


def _run_keyless_passes(ctx: _ConversionContext) -> list[dict]:
    """Ingest an already-plaintext capture; return its SSH connections.

    The QUIC handshake detection stays its own pass: the plaintext pass must
    not get the ``udp.port==443,quic`` Decode-As (friTap's decrypted HTTP/3
    would be skipped). It is skipped when the capture holds no UDP at all
    (:func:`_capture_may_carry_udp`). The plaintext pass also exports the SSH
    rows.
    """
    common = dict(extra_decode_as=ctx.extra_decode_as, heuristic=ctx.heuristic)
    encrypted_quic_streams: frozenset[str] = frozenset()
    if _capture_may_carry_udp(ctx.pcap_path):
        encrypted_quic_streams = _detect_encrypted_quic_streams(
            ctx.tshark_bin, ctx.pcap_path, quic_ports=ctx.quic_ports, **common)
    plaintext_tracker = _StreamDirectionTracker(
        server_ports=(*_PLAINTEXT_SERVER_PORTS, *ctx.tls_ports, *ctx.quic_ports))
    ssh = SshConnectionAccumulator()
    _emit_plaintext_streams_singlepass(
        ctx.tshark_bin, ctx.pcap_path, **common,
        bus=ctx.bus, state=ctx.state, result=ctx.result, tracker=plaintext_tracker,
        encrypted_quic_streams=encrypted_quic_streams, ssh_accumulator=ssh,
    )
    return ssh.result()


def _run_tls_riding_decryptors(ctx: _ConversionContext) -> None:
    """Run each present TLS-riding entry (e.g. Signal) over tshark's plaintext.

    Only with keys: these decoders consume the TLS plaintext the tshark stage
    decrypted.
    """
    if not ctx.has_keys:
        return
    for entry in ctx.tls_strip_entries:
        entry.emitter(
            pcap_path=ctx.pcap_path,
            proto_keylog=ctx.proto_keylogs[entry.protocol_name],
            tls_keylog_path=ctx.keylog_path,
            tshark_bin=ctx.tshark_bin,
            tls_ports=ctx.tls_ports,
            bus=ctx.bus, state=ctx.state, result=ctx.result,
            **_resync_kwargs(entry, ctx.resync_search_depth),
        )


def _entry_display_name(entry) -> str:
    """The protocol name an offline-decryptor *entry* is shown under in progress text."""
    return getattr(entry, "protocol_name", "") or "protocol"


def _run_independent_decryptors(ctx: _ConversionContext) -> None:
    """Run each self-contained decoder family (e.g. MTProto, RC4) over raw TCP.

    Independent of any tshark pass, so it runs with or without keys.
    """
    for entry, entry_keylogs in ctx.independent_plan:
        _emit_progress(
            ctx.progress,
            f"Decrypting {_entry_display_name(entry)}…",
        )
        _run_independent_entry(
            entry, entry_keylogs,
            pcap_path=ctx.pcap_path,
            tls_keylog_path=ctx.keylog_path,
            tshark_bin=ctx.tshark_bin,
            tls_ports=ctx.tls_ports,
            bus=ctx.bus, state=ctx.state, result=ctx.result,
            **_resync_kwargs(entry, ctx.resync_search_depth),
        )


def _finalize_conversion(ctx: _ConversionContext) -> None:
    """Fold post-collection metadata onto the live flows, then write every flow.

    The ``.tap`` header starts at the capture's FIRST packet (handshakes and
    undecryptable traffic precede the first decrypted record). Everything below
    mutates the LIVE flow objects and so must run before ``flush()``, which
    completes and writes them: the transport metadata layers (TLS -> HTTP/2 ->
    WebSocket -> inner), the ``TLS(midstream)`` relabel (only for flows without
    a richer inner protocol) and the registered attach hooks (RC4-in-TLS, the
    Telegram fold), whose fully absorbed TLS flows are not written.
    """
    ctx.state.ensure_open()
    ctx.state.note_capture_time(_first_packet_time(ctx.pcap_path))
    _attach_transport_metadata_layers(ctx.collector.live_flows(), ctx.state.inner_meta)
    _relabel_midstream_flows(ctx.collector.live_flows(), ctx.midstream_bound_keys)
    ctx.absorbed_flow_ids = _run_registered_attaches(ctx.collector, ctx.state)
    _write_remaining_flows(ctx)
    _emit_progress(ctx.progress, "Writing .tap…")


def _write_remaining_flows(ctx: _ConversionContext) -> None:
    """Flush the collector and write every flow the writer has not persisted.

    ``TapWriter.on_flow_event`` writes only on "completed", which offline
    reconstruction rarely emits, so ``flush()`` completes the active flows
    first. Post-attach flows (deferred by the writer) are written here exactly
    once with their attached layers; should one have been written early anyway,
    this rewrite wins (the flow index keeps the LAST record per flow_id).
    """
    ctx.collector.flush(end_at_last_activity=True)
    flows = [f for f in ctx.collector.get_flows()
             if f.flow_id not in ctx.absorbed_flow_ids]
    for flow in flows:
        transport = getattr(flow, "transport", "")
        if (not ctx.writer.has_written(flow.flow_id)
                or transport in ctx.post_attach_transports):
            ctx.writer.write_flow(flow)
    ctx.result.flow_count = len(flows)


def _report_conversion(result: ConvertResult) -> None:
    """Log the one-line conversion summary."""
    logger.info(
        "Offline conversion: %d flows, %d decrypted packets, %d streams, "
        "%d dropped TLS stream(s), %d dropped QUIC packet(s)",
        result.flow_count, result.decrypted_packet_count,
        result.stream_count, result.dropped_stream_count,
        result.dropped_packet_count,
    )


def convert_pcap_to_tap(
    pcap_path: str,
    keylog_path: str | None = None,
    tap_path: str | None = None,
    *,
    tls_ports: tuple[int, ...] = (),
    quic_ports: tuple[int, ...] = (),
    extra_decode_as: tuple[str, ...] = (),
    heuristic: bool = False,
    run_scan: bool = False,
    capture_target: str = "",
    tshark_path: str | None = None,
    protocol_keylogs: dict[str, str] | None = None,
    resync_search_depth: int | None = None,
    tls_midstream_secrets: str | None = None,
    progress: "Callable[[str], None] | None" = None,
    **legacy_protocol_keylogs: str | None,
) -> ConvertResult:
    """Decrypt *pcap_path* with tshark and reconstruct a friTap ``.tap`` file.

    Args:
        pcap_path: Encrypted capture (pcap/pcapng).
        keylog_path: NSS SSLKEYLOGFILE, or None for a DSB-embedded pcapng.
        tap_path: Output path; defaults to ``<pcap stem>.tap``.
        tls_ports / quic_ports: Custom server ports to Decode-As TLS / QUIC.
        extra_decode_as: Raw tshark ``-d`` rules passed through.
        heuristic: Enable tshark TLS-over-TCP heuristic dissection.
        run_scan: Run the analysis registry over the produced .tap afterward.
        capture_target: Target label stored in the .tap (defaults to basename).
        tshark_path: Explicit tshark binary path/command (else auto-discovered).
        protocol_keylogs: Generic ``{protocol_name: keylog_path}`` map for offline
            decryptors registered in :mod:`friTap.offline.registry` (including
            plugin protocols). Its entries win over the back-compat
            ``<protocol>_keylog`` kwargs (see *legacy_protocol_keylogs*).
        resync_search_depth: Generic maximum search depth when re-aligning a
            mid-stream flow to a memory-recovered key, applied to any offline
            decryptor that supports mid-stream recovery. Each registry entry
            names the emitter keyword that receives it (``resync_param``;
            MTProto/Telegram's ``obf_max_blocks`` today: 16-byte CTR blocks
            behind the live counter), and it is forwarded only to emitters that
            declare that keyword (via :func:`_resync_kwargs`); an entry without
            ``resync_param`` never receives it. ``None`` (the default)
            forwards nothing, so each emitter applies its own default (MTProto:
            :data:`~friTap.offline.mtproto.transport.DEFAULT_OBF_MAX_BLOCKS`,
            shown as :data:`DEFAULT_RESYNC_SEARCH_DEPTH`). An explicit value,
            including ``0`` (no lag search), is always forwarded.
        tls_midstream_secrets: Path to the memscan engine's JSONL sidecar of TLS
            1.3 secret bundles for flows captured with no ClientHello. When given
            (and the file exists), the mid-stream binding stage
            (:func:`friTap.offline.tls_midstream.pipeline.run_midstream_tls_stage`)
            trial-binds each bundle to the pcap's raw TLS streams, emits the
            recovered plaintext exactly like the tshark pass, and relabels the
            bound flows ``TLS(midstream)``.
        legacy_protocol_keylogs: Back-compat named keylog kwargs of the form
            ``<protocol>_keylog`` (e.g. ``mtproto_keylog=`` or a TLS-riding
            protocol's keylog). Each is folded into ``protocol_keylogs`` keyed by
            the leading ``<protocol>`` token, so historical callers keep working
            without the public core naming any specific protocol. Explicit
            ``protocol_keylogs`` entries win.

    Returns:
        A :class:`ConvertResult` summarizing the conversion.
    """
    if tap_path is None:
        tap_path = os.path.splitext(pcap_path)[0] + ".tap"
    ctx = _ConversionContext(
        pcap_path=pcap_path, keylog_path=keylog_path, tap_path=tap_path,
        tls_ports=tls_ports, quic_ports=quic_ports, extra_decode_as=extra_decode_as,
        heuristic=heuristic, capture_target=capture_target,
        resync_search_depth=resync_search_depth,
        tls_midstream_secrets=tls_midstream_secrets, progress=progress,
    )
    _prepare_conversion(ctx, protocol_keylogs, legacy_protocol_keylogs, tshark_path)
    _wire_pipeline(ctx)

    from friTap.offline.net.capture_cache import capture_cache_scope

    # Every raw-TCP reassembly below (mid-stream TLS, MTProto, RC4, ...) shares
    # ONE parse of the capture, released when the block ends. With fewer than
    # two possible consumers the scope caches nothing rather than holding the
    # parse across the tshark passes.
    raw_tcp_consumers = _possible_raw_tcp_consumers(
        ctx.tls_midstream_secrets, ctx.independent_plan)
    try:
        with capture_cache_scope(ctx.pcap_path, expected_consumers=raw_tcp_consumers):
            _run_midstream_stage(ctx)
            _run_tshark_stage(ctx)
            _run_tls_riding_decryptors(ctx)
            _run_independent_decryptors(ctx)
        _finalize_conversion(ctx)
    finally:
        if ctx.state.opened:
            ctx.writer.close()

    if run_scan:
        _emit_progress(progress, "Running analysis…")
        ctx.result.findings_count = _run_scan(tap_path)
    _report_conversion(ctx.result)
    return ctx.result


def _first_packet_time(pcap_path: str) -> float:
    """Capture time (epoch seconds) of the first packet in *pcap_path*.

    Reads only the first record via :func:`friTap.offline.net.pcap_fast.
    first_packet_time` (pcap and pcapng, including the pcapng timestamp
    resolution, identical to scapy's ``pkt.time``). Returns ``0.0``
    ("unknown") for an empty or unreadable capture, so callers can pass it
    straight to :meth:`_WriterState.note_capture_time`.
    """
    # scapy warns about an embedded DSB it cannot use; irrelevant here.
    scapy_log = logging.getLogger("scapy.runtime")
    previous_level = scapy_log.level
    scapy_log.setLevel(logging.ERROR)
    try:
        from friTap.offline.net.pcap_fast import first_packet_time

        return float(first_packet_time(pcap_path))
    except Exception:
        logger.debug("Could not read first packet time of %s", pcap_path,
                     exc_info=True)
    finally:
        scapy_log.setLevel(previous_level)
    return 0.0


def _run_scan(tap_path: str) -> int:
    """Run all registered analyzers over *tap_path*; return the finding count."""
    from friTap.analysis import analyze_tap_multi
    from friTap.analysis.registry import resolve_analyzers

    findings = analyze_tap_multi(resolve_analyzers("all"), tap_path)
    return len(findings)


def _merge_memory_scan_sidecars_into(
    ms_map: dict,
    pcap_path: str,
    keylog: str | None,
    protocol_keylogs: dict[str, str],
    legacy_keylogs: dict[str, str | None],
) -> str | None:
    """Union memory-scan sidecars into the effective keylog of each protocol.

    The effective per-protocol keylog is the one convert_pcap_to_tap will use:
    a ``protocol_keylogs`` entry first, then the back-compat ``<proto>_keylog``
    kwarg in *legacy_keylogs*. Merged paths are written back into BOTH maps
    (mutated in place, so they win downstream). TLS stays on the base
    ``keylog_path``. Returns the updated base *keylog*.
    """
    def _current(proto: str) -> str | None:
        if proto == "tls":
            return keylog
        return protocol_keylogs.get(proto) or legacy_keylogs.get(f"{proto}_keylog")

    from .keylog_picker import merge_memory_scan_sidecars

    merged_sidecars = merge_memory_scan_sidecars(
        ms_map, _current,
        out_dir=os.path.dirname(os.path.abspath(pcap_path)) or None)
    keylog = merged_sidecars.pop("tls", keylog)
    for proto, merged_path in merged_sidecars.items():
        protocol_keylogs[proto] = merged_path
        legacy_keylogs[f"{proto}_keylog"] = merged_path
    return keylog


def _with_manifest_protocol_keylogs(
    protocol_keylogs: dict[str, str] | None,
    explicit_legacy_keylogs: dict[str, str | None],
    manifest: dict,
) -> dict[str, str] | None:
    """*protocol_keylogs* plus the manifest's keylog for every protocol not given.

    A protocol counts as given when the caller passed it in *protocol_keylogs*
    or as a back-compat ``<protocol>_keylog`` kwarg (*explicit_legacy_keylogs*).
    The manifest's values come from :func:`friTap.offline.cli.
    manifest_protocol_keylogs` (``keylogs`` map first). Returns a new dict when
    the manifest adds anything, else *protocol_keylogs* unchanged.
    """
    from .cli import manifest_protocol_keylogs

    merged = dict(protocol_keylogs or {})
    for proto, path in manifest_protocol_keylogs(manifest).items():
        if not merged.get(proto) and not explicit_legacy_keylogs.get(f"{proto}_keylog"):
            merged[proto] = path
    return merged if merged != (protocol_keylogs or {}) else protocol_keylogs


def pcap_to_tap(
    pcap_path: str,
    *,
    keylog_path: str | None = None,
    tap_path: str | None = None,
    tls_ports: tuple[int, ...] = (),
    quic_ports: tuple[int, ...] = (),
    extra_decode_as: tuple[str, ...] = (),
    heuristic: bool = False,
    run_scan: bool = False,
    capture_target: str = "",
    tshark_path: str | None = None,
    protocol_keylogs: dict[str, str] | None = None,
    resync_search_depth: int | None = None,
    tls_midstream_secrets: str | None = None,
    use_manifest: bool = True,
    progress: "Callable[[str], None] | None" = None,
    **legacy_protocol_keylogs: str | None,
) -> ConvertResult:
    """Convert a captured pcap/pcapng to a friTap ``.tap``, manifest-aware.

    Presentation-agnostic wrapper around :func:`convert_pcap_to_tap` for
    external tools (Sandroid, web/TUI/CLI). When *use_manifest* is True and a
    ``<pcap>.fritap.json`` sidecar exists, the values the caller did NOT pass
    explicitly (``keylog_path``/``tls_ports``/``quic_ports``) are filled from
    it — the same precedence the ``fritap --from-pcap`` CLI uses (explicit
    arguments always win). Returns a :class:`ConvertResult`.

    Exposed at the package root as :func:`friTap.pcap_to_tap`. It lives in this
    submodule (not ``friTap/offline/__init__.py``) so it does not shadow the
    same-named ``friTap.offline.pcap_to_tap`` module attribute.

    Raises :class:`NoDecryptionKeysError` when the capture is encrypted and no
    keys (``--keylog`` / embedded DSB) are available; other tshark/IO failures
    propagate.
    """
    keylog = keylog_path
    tls = tuple(tls_ports)
    quic = tuple(quic_ports)
    midstream_secrets = tls_midstream_secrets
    # Back-compat ``<protocol>_keylog`` kwargs (e.g. ``mtproto_keylog`` or a
    # TLS-riding extension's keylog) are carried generically: the manifest's matching ``<protocol>_keylog``
    # key fills any the caller did not pass, and they flow through to
    # convert_pcap_to_tap as the same **kwargs (which folds them into the generic
    # protocol_keylogs map without the public core naming any extension protocol).
    legacy_keylogs: dict[str, str | None] = dict(legacy_protocol_keylogs)
    if use_manifest:
        # load_manifest takes a pcap path (not an argparse Namespace), so it is
        # safe to reuse here; imported lazily to avoid a cli <-> pcap_to_tap
        # import cycle (cli imports convert_pcap_to_tap from this module).
        from .cli import (
            load_manifest,
            resolve_manifest_keylog_paths,
            resolve_manifest_path,
        )

        # Every keylog path in the manifest is resolved against the manifest's
        # own directory (then the CWD), exactly as the CLI does.
        manifest = resolve_manifest_keylog_paths(pcap_path, load_manifest(pcap_path))
        if manifest:
            keylog = keylog or manifest.get("keylog") or None
            tls = tls or tuple(manifest.get("tls_ports", []))
            quic = quic or tuple(manifest.get("quic_ports", []))
            # Mid-stream TLS 1.3 secret-bundle sidecar (flows with no ClientHello).
            # A relative manifest value is resolved against the manifest's own
            # directory (then the CWD), so the result does not depend on where
            # the caller (e.g. the TUI) was started — same rule as the CLI.
            midstream_secrets = midstream_secrets or resolve_manifest_path(
                pcap_path, manifest.get("tls_midstream_secrets") or None)
            # Pull any ``<protocol>_keylog`` manifest keys (mtproto_keylog
            # included) the caller did not pass explicitly.
            for man_key, man_value in manifest.items():
                if (
                    man_key.endswith("_keylog")
                    and man_value
                    and not legacy_keylogs.get(man_key)
                ):
                    legacy_keylogs[man_key] = man_value
            # The per-protocol ``keylogs`` map (and each decryptor's top-level
            # field) fills every protocol the caller did not pass — the same
            # precedence as the CLI's merge_manifest.
            protocol_keylogs = _with_manifest_protocol_keylogs(
                protocol_keylogs, legacy_protocol_keylogs, manifest)
            # Memory-scan sidecars carry keys the hook keylog lacks (e.g. the
            # MTProto OBF + perm auth keys that make de-obfuscation possible).
            # The manifest records them under the nested ``memory_scan_keylogs``
            # map, which the ``*_keylog`` loop above never sees. Merge each into
            # the selected keylog for its protocol so the automatic decrypt uses
            # them — mirroring the wizard's manual "merge keylogs" step.
            #
            # The caller's ``protocol_keylogs`` map is what convert_pcap_to_tap
            # actually uses per protocol (its entries win over the back-compat
            # ``<proto>_keylog`` kwargs), so it is the
            # "current" keylog to merge into, and the merged result is written
            # back INTO it — otherwise a caller such as the TUI, which always
            # passes protocol_keylogs, would silently lose the sidecar keys.
            # Mirrors cli.merge_manifest.
            ms_map = manifest.get("memory_scan_keylogs") or {}
            if ms_map:
                protocol_keylogs = dict(protocol_keylogs or {})
                keylog = _merge_memory_scan_sidecars_into(
                    ms_map, pcap_path, keylog, protocol_keylogs, legacy_keylogs)

    return convert_pcap_to_tap(
        pcap_path,
        keylog_path=keylog,
        tap_path=tap_path,
        tls_ports=tls,
        quic_ports=quic,
        extra_decode_as=tuple(extra_decode_as),
        heuristic=heuristic,
        run_scan=run_scan,
        capture_target=capture_target,
        tshark_path=tshark_path,
        protocol_keylogs=protocol_keylogs,
        resync_search_depth=resync_search_depth,
        tls_midstream_secrets=midstream_secrets,
        progress=progress,
        **{k: v for k, v in legacy_keylogs.items() if v},
    )
