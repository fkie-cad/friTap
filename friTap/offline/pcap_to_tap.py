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

import heapq
import importlib
import inspect
import logging
import os
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Callable, Iterator, Sequence, Tuple

if TYPE_CHECKING:
    # Type-only import: the factories below annotate this return type, but import
    # it lazily inside their bodies to defer the registry import. Binding the name
    # here resolves the forward reference for ruff/type-checkers at no runtime cost.
    from friTap.offline.registry import OfflineDecryptorEntry

from friTap.connection_index import resolve_connection_key
from friTap.events import SESSION_STARTED, DatalogEvent, EventBus, SessionEvent
from friTap.flow.collector import FlowCollector
from friTap.flow.layer_pipeline import MESSAGE_TRANSPORTS
from friTap.flow.layers import SshLayer
from friTap.flow.tap_writer import TapWriter
from friTap.offline.keylog_paths import canonical_keylog_path
from friTap.offline.mtproto.transport import DEFAULT_OBF_MAX_BLOCKS
from friTap.offline.tls_spans import record_tls_span

from .tshark import (
    ENCRYPTED_RECORD_MARKERS,
    TSHARK_INSTALL_MESSAGE,
    TsharkNotFoundError,
    build_plaintext_command,
    build_quic_command,
    build_quic_detection_command,
    build_tls_command,
    capture_has_dsb,
    decode_hex,
    extract_quic_metadata,
    extract_ssh_connections,
    extract_tls_metadata,
    find_tshark,
    follow_tls_stream,
    list_tls_streams,
    stream_packets,
    tshark_version,
    warn_if_outdated,
)

logger = logging.getLogger(__name__)

# Well-known cleartext server ports used to anchor flow direction when ingesting
# an already-plaintext capture (there is no TLS/QUIC handshake to infer the
# server side from). Any --tls-port / --quic-port values are folded in as extra
# hints at the call site, since those are the only server-port signals fritap has.
_PLAINTEXT_SERVER_PORTS = (80, 8080, 8000)


@dataclass
class ConvertResult:
    """Summary of a pcap-to-tap conversion."""
    tap_path: str
    flow_count: int = 0
    decrypted_packet_count: int = 0
    stream_count: int = 0
    # QUIC per-packet drops (e.g. misaligned stream id/payload lists). Kept
    # distinct from dropped TLS streams below so the two are not conflated.
    dropped_packet_count: int = 0
    # TLS streams that could not be followed/decoded (whole-stream drops).
    dropped_stream_count: int = 0
    findings_count: int = 0
    # Streams skipped during a keyless (plaintext) conversion because they were
    # encrypted (TLS/QUIC) and therefore need keys. Drives the "looks encrypted —
    # pass --keylog" hint in the offline CLI.
    encrypted_streams_skipped: int = 0
    # MTProto (Telegram) offline-decryption counters (populated only when
    # --mtproto-keylog is supplied; the decryptor is friTap's own, not tshark).
    mtproto_messages: int = 0
    mtproto_streams: int = 0
    mtproto_records_undecryptable: int = 0
    mtproto_streams_degraded: int = 0
    # Protocol-generic counters keyed by counter_prefix, e.g.
    # ``{"mtproto": {"messages": 6, "streams": 2, "undecryptable": 0, "degraded": 0}}``.
    # The named ``mtproto_*`` fields above are kept as back-compat accessors and
    # stay mirrored; any OTHER registry-driven protocol (built-in or plugin) needs
    # only this dict (no new dataclass field). Populated via :meth:`record_protocol`.
    per_protocol: dict = field(default_factory=dict)

    def record_protocol(
        self,
        prefix: str,
        *,
        messages: int = 0,
        streams: int = 0,
        undecryptable: int = 0,
        degraded: int = 0,
        degraded_non_mtproto: int = 0,
        partial: int = 0,
        recovered_via_obf: int = 0,
        degraded_unrecovered: int = 0,
        short: int = 0,
        unsupported_framing: int = 0,
        e2e_only: bool = False,
        unknown_key_ids: dict | None = None,
    ) -> None:
        """Accumulate one protocol decryptor's counters (generic + back-compat).

        Writes the protocol-generic ``per_protocol[prefix]`` view AND, when a
        matching legacy named field exists (``<prefix>_messages`` etc.), mirrors
        the increment into it so existing readers of ``result.mtproto_messages`` /
        ``result.mtproto_streams`` keep working unchanged.

        The richer breakdown counters (``degraded_non_mtproto``/``partial`` from
        Workstream E, ``recovered_via_obf``/``degraded_unrecovered`` from F) are
        stored in the generic bucket only; the CLI summary reads them defensively
        (defaulting to 0) so older buckets keep printing exactly as before.

        Honest-diagnostics fields (also generic-bucket only, read defensively):
          * ``short`` / ``unsupported_framing`` -- streams the decryptor could not
            open for reasons that are NOT "started mid-connection" (a short/lossy
            client run, or an unsupported transport framing). Kept out of
            ``degraded`` so the mid-connection figure is not overstated.
          * ``e2e_only`` -- an E2E (secret-chat) key was present but no transport
            auth key, so the transport envelope never decrypted and the E2E blobs
            inside were never reached (a boolean OR-ed across calls).
          * ``unknown_key_ids`` -- hex ``auth_key_id -> count`` for records naming a
            key not in the keylog. They travel in the clear, so surfacing them tells
            the user exactly which transport keys to capture.
        """
        bucket = self.per_protocol.setdefault(
            prefix,
            {
                "messages": 0, "streams": 0, "undecryptable": 0, "degraded": 0,
                "degraded_non_mtproto": 0, "partial": 0,
                "recovered_via_obf": 0, "degraded_unrecovered": 0,
                "short": 0, "unsupported_framing": 0,
                "e2e_only": False, "unknown_key_ids": {},
            },
        )
        bucket["messages"] += messages
        bucket["streams"] += streams
        bucket["undecryptable"] += undecryptable
        bucket["degraded"] += degraded
        for extra_key, extra_value in (
            ("degraded_non_mtproto", degraded_non_mtproto),
            ("partial", partial),
            ("recovered_via_obf", recovered_via_obf),
            ("degraded_unrecovered", degraded_unrecovered),
            ("short", short),
            ("unsupported_framing", unsupported_framing),
        ):
            bucket[extra_key] = bucket.get(extra_key, 0) + extra_value
        # E2E-only is a latching signal: once any call reports it, keep it set.
        if e2e_only:
            bucket["e2e_only"] = True
        # Merge the unknown-key-id -> count map so repeated calls accumulate.
        if unknown_key_ids:
            merged = bucket.setdefault("unknown_key_ids", {})
            for key_id, count in unknown_key_ids.items():
                merged[key_id] = merged.get(key_id, 0) + count
        for legacy_suffix, value in (
            ("messages", messages),
            ("streams", streams),
            ("records_undecryptable", undecryptable),
            ("streams_degraded", degraded),
        ):
            attr = f"{prefix}_{legacy_suffix}"
            if hasattr(self, attr):
                setattr(self, attr, getattr(self, attr) + value)

    def to_dict(self) -> dict:
        """Return a JSON-safe dict view of this conversion summary.

        Lets web/API callers serialize the result of a pcap-to-tap conversion
        without reaching into the dataclass fields by hand.
        """
        from dataclasses import asdict
        return asdict(self)


# The messaging protocols whose obfuscated/self-contained transports friTap
# decrypts itself (not via tshark). Their counters all live in
# ``ConvertResult.per_protocol`` under these prefixes; only ``mtproto`` also
# mirrors into the legacy ``mtproto_*`` fields. Walking every prefix covers a
# ``telegram``-keylog run's counts too.
MESSAGING_PREFIXES = ("mtproto", "telegram", "signal")


def messaging_buckets(result) -> Iterator[Tuple[str, dict]]:
    """Yield ``(prefix, counters)`` for every messaging prefix, in fixed order.

    *counters* is ``result.per_protocol[prefix]`` (see
    :meth:`ConvertResult.record_protocol`), or ``{}`` when that protocol recorded
    nothing. Duck-typed: any object with (or without) a ``per_protocol`` dict works.
    """
    per_protocol = getattr(result, "per_protocol", None) or {}
    for prefix in MESSAGING_PREFIXES:
        yield prefix, per_protocol.get(prefix) or {}


class _StreamDirectionTracker:
    """Map each packet to "write" (client->server) or "read" (server->client).

    The client endpoint for a stream is chosen by SERVER PORT when possible: the
    endpoint that is NOT the well-known server port is the client. This mirrors
    how :func:`~friTap.offline.tshark._server_node_index` picks the server side
    on the TLS follow path, and it labels direction correctly even when the
    capture starts mid-flow or the first datagram is server-originated.

    Only when NEITHER endpoint matches a known server port do we fall back to
    the original first-packet-is-client order, so behaviour is unchanged for
    captures that hit a known port (the common case).
    """

    def __init__(self, server_ports: tuple[int, ...] = ()) -> None:
        self._client_endpoint: dict[str, tuple[str, int]] = {}
        # 443 is QUIC's well-known port; merge in any configured --quic-port(s).
        self._server_ports: set[int] = {443, *server_ports}

    @property
    def stream_count(self) -> int:
        """Number of distinct streams observed so far."""
        return len(self._client_endpoint)

    def direction_for(
        self,
        stream_key: str,
        src_ip: str,
        src_port: int,
        dst_ip: str | None = None,
        dst_port: int | None = None,
    ) -> str:
        """Return "write" or "read" for a packet on *stream_key*.

        When *dst_port* is a known server port the source is the client, and
        vice versa, regardless of which datagram arrived first. Falls back to
        the first-packet-is-client heuristic only when neither endpoint port is
        a known server port.
        """
        client = self._client_endpoint.get(stream_key)
        if client is None:
            client = self._derive_client_endpoint(
                src_ip, src_port, dst_ip, dst_port)
            self._client_endpoint[stream_key] = client
        return "write" if client == (src_ip, src_port) else "read"

    def _derive_client_endpoint(
        self,
        src_ip: str,
        src_port: int,
        dst_ip: str | None,
        dst_port: int | None,
    ) -> tuple[str, int]:
        """Pick the client endpoint for a stream's first observed packet.

        Prefer the server port: if the destination is a known server port the
        SOURCE is the client; if the SOURCE is a known server port this first
        packet is server-originated and the DESTINATION is the client. When
        neither matches, keep the legacy assumption that the first packet's
        source is the client.
        """
        if dst_port in self._server_ports:
            return (src_ip, src_port)
        if src_port in self._server_ports and dst_ip is not None and dst_port is not None:
            # Server-originated first packet: the destination is the client.
            return (dst_ip, dst_port)
        return (src_ip, src_port)


# tshark `-T ek` flattens field names by replacing '.' with '_' under the
# "layers" object. We look up both spellings so the code is robust to either.
def _field(layers: dict, dotted_name: str):
    """Return the raw value for *dotted_name* from a `-T ek` layers dict.

    Handles both ``"tls.app_data"`` and the flattened ``"tls_app_data"``
    spellings, and unwraps single-element lists to scalars.
    """
    value = layers.get(dotted_name)
    if value is None:
        value = layers.get(dotted_name.replace(".", "_"))
    return value


def _as_list(value) -> list:
    """Normalize a `-T ek` field value to a list (scalars become 1-element)."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _first(value):
    """Return the first element of a list-or-scalar field, or None."""
    items = _as_list(value)
    return items[0] if items else None



def _tls_segments_to_events(
    endpoints: tuple[str, int, str, int],
    segments: list[tuple[str, bytes]],
) -> list[DatalogEvent]:
    """Translate one followed TLS stream into ordered DatalogEvents.

    *segments* is the ``(direction, data)`` list from
    :func:`~friTap.offline.tshark.follow_tls_stream`, already in capture order
    and direction-tagged ("write" = client->server, "read" = server->client).
    We emit one event per segment, preserving order so per-direction byte
    order is reconstructed faithfully for the parsers.
    """
    client_addr, client_port, server_addr, server_port = endpoints
    ss_family = _ss_family_for(client_addr)

    events: list[DatalogEvent] = []
    for direction, data in segments:
        if not data:
            continue
        if direction == "write":
            src_addr, src_port = client_addr, client_port
            dst_addr, dst_port = server_addr, server_port
        else:
            src_addr, src_port = server_addr, server_port
            dst_addr, dst_port = client_addr, client_port
        events.append(DatalogEvent(
            timestamp=0.0,
            data=data,
            function="tshark_offline",
            direction=direction,
            src_addr=src_addr,
            src_port=src_port,
            dst_addr=dst_addr,
            dst_port=dst_port,
            ss_family=ss_family,
            ssl_session_id="",
            transport="tcp",
            stream_id=None,
        ))
    return events


def _extract_addrs(layers: dict) -> tuple[str, str, str]:
    """Return ``(src_addr, dst_addr, ss_family)`` from a `-T ek` layers dict.

    Prefers IPv6 endpoints when present, else IPv4. Shared by every
    packet->events translator so the address/family logic lives in one place.
    """
    ip6_src = _first(_field(layers, "ipv6.src"))
    ip6_dst = _first(_field(layers, "ipv6.dst"))
    if ip6_src or ip6_dst:
        return ip6_src or "", ip6_dst or "", "AF_INET6"
    return (
        _first(_field(layers, "ip.src")) or "",
        _first(_field(layers, "ip.dst")) or "",
        "AF_INET",
    )


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


def _tls_packet_to_events(
    pkt: dict,
    tracker: _StreamDirectionTracker,
    result: ConvertResult | None = None,
) -> list[DatalogEvent]:
    """Translate one TLS `-T ek` packet dict into DatalogEvents.

    Mirrors :func:`_quic_packet_to_events` but for TLS-over-TCP: the decrypted
    application bytes arrive in ``data.data`` (the HTTP subdissectors are
    disabled in :func:`~friTap.offline.tshark.build_tls_command` so plaintext
    surfaces there). A single frame may carry several TLS records, so
    ``data.data`` can be a parallel list — we concatenate the records in order
    into one event, preserving per-direction byte order for the parsers. The
    stream is keyed by ``tcp.stream`` and direction comes from *tracker* (seeded
    with the TLS server ports), exactly as the follow path's direction did.
    """
    layers = pkt.get("layers") or {}

    timestamp = _coerce_float(_first(_field(layers, "frame.time_epoch")))

    src_addr, dst_addr, ss_family = _extract_addrs(layers)

    src_port = _coerce_int(_first(_field(layers, "tcp.srcport")))
    dst_port = _coerce_int(_first(_field(layers, "tcp.dstport")))
    stream_key = f"tcp:{_first(_field(layers, 'tcp.stream'))}"
    direction = tracker.direction_for(
        stream_key, src_addr, src_port, dst_addr, dst_port)

    # data.data may be a list (several TLS records in one frame); join in order.
    payloads = _as_list(_field(layers, "data.data"))
    data = b"".join(decode_hex(str(p)) for p in payloads)
    if not data:
        return []

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
        transport="tcp",
        stream_id=None,
    )]


def _ss_family_for(addr: str) -> str:
    """Return "AF_INET6" when *addr* is an IPv6 literal, else "AF_INET"."""
    return "AF_INET6" if addr and ":" in addr else "AF_INET"


def _coerce_int(value, default: int | None = 0):
    """Coerce a tshark field value to int, or *default* on failure."""
    if value is None:
        return default
    try:
        return int(str(value))
    except (ValueError, TypeError):
        return default


def _coerce_float(value, default: float = 0.0) -> float:
    """Coerce a tshark field value to float, or *default* on failure."""
    if value is None:
        return default
    try:
        return float(str(value))
    except (ValueError, TypeError):
        return default


def _copy_keylog_into_tap(writer: TapWriter, keylog_path: str) -> None:
    """Copy each NSS keylog line into the .tap so it is self-describing."""
    try:
        with open(keylog_path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    writer.write_keylog(line)
    except OSError:
        logger.warning("Could not read keylog %s for embedding", keylog_path, exc_info=True)


class _WriterState:
    """Lazily open the TapWriter on first use, embedding the keylog once.

    Offline reconstruction may produce no events at all; opening lazily lets
    the caller still emit a valid empty .tap via :meth:`ensure_open` while
    avoiding writing a file before we know there is data.
    """

    def __init__(self, writer: TapWriter, tap_path: str, target: str,
                 keylog_path: str | None) -> None:
        self._writer = writer
        self._tap_path = tap_path
        self._target = target
        self._keylog_path = keylog_path
        self.opened = False
        # Side-channel for a TLS-riding decryptor's parsed inner metadata that
        # DatalogEvent cannot carry, keyed by canonical_4tuple; consumed by
        # _attach_transport_metadata_layers.
        self.inner_meta: dict = {}
        # Same side-channel pattern for parsed Telegram MTProto messages. Cloud
        # transport (mtproto) is keyed by normalize_4tuple like Signal; Secret-Chat
        # E2E (telegram_e2e) is keyed by its ``telegram_e2e:<fp>`` session id since
        # several chats share one 4-tuple. Both are consumed by _attach_telegram_meta.
        self.mtproto_meta: dict = {}
        self.telegram_e2e_meta: dict = {}
        # Identities of Telegram records already emitted during this conversion
        # (cloud: (auth_key_id_hex, msg_id, direction); E2E: (fp, msg_key_hex)),
        # so a second decoder pass over the same traffic never duplicates flows.
        self.telegram_emitted: set = set()
        # Lazily created by _telegram_ledger / _telegram_refs (None = no Telegram
        # record emitted yet) and the record counter behind _next_record_seq.
        self.telegram_ledger = None
        self.telegram_refs = None
        self.telegram_record_seq: int = 0
        # Per-frame provenance of the single-pass TLS plaintext, keyed by
        # canonical_4tuple then direction (see friTap.offline.tls_spans), and the
        # RC4 provenance derived from it (consumed by the nested RC4 path).
        self.tls_spans: dict = {}
        self.rc4_provenance: dict = {}

    def ensure_open(self, capture_start: float = 0.0) -> None:
        """Open the writer if it is not already open (idempotent)."""
        if self.opened:
            return
        self._writer.open(self._tap_path, target=self._target,
                           capture_start=capture_start)
        if self._keylog_path:
            _copy_keylog_into_tap(self._writer, self._keylog_path)
        self.opened = True

    def note_capture_time(self, ts: float) -> None:
        """Open the writer at *ts* (if needed) and lower the header start to it.

        *ts* is a real pcap capture time (epoch seconds); non-positive values
        mean "unknown" and only ensure the writer is open.
        """
        self.ensure_open(ts if ts > 0 else 0.0)
        self._writer.update_capture_start(ts)


def _emit_tls_session_event(
    bus: EventBus,
    endpoints: tuple[str, int, str, int],
    meta: dict,
) -> None:
    """Emit a SESSION_STARTED carrying handshake metadata for one TLS stream.

    Emitted on the SAME bus and BEFORE the stream's DatalogEvents so the
    collector caches it (``_stamp_tls_metadata``) and backfills the flow's TLS
    layer when the data events create it. The ``connection_id`` is computed with
    ``protocol="tls"`` to match the key ``on_data`` derives for the offline
    DatalogEvents (which default to the "tls" protocol).
    """
    c_addr, c_port, s_addr, s_port = endpoints
    if not c_addr and not s_addr:
        return  # no resolvable endpoints — nothing to key the metadata to
    conn_id = resolve_connection_key(
        c_addr, c_port, s_addr, s_port, protocol="tls")
    bus.emit(SessionEvent(
        event_type=SESSION_STARTED,
        connection_id=conn_id,
        server_name=meta.get("sni", ""),
        protocol_version=meta.get("version", ""),
        alpn=meta.get("alpn", ""),
        cipher_suite=meta.get("cipher", ""),
        src_addr=c_addr,
        src_port=c_port,
        dst_addr=s_addr,
        dst_port=s_port,
        protocol="tls",
    ))


def _emit_quic_session_event(bus: EventBus, meta: dict) -> None:
    """Emit a SESSION_STARTED carrying QUIC metadata for one ``udp.stream``.

    Emitted on the SAME bus and BEFORE the QUIC DatalogEvents so the collector
    caches it and stamps the flow's QUIC layer (``flow.quic`` — version, alpn,
    cipher) when the data events create the flow. ``protocol="quic"`` so the
    ``connection_id`` matches the key ``on_data`` derives for the QUIC data
    events (which now carry ``protocol="quic"``). Skipped when no endpoints.
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


def _emit_tls_streams(
    tshark_bin: str,
    pcap_path: str,
    keylog_path: str | None,
    *,
    tls_ports: tuple[int, ...],
    extra_decode_as: tuple[str, ...],
    heuristic: bool,
    bus: EventBus,
    state: _WriterState,
    result: ConvertResult,
    tls_meta_by_stream: dict[int, dict] | None = None,
) -> None:
    """Follow every TLS stream and emit its decrypted segments to *bus*.

    One ``-z follow,tls,raw`` invocation per stream — O(streams) tshark calls,
    so progress is logged. When *tls_meta_by_stream* carries handshake metadata
    for a stream, a :class:`SessionEvent` is emitted BEFORE that stream's
    DatalogEvents so the collector stamps the flow's TLS layer.
    """
    tls_meta_by_stream = tls_meta_by_stream or {}
    stream_ids = list_tls_streams(
        tshark_bin, pcap_path, keylog_path,
        tls_ports=tls_ports, extra_decode_as=extra_decode_as,
        heuristic=heuristic,
    )
    logger.info("Following %d TLS stream(s) for decrypted bytes", len(stream_ids))

    for index, stream_id in enumerate(stream_ids):
        logger.debug("Following TLS stream %d (%d/%d)",
                     stream_id, index + 1, len(stream_ids))
        try:
            endpoints, segments = follow_tls_stream(
                tshark_bin, pcap_path, stream_id, keylog_path,
                tls_ports=tls_ports, extra_decode_as=extra_decode_as,
                heuristic=heuristic,
            )
            events = _tls_segments_to_events(endpoints, segments)
        except Exception:
            # A whole TLS *stream* failed to follow/decode — count it as a
            # dropped stream, NOT a dropped packet (the QUIC path owns the
            # per-packet drop counter).
            result.dropped_stream_count += 1
            logger.debug("Skipping unfollowable TLS stream %d", stream_id, exc_info=True)
            continue
        if not events:
            continue

        result.stream_count += 1
        state.ensure_open()
        # Emit the handshake-metadata SessionEvent BEFORE this stream's data so
        # the collector caches/stamps the flow's TLS layer as the data creates
        # the flow.
        meta = tls_meta_by_stream.get(stream_id)
        if meta:
            _emit_tls_session_event(bus, endpoints, meta)
        for ev in events:
            result.decrypted_packet_count += 1
            bus.emit(ev)


def _emit_quic_streams(
    tshark_bin: str,
    pcap_path: str,
    keylog_path: str | None,
    *,
    quic_ports: tuple[int, ...],
    extra_decode_as: tuple[str, ...],
    heuristic: bool,
    bus: EventBus,
    state: _WriterState,
    result: ConvertResult,
    tracker: _StreamDirectionTracker,
) -> None:
    """Export decrypted QUIC stream data via ``-T ek`` and emit events."""
    cmd = build_quic_command(
        pcap_path, keylog_path,
        quic_ports=quic_ports, extra_decode_as=extra_decode_as,
        heuristic=heuristic,
    )
    cmd[0] = tshark_bin  # replace the literal "tshark" with the resolved path

    # Track DISTINCT QUIC stream identities, keyed by
    # (udp.stream, quic.stream.stream_id). A single UDP 4-tuple (one entry in
    # the direction tracker) can multiplex many QUIC streams, so counting UDP
    # connections would undercount. Counting (connection, stream_id) pairs keeps
    # the QUIC stream_count consistent with the TLS path, which counts real
    # streams.
    quic_stream_ids: set[tuple[int | None, int | None]] = set()
    reassembler = _QuicStreamReassembler()
    last_timestamp = 0.0
    for pkt in stream_packets(cmd):
        try:
            events = _quic_packet_to_events(pkt, tracker, result, reassembler)
        except Exception:
            result.dropped_packet_count += 1
            logger.debug("Skipping unparseable QUIC packet", exc_info=True)
            continue
        if not events:
            continue

        udp_stream = _coerce_int(
            _first(_field(pkt.get("layers") or {}, "udp.stream")), default=None)
        last_timestamp = events[-1].timestamp or last_timestamp
        _emit_quic_events(events, udp_stream, bus, state, result, quic_stream_ids)

    _emit_quic_leftovers(reassembler, last_timestamp, bus, state, result,
                         quic_stream_ids)
    result.stream_count += len(quic_stream_ids)


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


def _emit_tls_streams_singlepass(
    tshark_bin: str,
    pcap_path: str,
    keylog_path: str | None,
    *,
    tls_ports: tuple[int, ...],
    extra_decode_as: tuple[str, ...],
    heuristic: bool,
    bus: EventBus,
    state: _WriterState,
    result: ConvertResult,
    tracker: _StreamDirectionTracker,
    tls_meta_by_stream: dict[int, dict] | None = None,
) -> None:
    """Export decrypted TLS application data via ONE ``-T ek`` pass and emit events.

    Replaces the per-stream ``follow,tls,raw`` model (:func:`_emit_tls_streams`)
    with a single demuxed pass, mirroring :func:`_emit_quic_streams`. For each
    TLS stream, the handshake-metadata :class:`SessionEvent` is emitted once,
    before that stream's first DatalogEvent, so the collector caches it and
    backfills the flow's TLS layer when the data creates the flow (same contract
    the follow path honored, just emitted lazily on first sight per stream).
    """
    tls_meta_by_stream = tls_meta_by_stream or {}
    cmd = build_tls_command(
        pcap_path, keylog_path,
        tls_ports=tls_ports, extra_decode_as=extra_decode_as,
        heuristic=heuristic,
    )
    cmd[0] = tshark_bin  # replace the literal "tshark" with the resolved path

    seen_streams: set[int] = set()
    tcp_streams: set[int] = set()
    for pkt in stream_packets(cmd):
        try:
            events = _tls_packet_to_events(pkt, tracker, result)
        except Exception:
            result.dropped_packet_count += 1
            logger.debug("Skipping unparseable TLS packet", exc_info=True)
            continue
        if not events:
            continue

        tcp_stream = _coerce_int(
            _first(_field(pkt.get("layers") or {}, "tcp.stream")), default=None)

        state.ensure_open()
        # Emit the stream's handshake-metadata SessionEvent ONCE, before its
        # first data event. The conn_id resolve_connection_key derives is
        # perspective-independent for the net: tier, so the raw packet endpoints
        # key it identically to the data events the collector sees.
        if tcp_stream is not None and tcp_stream not in seen_streams:
            seen_streams.add(tcp_stream)
            meta = _tls_meta_for_packet(tls_meta_by_stream, pkt, tcp_stream)
            if meta:
                ev0 = events[0]
                _emit_tls_session_event(
                    bus,
                    (ev0.src_addr, ev0.src_port, ev0.dst_addr, ev0.dst_port),
                    meta,
                )
        if tcp_stream is not None:
            tcp_streams.add(tcp_stream)
        for ev in events:
            result.decrypted_packet_count += 1
            record_tls_span(state.tls_spans, pkt, ev)
            bus.emit(ev)

    result.stream_count += len(tcp_streams)


def _tls_meta_for_packet(tls_meta_by_stream: dict, pkt: dict, tcp_stream):
    """Handshake metadata of *pkt*'s stream.

    :func:`extract_tls_metadata` keys by ``tls.stream``, which differs from
    ``tcp.stream`` whenever non-TLS TCP streams precede the TLS one; prefer the
    packet's ``tls.stream`` and fall back to ``tcp.stream`` (older exports).
    """
    tls_stream = _coerce_int(
        _first(_field(pkt.get("layers") or {}, "tls.stream")), default=None)
    if tls_stream is not None and tls_stream in tls_meta_by_stream:
        return tls_meta_by_stream[tls_stream]
    return tls_meta_by_stream.get(tcp_stream)


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
        for pkt in stream_packets(cmd):
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
) -> None:
    """Export raw transport payload via ONE ``-T ek`` pass and emit events.

    The keyless counterpart to :func:`_emit_tls_streams_singlepass`: instead of
    decrypted ``data.data`` it reads ``tcp.payload`` / ``udp.payload`` for an
    already-plaintext capture. Encrypted streams are detected and skipped — TLS (and
    per-packet-marked QUIC) via :func:`_is_encrypted_record`, and handshake-confirmed
    QUIC via *encrypted_quic_streams* — with their count surfaced on *result* so the
    caller can hint that ``--keylog`` is required. Emitted bytes flow through the
    same EventBus -> FlowCollector -> parser pipeline as every other path.
    """
    cmd = build_plaintext_command(
        pcap_path, extra_decode_as=extra_decode_as, heuristic=heuristic)
    cmd[0] = tshark_bin  # replace the literal "tshark" with the resolved path

    encrypted_streams: set[str] = set()
    for pkt in stream_packets(cmd):
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


def _extract_tls_metadata_safe(
    tshark_bin: str,
    pcap_path: str,
    keylog_path: str | None,
    *,
    tls_ports: tuple[int, ...],
    extra_decode_as: tuple[str, ...],
    heuristic: bool,
) -> dict[int, dict]:
    """Run the TLS-handshake metadata pass, returning {} on any failure.

    The metadata is additive — it enriches flows with SNI/version/cipher/alpn
    but the decrypted-bytes reconstruction does not depend on it. A tshark
    failure here must therefore never abort the conversion.
    """
    try:
        return extract_tls_metadata(
            tshark_bin, pcap_path, keylog_path,
            tls_ports=tls_ports, extra_decode_as=extra_decode_as,
            heuristic=heuristic,
        )
    except Exception:
        logger.warning("TLS handshake metadata extraction failed; continuing "
                       "without SNI/version/cipher/alpn enrichment",
                       exc_info=True)
        return {}


def _extract_quic_metadata_safe(
    tshark_bin: str,
    pcap_path: str,
    keylog_path: str | None,
    *,
    quic_ports: tuple[int, ...],
    extra_decode_as: tuple[str, ...],
    heuristic: bool,
) -> dict[int, dict]:
    """Run the QUIC metadata pass, returning {} on any failure.

    Additive enrichment (quic.version + the QUIC-embedded TLS handshake's
    cipher/alpn) — the decrypted-bytes reconstruction does not depend on it, so
    a tshark failure here must never abort the conversion.
    """
    try:
        return extract_quic_metadata(
            tshark_bin, pcap_path, keylog_path,
            quic_ports=quic_ports, extra_decode_as=extra_decode_as,
            heuristic=heuristic,
        )
    except Exception:
        logger.warning("QUIC metadata extraction failed; continuing without "
                       "QUIC version/alpn/cipher enrichment", exc_info=True)
        return {}


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


def _parsed_mtproto_to_dicts(
    parsed_messages, direction: str, fallback_ts: float = 0.0,
) -> list:
    """Turn :class:`ParsedMtprotoMessage` objects into JSON-native dicts.

    Mirrors the per-message dict shape the Signal path stores (so flow_detail's
    generic ``_render_layer_parsed`` understands it). The TL parser yields no
    timestamp/sender for outbound text; a missing TL ``date`` falls back to
    *fallback_ts* (the carrying record's capture time, 0.0 = unknown).
    """
    return [
        {
            "sender": str(p.sender_id) if p.sender_id else "",
            "direction": direction,
            "timestamp": p.timestamp or fallback_ts,
            "kind": p.kind,
            "body": p.body,
            "method": getattr(p, "method", "") or "",
            "attachments": bool(p.has_media),
            "quote": False,
            "reaction": False,
            "peer_id": p.peer_id,
            "user_id": getattr(p, "user_id", 0) or 0,
        }
        for p in parsed_messages
    ]


def _user_dedup_key(item: dict):
    """Identity key for de-duplicating kind="user" rows within a flow.

    Prefers the Telegram user id (stable across the several RPC results that
    return the same identity); falls back to the rendered body when no id is
    available. Returns ``None`` for non-user items (never deduped).
    """
    if item.get("kind") != "user":
        return None
    uid = item.get("user_id") or 0
    if uid:
        return ("id", uid)
    return ("body", item.get("body", ""))


def _chunk_key(direction: str, data: bytes) -> str:
    """Identity of one flow chunk: its direction plus a short SHA-1 of its bytes.

    Each offline MTProto/E2E ``DatalogEvent`` carries exactly one decrypted
    record, which the collector stores verbatim as one ``FlowChunk`` (same
    ``"write"``/``"read"`` direction naming). Tagging the parsed messages of a
    record with this key lets :func:`_scope_messages_to_flow` hand each flow only
    the messages whose record actually landed in it.
    """
    import hashlib

    return f"{direction}:{hashlib.sha1(bytes(data or b'')).hexdigest()[:16]}"


def _tag_chunk_key(dicts: list, chunk_key: str) -> list:
    """Stamp *chunk_key* onto every dict of one record (no-op when empty)."""
    if chunk_key:
        for item in dicts:
            item["_chunk_key"] = chunk_key
    return dicts


def _append_mtproto_dicts_deduped(entry: dict, dicts: list) -> list:
    """Append parsed dicts to *entry* while collapsing duplicate user identities.

    The same user often appears in multiple RPC results within one flow (e.g.
    "db Forscher" returned by several queries). Each distinct ``kind="user"``
    identity is emitted only ONCE per flow, keyed by :func:`_user_dedup_key`.
    Text/chat/service items are NEVER deduped — they pass through untouched.
    Returns the dicts actually appended (the record's messages for the ledger).
    """
    seen = entry.setdefault("_user_keys", set())
    appended: list = []
    for item in dicts:
        key = _user_dedup_key(item)
        if key is not None:
            # Scoped per record when chunk-tagged, so a user repeated in a LATER
            # flow of the same connection survives until per-flow dedup.
            key = (item.get("_chunk_key", ""), key)
            if key in seen:
                continue
            seen.add(key)
        entry["messages"].append(item)
        appended.append(item)
    return appended


def _mark_seen(entry: dict, identity) -> bool:
    """Record *identity* in *entry*'s private ``_seen`` set.

    Returns True when it was already present (the caller should skip). The
    ``_seen`` set lives on the accumulating side-channel entry next to
    ``_user_keys``; only ``messages`` is folded onto the flow layer, so neither
    private key reaches the .tap.
    """
    return _already_emitted(entry.setdefault("_seen", set()), identity)


def _accumulate_mtproto_messages(
    meta: dict, key: str, tl_bytes: bytes, direction: str, msg_id: int = 0,
    capture_ts: float = 0.0, chunk_key: str = "",
) -> list:
    """Parse a cloud MTProto record's TL bytes and append to the side-channel.

    Tolerant by delegation: the parser never raises (degrades to no messages),
    so this can never break the conversion. A known *msg_id* makes the call
    idempotent: the same (msg_id, direction) record is accumulated only once.
    A *chunk_key* (see :func:`_chunk_key`) tags every parsed message of the
    record so the attach pass can scope messages to their own flow. Returns
    the dicts accumulated for THIS record (empty when nothing was added).
    """
    from friTap.offline.mtproto.content import parse_mtproto_message

    parsed = parse_mtproto_message(tl_bytes)
    if not parsed:
        return []
    entry = meta.setdefault(key, {"messages": []})
    if msg_id and _mark_seen(entry, ("msg", msg_id, direction)):
        return []
    dicts = _parsed_mtproto_to_dicts(parsed, direction, fallback_ts=capture_ts)
    return _append_mtproto_dicts_deduped(entry, _tag_chunk_key(dicts, chunk_key))


def _secret_chat_identity(parsed, direction: str, msg_key_hex: str):
    """Identity of one parsed E2E message within its per-fingerprint entry.

    Prefers the blob's msg_key (unique per encrypted packet), so two DISTINCT
    packets that reuse a ``random_id`` still each get their messages (the
    Message tab de-duplicates by ``random_id`` for display). Falls back to the
    sender-chosen ``random_id``, then to (body, direction) when neither is known.
    """
    if msg_key_hex:
        return ("mk", msg_key_hex)
    random_id = getattr(parsed, "random_id", 0) or 0
    if random_id:
        return ("rid", random_id)
    return ("body", parsed.body, direction)


def _accumulate_secret_chat_messages(
    meta: dict, key: str, tl_bytes: bytes, direction: str, chat_id: int,
    msg_key_hex: str = "", capture_ts: float = 0.0, chunk_key: str = "",
) -> list:
    """Parse a Secret-Chat E2E record's TL bytes and append to the side-channel.

    Idempotent per message: each E2E message is accumulated once per
    fingerprint entry, keyed by :func:`_secret_chat_identity`. E2E dicts carry
    ``random_id`` in addition to the shared cloud dict shape. A known
    *capture_ts* always wins as the E2E ``timestamp`` (Secret-Chat TL carries no
    trustworthy date of its own). *chunk_key* tags the record's messages as in
    :func:`_accumulate_mtproto_messages`, and the record's dicts are returned.
    """
    from friTap.offline.mtproto.content import parse_secret_chat_message

    parsed = parse_secret_chat_message(tl_bytes)
    if not parsed:
        return []
    entry = meta.setdefault(key, {"chat_id": chat_id, "messages": []})
    fresh = [
        p for p in parsed
        if not _mark_seen(entry, _secret_chat_identity(p, direction, msg_key_hex))
    ]
    dicts = _parsed_mtproto_to_dicts(fresh, direction, fallback_ts=capture_ts)
    for item, p in zip(dicts, fresh):
        item["random_id"] = getattr(p, "random_id", 0) or 0
        if capture_ts > 0:
            item["timestamp"] = capture_ts
    entry["messages"].extend(_tag_chunk_key(dicts, chunk_key))
    return dicts


def _unique_keylog_paths(keylog: str, keylogs: Sequence[str] = ()) -> list:
    """*keylog* plus any extra *keylogs*, de-duplicated by real path (order kept)."""
    paths: list = []
    seen: set = set()
    for path in (keylog, *keylogs):
        if not path:
            continue
        real = canonical_keylog_path(path)
        if real not in seen:
            seen.add(real)
            paths.append(path)
    return paths


def _load_telegram_keys(paths: Sequence[str]):
    """Load and merge cloud, obfuscation and Secret-Chat keys from *paths*.

    Returns ``(auth_keymap, obf_keys, secret_keymap)``: the two dicts are
    merged (first file wins on a key collision), the obf-key list is
    concatenated without duplicates.
    """
    from friTap.offline.mtproto.e2e.keylog import load_secret_chat_keylog
    from friTap.offline.mtproto.keylog import (
        load_mtproto_keylog,
        load_mtproto_obf_keylog,
    )

    auth_keymap: dict = {}
    obf_keys: list = []
    secret_keymap: dict = {}
    for path in paths:
        for key_id, key in load_mtproto_keylog(path).items():
            auth_keymap.setdefault(key_id, key)
        obf_keys.extend(k for k in load_mtproto_obf_keylog(path) if k not in obf_keys)
        for fp, key in load_secret_chat_keylog(path).items():
            secret_keymap.setdefault(fp, key)
    return auth_keymap, obf_keys, secret_keymap


def _set_state_attr(state, name: str, value) -> None:
    """Set *state*.<name>; a state that refuses attributes is left untouched."""
    try:
        setattr(state, name, value)
    except AttributeError:
        pass


def _state_attr(state, name: str, factory):
    """*state*.<name>, created by *factory* and attached when missing or None.

    Minimal state stand-ins (tests) without the attribute get one attached; a
    state that refuses attributes gets a call-local value instead.
    """
    value = getattr(state, name, None)
    if value is None:
        value = factory()
        _set_state_attr(state, name, value)
    return value


def _telegram_emitted_set(state) -> set:
    """The per-conversion set of already-emitted Telegram record identities.

    Lives on the writer state (``telegram_emitted``) so it spans every decoder
    pass (see :func:`_state_attr` for stand-in states).
    """
    return _state_attr(state, "telegram_emitted", set)


def _telegram_ledger(state):
    """The per-conversion :class:`RecordLedger` of emitted Telegram records.

    Lazily attached to the writer state like :func:`_telegram_emitted_set`, so
    minimal state stand-ins keep working; a state that refuses attributes gets
    a call-local ledger (the attach pass then falls back to scoping).
    """
    from friTap.offline.mtproto.packet_meta import RecordLedger

    return _state_attr(state, "telegram_ledger", RecordLedger)


def _next_record_seq(state) -> int:
    """Next monotonic record number of this conversion (starting at 1)."""
    seq = (getattr(state, "telegram_record_seq", 0) or 0) + 1
    _set_state_attr(state, "telegram_record_seq", seq)
    return seq


def _ledger_record(state, transport: str, chunk_key: str,
                   messages: list, envelope: dict) -> int:
    """Record one emitted Telegram packet (its messages + envelope) in the ledger.

    Returns the record's ``record_seq`` (used to key its cross-references).
    """
    record_seq = _next_record_seq(state)
    _telegram_ledger(state).add(transport, chunk_key, {
        "record_seq": record_seq,
        "transport": transport,
        "chunk_key": chunk_key,
        "messages": [_strip_private_keys(item) for item in messages or []],
        "envelope": envelope,
    })
    return record_seq


class _TelegramRefs:
    """Per-conversion cross-references, users and Secret-Chat hints by record_seq.

    Filled while records are emitted (one TL decode per cloud record; the tree
    itself is dropped) and consumed by :func:`_finalize_telegram_refs`.
    """

    def __init__(self) -> None:
        from friTap.offline.mtproto.crossref import CrossRefIndex

        self.index = CrossRefIndex()
        self.users_by_seq: dict = {}
        self.chat_nodes: list = []
        self.e2e_chats: dict = {}

    def add_cloud(self, record_seq: int, msg) -> None:
        """Decode one cloud record once: index its refs, keep its users/chat objects."""
        from friTap.offline.mtproto.crossref import REF_LIMITS, refs_from_tree
        from friTap.offline.mtproto.tl import decode_tl, iter_nodes
        from friTap.offline.mtproto.tl.users import extract_users, is_chat_related

        root = decode_tl(msg.message, domain="mtproto", limits=REF_LIMITS)
        self.index.add(refs_from_tree(
            root, record_seq=record_seq,
            auth_key_id=getattr(msg, "auth_key_id_hex", "") or "",
            direction=getattr(msg, "direction", "") or "",
            msg_id=getattr(msg, "msg_id", 0) or 0,
        ))
        users = extract_users(root)
        if users:
            self.users_by_seq[record_seq] = users
        self.chat_nodes.extend(n for n in iter_nodes(root) if is_chat_related(n))

    def add_e2e(self, record_seq: int, sc, carrier) -> None:
        """Register a Secret-Chat record and the cloud record carrying it."""
        self.index.add_e2e(record_seq, getattr(carrier, "auth_key_id_hex", "") or "",
                           getattr(carrier, "msg_id", 0) or 0)
        self.e2e_chats[record_seq] = (getattr(sc, "key_fingerprint_hex", "") or "",
                                      getattr(sc, "chat_id", 0) or 0,
                                      getattr(sc, "peer_user_id", 0) or 0)

    def directory(self) -> dict:
        """All users of the capture merged by id (later records win)."""
        from friTap.offline.mtproto.tl.users import merge_user_directory

        return merge_user_directory(
            user for seq in sorted(self.users_by_seq) for user in self.users_by_seq[seq]
        )


def _telegram_refs(state) -> "_TelegramRefs":
    """The per-conversion :class:`_TelegramRefs`, lazily attached to *state*."""
    return _state_attr(state, "telegram_refs", _TelegramRefs)


def _collect_cloud_refs(state, record_seq: int, msg) -> None:
    """Index one cloud record's refs/users; never lets a failure stop the emit."""
    try:
        _telegram_refs(state).add_cloud(record_seq, msg)
    except Exception as exc:  # noqa: BLE001 - forensic extras must not break conversion
        logger.debug("Telegram cross-reference extraction failed for record %s: %s",
                     record_seq, exc)


def _already_emitted(seen: set, identity) -> bool:
    """True when *identity* was emitted before; otherwise record it.

    A falsy identity (unknown msg_id / msg_key) is never deduplicated.
    """
    if identity is None:
        return False
    if identity in seen:
        return True
    seen.add(identity)
    return False


def _cloud_identity(msg):
    """Emission identity of a decrypted cloud record, or None if msg_id unknown."""
    msg_id = getattr(msg, "msg_id", 0) or 0
    if not msg_id:
        return None
    return ("cloud", msg.auth_key_id_hex, msg_id, msg.direction)


def _secret_chat_emit_identity(sc):
    """Emission identity of a decrypted E2E message, or None if msg_key unknown."""
    msg_key_hex = getattr(sc, "msg_key_hex", "") or ""
    if not msg_key_hex:
        return None
    return ("e2e", sc.key_fingerprint_hex, msg_key_hex)


def _emit_mtproto_streams(
    pcap_path: str,
    mtproto_keylog: str,
    *,
    bus: EventBus,
    state: "_WriterState",
    result: ConvertResult,
    extra_keylogs: Sequence[str] = (),
    obf_max_blocks: int = DEFAULT_OBF_MAX_BLOCKS,
) -> None:
    """Decrypt Telegram traffic from an ``.mtproto.keylog`` (cloud + Secret-Chat).

    The friTap memscan sidecar written by ``-ms mtproto`` carries BOTH
    ``MTPROTO_AUTH_KEY`` (cloud transport) and ``MTPROTO_E2E_KEY`` (Secret-Chat)
    lines, so ``--mtproto-keylog`` decrypts cloud AND E2E secret chats. Thin
    wrapper over :func:`_emit_telegram_like_streams`; cloud + E2E messages are
    counted under the ``mtproto`` protocol bucket.
    """
    _emit_telegram_like_streams(
        pcap_path, mtproto_keylog,
        counter_name="mtproto",
        cloud_function="mtproto_offline",
        bus=bus, state=state, result=result,
        keylogs=extra_keylogs,
        obf_max_blocks=obf_max_blocks,
    )


def _time_ordered(messages) -> list:
    """*messages* stably sorted by capture ``timestamp`` (ties keep yield order).

    Unknown (0.0) timestamps sort first, which keeps an all-unknown input in its
    original order.
    """
    return sorted(messages, key=lambda m: getattr(m, "timestamp", 0.0) or 0.0)


def _event_ts_kwargs(ts: float) -> dict:
    """``{"timestamp": ts}`` for a real capture time, else ``{}`` (keep the default)."""
    return {"timestamp": ts} if ts and ts > 0 else {}


def _open_at_capture_time(state, ts: float) -> None:
    """Open *state*'s writer and lower its header start to capture time *ts*.

    Falls back to a plain ``ensure_open`` for minimal writer-state stand-ins
    that do not implement ``note_capture_time``.
    """
    note = getattr(state, "note_capture_time", None)
    if note is not None:
        note(ts)
    else:
        state.ensure_open(ts if ts > 0 else 0.0)


def _emit_telegram_like_streams(
    pcap_path: str,
    keylog: str,
    *,
    counter_name: str,
    cloud_function: str,
    bus: EventBus,
    state: "_WriterState",
    result: ConvertResult,
    keylogs: Sequence[str] = (),
    obf_max_blocks: int = DEFAULT_OBF_MAX_BLOCKS,
) -> None:
    """Decrypt Telegram traffic (cloud + Secret-Chat) from ONE combined keylog.

    A friTap Telegram/MTProto keylog holds BOTH ``MTPROTO_AUTH_KEY`` (cloud
    transport) and ``MTPROTO_E2E_KEY`` (Secret-Chat) lines; the two loaders each
    read only their own label, so the same file feeds both decryptors. Unlike
    TLS/QUIC this does NOT use tshark — friTap's own decryptor reassembles the TCP
    streams and AES-IGE decrypts each record. For every decrypted cloud message we
    (a) emit it as a ``DatalogEvent(protocol="mtproto")`` flow, and (b) scan it for
    embedded Secret-Chat E2E blobs, emitting each decrypted one as a
    ``DatalogEvent(protocol="telegram_e2e")`` flow.

    *counter_name* selects the ``ConvertResult`` protocol bucket (so the same body
    serves both the ``--mtproto-keylog`` and ``--telegram-keylog`` flags), while
    *cloud_function* labels the emitted cloud events per caller (E2E events are
    always labelled ``telegram_e2e_offline``).

    *keylogs* optionally names further keylog files whose keys are merged with
    *keylog*'s, so one pass decrypts with the union (used when two registry
    entries of the same decoder family were given different files). Records
    already emitted during this conversion (see :func:`_telegram_emitted_set`)
    are skipped, so a repeated pass never duplicates flows or messages.

    Every emitted record is also queued in the state's :class:`RecordLedger`
    (see :func:`_ledger_record`) with its own messages, forensic envelope and a
    monotonic ``record_seq``, which :func:`_attach_telegram_meta` pops per flow.

    The optional crypto backend is imported lazily; a missing dependency logs a
    warning and skips decryption (the rest of the conversion is unaffected).
    """
    from friTap.offline.mtproto import MtprotoDependencyError
    from friTap.offline.mtproto.decrypt import MtprotoStats, iter_decrypted_messages
    from friTap.offline.mtproto.e2e.decrypt import iter_secret_chat_messages
    from friTap.offline.mtproto.e2e.records import SecretChatStats

    auth_keymap, obf_keys, secret_keymap = _load_telegram_keys(
        _unique_keylog_paths(keylog, keylogs)
    )
    emitted = _telegram_emitted_set(state)
    if not auth_keymap and not secret_keymap:
        logger.warning(
            "Telegram keylog %s has no usable cloud (MTPROTO_AUTH_KEY) or "
            "Secret-Chat (MTPROTO_E2E_KEY) keys; skipping Telegram decryption",
            keylog,
        )
        return

    tstats = MtprotoStats()
    sstats = SecretChatStats()
    try:
        for msg in _time_ordered(iter_decrypted_messages(
            pcap_path, auth_keymap, stats=tstats, obf_keys=obf_keys,
            obf_max_blocks=obf_max_blocks,
        )):
            # A record an earlier pass already emitted (same auth key, msg_id and
            # direction) is skipped whole: its E2E blobs were handled then too.
            if _already_emitted(emitted, _cloud_identity(msg)):
                continue
            # (a) the decrypted cloud transport message itself.
            _emit_cloud_record(msg, cloud_function=cloud_function,
                               bus=bus, state=state, result=result)
            # (b) any Secret-Chat E2E blobs carried inside this cloud message.
            for sc in iter_secret_chat_messages([msg], secret_keymap, stats=sstats):
                if _already_emitted(emitted, _secret_chat_emit_identity(sc)):
                    continue
                _emit_e2e_record(sc, msg, bus=bus, state=state, result=result)
    except MtprotoDependencyError as exc:
        logger.warning("Telegram decryption skipped: %s", exc)
        return

    # Honest E2E diagnostic: an E2E (secret-chat) key was loaded but NO transport
    # auth key, so every transport record missed the keymap, the transport envelope
    # never decrypted, and the E2E blobs inside it were never reached. Report this
    # exactly rather than as a generic mid-connection/undecryptable failure.
    e2e_only = bool(secret_keymap) and not auth_keymap
    _record_telegram_stats(result, counter_name, tstats, sstats, e2e_only=e2e_only)


def _emit_cloud_record(msg, *, cloud_function: str, bus: EventBus,
                       state: "_WriterState", result: ConvertResult) -> None:
    """Emit one decrypted cloud record as a ``protocol="mtproto"`` flow event.

    Its TL payload is parsed into displayable messages accumulated in the cloud
    side-channel keyed by the perspective-independent 4-tuple (folded onto the
    inner MtprotoLayer by :func:`_attach_telegram_meta`), and the record is
    queued in the ledger with its envelope and cross-references.
    """
    from friTap.connection_index import normalize_4tuple
    from friTap.offline.mtproto.packet_meta import build_cloud_envelope

    msg_ts = getattr(msg, "timestamp", 0.0) or 0.0
    cloud_ev = DatalogEvent(
        data=msg.message,
        function=cloud_function,
        direction=msg.direction,
        src_addr=msg.src_addr,
        src_port=msg.src_port,
        dst_addr=msg.dst_addr,
        dst_port=msg.dst_port,
        ss_family=msg.ss_family,
        transport="tcp",
        protocol="mtproto",
        **_event_ts_kwargs(msg_ts),
    )
    cloud_key = normalize_4tuple(
        msg.src_addr, msg.src_port, msg.dst_addr, msg.dst_port
    )
    cloud_chunk_key = _chunk_key(msg.direction, cloud_ev.data)
    cloud_dicts = _accumulate_mtproto_messages(
        state.mtproto_meta, cloud_key, msg.message, msg.direction,
        msg_id=getattr(msg, "msg_id", 0) or 0,
        capture_ts=msg_ts,
        chunk_key=cloud_chunk_key,
    )
    cloud_seq = _ledger_record(state, "mtproto", cloud_chunk_key, cloud_dicts,
                               build_cloud_envelope(msg))
    _collect_cloud_refs(state, cloud_seq, msg)
    _open_at_capture_time(state, msg_ts)
    result.decrypted_packet_count += 1
    bus.emit(cloud_ev)


def _emit_e2e_record(sc, carrier, *, bus: EventBus,
                     state: "_WriterState", result: ConvertResult) -> None:
    """Emit one decrypted Secret-Chat message found inside cloud record *carrier*.

    Secret chats ride INSIDE the same TCP connection as the cloud transport, so
    they share the cloud flow's 4-tuple. The event carries a per-chat session
    token (``telegram_e2e:<fp>``) so the collector keys it onto its OWN
    ``telegram_e2e`` flow (via the ``sid:`` tier) instead of folding its bytes
    into the cloud flow's MTProto parser; its messages are accumulated under
    that same session id.
    """
    from friTap.offline.mtproto.packet_meta import build_e2e_envelope

    session_id = f"telegram_e2e:{sc.key_fingerprint_hex}"
    sc_ts = getattr(sc, "timestamp", 0.0) or getattr(carrier, "timestamp", 0.0) or 0.0
    e2e_ev = DatalogEvent(
        data=sc.message,
        function="telegram_e2e_offline",
        direction=sc.direction,
        src_addr=sc.src_addr,
        src_port=sc.src_port,
        dst_addr=sc.dst_addr,
        dst_port=sc.dst_port,
        ss_family=sc.ss_family,
        ssl_session_id=session_id,
        transport="tcp",
        protocol="telegram_e2e",
        **_event_ts_kwargs(sc_ts),
    )
    e2e_chunk_key = _chunk_key(sc.direction, e2e_ev.data)
    e2e_dicts = _accumulate_secret_chat_messages(
        state.telegram_e2e_meta, session_id,
        sc.message, sc.direction, sc.chat_id,
        msg_key_hex=getattr(sc, "msg_key_hex", "") or "",
        capture_ts=sc_ts,
        chunk_key=e2e_chunk_key,
    )
    e2e_seq = _ledger_record(state, "telegram_e2e", e2e_chunk_key, e2e_dicts,
                             build_e2e_envelope(sc, carrier))
    _telegram_refs(state).add_e2e(e2e_seq, sc, carrier)
    _open_at_capture_time(state, sc_ts)
    result.decrypted_packet_count += 1
    bus.emit(e2e_ev)


def _record_telegram_stats(result: ConvertResult, counter_name: str,
                           tstats, sstats, *, e2e_only: bool) -> None:
    """Record the cloud + Secret-Chat decryption stats under *counter_name*."""
    result.record_protocol(
        counter_name,
        messages=tstats.messages + sstats.messages,
        streams=tstats.streams,
        undecryptable=tstats.records_undecryptable + sstats.records_undecryptable,
        degraded=tstats.streams_degraded,
        degraded_non_mtproto=tstats.streams_degraded_non_mtproto,
        partial=tstats.streams_partial,
        recovered_via_obf=tstats.streams_recovered_via_obf,
        degraded_unrecovered=tstats.streams_degraded_unrecovered,
        short=tstats.streams_short,
        unsupported_framing=tstats.streams_unsupported_framing,
        e2e_only=e2e_only,
        unknown_key_ids=dict(tstats.unknown_key_ids),
    )


def _emit_telegram_streams(
    pcap_path: str,
    telegram_keylog: str,
    *,
    bus: EventBus,
    state: "_WriterState",
    result: ConvertResult,
    extra_keylogs: Sequence[str] = (),
    obf_max_blocks: int = DEFAULT_OBF_MAX_BLOCKS,
) -> None:
    """Decrypt Telegram traffic (cloud + Secret-Chat) from ONE combined keylog.

    Thin wrapper over :func:`_emit_telegram_like_streams`; cloud + E2E messages
    are counted under the ``telegram`` protocol bucket. Behaviourally identical to
    ``--mtproto-keylog`` (both flags now decrypt cloud + E2E from the same combined
    keylog); the two entry points differ only in their summary counter name.
    """
    _emit_telegram_like_streams(
        pcap_path, telegram_keylog,
        counter_name="telegram",
        cloud_function="telegram_offline",
        bus=bus, state=state, result=result,
        keylogs=extra_keylogs,
        obf_max_blocks=obf_max_blocks,
    )


# --------------------------------------------------------------------------- #
# Offline-decryptor registry wiring
# --------------------------------------------------------------------------- #
#
# The built-in MTProto/Telegram decryptors are exposed through the offline
# registry so ``convert_pcap_to_tap`` iterates the registry instead of hardcoding
# per-protocol if-blocks (and so plugin protocols join automatically). The
# emitters above keep their original, expressive signatures; thin adapters below
# present the normalized :data:`~friTap.offline.registry.OfflineEmitter` shape.
# TLS-riding offline decryptors (which consume tshark's decrypted bytes) ship as
# self-registering subpackages discovered via :func:`_discover_offline_decryptor_extensions`.

def _mtproto_offline_emitter(
    *, pcap_path, proto_keylog, tls_keylog_path, tshark_bin, tls_ports,
    bus, state, result, extra_keylogs=(), obf_max_blocks=DEFAULT_OBF_MAX_BLOCKS,
) -> None:
    """Normalized adapter around :func:`_emit_mtproto_streams` (self-contained TCP)."""
    _emit_mtproto_streams(
        pcap_path, proto_keylog,
        bus=bus, state=state, result=result, extra_keylogs=extra_keylogs,
        obf_max_blocks=obf_max_blocks,
    )


def _telegram_offline_emitter(
    *, pcap_path, proto_keylog, tls_keylog_path, tshark_bin, tls_ports,
    bus, state, result, extra_keylogs=(), obf_max_blocks=DEFAULT_OBF_MAX_BLOCKS,
) -> None:
    """Normalized adapter around :func:`_emit_telegram_streams` (self-contained TCP)."""
    _emit_telegram_streams(
        pcap_path, proto_keylog,
        bus=bus, state=state, result=result, extra_keylogs=extra_keylogs,
        obf_max_blocks=obf_max_blocks,
    )


def _discover_offline_decryptor_extensions() -> None:
    """Import in-tree offline-decryptor subpackages so they self-register.

    Mirrors ``friTap.protocols.registry._discover_protocol_extensions``: scan the
    subpackages of the :mod:`friTap.offline` package and import every package
    (``info.ispkg``) whose name does not start with ``_``. A package that carries
    the discovery marker (``is_fritap_offline_decryptor``) self-registers its
    :class:`OfflineDecryptorEntry` on import; a package without the marker (e.g.
    the public ``mtproto`` subpackage) imports harmlessly and does NOT register.

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


def build_mtproto_offline_decryptor_entry() -> "OfflineDecryptorEntry":
    """Build the MTProto :class:`OfflineDecryptorEntry`.

    Named factory mirroring ``build_signal_offline_decryptor_entry`` (see
    :mod:`friTap.offline.signal.offline_decryptor`): the layer class and registry
    type are imported lazily so this is cheap to call at registration time.
    """
    from friTap.flow.layers import MtprotoLayer
    from friTap.offline.registry import OfflineDecryptorEntry

    return OfflineDecryptorEntry(
        protocol_name="mtproto",
        cli_flag="--mtproto-keylog",
        cli_dest="mtproto_keylog",
        requires_tls_strip=False,
        emitter=_mtproto_offline_emitter,
        layer_cls=MtprotoLayer,
        counter_prefix="mtproto",
        decoder_family="telegram",
        cli_help=(
            "friTap MTProto/Telegram keylog (MTPROTO_AUTH_KEY + MTPROTO_E2E_KEY "
            "lines, e.g. a .mtproto.keylog from -ms mtproto) — decrypts Telegram "
            "cloud chats AND Secret-Chat E2E. Decrypted by friTap's own decryptor "
            "(not tshark); distinct from --keylog."
        ),
    )


def build_telegram_offline_decryptor_entry() -> "OfflineDecryptorEntry":
    """Build the Telegram (cloud + Secret-Chat E2E) :class:`OfflineDecryptorEntry`.

    Named factory mirroring ``build_signal_offline_decryptor_entry``; lazy imports
    as above.
    """
    from friTap.flow.layers import TelegramE2ELayer
    from friTap.offline.registry import OfflineDecryptorEntry

    return OfflineDecryptorEntry(
        protocol_name="telegram",
        cli_flag="--telegram-keylog",
        cli_dest="telegram_keylog",
        requires_tls_strip=False,
        emitter=_telegram_offline_emitter,
        layer_cls=TelegramE2ELayer,
        counter_prefix="telegram",
        decoder_family="telegram",
        cli_help=(
            "friTap Telegram keylog (combined MTProto cloud auth keys + Secret-Chat "
            "E2E keys) — decrypts cloud chats and secret chats."
        ),
    )


def _register_builtin_offline_decryptors() -> None:
    """Register the built-in MTProto/Telegram offline decryptors (idempotent).

    TLS-riding decryptors ship as self-registering in-tree subpackages and are
    picked up by :func:`_discover_offline_decryptor_extensions` (called at the
    end), so the public core never names them.
    """
    from friTap.offline.registry import register_offline_decryptor

    register_offline_decryptor(build_mtproto_offline_decryptor_entry())
    register_offline_decryptor(build_telegram_offline_decryptor_entry())

    # Pick up in-tree TLS-riding / plugin decryptors that self-register on import
    # (the public core never names them). Done LAST so any built-in stays the
    # canonical registration for its name.
    _discover_offline_decryptor_extensions()


_register_builtin_offline_decryptors()


def _tls_riding_protocol_names() -> set:
    """Names of offline decryptors whose protocol rides inside TLS.

    Registry-driven (``requires_tls_strip``) rather than a hardcoded literal:
    today this is just ``{"signal"}``, but any future TLS-riding plugin protocol
    is picked up automatically.
    """
    from friTap.offline.registry import get_offline_decryptor_registry
    return {
        e.protocol_name
        for e in get_offline_decryptor_registry().list()
        if e.requires_tls_strip
    }


def _tls_nested_protocol_names() -> set:
    """Names of independent decryptors that can nest inside TLS (``nests_in_tls``).

    Registry-driven like :func:`_tls_riding_protocol_names` (today ``{"rc4"}``).
    """
    from friTap.offline.registry import get_offline_decryptor_registry
    return {
        e.protocol_name
        for e in get_offline_decryptor_registry().list()
        if getattr(e, "nests_in_tls", False)
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


def _attach_rc4_in_tls_layers(flows, state) -> set:
    """Fold nested RC4 flows into [TLS (owned), RC4 (chunks)]; return the ids of
    the TLS flows they fully absorbed. No-op without RC4 provenance."""
    if not getattr(state, "rc4_provenance", None):
        return set()
    from friTap.offline.rc4.tls_attach import attach_rc4_in_tls_layers
    return attach_rc4_in_tls_layers(flows, state)


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
    when the TLS ALPN advertises h2; the legacy plain-WebSocket transport gets
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

    tls_layer_by_endpoint: dict = {}
    for flow in flows:
        if getattr(flow, "transport", "") == "tls":
            tls_layer = flow.layer("tls")
            if tls_layer is not None:
                tls_layer_by_endpoint.setdefault(endpoint_key(flow), tls_layer)

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
        # when ALPN advertises h2; legacy transport is plain TLS -> WebSocket).
        if "h2" in (source.alpn or "").lower():
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


def _apply_mtproto_meta(layer, meta: dict | None) -> None:
    """Fold accumulated parsed Telegram messages onto an inner layer.

    Shared by the cloud ``MtprotoLayer`` and the Secret-Chat ``TelegramE2ELayer``
    (both expose ``messages``/``message_count``). No-op when *layer* or *meta* is
    absent, so a flow with no recovered messages keeps its empty-but-valid layer
    (degrades, never raises). Mirrors :func:`_apply_inner_meta`.
    """
    if layer is None or not meta:
        return
    messages = meta.get("messages", []) or []
    layer.messages = messages
    layer.message_count = len(messages)


def _flow_chunk_keys(flow) -> set:
    """The :func:`_chunk_key` of every chunk the collector put into *flow*."""
    return {
        _chunk_key(getattr(c, "direction", ""), getattr(c, "data", b""))
        for c in (getattr(flow, "chunks", None) or [])
    }


def _strip_private_keys(item: dict) -> dict:
    """Copy of a parsed-message dict without the private ``_chunk_key`` tag."""
    return {k: v for k, v in item.items() if k != "_chunk_key"}


def _scope_messages_to_flow(flow, messages) -> list:
    """Keep only the side-channel *messages* whose record landed in *flow*.

    Side-channel entries are accumulated per connection (cloud) or per chat
    (E2E), but the collector splits them into several exchange flows. A message
    is kept when its ``_chunk_key`` matches one of *flow*'s chunks. Messages from
    a path that never tagged keys (no dict has one) pass through unchanged.
    Returned dicts are copies with ``_chunk_key`` stripped, so it never reaches
    the .tap.
    """
    messages = list(messages or [])
    if not any("_chunk_key" in item for item in messages):
        return [_strip_private_keys(item) for item in messages]
    keys = _flow_chunk_keys(flow)
    return [
        _strip_private_keys(item) for item in messages
        if item.get("_chunk_key") in keys
    ]


def _scoped_cloud_meta(flow, meta: dict) -> dict:
    """Per-flow cloud entry: scoped messages, users re-deduped within the flow."""
    scoped: dict = {"messages": []}
    _append_mtproto_dicts_deduped(
        scoped, _scope_messages_to_flow(flow, meta.get("messages"))
    )
    return {"messages": scoped["messages"]}


def _scoped_e2e_meta(flow, meta: dict) -> dict:
    """Per-flow Secret-Chat entry: public fields plus the flow's own messages."""
    scoped = {k: v for k, v in meta.items() if not k.startswith("_")}
    scoped["messages"] = _scope_messages_to_flow(flow, meta.get("messages"))
    return scoped


def _single_chunk_key(flow) -> str:
    """:func:`_chunk_key` of a one-chunk (per-packet) flow, else ``""``."""
    chunks = getattr(flow, "chunks", None) or []
    if len(chunks) != 1:
        return ""
    return _chunk_key(getattr(chunks[0], "direction", ""), getattr(chunks[0], "data", b""))


def _apply_ledger_envelope(layer, envelope: dict) -> None:
    """Copy the envelope's identity fields onto the layer's typed attributes."""
    if getattr(layer, "NAME", "") == "mtproto":
        layer.transport = envelope.get("transport", "") or layer.transport
        layer.obfuscated = bool(envelope.get("obfuscated", layer.obfuscated))
        layer.dc_id = envelope.get("dc_id", 0) or layer.dc_id
        layer.auth_key_id = envelope.get("auth_key_id", "") or layer.auth_key_id
    else:
        layer.key_fingerprint = envelope.get("key_fingerprint", "") or layer.key_fingerprint
        layer.chat_id = envelope.get("chat_id", 0) or layer.chat_id


def _apply_ledger_record(layer, record: dict) -> None:
    """Fold one ledger record (messages + envelope + record_seq) onto *layer*."""
    messages = list(record.get("messages") or [])
    layer.messages = messages
    layer.message_count = len(messages)
    envelope = dict(record.get("envelope") or {})
    envelope["record_seq"] = record.get("record_seq", 0)
    layer.envelope = envelope
    _apply_ledger_envelope(layer, envelope)


def _meta_from_ledger(flow, ledger) -> bool:
    """Give a per-packet Telegram *flow* exactly its own ledger record.

    Pops the oldest record queued under the flow's transport and single chunk
    key; flows are walked in creation (= emission) order, so byte-identical
    packets are matched first-in-first-out. Returns False (caller falls back to
    side-channel scoping) when the flow is not one-chunk or no record is left.
    """
    inner_name = getattr(flow, "transport", "")
    chunk_key = _single_chunk_key(flow)
    record = ledger.take(inner_name, chunk_key) if chunk_key else None
    if record is None:
        logger.debug("No Telegram ledger record for flow %s (%s, key %r); "
                     "falling back to scoped metadata",
                     getattr(flow, "flow_id", "?"), inner_name, chunk_key)
        return False
    getattr(flow, inner_name)
    layer = flow.layer(inner_name)
    if layer is None:
        return False
    _apply_ledger_record(layer, record)
    return True


def _attach_scoped_meta(flow, mtproto_meta: dict | None,
                        telegram_e2e_meta: dict | None) -> None:
    """Fallback: fold the flow's scoped side-channel messages onto its layer."""
    from friTap.connection_index import normalize_4tuple

    inner_name = getattr(flow, "transport", "")
    if inner_name == "mtproto" and mtproto_meta:
        key = normalize_4tuple(
            flow.src_addr, flow.src_port, flow.dst_addr, flow.dst_port
        )
        meta = mtproto_meta.get(key)
        meta = _scoped_cloud_meta(flow, meta) if meta else None
    elif inner_name == "telegram_e2e" and telegram_e2e_meta:
        meta = telegram_e2e_meta.get(getattr(flow, "ssl_session_id", ""))
        meta = _scoped_e2e_meta(flow, meta) if meta else None
    else:
        return
    if not meta:
        return
    # Materialize the inner layer if the offline flow built it lazily
    # (``getattr`` triggers _create_layer, which appends the chunks-view
    # layer); then fold the parsed messages onto it.
    getattr(flow, inner_name)
    _apply_mtproto_meta(flow.layer(inner_name), meta)


_TELEGRAM_TRANSPORTS = MESSAGE_TRANSPORTS  # back-compat alias


def _attach_telegram_meta(
    flows,
    mtproto_meta: dict | None = None,
    telegram_e2e_meta: dict | None = None,
    ledger=None,
) -> None:
    """Fold parsed Telegram messages onto offline-decrypted MTProto/E2E flows.

    Unlike Signal, MTProto rides RAW TCP (no TLS to strip), so these flows are
    NOT processed by :func:`_attach_transport_metadata_layers`. This applies the
    side-channel parsed-message dicts accumulated by ``_emit_mtproto_streams`` /
    ``_emit_telegram_streams`` onto each flow's innermost decrypted layer:

      * cloud ``mtproto`` flows are keyed by the canonical 4-tuple (like Signal);
      * Secret-Chat ``telegram_e2e`` flows are keyed by their
        ``telegram_e2e:<fp>`` session id (several chats share one 4-tuple).

    Like the Signal pass it MUST run on the LIVE flow objects and BEFORE flush().
    Each flow receives only the messages whose record became one of ITS chunks
    (see :func:`_scope_messages_to_flow`), so sibling exchange flows of one
    connection/chat no longer share one connection-wide message list.
    Flows with no recovered messages are left untouched (degrades, never raises).

    When a :class:`RecordLedger` is given (the emitter's per-record queue), it
    is tried FIRST: each per-packet flow gets exactly its own record's messages
    and forensic envelope (:func:`_meta_from_ledger`), which stays correct even
    for byte-identical packets. The scoping above is the per-flow fallback.
    """
    for flow in flows:
        if getattr(flow, "transport", "") not in MESSAGE_TRANSPORTS:
            continue
        if ledger and _meta_from_ledger(flow, ledger):
            continue
        _attach_scoped_meta(flow, mtproto_meta, telegram_e2e_meta)


def _flow_record_seq(flow) -> tuple:
    """``(layer, record_seq)`` of a per-packet Telegram flow, or ``(None, 0)``."""
    transport = getattr(flow, "transport", "")
    if transport not in MESSAGE_TRANSPORTS:
        return None, 0
    layer = flow.layer(transport)
    envelope = getattr(layer, "envelope", None) or {}
    return layer, int(envelope.get("record_seq", 0) or 0)


def _fill_flow_ids(value, seq_to_flow: dict) -> None:
    """Add ``flow_id`` next to every ``record_seq`` in a refs structure (in place)."""
    if isinstance(value, list):
        for item in value:
            _fill_flow_ids(item, seq_to_flow)
    elif isinstance(value, dict):
        flow_id = seq_to_flow.get(value.get("record_seq"))
        if flow_id is not None:
            value["flow_id"] = flow_id
        for item in value.values():
            if isinstance(item, (dict, list)):
                _fill_flow_ids(item, seq_to_flow)


def _message_user_ids(messages) -> list:
    """Non-zero user ids a flow's chat messages reference (sender / peer / user)."""
    ids = []
    for message in messages or []:
        for key in ("sender_id", "peer_id", "user_id"):
            value = message.get(key) if isinstance(message, dict) else None
            if isinstance(value, int) and value and value not in ids:
                ids.append(value)
    return ids


def _dedupe_users(users) -> list:
    seen, out = set(), []
    for user in users:
        if user and user.get("id") not in seen:
            seen.add(user.get("id"))
            out.append(user)
    return out


def _cloud_flow_users(layer, record_users: list, directory: dict) -> list:
    """Users decoded in this packet, plus self + users its chat messages reference."""
    from friTap.offline.mtproto.tl.users import self_user

    referenced = _message_user_ids(getattr(layer, "messages", None))
    extra = [directory.get(uid) for uid in referenced]
    if referenced:
        extra.insert(0, self_user(directory))
    return _dedupe_users(list(record_users) + extra)


def _apply_e2e_peer(layer, refs_state, record_seq: int, directory: dict) -> None:
    """Link the Secret-Chat peer and set ``layer.peer`` / ``layer.users``.

    Resolution priority: the keylog's ``peer_user_id`` (agent-read, confident) →
    a wire-confirmed ``encryptedChat*`` link → the heuristic fallback (tagged
    ``matched_by="heuristic"``) for chats that predate the capture.
    """
    from friTap.offline.mtproto.tl.users import (
        infer_secret_chat_peer, keylog_peer, link_secret_chat_peer, self_user)

    fp_hex, chat_id, peer_user_id = refs_state.e2e_chats.get(record_seq, ("", 0, 0))
    if peer_user_id:
        peer = keylog_peer(peer_user_id, chat_id, directory)
    else:
        peer = link_secret_chat_peer(refs_state.chat_nodes, fp_hex, chat_id, directory)
        if not peer.get("user_id"):
            me = self_user(directory)
            peer = infer_secret_chat_peer(directory, me.get("id", 0) if me else 0, chat_id)
    layer.peer = peer
    layer.users = _dedupe_users([self_user(directory), peer.get("user")])


def _finalize_telegram_refs(flows, refs_state) -> None:
    """Write ``refs`` / ``users`` / ``peer`` onto every per-packet Telegram flow.

    Runs after :func:`_attach_telegram_meta` (which set ``envelope.record_seq``)
    on the LIVE flows, before flush. Referenced records gain their ``flow_id``.
    Degrades silently when no refs were collected (e.g. minimal test state).
    """
    if refs_state is None:
        return
    targets = [(flow, *_flow_record_seq(flow)) for flow in flows]
    targets = [(flow, layer, seq) for flow, layer, seq in targets if layer is not None and seq]
    seq_to_flow = {seq: flow.flow_id for flow, _layer, seq in targets}
    directory = refs_state.directory()
    for flow, layer, seq in targets:
        refs = refs_state.index.resolve(seq)
        _fill_flow_ids(refs, seq_to_flow)
        layer.refs = refs
        if flow.transport == "mtproto":
            layer.users = _cloud_flow_users(layer, refs_state.users_by_seq.get(seq, []), directory)
        else:
            _apply_e2e_peer(layer, refs_state, seq, directory)


def _entry_family(entry) -> str:
    """Decoder family of an offline entry (its own protocol name if unset)."""
    return getattr(entry, "decoder_family", "") or entry.protocol_name


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
        paths = _unique_keylog_paths(
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


def _drop_obf_max_blocks_unless_accepted(emitter, emitter_kwargs: dict) -> dict:
    """Remove ``obf_max_blocks`` from *emitter_kwargs* unless *emitter* accepts it.

    ``obf_max_blocks`` is MTProto/Telegram-specific: plugin decryptors (and Signal)
    with a fixed signature are never handed an argument they cannot take.
    """
    if "obf_max_blocks" in emitter_kwargs and not _emitter_accepts(
        emitter, "obf_max_blocks"
    ):
        emitter_kwargs.pop("obf_max_blocks")
    return emitter_kwargs


def _run_independent_entry(entry, keylogs: list, **emitter_kwargs) -> None:
    """Run one self-contained offline entry over its (possibly merged) keylogs.

    ``extra_keylogs`` is only passed when a family brought several distinct
    files, so single-keylog (plugin) emitters keep their plain signature.
    """
    if len(keylogs) > 1:
        emitter_kwargs["extra_keylogs"] = tuple(keylogs[1:])
    _drop_obf_max_blocks_unless_accepted(entry.emitter, emitter_kwargs)
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
    mtproto_keylog: str | None = None,
    protocol_keylogs: dict[str, str] | None = None,
    resync_search_depth: int = DEFAULT_OBF_MAX_BLOCKS,
    progress: "Callable[[str], None] | None" = None,
    **legacy_protocol_keylogs: str | None,
) -> ConvertResult:
    """Decrypt *pcap_path* with tshark and reconstruct a friTap ``.tap`` file.

    Args:
        pcap_path: Encrypted capture (pcap/pcapng).
        keylog_path: NSS SSLKEYLOGFILE, or None for a DSB-embedded pcapng.
        mtproto_keylog: friTap MTProto keylog (``MTPROTO_AUTH_KEY …`` lines). When
            given, Telegram MTProto streams are decrypted by friTap's own decryptor
            (tshark cannot) IN ADDITION to any TLS/QUIC passes. Distinct from
            ``keylog_path`` (NSS/TLS, consumed by tshark).
        tap_path: Output path; defaults to ``<pcap stem>.tap``.
        tls_ports / quic_ports: Custom server ports to Decode-As TLS / QUIC.
        extra_decode_as: Raw tshark ``-d`` rules passed through.
        heuristic: Enable tshark TLS-over-TCP heuristic dissection.
        run_scan: Run the analysis registry over the produced .tap afterward.
        capture_target: Target label stored in the .tap (defaults to basename).
        tshark_path: Explicit tshark binary path/command (else auto-discovered).
        protocol_keylogs: Generic ``{protocol_name: keylog_path}`` map for offline
            decryptors registered in :mod:`friTap.offline.registry` (including
            plugin protocols). This is the AUTHORITATIVE source for every protocol
            that does not have an explicit named argument here.
        resync_search_depth: Generic maximum search depth when re-aligning a
            mid-stream flow to a memory-recovered key, applied to any offline
            decryptor that supports mid-stream recovery. It maps onto the
            per-emitter unit (MTProto's ``obf_max_blocks`` today: 16-byte CTR
            blocks behind the live counter) and is forwarded only to emitters that
            declare it (via :func:`_emitter_accepts`). Defaults to
            :data:`~friTap.offline.mtproto.transport.DEFAULT_OBF_MAX_BLOCKS`.
        legacy_protocol_keylogs: Back-compat named keylog kwargs of the form
            ``<protocol>_keylog`` (e.g. a TLS-riding protocol's keylog). Each is
            folded into ``protocol_keylogs`` keyed by the leading ``<protocol>``
            token, so historical callers keep working without the public core
            naming any specific extension protocol. Explicit ``protocol_keylogs``
            entries win.

    Returns:
        A :class:`ConvertResult` summarizing the conversion.
    """
    if tap_path is None:
        tap_path = os.path.splitext(pcap_path)[0] + ".tap"

    # Generic-to-emitter mapping: the public boundary speaks resync_search_depth;
    # emitters speak their own unit (MTProto's obf_max_blocks). Map it here so the
    # single generic knob feeds every mid-stream-recovery decryptor downstream.
    obf_max_blocks = resync_search_depth

    # Decryption uses EITHER an explicit keylog file OR a pcapng with an embedded
    # Decryption Secrets Block (DSB). Three cases:
    #   * keys available            -> decrypt (TLS/QUIC passes below).
    #   * no --keylog and no DSB     -> treat the capture as already-plaintext and
    #     ingest the raw transport payload directly (encrypted streams are skipped
    #     and surfaced via result.encrypted_streams_skipped).
    #   * --keylog given but missing -> fail loud, so a typo'd keylog path is not
    #     silently masked as "plaintext".
    keylog_present = bool(keylog_path) and os.path.isfile(keylog_path)
    has_keys = keylog_present or capture_has_dsb(pcap_path)
    if keylog_path and not has_keys:
        _require_decryptable(pcap_path, keylog_path)  # raises NoDecryptionKeysError

    # Offline (friTap-owned) decryptors are driven by the registry rather than
    # hardcoded if-blocks. Build the per-protocol keylog map (named args folded
    # in for back-compat, generic map wins), then split the registered entries
    # into those that ride inside TLS (consume tshark's decrypted bytes; run only
    # under has_keys) and self-contained ones (decrypt raw TCP independently).
    # An independent-protocol-only capture (e.g. MTProto, no TLS keys) must NOT
    # fall into the keyless plaintext pass — its bytes would be bogus plaintext.
    from friTap.offline.registry import get_offline_decryptor_registry

    proto_keylogs: dict[str, str] = dict(protocol_keylogs or {})
    if mtproto_keylog:
        proto_keylogs.setdefault("mtproto", mtproto_keylog)
    # Fold any back-compat ``<protocol>_keylog`` kwargs (e.g. a TLS-riding
    # extension's keylog) into the generic map without naming the protocol here:
    # the leading token before ``_keylog`` is the protocol name. Explicit
    # protocol_keylogs entries already present win (setdefault).
    for kwarg_name, kwarg_value in legacy_protocol_keylogs.items():
        if kwarg_value and kwarg_name.endswith("_keylog"):
            proto_keylogs.setdefault(kwarg_name[: -len("_keylog")], kwarg_value)

    offline_entries = get_offline_decryptor_registry().list()
    present_entries = []
    for entry in offline_entries:
        keylog = proto_keylogs.get(entry.protocol_name)
        if not keylog:
            continue
        if not os.path.isfile(keylog):
            logger.warning(
                "%s keylog %s not found; skipping %s decryption",
                entry.protocol_name, keylog, entry.protocol_name,
            )
            continue
        present_entries.append(entry)

    tls_strip_entries = [e for e in present_entries if e.requires_tls_strip]
    independent_entries = [e for e in present_entries if not e.requires_tls_strip]
    # One pass per decoder family (mtproto + telegram share the Telegram decoder).
    independent_plan = _dedupe_independent_entries(independent_entries, proto_keylogs)

    tshark_bin = find_tshark(tshark_path)
    warn_if_outdated(tshark_version(tshark_bin))

    bus = EventBus()
    collector = FlowCollector(event_bus=bus)
    # Offline events carry pcap capture times: measure idle/sweep time by them.
    collector.use_event_clock(True)
    # Flows of these transports are written exactly once, after the post-collection
    # metadata attach below; the writer skips their early "completed" write.
    post_attach_transports = (_post_attach_transports()
                              | _tls_holdback_transports(present_entries))
    writer = TapWriter(
        defer_flow=lambda flow: getattr(flow, "transport", "") in post_attach_transports,
    )

    target = capture_target or os.path.basename(pcap_path)
    collector.set_capture_target(target)
    bus.subscribe(DatalogEvent, collector.on_data)
    bus.subscribe(SessionEvent, collector.on_session_event)
    collector.subscribe(writer.on_flow_event)

    # Seed each tracker with its protocol's known server ports so direction
    # labelling is anchored to the server port, not first-packet order (handles
    # captures that start mid-flow or with a server-originated first packet).
    # TLS and QUIC get separate trackers keyed on tcp.stream / udp.stream
    # respectively, seeded with the matching port set.
    tracker = _StreamDirectionTracker(server_ports=quic_ports)
    tls_tracker = _StreamDirectionTracker(server_ports=tls_ports)
    result = ConvertResult(tap_path=tap_path)

    # The .tap is opened lazily on the first event so an empty capture still
    # produces a valid (empty) file via the fallback below.
    state = _WriterState(writer, tap_path, target, keylog_path)
    try:
        if has_keys:
            _emit_progress(progress, "Decrypting TLS/QUIC streams…")
            # Extract TLS handshake metadata ONCE up front (SNI/version/cipher/alpn)
            # so each stream can emit a SessionEvent before its data, backfilling the
            # flow's TLS layer. Metadata failure is non-fatal — the decrypted-bytes
            # path is unaffected.
            tls_meta_by_stream = _extract_tls_metadata_safe(
                tshark_bin, pcap_path, keylog_path,
                tls_ports=tls_ports, extra_decode_as=extra_decode_as,
                heuristic=heuristic,
            )

            # Single ``-T ek`` pass over all TLS streams (was one
            # ``follow,tls,raw`` pass PER stream — O(streams x pcap)). The legacy
            # per-stream helpers (_emit_tls_streams / follow_tls_stream) are retained
            # as utilities but no longer drive the conversion.
            _emit_tls_streams_singlepass(
                tshark_bin, pcap_path, keylog_path,
                tls_ports=tls_ports, extra_decode_as=extra_decode_as,
                heuristic=heuristic,
                bus=bus, state=state, result=result, tracker=tls_tracker,
                tls_meta_by_stream=tls_meta_by_stream,
            )
            # QUIC metadata (transport version + embedded-TLS cipher/alpn) extracted
            # up front and emitted as SessionEvents BEFORE the QUIC data, so the
            # collector stamps each flow's QUIC layer when the data creates it.
            quic_meta_by_stream = _extract_quic_metadata_safe(
                tshark_bin, pcap_path, keylog_path,
                quic_ports=quic_ports, extra_decode_as=extra_decode_as,
                heuristic=heuristic,
            )
            for quic_meta in quic_meta_by_stream.values():
                _emit_quic_session_event(bus, quic_meta)

            _emit_quic_streams(
                tshark_bin, pcap_path, keylog_path,
                quic_ports=quic_ports, extra_decode_as=extra_decode_as,
                heuristic=heuristic,
                bus=bus, state=state, result=result, tracker=tracker,
            )
            # TLS-riding offline decryptors (friTap's own, e.g. Signal) consume the
            # tshark-decrypted TLS plaintext — they must run inside the has_keys
            # branch. Registry-driven: each present ``requires_tls_strip`` entry
            # is emitted via its normalized adapter.
            for entry in tls_strip_entries:
                tls_strip_kwargs: dict = dict(
                    pcap_path=pcap_path,
                    proto_keylog=proto_keylogs[entry.protocol_name],
                    tls_keylog_path=keylog_path,
                    tshark_bin=tshark_bin,
                    tls_ports=tls_ports,
                    bus=bus, state=state, result=result,
                    obf_max_blocks=obf_max_blocks,
                )
                # Same generality gate as the independent path: a tls-strip emitter
                # that declares obf_max_blocks gets it; Signal is left untouched.
                entry.emitter(**_drop_obf_max_blocks_unless_accepted(
                    entry.emitter, tls_strip_kwargs))
        elif not independent_entries:
            # No keys and no DSB: ingest the capture as already-plaintext. The raw
            # transport payload is fed through the SAME parser pipeline; encrypted
            # streams are detected and skipped (tallied for a --keylog hint).
            # Skipped when a self-contained offline decryptor (e.g. MTProto) is
            # present: its obfuscated bytes are not plaintext and are handled by
            # the independent-decryptor pass below.
            # A handshake pre-scan first identifies genuinely-encrypted QUIC streams
            # (header protection hides their per-packet marker), so they are skipped
            # rather than ingested as bogus plaintext.
            encrypted_quic_streams = _detect_encrypted_quic_streams(
                tshark_bin, pcap_path,
                quic_ports=quic_ports, extra_decode_as=extra_decode_as,
                heuristic=heuristic,
            )
            plaintext_tracker = _StreamDirectionTracker(
                server_ports=(*_PLAINTEXT_SERVER_PORTS, *tls_ports, *quic_ports))
            _emit_plaintext_streams_singlepass(
                tshark_bin, pcap_path,
                extra_decode_as=extra_decode_as, heuristic=heuristic,
                bus=bus, state=state, result=result, tracker=plaintext_tracker,
                encrypted_quic_streams=encrypted_quic_streams,
            )

        # SSH metadata pass: plaintext banners/KEXINIT need no keys. Purely
        # additive synthetic flows; failure never aborts the conversion.
        _emit_ssh_connections(
            tshark_bin, pcap_path, heuristic=heuristic,
            collector=collector, state=state,
        )

        # Self-contained offline decryptors (friTap's own, e.g. MTProto) decrypt
        # raw TCP independently of any tshark TLS/QUIC pass, so they run always.
        # Registry-driven: each present non-``requires_tls_strip`` entry is emitted.
        for entry, entry_keylogs in independent_plan:
            _emit_progress(
                progress,
                f"Decrypting {getattr(entry, 'name', getattr(entry, 'protocol', 'protocol'))}…",
            )
            _run_independent_entry(
                entry, entry_keylogs,
                pcap_path=pcap_path,
                tls_keylog_path=keylog_path,
                tshark_bin=tshark_bin,
                tls_ports=tls_ports,
                bus=bus, state=state, result=result,
                obf_max_blocks=obf_max_blocks,
            )

        state.ensure_open()
        # The header start is the capture's FIRST packet, not the earliest
        # decrypted record (handshakes/undecryptable traffic precede it).
        state.note_capture_time(_first_packet_time(pcap_path))

        # Correlate TLS metadata onto offline-decrypted TLS-riding flows (Signal)
        # by 4-tuple, building the TLS -> HTTP/2 -> WebSocket -> inner encapsulation
        # stack (metadata-only outer layers + the decrypted-chunk inner layer). MUST
        # run on the LIVE flow objects (not get_flows() snapshots) and BEFORE
        # flush(): flush completes+writes the live flows, so the layers have to be
        # attached to those very objects beforehand to land in the .tap.
        _attach_transport_metadata_layers(collector.live_flows(), state.inner_meta)
        # Nested RC4-in-TLS: rebuild each RC4 flow as [TLS (owned), RC4 (chunks)]
        # and learn which TLS flows it fully absorbed (not written below).
        absorbed_flow_ids = _attach_rc4_in_tls_layers(collector.live_flows(), state)

        # Fold parsed Telegram MTProto/Secret-Chat messages onto their (raw-TCP,
        # non-TLS-riding) flows. Same LIVE-flows-before-flush() requirement as
        # the Signal pass above.
        _attach_telegram_meta(
            collector.live_flows(), state.mtproto_meta, state.telegram_e2e_meta,
            ledger=getattr(state, "telegram_ledger", None),
        )
        # Cross-references (rpc_result/ack/container/E2E carrier), users and the
        # Secret-Chat peer need every record's flow_id, so they run after the fold.
        _finalize_telegram_refs(collector.live_flows(), getattr(state, "telegram_refs", None))

        # CRITICAL: TapWriter.on_flow_event only writes on "completed", which
        # offline reconstruction rarely emits (no SESSION_ENDED). flush() marks
        # active flows COMPLETE, then we sweep every flow the writer has not
        # already persisted.
        collector.flush(end_at_last_activity=True)
        flows = [f for f in collector.get_flows()
                 if f.flow_id not in absorbed_flow_ids]
        # Flows whose metadata is folded on AFTER collection (Signal TLS-riding +
        # Telegram MTProto/Secret-Chat) are deferred by the writer's on-complete
        # hook, so they are persisted here exactly once, with the attached
        # layers/messages. Should one have been written early anyway, this rewrite
        # still wins: the flow index keeps the LAST record per flow_id.
        for flow in flows:
            transport = getattr(flow, "transport", "")
            if (not writer.has_written(flow.flow_id)
                    or transport in post_attach_transports):
                writer.write_flow(flow)

        result.flow_count = len(flows)
        _emit_progress(progress, "Writing .tap…")
    finally:
        if state.opened:
            writer.close()

    if run_scan:
        _emit_progress(progress, "Running analysis…")
        result.findings_count = _run_scan(tap_path)

    logger.info(
        "Offline conversion: %d flows, %d decrypted packets, %d streams, "
        "%d dropped TLS stream(s), %d dropped QUIC packet(s)",
        result.flow_count, result.decrypted_packet_count,
        result.stream_count, result.dropped_stream_count,
        result.dropped_packet_count,
    )
    return result


def _first_packet_time(pcap_path: str) -> float:
    """Capture time (epoch seconds) of the first packet in *pcap_path*.

    Reads only the first record (scapy handles pcap and pcapng, including the
    pcapng timestamp resolution). Returns ``0.0`` ("unknown") for an empty or
    unreadable capture, so callers can pass it straight to
    :meth:`_WriterState.note_capture_time`.
    """
    # scapy warns about an embedded DSB it cannot use; irrelevant here.
    scapy_log = logging.getLogger("scapy.runtime")
    previous_level = scapy_log.level
    scapy_log.setLevel(logging.ERROR)
    try:
        from scapy.utils import PcapReader

        with PcapReader(pcap_path) as reader:
            for pkt in reader:
                return float(pkt.time)
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
    mtproto: str | None,
    protocol_keylogs: dict[str, str],
    legacy_keylogs: dict[str, str | None],
) -> tuple[str | None, str | None]:
    """Union memory-scan sidecars into the effective keylog of each protocol.

    The effective per-protocol keylog is the one convert_pcap_to_tap will use:
    a ``protocol_keylogs`` entry first, then the named ``mtproto_keylog`` /
    ``<proto>_keylog`` kwarg. Merged paths are written back into
    *protocol_keylogs* (mutated in place, so they win downstream) and into the
    named kwargs. TLS stays on the base ``keylog_path``. Returns the updated
    ``(keylog, mtproto)`` pair.
    """
    def _current(proto: str) -> str | None:
        if proto == "tls":
            return keylog
        named = mtproto if proto == "mtproto" else legacy_keylogs.get(f"{proto}_keylog")
        return protocol_keylogs.get(proto) or named

    from .keylog_picker import merge_memory_scan_sidecars

    merged_sidecars = merge_memory_scan_sidecars(
        ms_map, _current,
        out_dir=os.path.dirname(os.path.abspath(pcap_path)) or None)
    keylog = merged_sidecars.pop("tls", keylog)
    for proto, merged_path in merged_sidecars.items():
        protocol_keylogs[proto] = merged_path
        if proto == "mtproto":
            mtproto = merged_path
        else:
            legacy_keylogs[f"{proto}_keylog"] = merged_path
    return keylog, mtproto


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
    mtproto_keylog: str | None = None,
    protocol_keylogs: dict[str, str] | None = None,
    resync_search_depth: int = DEFAULT_OBF_MAX_BLOCKS,
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
    mtproto = mtproto_keylog
    tls = tuple(tls_ports)
    quic = tuple(quic_ports)
    # Back-compat ``<protocol>_keylog`` kwargs (e.g. a TLS-riding extension's
    # keylog) are carried generically: the manifest's matching ``<protocol>_keylog``
    # key fills any the caller did not pass, and they flow through to
    # convert_pcap_to_tap as the same **kwargs (which folds them into the generic
    # protocol_keylogs map without the public core naming any extension protocol).
    legacy_keylogs: dict[str, str | None] = dict(legacy_protocol_keylogs)
    if use_manifest:
        # load_manifest takes a pcap path (not an argparse Namespace), so it is
        # safe to reuse here; imported lazily to avoid a cli <-> pcap_to_tap
        # import cycle (cli imports convert_pcap_to_tap from this module).
        from .cli import load_manifest

        manifest = load_manifest(pcap_path)
        if manifest:
            keylog = keylog or manifest.get("keylog") or None
            mtproto = mtproto or manifest.get("mtproto_keylog") or None
            tls = tls or tuple(manifest.get("tls_ports", []))
            quic = quic or tuple(manifest.get("quic_ports", []))
            # Pull any further ``<protocol>_keylog`` manifest keys the caller did
            # not pass explicitly (excluding the named mtproto/base keylog).
            for man_key, man_value in manifest.items():
                if (
                    man_key.endswith("_keylog")
                    and man_key != "mtproto_keylog"
                    and man_value
                    and not legacy_keylogs.get(man_key)
                ):
                    legacy_keylogs[man_key] = man_value
            # Memory-scan sidecars carry keys the hook keylog lacks (e.g. the
            # MTProto OBF + perm auth keys that make de-obfuscation possible).
            # The manifest records them under the nested ``memory_scan_keylogs``
            # map, which the ``*_keylog`` loop above never sees. Merge each into
            # the selected keylog for its protocol so the automatic decrypt uses
            # them — mirroring the wizard's manual "merge keylogs" step.
            #
            # The caller's ``protocol_keylogs`` map is what convert_pcap_to_tap
            # actually uses per protocol (its entries win over the named
            # ``mtproto_keylog`` / ``<proto>_keylog`` kwargs), so it is the
            # "current" keylog to merge into, and the merged result is written
            # back INTO it — otherwise a caller such as the TUI, which always
            # passes protocol_keylogs, would silently lose the sidecar keys.
            # Mirrors cli.merge_manifest.
            ms_map = manifest.get("memory_scan_keylogs") or {}
            if ms_map:
                protocol_keylogs = dict(protocol_keylogs or {})
                keylog, mtproto = _merge_memory_scan_sidecars_into(
                    ms_map, pcap_path, keylog, mtproto,
                    protocol_keylogs, legacy_keylogs)

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
        mtproto_keylog=mtproto,
        protocol_keylogs=protocol_keylogs,
        resync_search_depth=resync_search_depth,
        progress=progress,
        **{k: v for k, v in legacy_keylogs.items() if v},
    )
