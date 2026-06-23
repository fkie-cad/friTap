#!/usr/bin/env python3
# -*- coding: utf-8 -*-

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

import importlib
import logging
import os
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    # Type-only import: the factories below annotate this return type, but import
    # it lazily inside their bodies to defer the registry import. Binding the name
    # here resolves the forward reference for ruff/type-checkers at no runtime cost.
    from friTap.offline.registry import OfflineDecryptorEntry

from friTap.connection_index import resolve_connection_key
from friTap.events import DatalogEvent, EventBus, SESSION_STARTED, SessionEvent
from friTap.flow.collector import FlowCollector
from friTap.flow.layers import SshLayer
from friTap.flow.tap_writer import TapWriter

from .tshark import (
    ENCRYPTED_RECORD_MARKERS,
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
    ) -> None:
        """Accumulate one protocol decryptor's counters (generic + back-compat).

        Writes the protocol-generic ``per_protocol[prefix]`` view AND, when a
        matching legacy named field exists (``<prefix>_messages`` etc.), mirrors
        the increment into it so existing readers of ``result.mtproto_messages`` /
        ``result.mtproto_streams`` keep working unchanged.
        """
        bucket = self.per_protocol.setdefault(
            prefix,
            {"messages": 0, "streams": 0, "undecryptable": 0, "degraded": 0},
        )
        bucket["messages"] += messages
        bucket["streams"] += streams
        bucket["undecryptable"] += undecryptable
        bucket["degraded"] += degraded
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


def _quic_packet_to_events(
    pkt: dict,
    tracker: _StreamDirectionTracker,
    result: ConvertResult | None = None,
) -> list[DatalogEvent]:
    """Translate one QUIC `-T ek` packet dict into DatalogEvents.

    ``quic.stream.stream_id`` and ``quic.stream_data`` are PARALLEL lists when
    a single packet carries multiple stream frames — we zip them and emit one
    event per (stream_id, stream_data) pair.

    These two fields are extracted as independent parallel ``-T ek`` lists, so a
    packet carrying a zero-length / FIN-only STREAM frame can make the lists
    differ in length. ``zip`` would silently truncate, attaching payloads to the
    wrong stream id. To avoid corrupt attribution we detect a length mismatch,
    log a warning, increment *result*'s drop counter (when supplied), and SKIP
    the whole packet rather than emit a wrong mapping.
    """
    layers = pkt.get("layers") or {}

    timestamp = _coerce_float(_first(_field(layers, "frame.time_epoch")))

    src_addr, dst_addr, ss_family = _extract_addrs(layers)

    src_port = _coerce_int(_first(_field(layers, "udp.srcport")))
    dst_port = _coerce_int(_first(_field(layers, "udp.dstport")))
    stream_key = f"udp:{_first(_field(layers, 'udp.stream'))}"
    direction = tracker.direction_for(
        stream_key, src_addr, src_port, dst_addr, dst_port)

    stream_ids = _as_list(_field(layers, "quic.stream.stream_id"))
    stream_payloads = _as_list(_field(layers, "quic.stream_data"))

    # Guard against zip() silently truncating misaligned parallel lists (e.g. a
    # zero-length/FIN-only STREAM frame contributes a stream id but no payload).
    # Skip the packet entirely rather than mis-attribute payloads to stream ids.
    if len(stream_ids) != len(stream_payloads):
        logger.warning(
            "QUIC packet on %s has mismatched stream id/payload counts "
            "(%d ids vs %d payloads); skipping packet to avoid misattribution.",
            stream_key, len(stream_ids), len(stream_payloads),
        )
        if result is not None:
            result.dropped_packet_count += 1
        return []

    events: list[DatalogEvent] = []
    for stream_id, payload in zip(stream_ids, stream_payloads):
        data = decode_hex(str(payload))
        if not data:
            continue
        events.append(DatalogEvent(
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
            transport="udp",
            protocol="quic",  # so the flow is keyed/typed as QUIC (flow.transport)
            stream_id=_coerce_int(stream_id, default=None),
        ))
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

    def ensure_open(self, capture_start: float = 0.0) -> None:
        """Open the writer if it is not already open (idempotent)."""
        if self.opened:
            return
        self._writer.open(self._tap_path, target=self._target,
                           capture_start=capture_start)
        if self._keylog_path:
            _copy_keylog_into_tap(self._writer, self._keylog_path)
        self.opened = True


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
    for pkt in stream_packets(cmd):
        try:
            events = _quic_packet_to_events(pkt, tracker, result)
        except Exception:
            result.dropped_packet_count += 1
            logger.debug("Skipping unparseable QUIC packet", exc_info=True)
            continue
        if not events:
            continue

        udp_stream = _coerce_int(
            _first(_field(pkt.get("layers") or {}, "udp.stream")), default=None)

        state.ensure_open(events[0].timestamp or 0.0)
        for ev in events:
            result.decrypted_packet_count += 1
            quic_stream_ids.add((udp_stream, ev.stream_id))
            bus.emit(ev)

    result.stream_count += len(quic_stream_ids)


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
            meta = tls_meta_by_stream.get(tcp_stream)
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
            bus.emit(ev)

    result.stream_count += len(tcp_streams)


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


def _parsed_mtproto_to_dicts(parsed_messages, direction: str) -> list:
    """Turn :class:`ParsedMtprotoMessage` objects into JSON-native dicts.

    Mirrors the per-message dict shape the Signal path stores (so flow_detail's
    generic ``_render_layer_parsed`` understands it). The TL parser yields no
    timestamp/sender for outbound text, so those fields stay zero/empty.
    """
    return [
        {
            "sender": str(p.sender_id) if p.sender_id else "",
            "direction": direction,
            "timestamp": p.timestamp,
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


def _append_mtproto_dicts_deduped(entry: dict, dicts: list) -> None:
    """Append parsed dicts to *entry* while collapsing duplicate user identities.

    The same user often appears in multiple RPC results within one flow (e.g.
    "db Forscher" returned by several queries). Each distinct ``kind="user"``
    identity is emitted only ONCE per flow, keyed by :func:`_user_dedup_key`.
    Text/chat/service items are NEVER deduped — they pass through untouched.
    """
    seen = entry.setdefault("_user_keys", set())
    for item in dicts:
        key = _user_dedup_key(item)
        if key is not None:
            if key in seen:
                continue
            seen.add(key)
        entry["messages"].append(item)


def _accumulate_mtproto_messages(
    meta: dict, key: str, tl_bytes: bytes, direction: str,
) -> None:
    """Parse a cloud MTProto record's TL bytes and append to the side-channel.

    Tolerant by delegation: the parser never raises (degrades to no messages),
    so this can never break the conversion.
    """
    from friTap.offline.mtproto.content import parse_mtproto_message

    parsed = parse_mtproto_message(tl_bytes)
    if not parsed:
        return
    entry = meta.setdefault(key, {"messages": []})
    _append_mtproto_dicts_deduped(entry, _parsed_mtproto_to_dicts(parsed, direction))


def _accumulate_secret_chat_messages(
    meta: dict, key: str, tl_bytes: bytes, direction: str, chat_id: int,
) -> None:
    """Parse a Secret-Chat E2E record's TL bytes and append to the side-channel."""
    from friTap.offline.mtproto.content import parse_secret_chat_message

    parsed = parse_secret_chat_message(tl_bytes)
    if not parsed:
        return
    entry = meta.setdefault(key, {"chat_id": chat_id, "messages": []})
    entry["messages"].extend(_parsed_mtproto_to_dicts(parsed, direction))


def _emit_mtproto_streams(
    pcap_path: str,
    mtproto_keylog: str,
    *,
    bus: EventBus,
    state: "_WriterState",
    result: ConvertResult,
) -> None:
    """Decrypt Telegram MTProto streams and emit decrypted messages as DatalogEvents.

    Unlike TLS/QUIC this does NOT use tshark — friTap's own MTProto decryptor
    (``friTap.offline.mtproto``) reassembles the TCP streams, strips the
    obfuscated transport, and AES-IGE-decrypts each record using the auth keys
    in *mtproto_keylog*. Each decrypted MTProto message becomes one
    ``DatalogEvent(protocol="mtproto")`` fed through the SAME collector/writer
    path as the tshark output; the collector types the flow as ``mtproto``.

    The optional crypto backend is imported lazily; a missing dependency logs a
    warning and skips MTProto (the rest of the conversion is unaffected).
    """
    from friTap.connection_index import normalize_4tuple
    from friTap.offline.mtproto import MtprotoDependencyError
    from friTap.offline.mtproto.decrypt import MtprotoStats, iter_decrypted_messages
    from friTap.offline.mtproto.keylog import load_mtproto_keylog

    keymap = load_mtproto_keylog(mtproto_keylog)
    if not keymap:
        logger.warning(
            "MTProto keylog %s has no usable auth keys; skipping MTProto decryption",
            mtproto_keylog,
        )
        return

    stats = MtprotoStats()
    try:
        for msg in iter_decrypted_messages(pcap_path, keymap, stats=stats):
            ev = DatalogEvent(
                data=msg.message,
                function="mtproto_offline",
                direction=msg.direction,
                src_addr=msg.src_addr,
                src_port=msg.src_port,
                dst_addr=msg.dst_addr,
                dst_port=msg.dst_port,
                ss_family=msg.ss_family,
                transport="tcp",
                protocol="mtproto",
            )
            # DatalogEvent cannot carry parsed TL content, so accumulate it in the
            # cloud side-channel keyed by the perspective-independent 4-tuple;
            # _attach_telegram_meta folds it onto the inner MtprotoLayer.
            key = normalize_4tuple(
                msg.src_addr, msg.src_port, msg.dst_addr, msg.dst_port
            )
            _accumulate_mtproto_messages(
                state.mtproto_meta, key, msg.message, msg.direction,
            )
            state.ensure_open(0.0)
            result.decrypted_packet_count += 1
            bus.emit(ev)
    except MtprotoDependencyError as exc:
        logger.warning("MTProto decryption skipped: %s", exc)
        return

    result.record_protocol(
        "mtproto",
        messages=stats.messages,
        streams=stats.streams,
        undecryptable=stats.records_undecryptable,
        degraded=stats.streams_degraded,
    )


def _emit_telegram_streams(
    pcap_path: str,
    telegram_keylog: str,
    *,
    bus: EventBus,
    state: "_WriterState",
    result: ConvertResult,
) -> None:
    """Decrypt Telegram traffic (cloud + Secret-Chat) from ONE combined keylog.

    The ``telegram`` keylog holds BOTH ``MTPROTO_AUTH_KEY`` (cloud transport) and
    ``MTPROTO_E2E_KEY`` (Secret-Chat) lines; the two loaders each read only their
    own label, so the same file feeds both decryptors. Like MTProto this does NOT
    use tshark — friTap's own decryptor reassembles the TCP streams and AES-IGE
    decrypts each record. For every decrypted cloud message we (a) emit it as a
    ``DatalogEvent(protocol="mtproto")`` flow, and (b) scan it for embedded
    Secret-Chat E2E blobs, emitting each decrypted one as a
    ``DatalogEvent(protocol="telegram_e2e")`` flow.

    The optional crypto backend is imported lazily; a missing dependency logs a
    warning and skips Telegram (the rest of the conversion is unaffected).
    """
    from friTap.connection_index import normalize_4tuple
    from friTap.offline.mtproto import MtprotoDependencyError
    from friTap.offline.mtproto.decrypt import MtprotoStats, iter_decrypted_messages
    from friTap.offline.mtproto.keylog import load_mtproto_keylog
    from friTap.offline.mtproto.e2e.keylog import load_secret_chat_keylog
    from friTap.offline.mtproto.e2e.decrypt import iter_secret_chat_messages
    from friTap.offline.mtproto.e2e.records import SecretChatStats

    auth_keymap = load_mtproto_keylog(telegram_keylog)
    secret_keymap = load_secret_chat_keylog(telegram_keylog)
    if not auth_keymap and not secret_keymap:
        logger.warning(
            "Telegram keylog %s has no usable cloud (MTPROTO_AUTH_KEY) or "
            "Secret-Chat (MTPROTO_E2E_KEY) keys; skipping Telegram decryption",
            telegram_keylog,
        )
        return

    tstats = MtprotoStats()
    sstats = SecretChatStats()
    try:
        for msg in iter_decrypted_messages(pcap_path, auth_keymap, stats=tstats):
            # (a) the decrypted cloud transport message itself.
            cloud_ev = DatalogEvent(
                data=msg.message,
                function="telegram_offline",
                direction=msg.direction,
                src_addr=msg.src_addr,
                src_port=msg.src_port,
                dst_addr=msg.dst_addr,
                dst_port=msg.dst_port,
                ss_family=msg.ss_family,
                transport="tcp",
                protocol="mtproto",
            )
            # Parse the cloud TL payload into displayable messages (same cloud
            # side-channel + 4-tuple key as _emit_mtproto_streams).
            cloud_key = normalize_4tuple(
                msg.src_addr, msg.src_port, msg.dst_addr, msg.dst_port
            )
            _accumulate_mtproto_messages(
                state.mtproto_meta, cloud_key, msg.message, msg.direction,
            )
            state.ensure_open(0.0)
            result.decrypted_packet_count += 1
            bus.emit(cloud_ev)

            # (b) any Secret-Chat E2E blobs carried inside this cloud message.
            # Secret chats ride INSIDE the same TCP connection as the cloud
            # transport, so they share the cloud flow's 4-tuple. Tag each E2E
            # event with a per-chat session token so the collector keys it onto
            # its OWN ``telegram_e2e`` flow (via the ``sid:`` tier) instead of
            # folding its bytes into the cloud flow's MTProto parser.
            for sc in iter_secret_chat_messages([msg], secret_keymap, stats=sstats):
                e2e_ev = DatalogEvent(
                    data=sc.message,
                    function="telegram_e2e_offline",
                    direction=sc.direction,
                    src_addr=sc.src_addr,
                    src_port=sc.src_port,
                    dst_addr=sc.dst_addr,
                    dst_port=sc.dst_port,
                    ss_family=sc.ss_family,
                    ssl_session_id=f"telegram_e2e:{sc.key_fingerprint_hex}",
                    transport="tcp",
                    protocol="telegram_e2e",
                )
                # Parse the E2E TL payload; accumulate keyed by the same
                # ``telegram_e2e:<fp>`` session id the collector uses for the flow.
                _accumulate_secret_chat_messages(
                    state.telegram_e2e_meta,
                    f"telegram_e2e:{sc.key_fingerprint_hex}",
                    sc.message, sc.direction, sc.chat_id,
                )
                state.ensure_open(0.0)
                result.decrypted_packet_count += 1
                bus.emit(e2e_ev)
    except MtprotoDependencyError as exc:
        logger.warning("Telegram decryption skipped: %s", exc)
        return

    result.record_protocol(
        "telegram",
        messages=tstats.messages + sstats.messages,
        streams=tstats.streams,
        undecryptable=tstats.records_undecryptable + sstats.records_undecryptable,
        degraded=tstats.streams_degraded,
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
    bus, state, result,
) -> None:
    """Normalized adapter around :func:`_emit_mtproto_streams` (self-contained TCP)."""
    _emit_mtproto_streams(
        pcap_path, proto_keylog,
        bus=bus, state=state, result=result,
    )


def _telegram_offline_emitter(
    *, pcap_path, proto_keylog, tls_keylog_path, tshark_bin, tls_ports,
    bus, state, result,
) -> None:
    """Normalized adapter around :func:`_emit_telegram_streams` (self-contained TCP)."""
    _emit_telegram_streams(
        pcap_path, proto_keylog,
        bus=bus, state=state, result=result,
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
        cli_help=(
            "friTap MTProto keylog (MTPROTO_AUTH_KEY lines) for Telegram traffic. "
            "Decrypted by friTap's own MTProto decryptor (not tshark); distinct "
            "from --keylog."
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
    from friTap.flow.layers import AppLayer, TlsLayer
    from friTap.connection_index import canonical_4tuple, normalize_addr

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


def _attach_telegram_meta(
    flows,
    mtproto_meta: dict | None = None,
    telegram_e2e_meta: dict | None = None,
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
    Flows with no recovered messages are left untouched (degrades, never raises).
    """
    from friTap.connection_index import normalize_4tuple

    for flow in flows:
        inner_name = getattr(flow, "transport", "")
        if inner_name == "mtproto" and mtproto_meta:
            key = normalize_4tuple(
                flow.src_addr, flow.src_port, flow.dst_addr, flow.dst_port
            )
            meta = mtproto_meta.get(key)
        elif inner_name == "telegram_e2e" and telegram_e2e_meta:
            meta = telegram_e2e_meta.get(getattr(flow, "ssl_session_id", ""))
        else:
            continue
        if not meta:
            continue
        # Materialize the inner layer if the offline flow built it lazily
        # (``getattr`` triggers _create_layer, which appends the chunks-view
        # layer); then fold the parsed messages onto it.
        getattr(flow, inner_name)
        _apply_mtproto_meta(flow.layer(inner_name), meta)


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

    tshark_bin = find_tshark(tshark_path)
    warn_if_outdated(tshark_version(tshark_bin))

    bus = EventBus()
    collector = FlowCollector(event_bus=bus)
    writer = TapWriter()

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
                entry.emitter(
                    pcap_path=pcap_path,
                    proto_keylog=proto_keylogs[entry.protocol_name],
                    tls_keylog_path=keylog_path,
                    tshark_bin=tshark_bin,
                    tls_ports=tls_ports,
                    bus=bus, state=state, result=result,
                )
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
        for entry in independent_entries:
            entry.emitter(
                pcap_path=pcap_path,
                proto_keylog=proto_keylogs[entry.protocol_name],
                tls_keylog_path=keylog_path,
                tshark_bin=tshark_bin,
                tls_ports=tls_ports,
                bus=bus, state=state, result=result,
            )

        state.ensure_open()

        # Correlate TLS metadata onto offline-decrypted TLS-riding flows (Signal)
        # by 4-tuple, building the TLS -> HTTP/2 -> WebSocket -> inner encapsulation
        # stack (metadata-only outer layers + the decrypted-chunk inner layer). MUST
        # run on the LIVE flow objects (not get_flows() snapshots) and BEFORE
        # flush(): flush completes+writes the live flows, so the layers have to be
        # attached to those very objects beforehand to land in the .tap.
        _attach_transport_metadata_layers(collector.live_flows(), state.inner_meta)

        # Fold parsed Telegram MTProto/Secret-Chat messages onto their (raw-TCP,
        # non-TLS-riding) flows. Same LIVE-flows-before-flush() requirement as
        # the Signal pass above.
        _attach_telegram_meta(
            collector.live_flows(), state.mtproto_meta, state.telegram_e2e_meta,
        )

        # CRITICAL: TapWriter.on_flow_event only writes on "completed", which
        # offline reconstruction rarely emits (no SESSION_ENDED). flush() marks
        # active flows COMPLETE, then we sweep every flow the writer has not
        # already persisted.
        collector.flush()
        flows = collector.get_flows()
        # Flows whose metadata is folded on AFTER collection (Signal TLS-riding +
        # Telegram MTProto/Secret-Chat) can be written EARLY by an on-complete event
        # during collection — before _attach_*_meta ran — leaving the persisted record
        # without the attached layers/messages. Re-write those so the post-attach state
        # wins: the reader's flow index keeps the LAST record per flow_id, and only the
        # handful of offline-decrypted flows ever get a (harmless) duplicate record.
        offline_attached = _tls_riding_protocol_names() | {"mtproto", "telegram_e2e"}
        for flow in flows:
            transport = getattr(flow, "transport", "")
            if (flow.flow_id not in writer.written_flow_ids
                    or transport in offline_attached):
                writer.write_flow(flow)

        result.flow_count = len(flows)
    finally:
        if state.opened:
            writer.close()

    if run_scan:
        result.findings_count = _run_scan(tap_path)

    logger.info(
        "Offline conversion: %d flows, %d decrypted packets, %d streams, "
        "%d dropped TLS stream(s), %d dropped QUIC packet(s)",
        result.flow_count, result.decrypted_packet_count,
        result.stream_count, result.dropped_stream_count,
        result.dropped_packet_count,
    )
    return result


def _run_scan(tap_path: str) -> int:
    """Run all registered analyzers over *tap_path*; return the finding count."""
    from friTap.analysis import analyze_tap_multi
    from friTap.analysis.registry import resolve_analyzers

    findings = analyze_tap_multi(resolve_analyzers("all"), tap_path)
    return len(findings)


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
    use_manifest: bool = True,
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
        **{k: v for k, v in legacy_keylogs.items() if v},
    )
