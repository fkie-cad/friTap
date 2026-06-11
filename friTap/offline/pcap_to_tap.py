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

import logging
import os
from dataclasses import dataclass

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
        else:
            # No keys and no DSB: ingest the capture as already-plaintext. The raw
            # transport payload is fed through the SAME parser pipeline; encrypted
            # streams are detected and skipped (tallied for a --keylog hint).
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

        state.ensure_open()

        # CRITICAL: TapWriter.on_flow_event only writes on "completed", which
        # offline reconstruction rarely emits (no SESSION_ENDED). flush() marks
        # active flows COMPLETE, then we sweep every flow the writer has not
        # already persisted.
        collector.flush()
        flows = collector.get_flows()
        for flow in flows:
            if flow.flow_id not in writer.written_flow_ids:
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
    use_manifest: bool = True,
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
    if use_manifest:
        # load_manifest takes a pcap path (not an argparse Namespace), so it is
        # safe to reuse here; imported lazily to avoid a cli <-> pcap_to_tap
        # import cycle (cli imports convert_pcap_to_tap from this module).
        from .cli import load_manifest

        manifest = load_manifest(pcap_path)
        if manifest:
            keylog = keylog or manifest.get("keylog") or None
            tls = tls or tuple(manifest.get("tls_ports", []))
            quic = quic or tuple(manifest.get("quic_ports", []))

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
    )
