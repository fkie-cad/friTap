"""Thread-safe flow collector that groups SSL events into flows.

``FlowCollector`` keeps all state (``__init__``), data ingestion (``on_data``),
publication and the flow queries. Cohesive method groups live in mixins
(``parser_flow``, ``connection_lifecycle``, ``flow_metadata``, ``orphan_flow``,
``caller_stack_flow``, ``request_join_flow``, ``signal_flow``, ``h2_flow``,
``quic_flow``). The constants below stay here; the mixins read them at call time.
"""

import copy
import logging
import threading
import time
import weakref
from collections import OrderedDict
from typing import TYPE_CHECKING, Callable, Optional

if TYPE_CHECKING:
    from .models import FlowSummary

from friTap.connection_index import (
    ConnectionKeyAliases,
    connection_scoped_session_key,
    resolve_connection_key,
)
from friTap.constants import direction_for_function
from friTap.events import (
    SESSION_DESTROYED,
    SESSION_ENDED,
    SESSION_RESUMED,
    SESSION_STARTED,
    CallerStackEvent,
    DatalogEvent,
    ErrorEvent,
    FlowEvent,
    KeylogEvent,
    LibraryDetectedEvent,
    OhttpEvent,
    RequestContextEvent,
    SessionEvent,
)
from friTap.parsers.base import unwrap_parser
from friTap.parsers.bhttp import parse_bhttp
from friTap.parsers.hexdump import HexdumpParser
from friTap.parsers.http2 import Http2Parser, is_h2_control_frame_data
from friTap.parsers.http3 import build_h3_result_from_headers
from friTap.parsers.registry import get_default_registry

from .attribution import direct_attribution  # noqa: F401 - patch target for the mixins
from .caller_stack_flow import CallerStackAttributionMixin
from .caller_stack_stash import CallerStackStash
from .collector_state import (  # noqa: F401 - private names re-exported for tests
    _ConnectionAttribution,
    _ConnectionState,
    _merge_connection_attribution,
    _merge_pop,
    _merge_session_meta,
    _PendingEvents,
    _Publication,
)
from .connection_lifecycle import ConnectionLifecycleMixin
from .flow_metadata import FlowMetadataMixin
from .h2_flow import Http2StreamFlowMixin
from .layer_pipeline import MESSAGE_TRANSPORTS, LayerPipeline
from .models import Flow, FlowChunk, FlowEventType, FlowState
from .orphan_flow import OrphanFlowMixin
from .parser_flow import ParserFlowMixin
from .quic_flow import QuicStreamFlowMixin
from .request_context_join import RequestContextStore
from .request_join_flow import RequestContextJoinMixin
from .signal_flow import SignalMessageFlowMixin

logger = logging.getLogger(__name__)

# If no data arrives for this many seconds and then resumes, treat as new connection.
IDLE_THRESHOLD = 30.0

# Bytes buffered before committing to the HexdumpParser fallback, so HTTP/2
# (9-byte frame header) and HTTP/3 (varint) have enough data for detection.
PARSER_DETECTION_BUFFER_SIZE = 256

# Run periodic maintenance sweep every N data events.
_SWEEP_INTERVAL = 500

# Distinct agent-guessed QUIC tuples remembered per connection until its real one appears.
_MAX_PROVISIONAL_SIDES = 8

# Per-flow cap on retained payload chunk bytes. The payload comes from a possibly hostile
# process: past the cap the flow keeps counting bytes but stops retaining chunks.
MAX_FLOW_CHUNK_BYTES = 64 * 1024 * 1024

# Per-connection, per-direction cap on the raw buffer for live Signal decoding (the live
# decryptor re-decrypts the whole buffer per event); decoding stops for a direction past it.
MAX_SIGNAL_RAW_BYTES = 16 * 1024 * 1024

# LRU caps on per-connection state. Connection ids come from the (possibly hostile) agent
# (e.g. a random client_random per event), so ``_connections`` and the orphan-request index
# must not grow without bound; an evicted connection is finalized exactly like an idle one.
MAX_TRACKED_CONNECTIONS = 4096
MAX_ORPHAN_REQUESTS = 1024
# Bounds on flows waiting for a request context that arrives after them (oldest dropped first).
MAX_REQUEST_JOIN_KEYS = 1024
MAX_REQUEST_JOIN_FLOWS_PER_KEY = 16
# Cap on the module -> load-path map from LibraryDetectedEvent (target-controlled names).
MAX_MODULE_PATHS = 256

# Decrypted-TL transports whose parser is pinned by the registry (not byte-sniffed); each event is one packet.
_TRANSPORT_TELEGRAM_E2E = "telegram_e2e"


class FlowCollector(
    SignalMessageFlowMixin,
    CallerStackAttributionMixin,
    RequestContextJoinMixin,
    OrphanFlowMixin,
    ParserFlowMixin,
    FlowMetadataMixin,
    ConnectionLifecycleMixin,
    QuicStreamFlowMixin,
    Http2StreamFlowMixin,
):
    """Thread-safe flow collector that groups SSL events into flows."""

    def __init__(self, event_bus=None, show_control_frames: bool = True,
                 signal_messages: bool = False, retain_completed: bool = True):
        self._lock = threading.Lock()
        self._flows: dict[str, Flow] = {}  # flow_id -> Flow
        # Headless ``--tap`` sets False: a flow is dropped from _flows once its COMPLETED notification
        # reached every subscriber (the TapWriter persisted it), bounding memory; a late orphan
        # response can then no longer merge into it. The TUI keeps True.
        self._retain_completed = retain_completed
        # conn_id -> [flow_id], in lockstep with _flows, so per-connection work avoids an O(flows)
        # scan per session/synthetic event (which made offline conversion O(streams x flows)).
        self._flow_index: dict[str, list[str]] = {}
        # conn_id -> next flow sequence number. On the collector (not _ConnectionState) so it
        # survives an idle-reset: re-minting "conn_id:0" would overwrite a completed flow still in
        # _flows. Shared by _make_flow and add_synthetic_flow; monotonic, only cleared in clear().
        self._flow_seq: dict[str, int] = {}
        # conn_id -> first flow sequence of the connection's CURRENT lifetime, recorded whenever its
        # state is created or rebuilt (new connection, idle-reset, eviction/session-end reuse).
        # _flow_seq is monotonic, so "first flow" (direct-join rule) and "a flow of this lifetime"
        # compare against this, not sequence 0. Outlives the state (a late join may target a
        # finalized connection); only cleared in clear().
        self._lifetime_first_seq: dict[str, int] = {}
        # UPDATED events raised where no pending list is threaded (flow birth in _make_flow); drained into on_data's. Under _lock.
        self._staged_updates: list = []
        # conn_id -> state, least-recently-used first (MAX_TRACKED_CONNECTIONS / _touch_connection).
        self._connections: OrderedDict[str, _ConnectionState] = OrderedDict()
        # Folds the net:/sid: keys one live 4-tuple is seen under into the first (TLS 1.3: SSL_write
        # has no session id yet, SSL_read does), so a connection never splits into request and response flows.
        self._key_aliases = ConnectionKeyAliases(capacity=4 * MAX_TRACKED_CONNECTIONS)
        # Owns the vertical layer-stack structure; invoked at flow finalize (inside the lock, before the COMPLETE flip).
        self._pipeline = LayerPipeline()
        self._callbacks: list[Callable] = []
        self._event_bus = event_bus
        self._show_control_frames = show_control_frames
        # HTTP/2 stream-level index: (conn_id, stream_id) -> flow_id
        self._h2_stream_flows: dict[tuple[str, int], str] = {}
        # Per-connection cache of handshake metadata from SESSION_STARTED/RESUMED, so _stamp_metadata
        # can backfill flows created AFTER the session event. Cleared in _finalize_connection.
        self._session_tls: dict[str, dict] = {}  # conn_id -> {version,sni,alpn,cipher}
        # Caller stacks (--attribute-sdk) that arrived before their flow. Join keys, strongest first:
        # ("cr", client_random), the unordered 5-tuple (_sdk_tuple_key; ssl_session_id is still "0"
        # at backtrace time), then a real ssl_session_id. Each key holds a FIFO drained one entry per
        # matching flow at birth and consumed on use, so a later connection reusing the 5-tuple
        # does not inherit it. Bounded by MAX_STASHED and STASH_TTL_SECONDS on self._now().
        self._sdk_pending: CallerStackStash = CallerStackStash()
        # client_random -> connection_id (set in _record_client_random, popped in _finalize_connection): O(1) first-choice caller_stack join.
        self._conn_by_client_random: dict[str, str] = {}
        # connection_id -> first SDK / caller stack, so flows born after the join inherit them even
        # after a sibling was released (headless). Written only by _remember_connection_attribution, popped in _finalize_connection.
        self._connection_attributions: dict[str, _ConnectionAttribution] = {}
        # Request-context join (--attribute-sdk); off until the first RequestContextEvent.
        self._request_join_enabled = False
        self._request_contexts = RequestContextStore(self._classify_request_frames)
        # request key -> [(flow first-request host time, flow_id)] of flows waiting for a context (bounded, oldest key dropped first).
        self._request_join_flows: OrderedDict = OrderedDict()
        # flow_id -> Flow already tried. Weak values: an entry dies with its flow, so a live flow is never retried or given a newer flow's context.
        self._request_join_attempted: weakref.WeakValueDictionary[str, Flow] = (
            weakref.WeakValueDictionary())
        # The chromium-internal bucket is skipped until a Chromium-family transport shows up.
        self._chromium_transport_seen = False
        # Finished contexts staged under the lock for the sink (set_request_context_sink), emitted after it is released.
        self._finished_request_contexts: list = []
        self._request_context_sink: Optional[Callable[[dict], object]] = None
        # Orphan request index: server_key -> [(timestamp, flow_id)] keyed by the REMOTE endpoint
        # (_orphan_key), least-recently-appended first; capped at MAX_ORPHAN_REQUESTS in total (_orphan_request_total).
        self._orphan_requests: OrderedDict[str, list[tuple[float, str]]] = OrderedDict()
        self._orphan_request_total = 0
        # Names of the state caps that already tripped (warned once each).
        self._caps_warned: set[str] = set()
        # Merge targets already COMPLETE when an orphan response was folded in (refreshed via UPDATED by flush); reset per merge pass.
        self._stale_merge_targets: list[Flow] = []
        self._event_count = 0
        # Offline conversion opts in: sweep/idle logic uses the newest event timestamp as "now", so
        # replayed pcap timestamps are not all "hours ago". Live capture uses time.time().
        self._use_event_clock = False
        self._max_event_ts = 0.0
        # Metadata stamped onto each new Flow; read under _lock. Last detected library per protocol tag, so under
        # --protocol auto an RC4/SSH/... announcement never re-labels TLS/QUIC flows.
        self._detected_libraries: dict[str, str] = {}
        # Module basename -> load path from LibraryDetectedEvent, oldest first, capped at MAX_MODULE_PATHS
        # (lets the transport classifier see e.g. a Play-services Cronet path).
        self._module_paths: OrderedDict[str, str] = OrderedDict()
        self._capture_target: str = ""
        self._process_name: str = ""
        self._package_name: str = ""
        # ErrorEvents staged under _lock by _on_parser_failure, emitted after release so EventBus.emit cannot deadlock subscribers reading collector state.
        self._pending_errors: list[ErrorEvent] = []
        # Opt-in live Signal decoding; created only on request so non-Signal captures pay no import cost.
        self._signal_messages = signal_messages
        self._signal_decryptor = None
        # Retained chunk bytes per flow id, and flows that hit MAX_FLOW_CHUNK_BYTES (Flow has no truncation flag).
        self._flow_retained_bytes: dict[str, int] = {}
        self._truncated_flow_ids: set[str] = set()
        if signal_messages:
            try:
                from .signal_live import LiveSignalDecryptor
                self._signal_decryptor = LiveSignalDecryptor()
            except ImportError:
                # Optional: with the decryptor None every Signal path no-ops.
                logger.debug(
                    "Live Signal decoder unavailable; Signal message decoding "
                    "disabled (other flows unaffected)",
                    exc_info=True,
                )

    def _drain_pending_errors(self) -> list:
        """Snapshot and clear the pending-error queue. Under _lock."""
        if not self._pending_errors:
            return []
        errors = list(self._pending_errors)
        self._pending_errors.clear()
        return errors

    def _emit_errors(self, errors: list) -> None:
        """Emit deferred ErrorEvents on the event bus. Must NOT hold _lock."""
        if not errors or self._event_bus is None:
            return
        for ev in errors:
            try:
                self._event_bus.emit(ev)
            except Exception:
                logger.debug("ErrorEvent emit failed", exc_info=True)

    def set_event_bus(self, event_bus) -> None:
        """Set the EventBus for FlowEvent emission."""
        self._event_bus = event_bus

    def set_show_control_frames(self, show: bool) -> None:
        """Toggle visibility of HTTP/2 control frames (PING, SETTINGS, etc.)."""
        with self._lock:
            self._show_control_frames = show

    def subscribe(self, callback: Callable) -> None:
        """Register ``callback(flow, event_type)``; event_type is a FlowEventType value ('created', 'updated', 'completed')."""
        with self._lock:
            self._callbacks.append(callback)

    def subscribe_to(self, event_bus) -> None:
        """Subscribe the ``on_*`` handlers to *event_bus*: the wiring every capture front end (API, CLI, TUI, ``.tap``) shares."""
        event_bus.subscribe(DatalogEvent, self.on_data)
        # A no-op unless the collector was built with signal_messages=True.
        event_bus.subscribe(KeylogEvent, self.on_keylog)
        event_bus.subscribe(OhttpEvent, self.on_ohttp)
        event_bus.subscribe(LibraryDetectedEvent, self.on_library_detected)
        event_bus.subscribe(SessionEvent, self.on_session_event)
        # Opt-in SDK attribution (--attribute-sdk).
        event_bus.subscribe(CallerStackEvent, self.on_sdk)
        event_bus.subscribe(RequestContextEvent, self.on_request_context)

    def on_data(self, event) -> None:
        """EventBus subscriber for DatalogEvent."""
        # Tiered key (client_random -> session_token -> 4-tuple) scoped by protocol, so an RC4 flow never merges
        # into a TLS flow on the same 4-tuple. Shared with MessageRouter._emit_lifecycle so both agree.
        protocol = getattr(event, 'protocol', 'tls')
        record_key = resolve_connection_key(
            event.src_addr, event.src_port,
            event.dst_addr, event.dst_port,
            session_token=getattr(event, 'ssl_session_id', ''),
            client_random=getattr(event, 'client_random', ''),
            protocol=protocol,
        )
        session_key = connection_scoped_session_key(
            getattr(event, 'ssl_session_id', ''), protocol, record_key)

        pending = []
        signal_events: list = []

        with self._lock:
            conn_id = self._key_aliases.resolve(
                record_key, event.src_addr, event.src_port,
                event.dst_addr, event.dst_port, str(protocol or "tls"),
                self._connections.__contains__, session_key=session_key,
                may_promote=self._may_promote_connection,
            )
            promoted_from = self._key_aliases.promoted_from
            if promoted_from is not None:
                self._rename_connection(self._connections[promoted_from], conn_id, pending)
            conn = self._touch_connection(conn_id, event, pending)

            # Idle too long: finalize and treat as a new connection.
            if self._is_idle_gap(conn, event.timestamp):
                self._finalize_connection(conn, conn.last_activity, pending)
                self._connections[conn_id] = self._start_connection_lifetime(conn_id, event)
                conn = self._connections[conn_id]

            conn.last_activity = event.timestamp
            self._observe_event_time(event.timestamp)
            self._record_client_random(conn, event, pending)
            self._learn_real_endpoints(conn, event, pending)

            direction = getattr(event, 'direction', '') or self._get_direction(event.function)
            is_quic_stream = self._is_quic_stream_event(conn, event)

            chunk = FlowChunk(
                data=event.data,
                direction=direction,
                timestamp=event.timestamp,
                function=event.function,
                stream_id=self._chunk_stream_id(conn, event, is_quic_stream),
            )

            # App-api mode: decoded HTTP/3 headers become a ParseResult directly (no QPACK/framing), keyed by synthetic stream id.
            h3_headers = getattr(event, 'http3_headers', None)
            if h3_headers is not None:
                real_qsid = self._quic_stream_id(event)
                synthetic_id = conn.map_qsid(real_qsid) if real_qsid is not None else 0
                result = build_h3_result_from_headers(h3_headers, synthetic_id, direction)
                flow = self._create_or_update_flow(conn, chunk, result, event, pending)
                self._append_progress(pending, flow)
            # Registry-pinned transport (decrypted Telegram TL): one event = one packet; no sniffing, buffering, upgrade or trailing data.
            elif self._is_pinned_transport(conn):
                self._feed_pinned_packet(conn, chunk, event, pending)
            # De-framed QUIC body bytes: their stream's flow, else the connection's unattributed-body flow.
            elif self._is_quic_body_payload(event):
                self._handle_quic_body_chunk(conn, chunk, event, pending)
            # QUIC raw stream bytes with a real stream id: per-stream HTTP/3.
            elif is_quic_stream:
                self._handle_quic_stream_chunk(conn, chunk, event, pending)
            # No parser yet: buffer until detection is reliable.
            elif conn.parser is None:
                conn.pending_chunks.append(chunk)
                conn.pending_bytes += len(event.data)

                try:
                    combined = b"".join(c.data for c in conn.pending_chunks)
                    detected = self._detect_parser(conn, combined)
                except Exception:
                    logger.debug("Parser detection failed", exc_info=True)
                    detected = HexdumpParser()

                is_fallback = isinstance(detected, HexdumpParser)

                if not is_fallback or conn.pending_bytes >= PARSER_DETECTION_BUFFER_SIZE:
                    conn.parser = self._wrap_parser(detected, conn)
                    for pending_chunk in conn.pending_chunks:
                        if self._is_h2_connection(conn):
                            # HTTP/2: each stream's flow gets its own frames.
                            self._process_h2_chunk(conn, pending_chunk, event, pending)
                            continue
                        results = conn.parser.feed(pending_chunk.data, pending_chunk.direction)
                        results = self._filter_control_frames(results)
                        if results:
                            for result in results:
                                flow = self._create_or_update_flow(conn, pending_chunk, result, event, pending)
                                self._append_progress(pending, flow)
                        else:
                            flow = self._get_or_create_active_flow(conn, event, pending)
                            self._append_chunk(flow, pending_chunk)
                            self._append_progress(pending, flow)
                    # Stamp detected_protocol even without a ParseResult (e.g. HTTP/2 SETTINGS-only prelude);
                    # a parser that recognized nothing (WebSocket false positive) defers it.
                    if not is_fallback:
                        conn.protocol_stamp_pending = not self._stamp_detected_protocol(conn)
                    if conn.active_flow_id and conn.active_flow_id in self._flows:
                        self._propagate_trailing_data(conn.parser, self._flows[conn.active_flow_id])
                    conn.pending_chunks = []
                    conn.pending_bytes = 0
                else:
                    # Still buffering: keep the chunk on the flow, parser not fed yet.
                    flow = self._get_or_create_active_flow(conn, event, pending)
                    self._append_chunk(flow, chunk)
                    self._append_progress(pending, flow)
            else:
                # Committed parser; a hexdump fallback may still upgrade.
                if isinstance(unwrap_parser(conn.parser), HexdumpParser):
                    self._try_parser_upgrade(conn, event.data)
                if self._is_h2_connection(conn):
                    # HTTP/2: each stream's flow gets exactly its own frames.
                    self._process_h2_chunk(conn, chunk, event, pending)
                else:
                    self._process_committed_chunk(conn, chunk, event, direction, pending)

            # After normal processing, so messages attach to the active flow.
            if self._signal_messages:
                self._collect_signal_messages(conn, direction, event, signal_events)

            self._event_count += 1
            if self._event_count % _SWEEP_INTERVAL == 0:
                self._periodic_sweep(pending)

            self._drain_staged_updates(pending)
            publication = self._stage_publication(pending)
            errors_to_emit = self._drain_pending_errors()

        self._publish(publication)
        self._emit_errors(errors_to_emit)
        self._emit_message_events(signal_events)

    def _process_committed_chunk(self, conn: '_ConnectionState', chunk: FlowChunk,
                                 event, direction: str, pending: list) -> None:
        """Feed *chunk* to the committed parser and place it whole. Under lock.

        Generic (non-HTTP/2) path: the record goes to every flow a result touched, else the active flow.
        HTTP/2 uses :meth:`_process_h2_chunk` unless its parser failed.
        """
        # Remap a real QUIC stream id onto a dense positive id so it never collides with the stream_id == 0 "ghost" sentinel.
        qsid = self._quic_stream_id(event)
        feed_sid = conn.map_qsid(qsid) if qsid is not None else None
        results = conn.parser.feed(event.data, direction, stream_id=feed_sid)
        if conn.protocol_stamp_pending:
            conn.protocol_stamp_pending = not self._stamp_detected_protocol(conn)

        if results:
            results = self._filter_control_frames(results)
            flow = None
            for result in results:
                flow = self._create_or_update_flow(conn, chunk, result, event, pending)
                self._append_progress(pending, flow)
            if flow is not None:
                self._propagate_trailing_data(conn.parser, flow)
            # Protocol upgrade handoff (e.g. HTTP/1 -> WebSocket after 101).
            self._check_parser_upgrade(conn)
        else:
            if (not self._show_control_frames
                    and isinstance(unwrap_parser(conn.parser), Http2Parser)
                    and is_h2_control_frame_data(event.data)):
                pass
            else:
                flow = self._get_or_create_active_flow(conn, event, pending)
                self._append_chunk(flow, chunk)
                self._propagate_trailing_data(conn.parser, flow)
                self._append_progress(pending, flow)

    def _drain_staged_updates(self, pending: list) -> None:
        """Move ``_staged_updates`` onto *pending*, skipping flows already queued there. Under lock."""
        queued = {id(flow) for _, flow in pending}
        for event_type, flow in self._staged_updates:
            if id(flow) not in queued:
                pending.append((event_type, flow))
                queued.add(id(flow))
        self._staged_updates.clear()

    @staticmethod
    def _is_pinned_transport(conn: '_ConnectionState') -> bool:
        """True if the registry pins a parser to *conn*'s transport."""
        registry = get_default_registry()
        return registry.pinned_parser_for(conn.transport) is not None

    def _feed_pinned_packet(self, conn, chunk, event, pending) -> None:
        """Feed ONE event to the transport-pinned parser as its own packet (pinned parsers never buffer, so no bytes bleed between events). Under lock."""
        if conn.parser is None:
            registry = get_default_registry()
            conn.parser = self._wrap_parser(
                registry.detect(b"", transport=conn.transport), conn)
        results = self._filter_control_frames(
            conn.parser.feed(chunk.data, chunk.direction))
        if not results and conn.transport in MESSAGE_TRANSPORTS:
            self._emit_packet_flow(conn, chunk, None, event, pending)
            return
        if not results:
            flow = self._get_or_create_active_flow(conn, event, pending)
            self._append_chunk(flow, chunk)
            self._append_progress(pending, flow)
            return
        for result in results:
            flow = self._create_or_update_flow(conn, chunk, result, event, pending)
            self._append_progress(pending, flow)

    def on_ohttp(self, event) -> None:
        """EventBus subscriber for OhttpEvent -- attach decrypted bhttp payload to last active flow."""
        result = parse_bhttp(event.data)
        if result is None:
            logger.debug("on_ohttp: parse_bhttp returned None for %d bytes", len(event.data))
            return

        pending = []
        with self._lock:
            if not self._flows:
                logger.debug("on_ohttp: no flows to attach OHTTP payload to")
                return
            flow_id = next(reversed(self._flows))
            flow = self._flows[flow_id]

            if event.direction == "request" or result.is_request:
                flow.ohttp_inner_request = result
                inner_field = "ohttp_inner_request"
            else:
                flow.ohttp_inner_response = result
                inner_field = "ohttp_inner_response"

            # ohttp_inner_* stay the source of truth; the "ohttp" layer mirrors them via parsed_field (request preferred).
            ohttp_layer = self._pipeline.push_layer(
                flow, protocol="ohttp", source="event:ohttp")
            if inner_field == "ohttp_inner_request" or not ohttp_layer._parsed_field:
                ohttp_layer._parsed_field = inner_field

            pending.append((FlowEventType.UPDATED, flow))
            publication = self._stage_publication(pending)

        self._publish(publication)

    def on_session_event(self, event) -> None:
        """EventBus subscriber for SessionEvent -- handle connection lifecycle."""
        # STARTED/RESUMED only stamp handshake metadata; they never finalize.
        if event.event_type in (SESSION_STARTED, SESSION_RESUMED):
            self._stamp_tls_metadata(event)
            return

        if event.event_type not in (SESSION_ENDED, SESSION_DESTROYED):
            return

        conn_id = getattr(event, 'connection_id', '')
        if not conn_id:
            return

        pending = []
        errors_to_emit: list = []
        with self._lock:
            conn_id = self._lifecycle_conn_id(event, conn_id)
            conn = self._connections.get(conn_id)
            if conn is None:
                return

            self._finalize_connection(conn, event.timestamp, pending)

            del self._connections[conn_id]
            publication = self._stage_publication(pending)
            errors_to_emit = self._drain_pending_errors()

        self._publish(publication)
        self._emit_errors(errors_to_emit)

    def _stage_publication(self, pending: list, finish_contexts: bool = False) -> '_Publication':
        """Prepare *pending* for :meth:`_publish` and take the finished request contexts (*finish_contexts* finishes live ones too: flush, clear). Under lock."""
        self._prepare_for_notify(pending)
        if finish_contexts:
            self._finished_request_contexts.extend(self._request_contexts.drain())
        finished, self._finished_request_contexts = self._finished_request_contexts, []
        sink = self._request_context_sink
        records = [context.to_record() for context in finished] if sink is not None else []
        return _Publication(pending, records, sink)

    def _publish(self, publication: '_Publication') -> None:
        """Notify the staged flow events, then hand the request records to the sink. Must NOT hold _lock."""
        for event_type, flow in publication.events:
            self._notify(event_type, flow)
        for record in publication.request_records:
            try:
                publication.request_sink(record)
            except Exception:  # noqa: BLE001 - a sink failure must not break capture
                logger.debug("request-context sink failed", exc_info=True)

    def _connection_flows(self, conn_id):
        """Yield the present flows of connection *conn_id* in index order. Under lock."""
        for flow_id in self._flow_index.get(conn_id, ()):
            flow = self._flows.get(flow_id)
            if flow is not None:
                yield flow

    def get_flow_summaries(self) -> list["FlowSummary"]:
        """Lightweight summaries for all flows (cheaper than ``get_flows()``: no chunk lists copied)."""
        from friTap.flow.models import FlowSummary
        with self._lock:
            flows_snapshot = list(self._flows.values())
        return [FlowSummary.from_flow(f) for f in flows_snapshot]

    def get_flows(self) -> list[Flow]:
        """All flows in insertion order (chronological). Returns snapshots."""
        with self._lock:
            result = []
            for flow in self._flows.values():
                snapshot = copy.copy(flow)
                snapshot.chunks = list(flow.chunks)

                result.append(snapshot)
            return result

    def live_flows(self) -> list[Flow]:
        """The collector's own Flow objects (not snapshots), for pre-write passes that must mutate what ``flush()`` serializes."""
        with self._lock:
            return list(self._flows.values())

    def get_flow(self, flow_id: str) -> Optional[Flow]:
        """Return a snapshot of a single flow, or None."""
        with self._lock:
            flow = self._flows.get(flow_id)
            if flow is None:
                return None
            snapshot = copy.copy(flow)
            snapshot.chunks = list(flow.chunks)
            return snapshot

    def clear(self) -> None:
        with self._lock:
            # Live request contexts are finished (persisted) before dropping.
            publication = self._stage_publication([], finish_contexts=True)
            self._request_join_enabled = False
            self._chromium_transport_seen = False
            self._request_join_flows.clear()
            self._request_join_attempted.clear()
            self._flows.clear()
            self._flow_index.clear()
            self._flow_seq.clear()
            self._lifetime_first_seq.clear()
            self._staged_updates.clear()
            self._connections.clear()
            self._key_aliases.clear()
            self._h2_stream_flows.clear()
            self._clear_orphan_requests()
            self._session_tls.clear()
            self._sdk_pending.clear()
            self._connection_attributions.clear()
            self._conn_by_client_random.clear()
            # _module_paths is process-lifetime state (like _detected_libraries, _process_name): kept.
            self._flow_retained_bytes.clear()
            self._truncated_flow_ids.clear()
        self._publish(publication)

    def is_flow_truncated(self, flow_id: str) -> bool:
        """True when *flow_id* exceeded :data:`MAX_FLOW_CHUNK_BYTES` (bytes still counted, chunks no longer retained)."""
        with self._lock:
            return flow_id in self._truncated_flow_ids

    def add_synthetic_flow(
        self,
        *,
        src_addr: str,
        src_port: int,
        dst_addr: str,
        dst_port: int,
        layer=None,
        detected_protocol: str = "",
        transport: str = "tcp",
        protocol: str = "",
        started: float = 0.0,
        ssl_session_id: str = "",
    ) -> Flow:
        """Register a metadata-only synthetic flow (SSH, IPsec: metadata recoverable offline, no payload); emit CREATED then COMPLETED.

        *layer* holds the metadata. Created already COMPLETE so the TapWriter persists it. Notifies outside the lock.
        """
        conn_id = resolve_connection_key(
            src_addr, src_port, dst_addr, dst_port,
            session_token=ssl_session_id,
            protocol=protocol or transport,
        )
        pending: list = []
        with self._lock:
            # Same allocator as _make_flow, so a synthetic and a data flow never mint the same "conn_id:N".
            flow_id = self._flow_id(conn_id, self._next_flow_sequence(conn_id))
            flow = Flow(
                flow_id=flow_id,
                connection_id=conn_id,
                src_addr=src_addr,
                src_port=src_port,
                dst_addr=dst_addr,
                dst_port=dst_port,
                ssl_session_id=ssl_session_id,
                started=started,
                ended=started,
                state=FlowState.COMPLETE,
                transport=transport,
            )
            # No event to stamp from: identity endpoints plus collector metadata.
            flow.local_addr = src_addr
            flow.local_port = src_port
            flow.remote_addr = dst_addr
            flow.remote_port = dst_port
            flow.process_name = self._process_name
            flow.package_name = self._package_name
            flow.detected_protocol = detected_protocol
            if layer is not None:
                flow.add_layer(layer)
            self._flows[flow_id] = flow
            self._index_flow(flow)
            pending.append((FlowEventType.CREATED, flow))
            pending.append((FlowEventType.COMPLETED, flow))
            publication = self._stage_publication(pending)

        self._publish(publication)
        return flow

    def _complete_flow(self, flow: Flow, ended: float, out: list) -> bool:
        """Transition a flow ACTIVE->COMPLETE exactly once (idempotent), enqueuing COMPLETED; True iff it transitioned.

        The one completion site for _attach_response, flush() and _finalize_connection(). The layer stack is
        built before the flip because the writer encodes the flow at the COMPLETED notify. Under lock.
        """
        if flow.state != FlowState.ACTIVE:
            return False
        self._pipeline.finalize(flow)
        flow.state = FlowState.COMPLETE
        flow.ended = ended
        out.append((FlowEventType.COMPLETED, flow))
        return True

    @staticmethod
    def _append_progress(pending: list, flow: Flow) -> None:
        """Enqueue UPDATED for an ACTIVE flow (a just-completed flow already has COMPLETED queued; UPDATED would follow the terminal event)."""
        if flow.state == FlowState.ACTIVE:
            pending.append((FlowEventType.UPDATED, flow))

    def use_event_clock(self, enabled: bool = True) -> None:
        """Measure sweep/idle time by the newest event timestamp, not the wall clock (offline conversion: pcap timestamps would make every connection look idle). Off for live capture."""
        with self._lock:
            self._use_event_clock = enabled

    def _observe_event_time(self, ts: float) -> None:
        """Advance the event clock to *ts* if it is newer. Under lock."""
        if ts > self._max_event_ts:
            self._max_event_ts = ts

    def _now(self) -> float:
        """Current time for sweeps: the event clock if enabled and known, else wall time."""
        if self._use_event_clock and self._max_event_ts > 0:
            return self._max_event_ts
        return time.time()

    @staticmethod
    def _last_activity_of(flow: Flow) -> float:
        """Newest chunk timestamp of *flow*, falling back to ``flow.started``."""
        latest = max((c.timestamp for c in flow.chunks), default=0.0)
        return latest if latest > 0 else flow.started

    def flush(self, *, end_at_last_activity: bool = False) -> None:
        """Flush all parsers, merge orphans and finalize active flows; COMPLETED only for flows transitioned here.

        With ``end_at_last_activity`` (offline conversion) a flow ends at its newest chunk timestamp, not the wall clock.
        """
        removed_flows: list[Flow] = []
        completed_events: list = []
        with self._lock:
            for conn in self._connections.values():
                if self._is_quic_connection(conn):
                    self._flush_quic_connection(conn, completed_events)
                if conn.parser is None and conn.pending_chunks:
                    self._commit_pending(conn)

                if conn.parser:
                    self._flush_parser_to_flow(conn, completed_events)

            removed_flows = self._merge_remaining_orphans()
            # A merge target already completed was notified (maybe written) without the absorbed response: send UPDATED.
            for stale_flow in self._stale_merge_targets:
                completed_events.append((FlowEventType.UPDATED, stale_flow))

            for flow in self._flows.values():
                ended = (self._last_activity_of(flow) if end_at_last_activity
                         else time.time())
                self._complete_flow(flow, ended, completed_events)

            self._clear_orphan_requests()
            # End of capture: live request contexts are finished and handed to the sink (after the join consumed its matches).
            publication = self._stage_publication(completed_events, finish_contexts=True)
            errors_to_emit = self._drain_pending_errors()

        for removed_flow in removed_flows:
            self._notify(FlowEventType.REMOVED, removed_flow)
        self._publish(publication)
        self._emit_errors(errors_to_emit)

    def memory_stats(self) -> dict:
        """Return diagnostic stats about internal structure sizes."""
        with self._lock:
            total_chunk_bytes = sum(
                sum(len(c.data) for c in f.chunks)
                for f in self._flows.values()
            )
            return {
                "flow_count": len(self._flows),
                "connection_count": len(self._connections),
                "h2_stream_index_count": len(self._h2_stream_flows),
                "orphan_request_count": sum(
                    len(v) for v in self._orphan_requests.values()
                ),
                "total_chunk_bytes": total_chunk_bytes,
                "active_flows": sum(
                    1 for f in self._flows.values()
                    if f.state == FlowState.ACTIVE
                ),
                "complete_flows": sum(
                    1 for f in self._flows.values()
                    if f.state == FlowState.COMPLETE
                ),
            }

    def _get_direction(self, function: str) -> str:
        """Determine direction from function name."""
        return direction_for_function(function)

    def _create_or_update_flow(self, conn, chunk, result, event, pending):
        """Create new flow or update existing based on parse result."""
        if conn.transport in MESSAGE_TRANSPORTS:
            return self._emit_packet_flow(conn, chunk, result, event, pending)
        stream_id = getattr(result, 'stream_id', 0)

        if result.is_request:
            # Reuse the active flow when it is a ghost (no request yet, e.g. an HTTP/2 SETTINGS preamble)
            # and stream_id == 0, or for an "unknown" continuation. HTTP/2 HEADERS on stream > 0 take the
            # stream-keyed path to preserve multiplexing.
            if conn.active_flow_id and conn.active_flow_id in self._flows:
                flow = self._flows[conn.active_flow_id]
                if flow.state == FlowState.ACTIVE:
                    is_ghost = flow.request is None and stream_id == 0
                    is_unknown_group = result.protocol == "unknown"
                    if is_ghost or is_unknown_group:
                        if flow.request is None:
                            flow.request = result
                        self._append_chunk(flow, chunk)
                        return flow
            if stream_id > 0:
                existing_fid = self._h2_stream_flows.get((conn.conn_id, stream_id))
                if existing_fid and existing_fid in self._flows:
                    flow = self._flows[existing_fid]
                    flow.request = result
                    self._append_chunk(flow, chunk)
                    return flow
            flow = self._make_flow(conn, event)
            flow.request = result
            self._append_chunk(flow, chunk)
            conn.active_flow_id = flow.flow_id
            if stream_id > 0:
                self._h2_stream_flows[(conn.conn_id, stream_id)] = flow.flow_id
            self._register_orphan_request(
                self._orphan_key(event, chunk.direction),
                event.timestamp, flow.flow_id)
            pending.append((FlowEventType.CREATED, flow))
            return flow
        else:
            # Response: HTTP/2 stream match first.
            if stream_id > 0:
                stream_key = (conn.conn_id, stream_id)
                matched_flow_id = self._h2_stream_flows.get(stream_key)
                if matched_flow_id and matched_flow_id in self._flows:
                    self._attach_response(self._flows[matched_flow_id], result, chunk, event.timestamp, pending)
                    if result.is_complete:
                        self._h2_stream_flows.pop(stream_key, None)
                    return self._flows[matched_flow_id]

            # Active flow only while ACTIVE: a completed flow would have its response overwritten with no
            # second COMPLETED (the TapWriter would never see it); such a response goes to orphan-match / new flow.
            active = None
            if conn.active_flow_id and conn.active_flow_id in self._flows:
                candidate = self._flows[conn.active_flow_id]
                if candidate.state == FlowState.ACTIVE:
                    active = candidate
            if active is not None:
                self._attach_response(active, result, chunk, event.timestamp, pending)
                return active
            else:
                matched = self._match_orphan_request(event, chunk.direction)
                if matched:
                    self._attach_response(matched, result, chunk, event.timestamp, pending)
                    return matched
                # Orphan response flow. CREATED is queued before _attach_response (a complete response
                # queues COMPLETED there); subscribers must never see COMPLETED before CREATED.
                flow = self._make_flow(conn, event)
                conn.active_flow_id = flow.flow_id
                pending.append((FlowEventType.CREATED, flow))
                self._attach_response(flow, result, chunk, event.timestamp, pending)
                return flow

    def _emit_packet_flow(self, conn, chunk, result, event, pending) -> Flow:
        """Emit one complete flow per decrypted message-transport packet (MTProto, Secret Chat).

        Packets are independent, so each is its own row with the event's real src/dst; a write is the
        ``request``, a read the ``response``. *result* may be None. Under lock.
        """
        flow = self._make_flow(conn, event)
        pending.append((FlowEventType.CREATED, flow))
        if chunk.direction == "read":
            flow.response = result
        else:
            flow.request = result
        self._append_chunk(flow, chunk)
        self._complete_flow(flow, event.timestamp, pending)
        conn.active_flow_id = None
        return flow

    def _get_or_create_active_flow(self, conn, event, pending):
        """Get current active flow or create a new one."""
        if conn.active_flow_id and conn.active_flow_id in self._flows:
            flow = self._flows[conn.active_flow_id]
            if flow.state == FlowState.ACTIVE:
                return flow
        flow = self._make_flow(conn, event)
        conn.active_flow_id = flow.flow_id
        pending.append((FlowEventType.CREATED, flow))
        return flow

    def _next_flow_sequence(self, conn_id: str) -> int:
        """Allocate the next monotonic flow sequence for *conn_id* (``_flow_seq``). Under lock."""

        seq = self._flow_seq.get(conn_id, 0)
        self._flow_seq[conn_id] = seq + 1
        return seq

    @staticmethod
    def _flow_id(conn_id: str, seq: int) -> str:
        """The id of *conn_id*'s flow number *seq* (see :meth:`_next_flow_sequence`)."""
        return f"{conn_id}:{seq}"

    @staticmethod
    def _flow_sequence_of(flow: Flow) -> Optional[int]:
        """The sequence of *flow*'s id (:meth:`_flow_id`), else ``None``; parsed from the id tail, not checked against ``connection_id`` (a promoted connection's flows keep their old prefix)."""
        try:
            return int(flow.flow_id.rpartition(":")[2])
        except ValueError:
            return None

    def _make_flow(self, conn, event, endpoints: Optional[tuple] = None) -> Flow:
        """Create and index a new Flow for *event*; *endpoints* optionally overrides the ``(src, dst)`` orientation (:meth:`_oriented_endpoints`)."""
        src_addr, src_port, dst_addr, dst_port = endpoints or (
            event.src_addr, event.src_port, event.dst_addr, event.dst_port)
        flow_id = self._flow_id(conn.conn_id, self._next_flow_sequence(conn.conn_id))
        flow = Flow(
            flow_id=flow_id,
            connection_id=conn.conn_id,
            src_addr=src_addr,
            src_port=src_port,
            dst_addr=dst_addr,
            dst_port=dst_port,
            ssl_session_id=getattr(event, 'ssl_session_id', ''),
            started=event.timestamp,
        )
        self._stamp_metadata(flow, event)
        self._stamp_synthetic_endpoints(flow, conn, event)
        self._flows[flow_id] = flow
        self._index_flow(flow)
        return flow

    def _index_flow(self, flow: Flow) -> None:
        """Record *flow* under its connection_id; run under the lock at every site adding to ``_flows`` so ``_flow_index`` mirrors it."""
        self._flow_index.setdefault(flow.connection_id, []).append(flow.flow_id)

    def _unindex_flow(self, flow: Flow) -> None:
        """Drop *flow* from the per-connection index; run under the lock at every site removing from ``_flows`` (orphan merge, :meth:`_release_flow`)."""
        ids = self._flow_index.get(flow.connection_id)
        if not ids:
            return
        try:
            ids.remove(flow.flow_id)
        except ValueError:
            pass
        if not ids:
            del self._flow_index[flow.connection_id]

    def _notify(self, event_type: str, flow: Flow) -> None:
        """Call all subscribers and emit FlowEvent to EventBus (outside lock)."""
        for cb in self._callbacks:
            try:
                cb(flow, event_type)
            except Exception:
                logger.debug("FlowCollector callback error", exc_info=True)
        if self._event_bus is not None:
            try:
                self._event_bus.emit(FlowEvent(
                    flow=flow,
                    flow_event_type=event_type,
                ))
            except Exception:
                logger.debug("FlowEvent emit error", exc_info=True)
        if event_type == FlowEventType.COMPLETED and not self._retain_completed:
            self._release_flow(flow)

    def _release_flow(self, flow: Flow) -> None:
        """Forget a completed flow (``retain_completed=False``). Takes the lock.

        Every flow-id lookup (active flow, HTTP/2 stream map, orphan index) is guarded by ``in self._flows``/``.get``, so stale ids are skipped.
        """
        with self._lock:
            if self._flows.get(flow.flow_id) is not flow:
                return
            del self._flows[flow.flow_id]
            self._unindex_flow(flow)
            self._flow_retained_bytes.pop(flow.flow_id, None)
            self._truncated_flow_ids.discard(flow.flow_id)
