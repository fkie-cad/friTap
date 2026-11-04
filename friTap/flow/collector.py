"""Thread-safe flow collector that groups SSL events into flows."""

import copy
import logging
import re
import threading
import time
from collections import OrderedDict
from typing import TYPE_CHECKING, Callable, Optional

if TYPE_CHECKING:
    from .models import FlowSummary

from friTap.connection_index import ConnectionKeyAliases, resolve_connection_key
from friTap.constants import direction_for_function
from friTap.events import (
    ERROR_SEVERITY_WARNING,
    SESSION_DESTROYED,
    SESSION_ENDED,
    SESSION_RESUMED,
    SESSION_STARTED,
    ErrorEvent,
    FlowEvent,
)
from friTap.parsers.base import (
    MAX_PARSER_RESETS,
    BaseParser,
    ParserFailure,
    SafeParserAdapter,
    unwrap_parser,
)
from friTap.parsers.bhttp import parse_bhttp
from friTap.parsers.hexdump import HexdumpParser
from friTap.parsers.http2 import Http2Parser, is_h2_control_frame_data
from friTap.parsers.http3 import build_h3_result_from_headers
from friTap.parsers.registry import get_default_registry

from .h2_flow import Http2StreamFlowMixin
from .layer_pipeline import MESSAGE_TRANSPORTS, LayerPipeline
from .models import Flow, FlowChunk, FlowEventType, FlowState
from .quic_flow import QuicStreamFlowMixin

logger = logging.getLogger(__name__)

# If no data arrives for this many seconds and then resumes, treat as new connection.
IDLE_THRESHOLD = 30.0

# Buffer this many bytes before committing to HexdumpParser fallback.
# Ensures HTTP/2 (9-byte frame header) and HTTP/3 (varint) have enough data for detection.
PARSER_DETECTION_BUFFER_SIZE = 256

# Run periodic maintenance sweep every N data events.
_SWEEP_INTERVAL = 500

# Per-flow cap on retained payload chunk bytes. Payload comes from a possibly
# hostile process, so one endless stream must not grow memory without bound:
# past the cap the flow keeps counting bytes but stops retaining chunks.
MAX_FLOW_CHUNK_BYTES = 64 * 1024 * 1024

# Per-connection, per-direction cap on the raw byte buffer kept for live Signal
# message decoding. The live decryptor re-decrypts the WHOLE buffer on every
# event (its dedup is identity-based over a full re-decrypt), so the buffer is
# capped and decoding stops for that direction once it is exceeded.
MAX_SIGNAL_RAW_BYTES = 16 * 1024 * 1024

# LRU caps on per-connection collector state. Connection ids come from the
# (possibly hostile) agent -- e.g. a random client_random per event -- so within
# the idle window ``_connections`` and the orphan-request index could otherwise
# grow without bound. Past a cap the least-recently-used entry is evicted; an
# evicted connection is finalized exactly like an idle one (its flows complete
# and are emitted).
MAX_TRACKED_CONNECTIONS = 4096
MAX_ORPHAN_REQUESTS = 1024

# Decrypted-TL transports (Flow.transport values) whose parser is pinned by the
# registry instead of byte-sniffed; every event on them is exactly one packet.
_TRANSPORT_TELEGRAM_E2E = "telegram_e2e"


class FlowCollector(QuicStreamFlowMixin, Http2StreamFlowMixin):
    """Thread-safe flow collector that groups SSL events into flows."""

    def __init__(self, event_bus=None, show_control_frames: bool = True,
                 signal_messages: bool = False, retain_completed: bool = True):
        self._lock = threading.Lock()
        self._flows: dict[str, Flow] = {}  # flow_id -> Flow
        # Opt-in (headless ``--tap``): when False, a flow is dropped from
        # _flows once its COMPLETED notification has reached every subscriber
        # (i.e. after the TapWriter persisted it), so a long capture does not
        # keep every flow's chunks in memory. Trade-off: a late orphan response
        # can no longer be merged into an already-released request flow. The
        # TUI keeps the default (True): it browses completed flows.
        self._retain_completed = retain_completed
        # conn_id -> [flow_id], maintained in lockstep with _flows. Lets
        # per-connection work (metadata stamping, synthetic-flow sequencing)
        # look up a connection's flows directly instead of scanning every flow
        # on each session/synthetic event (O(flows) -> O(1) lookup, turning an
        # O(streams x flows) offline conversion back into O(streams)).
        self._flow_index: dict[str, list[str]] = {}
        # conn_id -> next flow sequence number. The flow-id counter lives HERE
        # (on the collector), not on _ConnectionState, so it survives an
        # idle-reset that rebuilds the connection state: re-minting "conn_id:0"
        # after a reset would otherwise overwrite an already-completed flow still
        # held in _flows. It is also the single id source shared by _make_flow
        # and add_synthetic_flow, so those two paths can never collide on the
        # "conn_id:N" namespace. Monotonic per conn_id; only cleared in clear().
        self._flow_seq: dict[str, int] = {}
        # conn_id -> state, in least-recently-used order (see
        # MAX_TRACKED_CONNECTIONS / _touch_connection).
        self._connections: OrderedDict[str, _ConnectionState] = OrderedDict()
        # Folds the net:/sid: keys one live 4-tuple is seen under into the
        # first one (TLS 1.3 legacy: SSL_write has no session id yet, SSL_read
        # does), so a connection never splits into a request and a response flow.
        self._key_aliases = ConnectionKeyAliases(capacity=4 * MAX_TRACKED_CONNECTIONS)
        # Owns the *vertical* layer-stack structure (transport -> app -> inner).
        # Invoked at flow finalize (inside the lock, before the COMPLETE flip).
        self._pipeline = LayerPipeline()
        self._callbacks: list[Callable] = []
        self._event_bus = event_bus
        self._show_control_frames = show_control_frames
        # HTTP/2 stream-level index: (conn_id, stream_id) -> flow_id
        self._h2_stream_flows: dict[tuple[str, int], str] = {}
        # Per-connection cache of TLS handshake metadata from SESSION_STARTED/
        # RESUMED events. Lets _stamp_metadata() backfill TLS fields onto flows
        # created AFTER the session event arrived (the common handshake-before-
        # data ordering). Keyed by connection_id; cleared in _finalize_connection.
        self._session_tls: dict[str, dict] = {}  # conn_id -> {version,sni,alpn,cipher}
        # Orphan request index: server_key -> [(timestamp, flow_id), ...], keyed
        # by the REMOTE (server) endpoint of the request (see _orphan_key), in
        # least-recently-appended order; capped at MAX_ORPHAN_REQUESTS entries
        # in total (tracked by _orphan_request_total).
        self._orphan_requests: OrderedDict[str, list[tuple[float, str]]] = OrderedDict()
        self._orphan_request_total = 0
        # Names of the state caps that already tripped (warned once each).
        self._caps_warned: set[str] = set()
        # Merge targets that were already COMPLETE when an orphan response was
        # folded in (refreshed via UPDATED by flush). Reset per merge pass.
        self._stale_merge_targets: list[Flow] = []
        self._event_count = 0
        # Opt-in event clock (offline conversion): when enabled, sweep/idle logic
        # measures "now" as the newest event timestamp seen instead of the wall
        # clock, so replayed pcap timestamps are not all "hours ago". Live capture
        # leaves this off and keeps using time.time().
        self._use_event_clock = False
        self._max_event_ts = 0.0
        # Cheaply-available metadata stamped onto each new Flow. Populated by
        # on_library_detected() and set_capture_target(); read under _lock.
        # Last detected library per protocol tag (LibraryDetectedEvent.protocol
        # -> library). Keyed by protocol so that under --protocol auto an RC4/
        # SSH/... library announcement never re-labels TLS/QUIC flows.
        self._detected_libraries: dict[str, str] = {}
        self._capture_target: str = ""
        self._process_name: str = ""
        self._package_name: str = ""
        # ErrorEvents staged by SafeParserAdapter via _on_parser_failure;
        # populated under _lock and drained by entry-point methods after the
        # lock is released so EventBus.emit cannot deadlock against TUI
        # subscribers that may need to read collector state.
        self._pending_errors: list[ErrorEvent] = []
        # Opt-in live Signal message decoding (enabled when on_message consumers
        # exist). The decryptor reuses the offline Signal pipeline; it is created
        # only when requested so a non-Signal capture pays no import cost.
        self._signal_messages = signal_messages
        self._signal_decryptor = None
        # Retained chunk bytes per flow id, and the flows that hit
        # MAX_FLOW_CHUNK_BYTES (kept here: Flow has no truncation flag).
        self._flow_retained_bytes: dict[str, int] = {}
        self._truncated_flow_ids: set[str] = set()
        if signal_messages:
            try:
                from .signal_live import LiveSignalDecryptor
                self._signal_decryptor = LiveSignalDecryptor()
            except ImportError:
                # Live Signal decoding is an optional component that may be
                # absent from some builds. When it is, the decryptor stays None
                # and every signal path below no-ops (see on_data /
                # _collect_signal_messages), so on_message() still works for all
                # other flows instead of crashing the capture.
                logger.debug(
                    "Live Signal decoder unavailable; Signal message decoding "
                    "disabled (other flows unaffected)",
                    exc_info=True,
                )

    def _wrap_parser(
        self,
        parser: BaseParser,
        conn: Optional['_ConnectionState'] = None,
    ) -> BaseParser:
        """Wrap *parser* in a SafeParserAdapter unless already wrapped.

        All parsers that get assigned to ``conn.parser`` go through this
        helper so a malformed stream can never crash the collector. When
        a connection state is supplied, the per-connection failure
        callback also resets the active flow's ``detected_protocol`` once
        the adapter gives up for good (its reset budget is spent), so the UI
        does not keep claiming HTTP/1.1 (or whatever the dead parser
        asserted) while raw bytes are now flowing untyped. A failure the
        adapter recovers from (fresh parser instance) keeps the label. It also
        stamps the connection's transport on the parser (``flow_transport``)
        so its trailing-data detection honours that transport's rules.
        """
        if parser is not None and conn is not None:
            parser.flow_transport = conn.transport
        if parser is None or isinstance(parser, SafeParserAdapter):
            return parser
        if conn is None:
            return SafeParserAdapter(parser, on_failure=self._on_parser_failure)

        adapter_ref: list[SafeParserAdapter] = []

        def _on_failure_with_conn(failure: ParserFailure) -> None:
            self._on_parser_failure(failure)
            if adapter_ref and self._parser_gives_up(adapter_ref[0]):
                self._mark_active_flow_unknown(conn)

        adapter = SafeParserAdapter(parser, on_failure=_on_failure_with_conn)
        adapter_ref.append(adapter)
        return adapter

    @staticmethod
    def _parser_gives_up(adapter: SafeParserAdapter) -> bool:
        """True when *adapter*'s current failure disables it for good.

        The on_failure callback runs BEFORE the adapter swaps in a fresh parser
        or disables itself, so the outcome is read from its reset budget: once
        ``MAX_PARSER_RESETS`` resets are spent, this failure disables it.
        """
        return adapter.disabled or adapter.reset_count >= MAX_PARSER_RESETS

    def _mark_active_flow_unknown(self, conn: '_ConnectionState') -> None:
        """Label *conn*'s active flow "unknown" (its parser is gone). Under lock."""
        flow = self._flows.get(conn.active_flow_id or "")
        if flow is not None:
            flow.detected_protocol = "unknown"

    def _on_parser_failure(self, failure: ParserFailure) -> None:
        """SafeParserAdapter callback. Stages an ErrorEvent for deferred emit.

        Called from within feed/flush while ``self._lock`` is held. Emitting
        the EventBus event synchronously here would risk a re-entrant
        deadlock with TUI subscribers, so we append to ``_pending_errors``
        and let the calling entry-point flush it after releasing the lock.
        """
        self._pending_errors.append(ErrorEvent(
            error=f"Parser {failure.parser_name} failed",
            description=f"{failure.exc_class}: {failure.exc_message}",
            stack=failure.traceback_text,
            severity=ERROR_SEVERITY_WARNING,
        ))

    def _drain_pending_errors(self) -> list:
        """Snapshot and clear the pending-error queue. Must be called under _lock."""
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

    def on_library_detected(self, event) -> None:
        """EventBus subscriber for LibraryDetectedEvent.

        Records the detected library under the event's protocol tag so it can
        be stamped onto each new Flow of that same protocol (``tls.library`` /
        ``quic.library``). Data events carry no library/module of their own, so
        the protocol tag is the finest attribution available.
        """
        library = getattr(event, 'library', '') or ''
        if not library:
            return
        protocol = getattr(event, 'protocol', 'tls') or 'tls'
        with self._lock:
            self._detected_libraries[protocol] = library

    def on_keylog(self, event) -> None:
        """EventBus subscriber for KeylogEvent — feed Signal keys to the live
        decryptor.

        Only active when live Signal message decoding was requested
        (``signal_messages``). TLS keylog events carry ``key_data`` (not a
        ``payload`` dict) and are ignored here; non-Signal ``payload`` dicts are
        rejected by the decryptor's keylog-spec validation.
        """
        if not self._signal_messages or self._signal_decryptor is None:
            return
        payload = getattr(event, 'payload', None)
        if not payload:
            return
        with self._lock:
            self._signal_decryptor.add_key(payload)

    def set_capture_target(self, target: str) -> None:
        """Record the capture target and derive process/package names.

        The whole target string is used as ``process_name``. It is ALSO used as
        ``package_name`` only when it has Android-package shape — dot-separated
        identifier segments (``com.example.app``) — and is not an IP address,
        a numeric PID, a path, or a known native/binary file (``.so``/``.exe``/
        etc.). This avoids misclassifying IPs, PIDs, paths and executables.
        """
        target = target or ""
        looks_like_package = self._looks_like_android_package(target)
        with self._lock:
            self._capture_target = target
            self._process_name = target
            self._package_name = target if looks_like_package else ""

    # Android package: dot-separated identifier segments, each starting with a
    # letter (e.g. "com.example.app"). Single-segment names (no dot) are not
    # packages — they are plain process/executable names.
    _ANDROID_PACKAGE_RE = re.compile(
        r"^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$"
    )
    # File/binary extensions a real package name would never end in.
    _NON_PACKAGE_EXTENSIONS = (
        ".so", ".exe", ".bin", ".apk", ".dll", ".dylib",
        ".jar", ".dex", ".out", ".elf",
    )

    @classmethod
    def _looks_like_android_package(cls, target: str) -> bool:
        """Return True only for strings shaped like an Android package id.

        Rejects whitespace, paths, IP addresses, bare numeric PIDs and names
        ending in a known binary/file extension so that those are not
        misclassified as package names.
        """
        if not target or any(c.isspace() for c in target):
            return False
        if "/" in target or "\\" in target:  # paths like /proc/1/exe
            return False
        lowered = target.lower()
        if lowered.endswith(cls._NON_PACKAGE_EXTENSIONS):
            return False
        if not cls._ANDROID_PACKAGE_RE.match(target):
            return False
        # An all-numeric-segment dotted string (e.g. "10.0.0.1") is an IP, not a
        # package — every package must have at least one alphabetic segment.
        # The regex already forces each segment to start with a letter, so any
        # match here is alphabetic-led and an IPv4 literal cannot match.
        return True

    def set_show_control_frames(self, show: bool) -> None:
        """Toggle visibility of HTTP/2 control frames (PING, SETTINGS, etc.)."""
        with self._lock:
            self._show_control_frames = show

    def subscribe(self, callback: Callable) -> None:
        """Register callback(flow, event_type) listener.

        event_type is a FlowEventType value: 'created', 'updated', 'completed'
        """
        with self._lock:
            self._callbacks.append(callback)

    def on_data(self, event) -> None:
        """EventBus subscriber for DatalogEvent."""
        # Build connection ID using tiered key resolution (client_random →
        # session_token → 4-tuple). The ``protocol`` is passed so the cr:/sid:
        # prefix reflects the event's real protocol (e.g. "quic") and the net:
        # tier is protocol-scoped for non-TLS protocols (net:<proto>:<4tuple>),
        # so e.g. an RC4 flow never merges into a TLS flow on the same 4-tuple; empty/
        # None is normalized to "tls" inside resolve_connection_key, the same
        # single source of truth MessageRouter._emit_lifecycle keys through, so
        # lifecycle and data events always resolve to the same key.
        protocol = getattr(event, 'protocol', 'tls')
        record_key = resolve_connection_key(
            event.src_addr, event.src_port,
            event.dst_addr, event.dst_port,
            session_token=getattr(event, 'ssl_session_id', ''),
            client_random=getattr(event, 'client_random', ''),
            protocol=protocol,
        )

        pending = []
        signal_events: list = []

        with self._lock:
            conn_id = self._key_aliases.resolve(
                record_key, event.src_addr, event.src_port,
                event.dst_addr, event.dst_port, str(protocol or "tls"),
                self._connections.__contains__,
            )
            # Get or create connection state (LRU-capped)
            conn = self._touch_connection(conn_id, event, pending)

            # Time-gap heuristic: if idle too long, reset connection state
            if self._is_idle_gap(conn, event.timestamp):
                self._finalize_connection(conn, conn.last_activity, pending)
                # Reset to fresh state
                self._connections[conn_id] = self._new_connection_state(conn_id, event)
                conn = self._connections[conn_id]

            conn.last_activity = event.timestamp
            self._observe_event_time(event.timestamp)

            # Prefer event.direction; fall back to function-name heuristic
            direction = getattr(event, 'direction', '') or self._get_direction(event.function)
            is_quic_stream = self._is_quic_stream_event(conn, event)

            # Create chunk
            chunk = FlowChunk(
                data=event.data,
                direction=direction,
                timestamp=event.timestamp,
                function=event.function,
                stream_id=self._chunk_stream_id(conn, event, is_quic_stream),
            )

            # Boundary-4 (app-api) mode: the agent forwarded already-decoded
            # HTTP/3 headers. Build a ParseResult directly — no QPACK, no frame
            # parsing — and correlate it into a flow by (synthetic) stream id.
            h3_headers = getattr(event, 'http3_headers', None)
            if h3_headers is not None:
                real_qsid = self._quic_stream_id(event)
                synthetic_id = conn.map_qsid(real_qsid) if real_qsid is not None else 0
                result = build_h3_result_from_headers(h3_headers, synthetic_id, direction)
                flow = self._create_or_update_flow(conn, chunk, result, event, pending)
                self._append_progress(pending, flow)
            # Registry-pinned transport (decrypted Telegram TL): no sniffing,
            # buffering, upgrade or trailing-data handling — one event, one packet.
            elif self._is_pinned_transport(conn):
                self._feed_pinned_packet(conn, chunk, event, pending)
            # De-framed QUIC body bytes with a real stream id: their stream's flow.
            elif self._is_quic_body_event(event):
                self._handle_quic_body_chunk(conn, chunk, event, pending)
            # QUIC raw stream bytes with a real stream id: per-stream HTTP/3.
            elif is_quic_stream:
                self._handle_quic_stream_chunk(conn, chunk, event, pending)
            # Parser detection with buffering retry
            elif conn.parser is None:
                # Buffer chunks until we have enough data for reliable detection
                conn.pending_chunks.append(chunk)
                conn.pending_bytes += len(event.data)

                try:
                    combined = b"".join(c.data for c in conn.pending_chunks)
                    detected = self._detect_parser(conn, combined)
                except Exception:
                    logger.debug("Parser detection failed", exc_info=True)
                    detected = HexdumpParser()

                # Check if we got a real parser or just the fallback
                is_fallback = isinstance(detected, HexdumpParser)

                if not is_fallback or conn.pending_bytes >= PARSER_DETECTION_BUFFER_SIZE:
                    # Commit to parser and feed all buffered chunks
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
                    # Stamp detected_protocol on the active flow when the parser
                    # matched a real protocol but produced no ParseResult yet
                    # (e.g. HTTP/2 SETTINGS-only prelude). A parser that has not
                    # recognized anything yet (WebSocket false positive) defers
                    # the stamp to its first successful direct feed.
                    if not is_fallback:
                        conn.protocol_stamp_pending = not self._stamp_detected_protocol(conn)
                    # Propagate trailing data from buffered-chunk parsing
                    if conn.active_flow_id and conn.active_flow_id in self._flows:
                        self._propagate_trailing_data(conn.parser, self._flows[conn.active_flow_id])
                    conn.pending_chunks = []
                    conn.pending_bytes = 0
                else:
                    # Still buffering — create/update flow with chunk but don't feed parser yet
                    flow = self._get_or_create_active_flow(conn, event, pending)
                    self._append_chunk(flow, chunk)
                    self._append_progress(pending, flow)
            else:
                # Parser already committed — try upgrade if on fallback
                if isinstance(unwrap_parser(conn.parser), HexdumpParser):
                    self._try_parser_upgrade(conn, event.data)
                if self._is_h2_connection(conn):
                    # HTTP/2: each stream's flow gets exactly its own frames.
                    self._process_h2_chunk(conn, chunk, event, pending)
                else:
                    self._process_committed_chunk(conn, chunk, event, direction, pending)

            # Live Signal message decoding (opt-in). Runs after the normal flow
            # processing so it can attach to the connection's active flow.
            if self._signal_messages:
                self._collect_signal_messages(conn, direction, event, signal_events)

            self._event_count += 1
            if self._event_count % _SWEEP_INTERVAL == 0:
                self._periodic_sweep(pending)

            errors_to_emit = self._drain_pending_errors()

        for event_type, flow in pending:
            self._notify(event_type, flow)
        self._emit_errors(errors_to_emit)
        self._emit_message_events(signal_events)

    def _process_committed_chunk(self, conn: '_ConnectionState', chunk: FlowChunk,
                                 event, direction: str, pending: list) -> None:
        """Feed *chunk* to the committed parser and place it whole. Under lock.

        The generic (non-HTTP/2) path: the record goes to every flow a result
        touched, else to the connection's active flow. HTTP/2 uses
        :meth:`_process_h2_chunk` instead, unless its parser failed.
        """
        # Feed directly. For QUIC the agent supplies a real stream id;
        # remap it onto a dense positive id so HTTP/3 multiplexing works
        # (and never collides with the stream_id == 0 "ghost" sentinel).
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
            # Propagate trailing data to flow
            if flow is not None:
                self._propagate_trailing_data(conn.parser, flow)
            # Protocol upgrade handoff (e.g., HTTP/1→WebSocket after 101)
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

    def _stamp_detected_protocol(self, conn: '_ConnectionState') -> bool:
        """Stamp the parser's PROTOCOL on the active flow if it recognized any.

        Returns True when no further stamping is needed (stamped, or the flow
        already carries a protocol); False while it is still pending.
        """
        active = self._flows.get(conn.active_flow_id) if conn.active_flow_id else None
        if active is None:
            return False
        return self._stamp_protocol_on(active, conn)

    @staticmethod
    def _stamp_protocol_on(flow: Flow, conn: '_ConnectionState') -> bool:
        """Fill *flow*'s empty ``detected_protocol`` from *conn*'s parser.

        Returns False while the parser has not recognized anything yet.
        """
        if conn.parser is None or not conn.parser.recognized_any():
            return False
        if not flow.detected_protocol:
            flow.detected_protocol = conn.parser.PROTOCOL
        return True

    @staticmethod
    def _new_connection_state(conn_id: str, event) -> '_ConnectionState':
        """Fresh per-connection state carrying the event's transport."""
        transport = getattr(event, 'protocol', 'tls') or 'tls'
        return _ConnectionState(conn_id, transport=transport)

    @staticmethod
    def _is_exempt_from_idle(conn: '_ConnectionState') -> bool:
        """Secret-Chat connections keep their open request across idle gaps.

        A reply to a sent Secret-Chat message routinely arrives minutes later;
        an idle reset/sweep would finalize the waiting request-only flow and
        break the request/response pairing.
        """
        return conn.transport == _TRANSPORT_TELEGRAM_E2E

    def _is_idle_gap(self, conn: '_ConnectionState', timestamp: float) -> bool:
        """True if *conn* sat idle longer than IDLE_THRESHOLD before *timestamp*."""
        if conn.last_activity <= 0 or self._is_exempt_from_idle(conn):
            return False
        return (timestamp - conn.last_activity) > IDLE_THRESHOLD

    @staticmethod
    def _is_pinned_transport(conn: '_ConnectionState') -> bool:
        """True if the registry pins a parser to *conn*'s transport."""
        registry = get_default_registry()
        return registry.pinned_parser_for(conn.transport) is not None

    def _feed_pinned_packet(self, conn, chunk, event, pending) -> None:
        """Feed ONE event to the transport-pinned parser as its own packet.

        Pinned parsers never buffer, so each result stems solely from *chunk*
        and no bytes of one event can bleed into another event's result.
        Must be called under lock.
        """
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

    def _collect_signal_messages(self, conn, direction, event, out_events) -> None:
        """Decode newly-arrived live Signal messages for one DatalogEvent.

        Accumulates the raw decrypted-TLS bytes per direction on the connection
        and re-runs the offline Signal pipeline over the growing buffer, emitting
        only messages not previously seen. Attaches new messages to the
        connection's active flow's ``SignalLayer`` and stages a ``MessageEvent``
        per message in *out_events* (emitted by the caller outside the lock).

        Must be called under ``self._lock``. Assumes a message's key arrives
        before (or with) its bytes — the common live ordering; a key that lands
        strictly after its message's bytes is recovered offline, not here.
        """
        decryptor = self._signal_decryptor
        if decryptor is None or direction not in ("read", "write"):
            return
        data = getattr(event, 'data', b'') or b''
        if not data:
            return
        # Accumulate even before keys arrive so history is intact once they do.
        buf = self._extend_signal_buffer(conn, direction, data)
        if buf is None or not decryptor.has_keys:
            return

        # id(conn) disambiguates a reset connection (fresh state, empty buffer)
        # reusing the same conn_id, so dedup counters restart correctly.
        stream_key = f"{conn.conn_id}:{direction}:{id(conn)}"
        new_msgs = decryptor.feed(
            stream_key, bytes(buf), direction,
            src_addr=getattr(event, 'src_addr', ''),
            src_port=getattr(event, 'src_port', 0),
            dst_addr=getattr(event, 'dst_addr', ''),
            dst_port=getattr(event, 'dst_port', 0),
            ss_family=getattr(event, 'ss_family', 'AF_INET'),
        )
        if not new_msgs:
            return

        flow = self._flows.get(conn.active_flow_id) if conn.active_flow_id else None
        if flow is not None:
            self._attach_signal_messages(flow, new_msgs)
        for msg in new_msgs:
            out_events.append(self._build_message_event(msg))

    @staticmethod
    def _extend_signal_buffer(conn, direction: str, data: bytes) -> Optional[bytearray]:
        """Append *data* to the live Signal buffer, or ``None`` once it is capped.

        The live decryptor needs the whole per-direction stream and re-decrypts
        it on every event, so an unbounded buffer is both a memory and an O(n²)
        CPU hazard. Past :data:`MAX_SIGNAL_RAW_BYTES` the buffer is released and
        decoding stops for that connection direction (logged once).
        """
        if direction in conn.signal_capped:
            return None
        buf = conn.signal_raw.setdefault(direction, bytearray())
        if len(buf) + len(data) > MAX_SIGNAL_RAW_BYTES:
            conn.signal_capped.add(direction)
            conn.signal_raw[direction] = bytearray()
            logger.warning(
                "Live Signal decoding stopped for %s (%s): stream exceeded %d bytes",
                conn.conn_id, direction, MAX_SIGNAL_RAW_BYTES)
            return None
        buf.extend(data)
        return buf

    def _attach_signal_messages(self, flow, msgs) -> None:
        """Append decrypted Signal messages onto *flow*'s SignalLayer (live).

        Mirrors the offline
        :func:`friTap.offline.signal.offline_decryptor._ingest_signal_message`
        per-message dict shape so live and offline ``SignalLayer.messages`` are
        identical. A typed
        :class:`~friTap.flow.layers.SignalLayer` is created on first use (the
        generic ``push_layer`` only makes an untyped ``AppLayer``).
        """
        from friTap.flow.layers import SignalLayer
        layer = flow.layer(SignalLayer.NAME)
        if not isinstance(layer, SignalLayer):
            layer = flow.add_layer(SignalLayer())
        if msgs and not getattr(layer, 'chat_type', ''):
            layer.chat_type = msgs[0].chat_type
            layer.identifier = msgs[0].identifier_hex
        for m in msgs:
            layer.messages.append({
                "sender": m.sender,
                "direction": m.direction,
                "timestamp": m.timestamp,
                "kind": m.kind,
                "body": m.body,
                "attachments": m.has_attachments,
                "quote": m.has_quote,
                "reaction": m.has_reaction,
            })
        layer.message_count = len(layer.messages)

    @staticmethod
    def _build_message_event(msg):
        """Build a MessageEvent from an offline-style DecryptedMessage."""
        from friTap.events import MessageEvent
        return MessageEvent(
            protocol="signal",
            direction=msg.direction,
            src_addr=msg.src_addr,
            src_port=msg.src_port,
            dst_addr=msg.dst_addr,
            dst_port=msg.dst_port,
            ss_family=msg.ss_family,
            chat_type=msg.chat_type,
            identifier=msg.identifier_hex,
            sender=msg.sender,
            kind=msg.kind,
            body=msg.body,
            timestamp=msg.timestamp,
            has_attachments=msg.has_attachments,
            has_quote=msg.has_quote,
            has_reaction=msg.has_reaction,
            raw=msg.message,
        )

    def _emit_message_events(self, events) -> None:
        """Emit staged MessageEvents on the bus. Must NOT hold _lock."""
        if not events or self._event_bus is None:
            return
        for ev in events:
            try:
                self._event_bus.emit(ev)
            except Exception:
                logger.debug("MessageEvent emit failed", exc_info=True)

    def on_ohttp(self, event) -> None:
        """EventBus subscriber for OhttpEvent -- attach decrypted bhttp payload to last active flow."""
        result = parse_bhttp(event.data)
        if result is None:
            logger.debug("on_ohttp: parse_bhttp returned None for %d bytes", len(event.data))
            return

        pending = []
        with self._lock:
            # Find the last flow in insertion order
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

            # Route the event-fed inner protocol into the layer model. The
            # legacy ohttp_inner_* fields stay the source of truth; the "ohttp"
            # layer MIRRORS them via parsed_field (no byte/result duplication).
            # The request is the canonical parsed reference when both exist.
            ohttp_layer = self._pipeline.push_layer(
                flow, protocol="ohttp", source="event:ohttp")
            if inner_field == "ohttp_inner_request" or not ohttp_layer._parsed_field:
                ohttp_layer._parsed_field = inner_field

            pending.append((FlowEventType.UPDATED, flow))

        for event_type, flow in pending:
            self._notify(event_type, flow)

    def on_session_event(self, event) -> None:
        """EventBus subscriber for SessionEvent -- handle connection lifecycle."""
        # On STARTED/RESUMED, stamp any available TLS handshake metadata onto
        # the flows belonging to this connection. This path does not finalize
        # or remove the connection, so it returns once stamping is done.
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

            # Remove connection state so next data creates fresh state
            del self._connections[conn_id]
            errors_to_emit = self._drain_pending_errors()

        for event_type, flow in pending:
            self._notify(event_type, flow)
        self._emit_errors(errors_to_emit)

    def _lifecycle_conn_id(self, event, conn_id: str) -> str:
        """Map a SessionEvent's key onto the live connection it aliases. Under lock."""
        return self._key_aliases.lookup(
            conn_id,
            getattr(event, 'src_addr', ''), getattr(event, 'src_port', 0),
            getattr(event, 'dst_addr', ''), getattr(event, 'dst_port', 0),
            self._connections.__contains__,
        )

    @staticmethod
    def _apply_session_metadata(flow: Flow, meta: dict) -> bool:
        """Stamp cached session metadata onto the flow's transport layer.

        Transport-aware: a QUIC flow stamps onto ``flow.quic`` (transport
        version from ``quic_version``, plus alpn/cipher recovered from the
        QUIC-embedded TLS handshake); a TLS flow stamps onto ``flow.tls``
        (version/sni/alpn/cipher). Only empty fields are filled. Returns True if
        anything changed (so callers can decide whether to notify).
        """
        changed = False
        if getattr(flow, "transport", "tls") == "quic":
            layer = flow.quic
            qv = meta.get("quic_version", "")
            if qv and not layer.version:
                layer.version = qv
                changed = True
            if meta.get("sni") and not layer.sni:
                layer.sni = meta["sni"]
                changed = True
            if meta.get("alpn") and not layer.alpn:
                layer.alpn = meta["alpn"]
                changed = True
            if meta.get("cipher") and not layer.cipher:
                layer.cipher = meta["cipher"]
                changed = True
        else:
            layer = flow.tls
            if meta.get("version") and not layer.version:
                layer.version = meta["version"]
                changed = True
            if meta.get("sni") and not layer.sni:
                layer.sni = meta["sni"]
                changed = True
            if meta.get("alpn") and not layer.alpn:
                layer.alpn = meta["alpn"]
                changed = True
            if meta.get("cipher") and not layer.cipher:
                layer.cipher = meta["cipher"]
                changed = True
        return changed

    def _stamp_tls_metadata(self, event) -> None:
        """Stamp handshake metadata from a SessionEvent onto matching flows.

        Transport-aware (TLS -> ``flow.tls``, QUIC -> ``flow.quic``): caches the
        metadata by ``connection_id`` so flows created LATER (handshake-before-
        data ordering) are backfilled by :meth:`_stamp_metadata`, and stamps any
        flows that already exist. Metadata is OFFLINE-ONLY — the live agent path
        emits none, so in practice only the offline pcap->tap producer's
        SessionEvents reach here. Updated flows are notified after the lock.
        """
        conn_id = getattr(event, 'connection_id', '')
        if not conn_id:
            return

        meta = {
            "version": getattr(event, 'protocol_version', '') or '',
            "sni": getattr(event, 'server_name', '') or '',
            "alpn": getattr(event, 'alpn', '') or '',
            "cipher": (getattr(event, 'cipher', '')
                       or getattr(event, 'cipher_suite', '') or ''),
            "quic_version": getattr(event, 'quic_version', '') or '',
        }
        if not any(meta.values()):
            return

        pending = []
        with self._lock:
            conn_id = self._lifecycle_conn_id(event, conn_id)
            # Merge into any existing cache entry so a partial RESUMED event
            # never blanks fields a prior STARTED already set.
            cached = self._session_tls.setdefault(conn_id, {})
            for key, value in meta.items():
                if value:
                    cached[key] = value

            # Look up this connection's flows via the index instead of scanning
            # every flow (which was O(flows) per session event -> O(streams x
            # flows) over an offline conversion). Index order mirrors _flows
            # insertion order, so UPDATED events fire in the same order as before.
            for flow_id in self._flow_index.get(conn_id, ()):
                flow = self._flows.get(flow_id)
                if flow is None:
                    continue
                # Only notify flows that actually changed — a re-RESUMED
                # connection whose flows already carry metadata is a no-op.
                if self._apply_session_metadata(flow, meta):
                    pending.append((FlowEventType.UPDATED, flow))

        for event_type, flow in pending:
            self._notify(event_type, flow)

    def get_flow_summaries(self) -> list["FlowSummary"]:
        """Lightweight summaries for all flows (no chunks, no body bytes).

        Much cheaper than ``get_flows()`` — creates frozen ``FlowSummary``
        objects (~200 bytes each) without copying chunk lists.
        """
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
                snapshot.chunks = list(flow.chunks)  # Snapshot the chunk list
                result.append(snapshot)
            return result

    def live_flows(self) -> list[Flow]:
        """The LIVE flow objects in insertion order (NOT snapshots).

        Unlike :meth:`get_flows` (which returns ``copy.copy`` snapshots), this
        exposes the collector's own ``Flow`` instances so a pre-write
        post-processing pass (e.g. offline TLS-metadata correlation onto Signal
        flows) can mutate the exact objects ``flush()`` will serialize. Mutate
        with care — these are the collector's working set.
        """
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
            self._flows.clear()
            self._flow_index.clear()
            self._flow_seq.clear()
            self._connections.clear()
            self._key_aliases.clear()
            self._h2_stream_flows.clear()
            self._clear_orphan_requests()
            self._session_tls.clear()
            self._flow_retained_bytes.clear()
            self._truncated_flow_ids.clear()

    def is_flow_truncated(self, flow_id: str) -> bool:
        """True when *flow_id* exceeded :data:`MAX_FLOW_CHUNK_BYTES`.

        Such a flow keeps counting its bytes (``total_bytes``) but no longer
        retains payload chunks past the cap.
        """
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
        """Register a metadata-only synthetic flow; emit CREATED then COMPLETED.

        For protocols whose METADATA is recoverable offline but whose payload is
        NOT — SSH (plaintext KEXINIT/banner, no session keys) and IPsec (stub).
        The flow carries no chunks; *layer* (e.g. an SshLayer/IpsecLayer) holds
        the metadata and *detected_protocol* drives display. The flow is created
        already COMPLETE so the TapWriter persists it on the COMPLETED notify.
        Thread-safe; notifies outside the lock.
        """
        conn_id = resolve_connection_key(
            src_addr, src_port, dst_addr, dst_port,
            session_token=ssl_session_id,
            protocol=protocol or transport,
        )
        pending: list = []
        with self._lock:
            # Sequence within this connection so repeated synthetic flows for
            # the same endpoints get distinct ids. Drawn from the SAME monotonic
            # allocator _make_flow uses, so a synthetic flow and a data flow on
            # the same conn_id can never mint the same "conn_id:N" (the old
            # len(_flow_index) scheme could: it counts current entries, which
            # diverges from _make_flow's sequence after any reset/unindex).
            seq = self._next_flow_sequence(conn_id)
            flow_id = f"{conn_id}:{seq}"
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
            # Lightweight metadata (no event to stamp from): identity endpoints
            # + process/package/library known to the collector.
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

        for event_type, f in pending:
            self._notify(event_type, f)
        return flow

    def _complete_flow(self, flow: Flow, ended: float, out: list) -> bool:
        """Transition a flow ACTIVE->COMPLETE exactly once, enqueuing COMPLETED.

        The single shared completion site for all three paths that finalize a
        flow: on_data (via _attach_response, when a response is is_complete),
        flush(), and _finalize_connection(). It builds the layer stack BEFORE
        the state flip (write-ordering: the writer encodes the flow at the
        COMPLETED notify) and appends exactly one ``(COMPLETED, flow)`` to
        *out*. The ACTIVE guard makes it idempotent — a flow already COMPLETE is
        never re-flipped or re-emitted, so no caller double-processes it and the
        COMPLETED event fires exactly once whichever path reaches it first.
        Returns True iff it performed the transition. Must be called under lock.
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
        """Enqueue a non-terminal UPDATED event for an in-progress flow.

        Skips a flow that just reached COMPLETE: its single COMPLETED event was
        already enqueued at the completion site (_complete_flow via
        _attach_response), so a trailing UPDATED would be redundant and emitted
        out of order after the terminal event.
        """
        if flow.state == FlowState.ACTIVE:
            pending.append((FlowEventType.UPDATED, flow))

    def use_event_clock(self, enabled: bool = True) -> None:
        """Measure sweep/idle time by the newest event timestamp, not the wall clock.

        For offline conversion, where event timestamps are pcap capture times: with
        the wall clock every replayed connection looks idle for hours and is
        finalized on each periodic sweep. Live capture should leave this off.
        """
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
        """Flush all parsers and finalize active flows.

        With ``end_at_last_activity`` (offline conversion) each flow finalized here
        ends at its newest chunk timestamp (fallback ``flow.started``) instead of
        the wall-clock time of the flush.

        Emits a COMPLETED FlowEvent for every flow this call transitions from
        ACTIVE to COMPLETE, mirroring _finalize_connection. This lets the
        end-of-capture path (legacy ssl_logger_core._finalize_live_scan) enqueue
        still-active flows for passive analysis. _complete_flow guards on
        FlowState.ACTIVE so flows already completed/notified earlier (by
        _finalize_connection or by _attach_response during on_data) are never
        re-emitted (no double-processing for any caller).
        """
        removed_flows: list[Flow] = []
        completed_events: list = []
        with self._lock:
            for conn in self._connections.values():
                if self._is_quic_connection(conn):
                    self._flush_quic_connection(conn, completed_events)
                # Commit parser for connections still in the buffering phase
                if conn.parser is None and conn.pending_chunks:
                    self._commit_pending(conn)

                if conn.parser:
                    self._flush_parser_to_flow(conn, completed_events)

            # Merge orphan request-only + response-only flows by destination
            removed_flows = self._merge_remaining_orphans()
            # A merge target that had ALREADY completed was notified (and
            # possibly written) without the absorbed response: tell
            # subscribers it changed so persisted copies can be refreshed.
            for stale_flow in self._stale_merge_targets:
                completed_events.append((FlowEventType.UPDATED, stale_flow))

            # Complete every still-active flow (building its layer stack first,
            # inside the lock, before the COMPLETE flip). Already-COMPLETE flows
            # are skipped by _complete_flow's guard, so they are never notified
            # twice.
            for flow in self._flows.values():
                ended = (self._last_activity_of(flow) if end_at_last_activity
                         else time.time())
                self._complete_flow(flow, ended, completed_events)

            self._clear_orphan_requests()
            errors_to_emit = self._drain_pending_errors()

        # Notify about removed flows (outside lock)
        for removed_flow in removed_flows:
            self._notify(FlowEventType.REMOVED, removed_flow)
        # Emit COMPLETED for flows this flush finalized (outside lock).
        for event_type, completed_flow in completed_events:
            self._notify(event_type, completed_flow)
        self._emit_errors(errors_to_emit)

    @staticmethod
    def _is_orphan_merge_candidate(flow: Flow) -> bool:
        """True when *flow* may take part in request/response orphan merging.

        Message-stream transports (MTProto cloud, Telegram Secret Chats) are
        excluded: their records are independent TL messages, not the two halves
        of one HTTP exchange, so folding a lone ``pong`` read into a later
        ``msgs_ack`` write would graft unrelated messages together (and move
        the chunks without the inner layer's parsed messages). Secret-Chat flows
        are additionally one flow per packet (``_emit_packet_flow``).
        """
        return (getattr(flow, "transport", "") or "") not in MESSAGE_TRANSPORTS

    def _merge_remaining_orphans(self) -> list[Flow]:
        """Pair leftover request-only and response-only flows. Under lock.

        Two passes, most-precise first:

        1. By ``connection_id`` — a request half and its response half of one
           logical exchange share the (endpoint-derived) connection key, so this
           pairs the two halves of the SAME connection unambiguously.
        2. By destination ``host:port``, but ONLY when exactly one request-only
           flow remains for that destination. This keeps the original
           single-connection-per-host heuristic (a request and response that
           ended up with different connection keys still merge) while refusing to
           graft a response onto an arbitrary request when several concurrent
           connections to the same host compete — the old "first request wins"
           behaviour silently mis-attributed the response to the wrong exchange
           and left the true owner response-less.

        Returns list of removed Flow objects (for REMOVED notifications).
        """
        request_only: list[str] = []
        response_only: list[str] = []
        for fid, flow in self._flows.items():
            if not self._is_orphan_merge_candidate(flow):
                continue
            if flow.request is not None and flow.response is None:
                request_only.append(fid)
            elif flow.response is not None and flow.request is None:
                response_only.append(fid)

        removed: list[Flow] = []
        self._stale_merge_targets = []
        if not request_only or not response_only:
            return removed

        # Request-only flows still available to absorb a response, consumed as
        # they are matched so one request is never claimed by two responses.
        avail_req: set[str] = set(request_only)

        def _merge(resp_fid: str, req_fid: str) -> bool:
            req_flow = self._flows.get(req_fid)
            resp_flow = self._flows.get(resp_fid)
            if not req_flow or not resp_flow:
                return False
            if abs(resp_flow.started - req_flow.started) > IDLE_THRESHOLD:
                return False
            if req_flow.state == FlowState.COMPLETE:
                # Already persisted/notified: its record is now stale.
                self._stale_merge_targets.append(req_flow)
            req_flow.response = resp_flow.response
            req_flow.chunks.extend(resp_flow.chunks)
            req_flow._total_bytes += resp_flow._total_bytes
            self._merge_retained_bytes(req_fid, resp_fid)
            req_flow.truncated = req_flow.truncated or resp_flow.truncated
            if resp_flow.ended > req_flow.ended:
                req_flow.ended = resp_flow.ended
            del self._flows[resp_fid]
            self._unindex_flow(resp_flow)
            removed.append(resp_flow)
            avail_req.discard(req_fid)
            return True

        # Pass 1: exact pairing by connection_id (same-connection halves).
        req_by_conn: dict[str, list[str]] = {}
        for fid in request_only:
            f = self._flows.get(fid)
            if f is not None:
                req_by_conn.setdefault(f.connection_id, []).append(fid)
        unmatched_resp: list[str] = []
        for resp_fid in response_only:
            resp_flow = self._flows.get(resp_fid)
            if resp_flow is None:
                continue
            candidates = [r for r in req_by_conn.get(resp_flow.connection_id, ())
                          if r in avail_req]
            if not (candidates and _merge(resp_fid, candidates[0])):
                unmatched_resp.append(resp_fid)

        # Pass 2: dst-keyed fallback, only when unambiguous (one candidate).
        for resp_fid in unmatched_resp:
            resp_flow = self._flows.get(resp_fid)
            if resp_flow is None:
                continue
            dst_key = f"{resp_flow.dst_addr}:{resp_flow.dst_port}"
            matches = []
            for r in avail_req:
                rf = self._flows.get(r)
                if rf is not None and f"{rf.dst_addr}:{rf.dst_port}" == dst_key:
                    matches.append(r)
            if len(matches) == 1:  # 0 = nothing; >1 = ambiguous, refuse to guess
                _merge(resp_fid, matches[0])

        return removed

    def _finalize_connection(self, conn: '_ConnectionState', ended: float,
                              pending: list) -> None:
        """Flush parser and mark the active flow as complete. Must be called under lock."""
        self._complete_quic_stream_flows(conn, ended, pending)
        # Commit parser for connections still in the buffering phase
        if conn.parser is None and conn.pending_chunks:
            self._commit_pending(conn)

        if conn.parser:
            self._flush_parser_to_flow(conn, pending)
        if conn.active_flow_id and conn.active_flow_id in self._flows:
            self._complete_flow(self._flows[conn.active_flow_id], ended, pending)
        self._complete_h2_side_flows(conn, ended, pending)

        # Clean up H2 stream index entries for this connection
        stale_streams = [key for key in self._h2_stream_flows
                         if key[0] == conn.conn_id]
        for key in stale_streams:
            del self._h2_stream_flows[key]

        # Drop the cached TLS metadata for this connection to avoid unbounded
        # growth across many short-lived connections.
        self._session_tls.pop(conn.conn_id, None)

    def _periodic_sweep(self, pending: list) -> None:
        """Periodic maintenance: clean stale indices, idle connections, body caches.

        Must be called under lock.
        """
        now = self._now()

        # 1. Sweep orphan requests: prune entries older than IDLE_THRESHOLD
        #    or referencing flows that no longer exist
        for key, candidates in list(self._orphan_requests.items()):
            valid = [(ts, fid) for ts, fid in candidates
                     if (now - ts) <= IDLE_THRESHOLD and fid in self._flows]
            self._replace_orphan_candidates(key, valid)

        # 2. Sweep H2 stream index: remove entries for finalized connections
        #    or completed/missing flows
        stale_streams = [
            key for key, fid in self._h2_stream_flows.items()
            if key[0] not in self._connections
            or fid not in self._flows
            or self._flows[fid].state == FlowState.COMPLETE
        ]
        for key in stale_streams:
            del self._h2_stream_flows[key]

        # 3. Sweep idle connections: finalize connections with no activity
        #    for 2x IDLE_THRESHOLD (covers connections that never get SESSION_ENDED)
        idle_threshold = 2 * IDLE_THRESHOLD
        idle_conn_ids = [
            cid for cid, conn in self._connections.items()
            if conn.last_activity > 0 and (now - conn.last_activity) > idle_threshold
            and not self._is_exempt_from_idle(conn)
        ]
        for conn_id in idle_conn_ids:
            conn = self._connections[conn_id]
            self._finalize_connection(conn, conn.last_activity, pending)
            del self._connections[conn_id]

        # 4. Invalidate body caches on completed flows (reconstructed on demand)
        for flow in self._flows.values():
            if flow.state == FlowState.COMPLETE and flow._body_cache:
                flow._body_cache.clear()

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

    def _filter_control_frames(self, results: list) -> list:
        """Remove control-frame results when show_control_frames is disabled."""
        if self._show_control_frames:
            return results
        return [r for r in results if not r.is_control_frame]

    def _append_chunk(self, flow: Flow, chunk: Optional[FlowChunk]) -> None:
        """Append a chunk to a flow and update the cached byte total.

        The byte total always grows; the chunk itself is retained only while
        the flow stays within :data:`MAX_FLOW_CHUNK_BYTES` (see
        :meth:`_retain_chunk_bytes`). ``None`` (no bytes for this flow, e.g.
        an HTTP/2 result whose frames were already attached) is a no-op.
        """
        if chunk is None:
            return
        flow._total_bytes += len(chunk.data)
        if not self._retain_chunk_bytes(flow, len(chunk.data)):
            return
        flow.chunks.append(chunk)
        flow.invalidate_body_cache()

    def _retain_chunk_bytes(self, flow: Flow, size: int) -> bool:
        """Account *size* retained bytes to *flow*; ``False`` once over the cap.

        The first refusal marks the flow truncated (``flow.truncated`` and
        :meth:`is_flow_truncated`) and logs a warning; later chunks of that flow are dropped silently.
        """
        flow_id = flow.flow_id
        if flow_id in self._truncated_flow_ids:
            return False
        retained = self._flow_retained_bytes.get(flow_id, 0) + size
        if retained > MAX_FLOW_CHUNK_BYTES:
            self._truncated_flow_ids.add(flow_id)
            flow.truncated = True
            logger.warning(
                "Flow %s exceeded %d retained bytes; further payload is counted "
                "but not retained", flow_id, MAX_FLOW_CHUNK_BYTES)
            return False
        self._flow_retained_bytes[flow_id] = retained
        return True

    def _merge_retained_bytes(self, into_flow_id: str, from_flow_id: str) -> None:
        """Fold *from_flow_id*'s retained-byte/truncation state into *into_flow_id*."""
        moved = self._flow_retained_bytes.pop(from_flow_id, 0)
        if moved:
            self._flow_retained_bytes[into_flow_id] = (
                self._flow_retained_bytes.get(into_flow_id, 0) + moved)
        if from_flow_id in self._truncated_flow_ids:
            self._truncated_flow_ids.discard(from_flow_id)
            self._truncated_flow_ids.add(into_flow_id)

    def _attach_response(self, flow: Flow, result, chunk: FlowChunk,
                          timestamp: float, pending: list) -> None:
        """Attach a response ParseResult to a flow and optionally complete it.

        Instance method (rather than static) so the COMPLETE transition that an
        ``is_complete`` response triggers here — a flow-finalization site
        distinct from flush()/`_finalize_connection`, and the common case for
        Content-Length HTTP/1 responses — runs through the shared
        :meth:`_complete_flow`. That builds the layer stack before the flip AND
        enqueues the COMPLETED event onto *pending* (emitted after the lock by
        on_data), so these flows are persisted/analyzed like any other; before
        this they flipped to COMPLETE but were only ever notified UPDATED, so
        the TapWriter (which writes on COMPLETED) silently dropped them.
        """
        flow.response = result
        self._append_chunk(flow, chunk)
        if result.is_complete:
            self._complete_flow(flow, timestamp, pending)

    def _commit_pending(self, conn: '_ConnectionState') -> None:
        """Commit a parser and feed pending chunks for a buffering-phase connection.

        Called by flush() and _finalize_connection() when a connection still
        has uncommitted pending_chunks.  Must be called under lock.
        """
        try:
            # Only concatenate enough bytes for detection (parsers only check first bytes)
            prefix = bytearray()
            for c in conn.pending_chunks:
                prefix += c.data
                if len(prefix) >= PARSER_DETECTION_BUFFER_SIZE:
                    break
            conn.parser = self._wrap_parser(
                self._detect_parser(conn, bytes(prefix)), conn)
        except Exception:
            conn.parser = self._wrap_parser(HexdumpParser(), conn)

        flow = None
        if conn.active_flow_id and conn.active_flow_id in self._flows:
            flow = self._flows[conn.active_flow_id]

        for pending_chunk in conn.pending_chunks:
            # SafeParserAdapter.feed never raises, but defensive belt+braces
            # against a future non-adapted parser sneaking in here.
            try:
                results = conn.parser.feed(pending_chunk.data, pending_chunk.direction)
            except Exception:
                logger.debug("parser.feed in _commit_pending raised", exc_info=True)
                continue
            if flow is not None:
                for result in results:
                    if result.is_request and flow.request is None:
                        flow.request = result
                    elif not result.is_request and flow.response is None:
                        flow.response = result

        conn.pending_chunks = []
        conn.pending_bytes = 0

    def _flush_parser_to_flow(self, conn: '_ConnectionState',
                              pending: Optional[list] = None) -> None:
        """Flush the committed parser and assign results to the active flow.

        *pending* collects events of flows opened for HTTP/2 leftovers.
        Must be called under lock.
        """
        try:
            results = conn.parser.flush()
        except Exception:
            return
        self._attach_h2_leftovers(conn, pending)
        if not conn.active_flow_id or conn.active_flow_id not in self._flows:
            return
        flow = self._flows[conn.active_flow_id]
        for result in results:
            if result.is_request:
                if flow.request is None:
                    flow.request = result
            else:
                if flow.response is None:
                    flow.response = result

    def _propagate_trailing_data(self, parser, flow: Flow) -> None:
        """Move trailing data from a parser instance to a Flow. Must be called under lock.

        Instance method (rather than static) so the trailing data is also routed
        into the layer model: a "trailing" layer MIRRORS ``flow.trailing_parse``
        via parsed_field (the trailing_* fields remain the source of truth and
        the trailing bytes are NOT re-stored — they already serialize via
        meta["trailing_*"], so the layer carries no owned data).
        """
        td = getattr(parser, 'trailing_data', None)
        if td is None:
            return
        protocol = getattr(parser, 'trailing_protocol', '')
        sub_parse = getattr(parser, 'trailing_sub_parse', None)
        parser.trailing_data = None
        if getattr(parser, 'trailing_direction', '') == "read":
            self._store_response_trailing(flow, td, protocol, sub_parse)
            return
        flow.trailing_bytes = td
        flow.trailing_protocol = protocol
        flow.trailing_parse = sub_parse
        if flow.trailing_parse is not None:
            self._pipeline.push_layer(
                flow, protocol="trailing", source="trailing",
                parsed_field="trailing_parse")

    def _store_response_trailing(self, flow: Flow, data: bytes, protocol: str,
                                 sub_parse) -> None:
        """Keep read-direction leftovers in the response_* slot (never the request's)."""
        flow.response_trailing_bytes = data
        flow.response_trailing_protocol = protocol
        flow.response_trailing_parse = sub_parse
        if sub_parse is not None:
            self._pipeline.push_layer(
                flow, protocol="response_trailing", source="response_trailing",
                parsed_field="response_trailing_parse")

    def _check_parser_upgrade(self, conn: '_ConnectionState') -> None:
        """Swap the parser if the current one signals a protocol upgrade (e.g., 101 → WebSocket)."""
        upgrade = getattr(conn.parser, 'upgrade_protocol', '')
        if not upgrade:
            return
        # Save trailing bytes from the old parser before swapping
        old_trailing = getattr(conn.parser, 'trailing_data', None)
        from friTap.parsers.websocket import WebSocketParser
        if "websocket" in upgrade.lower():
            conn.parser = self._wrap_parser(WebSocketParser(), conn)
        # Feed trailing bytes from the old parser into the new one. Use a
        # narrow local try/except rather than relying on SafeParserAdapter
        # so a malformed trailing frame on a freshly-installed parser logs
        # but does NOT mark the parser as failed for the rest of the flow.
        if old_trailing:
            try:
                conn.parser.feed(old_trailing, "read")
            except Exception:
                logger.warning(
                    "Trailing-data feed after upgrade raised", exc_info=True
                )

    def _detect_parser(self, conn: '_ConnectionState', data: bytes) -> BaseParser:
        """Sniff *data* for *conn*'s transport (HTTP/3 vetoed on unframeable bytes)."""
        detected = get_default_registry().detect(data, transport=conn.transport)
        return self._screen_h3_detection(detected, data, conn.transport)

    def _try_parser_upgrade(self, conn: '_ConnectionState', data: bytes) -> bool:
        """Attempt to upgrade from HexdumpParser if data starts a known protocol.

        Returns True if parser was upgraded, False otherwise.
        Must be called under lock.
        """
        if not isinstance(unwrap_parser(conn.parser), HexdumpParser):
            return False
        if self._is_pinned_transport(conn):
            return False
        try:
            detected = self._detect_parser(conn, data)
        except Exception:
            return False
        if isinstance(detected, HexdumpParser):
            return False
        conn.parser = self._wrap_parser(detected, conn)
        return True

    def _get_direction(self, function: str) -> str:
        """Determine direction from function name."""
        return direction_for_function(function)

    def _create_or_update_flow(self, conn, chunk, result, event, pending):
        """Create new flow or update existing based on parse result."""
        if conn.transport in MESSAGE_TRANSPORTS:
            return self._emit_packet_flow(conn, chunk, result, event, pending)
        stream_id = getattr(result, 'stream_id', 0)

        if result.is_request:
            # Reuse the active flow instead of creating a new one when either:
            #   * it's a ghost (no request yet, e.g. HTTP/2 SETTINGS preamble)
            #     and the new request is not HTTP/2-multiplexed (stream_id == 0),
            #   * or the result is an "unknown" protocol continuation that
            #     should stay grouped with the existing flow.
            # HTTP/2 HEADERS on stream > 0 fall through to the stream-keyed
            # path below to preserve multiplexing.
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
            # HTTP/2: update existing flow for this stream if headers already emitted
            if stream_id > 0:
                existing_fid = self._h2_stream_flows.get((conn.conn_id, stream_id))
                if existing_fid and existing_fid in self._flows:
                    flow = self._flows[existing_fid]
                    flow.request = result
                    self._append_chunk(flow, chunk)
                    return flow
            # New request = new flow
            flow = self._make_flow(conn, event)
            flow.request = result
            self._append_chunk(flow, chunk)
            conn.active_flow_id = flow.flow_id
            # Index by HTTP/2 stream_id for response correlation
            if stream_id > 0:
                self._h2_stream_flows[(conn.conn_id, stream_id)] = flow.flow_id
            # Register in orphan index for server-keyed matching
            self._register_orphan_request(
                self._orphan_key(event, chunk.direction),
                event.timestamp, flow.flow_id)
            pending.append((FlowEventType.CREATED, flow))
            return flow
        else:
            # Response — try stream-level match first (HTTP/2 multiplexing)
            if stream_id > 0:
                stream_key = (conn.conn_id, stream_id)
                matched_flow_id = self._h2_stream_flows.get(stream_key)
                if matched_flow_id and matched_flow_id in self._flows:
                    self._attach_response(self._flows[matched_flow_id], result, chunk, event.timestamp, pending)
                    # Remove stream mapping when response is complete
                    if result.is_complete:
                        self._h2_stream_flows.pop(stream_key, None)
                    return self._flows[matched_flow_id]

            # Fall back to the active flow on this connection — but ONLY while it
            # is still ACTIVE. Once a flow has COMPLETED (e.g. a Content-Length
            # response already finalized it), conn.active_flow_id still points at
            # it; attaching a second response there would overwrite flow.response
            # and be silently swallowed (_complete_flow no-ops on a non-ACTIVE
            # flow, so no COMPLETED fires and the TapWriter never sees it). Mirror
            # the request branch's `state == FlowState.ACTIVE` guard and let a
            # post-completion response fall through to orphan-match / new-flow.
            active = None
            if conn.active_flow_id and conn.active_flow_id in self._flows:
                candidate = self._flows[conn.active_flow_id]
                if candidate.state == FlowState.ACTIVE:
                    active = candidate
            if active is not None:
                self._attach_response(active, result, chunk, event.timestamp, pending)
                return active
            else:
                # Response without an active request flow — try orphan index match
                matched = self._match_orphan_request(event, chunk.direction)
                if matched:
                    self._attach_response(matched, result, chunk, event.timestamp, pending)
                    return matched
                # No match — create orphan flow. Enqueue CREATED BEFORE
                # _attach_response: a self-contained complete response makes
                # _attach_response -> _complete_flow enqueue COMPLETED, and
                # subscribers (drained FIFO) must never see COMPLETED for a
                # flow_id whose CREATED they have not seen yet.
                flow = self._make_flow(conn, event)
                conn.active_flow_id = flow.flow_id
                pending.append((FlowEventType.CREATED, flow))
                self._attach_response(flow, result, chunk, event.timestamp, pending)
                return flow

    def _emit_packet_flow(self, conn, chunk, result, event, pending) -> Flow:
        """Emit ONE complete flow for one decrypted message-transport packet.

        MTProto cloud records and Secret-Chat messages are independent
        packets, so each becomes its own row (forensic, Wireshark-like): the
        flow keeps the event's REAL src/dst, a write lands in ``request`` and
        a read in ``response``, it holds exactly this packet's chunk, and it
        completes immediately (CREATED then COMPLETED). *result* may be None
        when the pinned parser produced nothing. Must be called under lock.
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

    @staticmethod
    def _oriented_endpoints(event, direction: str = "") -> tuple:
        """``(src_addr, src_port, dst_addr, dst_port)`` oriented device -> server.

        A received (read) packet travels server -> device, so its src/dst are
        swapped; a sent (write) packet is already device -> server. *direction*
        overrides ``event.direction`` (e.g. the function-name fallback).
        """
        if (direction or getattr(event, 'direction', '')) == "read":
            return (event.dst_addr, event.dst_port,
                    event.src_addr, event.src_port)
        return (event.src_addr, event.src_port,
                event.dst_addr, event.dst_port)

    @classmethod
    def _orphan_key(cls, event, direction: str = "") -> str:
        """``host:port`` of the REMOTE (server) endpoint of *event*.

        Requests and responses are keyed by the server they talk to. A read
        travels server -> device, so its raw ``dst`` is the device's own
        address; keying on it would let one UDP socket shared by several QUIC
        servers attach server A's datagram to server B's leftover request.
        """
        _src_addr, _src_port, addr, port = cls._oriented_endpoints(event, direction)
        return f"{addr}:{port}"

    def _match_orphan_request(self, event, direction: str = "") -> Optional[Flow]:
        """Find a recent request-only flow to the same server endpoint."""
        key = self._orphan_key(event, direction)
        candidates = self._orphan_requests.get(key)
        if not candidates:
            return None
        now = event.timestamp
        # Prune stale entries (always, not only when matched)
        valid = [(ts, fid) for ts, fid in candidates
                 if (now - ts) <= IDLE_THRESHOLD and fid in self._flows]
        self._replace_orphan_candidates(key, valid)
        if not valid:
            return None
        # Pick the closest in time
        _, flow_id = min(valid, key=lambda x: abs(now - x[0]))
        flow = self._flows.get(flow_id)
        if flow and flow.request is not None and flow.response is None:
            self._replace_orphan_candidates(
                key, [(ts, fid) for ts, fid in valid if fid != flow_id])
            return flow
        return None

    # ------------------------------------------------------------------
    # Bounded state (LRU caps)
    # ------------------------------------------------------------------

    def _register_orphan_request(self, key: str, timestamp: float,
                                 flow_id: str) -> None:
        """Index a request-only flow under its server *key*. Under lock."""
        self._orphan_requests.setdefault(key, []).append((timestamp, flow_id))
        self._orphan_requests.move_to_end(key)
        self._orphan_request_total += 1
        while self._orphan_request_total > MAX_ORPHAN_REQUESTS:
            self._evict_oldest_orphan_request()

    def _evict_oldest_orphan_request(self) -> None:
        """Drop the oldest entry of the least-recently-used key. Under lock.

        Only the index entry goes; the request flow itself stays on its
        connection and is still paired by the flush-time orphan merge.
        """
        key, candidates = next(iter(self._orphan_requests.items()))
        self._warn_cap_once("orphan requests", MAX_ORPHAN_REQUESTS)
        self._replace_orphan_candidates(key, candidates[1:])

    def _replace_orphan_candidates(self, key: str, candidates: list) -> None:
        """Set *key*'s orphan entries (dropping an empty key), keeping the total."""
        old = self._orphan_requests.get(key)
        self._orphan_request_total += len(candidates) - (len(old) if old else 0)
        if candidates:
            if old is None:
                self._orphan_requests[key] = candidates
            else:
                old[:] = candidates
        elif old is not None:
            del self._orphan_requests[key]

    def _clear_orphan_requests(self) -> None:
        """Drop the whole orphan index. Under lock."""
        self._orphan_requests.clear()
        self._orphan_request_total = 0

    def _touch_connection(self, conn_id: str, event, pending: list) -> '_ConnectionState':
        """Return *conn_id*'s state (created if new), marked most recently used.

        Creating a connection past MAX_TRACKED_CONNECTIONS evicts the least
        recently used one. Under lock.
        """
        conn = self._connections.get(conn_id)
        if conn is not None:
            self._connections.move_to_end(conn_id)
            return conn
        conn = self._new_connection_state(conn_id, event)
        self._connections[conn_id] = conn
        while len(self._connections) > MAX_TRACKED_CONNECTIONS:
            self._evict_oldest_connection(pending)
        return conn

    def _evict_oldest_connection(self, pending: list) -> None:
        """Finalize and forget the least recently used connection. Under lock.

        Mirrors the idle sweep: the connection's flows are completed (and
        their COMPLETED events queued on *pending*) before its state goes.
        """
        _conn_id, conn = self._connections.popitem(last=False)
        self._warn_cap_once("connections", MAX_TRACKED_CONNECTIONS)
        self._finalize_connection(conn, conn.last_activity or self._now(), pending)

    def _warn_cap_once(self, what: str, cap: int) -> None:
        """Log one warning the first time the *what* cap trips."""
        if what in self._caps_warned:
            return
        self._caps_warned.add(what)
        logger.warning(
            "Flow collector tracks more than %d %s; evicting the least "
            "recently used (possible connection-id flood)", cap, what)

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
        """Allocate the next monotonic flow sequence for *conn_id*. Under lock.

        Single id source for both :meth:`_make_flow` and
        :meth:`add_synthetic_flow`. Monotonic and collector-owned (see
        ``self._flow_seq``) so it never restarts at 0 on an idle-reset and the
        two minting paths never collide on the shared ``conn_id:N`` namespace.
        """
        seq = self._flow_seq.get(conn_id, 0)
        self._flow_seq[conn_id] = seq + 1
        return seq

    def _make_flow(self, conn, event, endpoints: Optional[tuple] = None) -> Flow:
        """Create and index a new Flow for *event*.

        *endpoints* optionally overrides the event's ``(src_addr, src_port,
        dst_addr, dst_port)`` orientation (see :meth:`_oriented_endpoints`).
        """
        src_addr, src_port, dst_addr, dst_port = endpoints or (
            event.src_addr, event.src_port, event.dst_addr, event.dst_port)
        flow_id = f"{conn.conn_id}:{self._next_flow_sequence(conn.conn_id)}"
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
        self._flows[flow_id] = flow
        self._index_flow(flow)
        return flow

    def _index_flow(self, flow: Flow) -> None:
        """Record *flow* under its connection_id. Must run under the lock, at
        every site that adds to ``_flows`` (``_make_flow``, ``add_synthetic_flow``)
        so ``_flow_index`` stays a faithful mirror of ``_flows``."""
        self._flow_index.setdefault(flow.connection_id, []).append(flow.flow_id)

    def _unindex_flow(self, flow: Flow) -> None:
        """Drop *flow* from the per-connection index. Must run under the lock, at
        every site that removes from ``_flows`` (the orphan-merge in
        :meth:`_merge_remaining_orphans` and :meth:`_release_flow`)."""
        ids = self._flow_index.get(flow.connection_id)
        if not ids:
            return
        try:
            ids.remove(flow.flow_id)
        except ValueError:
            pass
        if not ids:
            del self._flow_index[flow.connection_id]

    # Transports whose layer carries a ``library`` field (TlsLayer/QuicLayer).
    _LIBRARY_TRANSPORTS = ("tls", "quic")
    def _stamp_detected_library(self, flow: Flow, event) -> None:
        """Stamp the producing library onto the flow's transport layer.

        Prefers the record's own ``library`` (the module that produced it);
        falls back to the last library announced for the flow's own transport
        (no cross-family fallback). Only TLS and QUIC flows get it, on
        ``flow.tls`` / ``flow.quic`` respectively. Attribute access
        auto-creates the layer, so stamping any other transport (MTProto,
        Telegram E2E, ...) would attach a stray layer and make the flow match
        the "tls"/"quic" filter.
        """
        if flow.transport not in self._LIBRARY_TRANSPORTS:
            return
        library = (getattr(event, 'library', '') or ''
                   or self._detected_libraries.get(flow.transport, ''))
        if not library:
            return
        layer = getattr(flow, flow.transport)
        if not layer.library:
            layer.library = library

    def _stamp_metadata(self, flow: Flow, event) -> None:
        """Stamp cheaply-available metadata onto a freshly-created Flow.

        Must be called under lock. Fills the detected TLS library, process /
        package names from the capture target, the originating hook function,
        and defaults local/remote endpoints from the event's src/dst.
        """
        # Transport/encryption protocol ("tls" or "quic"), the only transport
        # hint the Flow stores. Mirrors the value on_data folds into the
        # connection key. Set FIRST so the layer pipeline picks TlsLayer vs
        # QuicLayer and the metadata backfill below targets the right layer.
        flow.transport = getattr(event, 'protocol', 'tls') or 'tls'
        self._stamp_detected_library(flow, event)
        # Backfill handshake metadata cached from an earlier SESSION_STARTED/
        # RESUMED for this connection (handshake arrives before the first data
        # event, so _stamp_tls_metadata found no flow to stamp at that time).
        # Transport-aware: stamps flow.tls or flow.quic per flow.transport.
        # Only fills fields that are still empty so we never clobber later data.
        cached_meta = self._session_tls.get(flow.connection_id)
        if cached_meta:
            self._apply_session_metadata(flow, cached_meta)
        flow.process_name = self._process_name
        flow.package_name = self._package_name
        # Hook origin: prefer the first chunk's function, fall back to event.
        hook = ""
        if flow.chunks:
            hook = flow.chunks[0].function
        if not hook:
            hook = getattr(event, 'function', '') or ''
        flow.hook_function = hook
        # Default local/remote endpoints, orientation-aware for per-packet
        # message-transport flows (see _local_remote_endpoints).
        (flow.local_addr, flow.local_port,
         flow.remote_addr, flow.remote_port) = self._local_remote_endpoints(flow, event)

    def _local_remote_endpoints(self, flow: Flow, event) -> tuple:
        """``(local_addr, local_port, remote_addr, remote_port)`` for *flow*.

        Message-transport flows keep the packet's real src/dst, so a received
        (read) packet travels remote -> local: local is its dst. Every other
        flow is oriented local -> remote already (src = local).
        """
        if flow.transport in MESSAGE_TRANSPORTS and self._event_direction(event) == "read":
            return (flow.dst_addr, flow.dst_port, flow.src_addr, flow.src_port)
        return (flow.src_addr, flow.src_port, flow.dst_addr, flow.dst_port)

    def _event_direction(self, event) -> str:
        """The event's direction, falling back to the hook-function heuristic."""
        return (getattr(event, 'direction', '')
                or self._get_direction(getattr(event, 'function', '') or ''))

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

        Every lookup of a flow id (active flow, HTTP/2 stream map, orphan
        index) is guarded by ``in self._flows``/``.get``, so stale ids left in
        those maps are simply skipped.
        """
        with self._lock:
            if self._flows.get(flow.flow_id) is not flow:
                return
            del self._flows[flow.flow_id]
            self._unindex_flow(flow)
            self._flow_retained_bytes.pop(flow.flow_id, None)
            self._truncated_flow_ids.discard(flow.flow_id)


class _ConnectionState:
    """Internal per-connection tracking."""
    def __init__(self, conn_id: str, transport: str = ""):
        self.conn_id = conn_id
        # Flow.transport of this connection's events (``tls``/``quic``/
        # ``mtproto``/``telegram_e2e``); selects a registry-pinned parser.
        self.transport = transport
        self.parser = None  # BaseParser instance
        self.active_flow_id: Optional[str] = None
        # Flow-id sequencing lives on FlowCollector._flow_seq (keyed by conn_id),
        # not here: a per-connection counter resets to 0 when this state object is
        # rebuilt on idle-reset, which would re-mint an existing flow id and
        # overwrite a completed flow. See FlowCollector._next_flow_sequence.
        self.last_activity: float = 0.0
        self.pending_chunks: list[FlowChunk] = []  # buffered before parser committed
        self.pending_bytes: int = 0  # total bytes in pending_chunks
        # detected_protocol stamp deferred until the committed parser
        # recognizes something (see FlowCollector._stamp_detected_protocol).
        self.protocol_stamp_pending: bool = False
        # Raw decrypted-TLS bytes per direction, accumulated only when live
        # Signal message decoding is enabled. The offline Signal pipeline needs
        # the full per-direction WebSocket/HTTP-2 byte stream (it does its own
        # de-framing), which the parser-oriented flow chunks do not preserve.
        self.signal_raw: dict[str, bytearray] = {"read": bytearray(), "write": bytearray()}
        # Directions whose signal_raw exceeded MAX_SIGNAL_RAW_BYTES (decoding off).
        self.signal_capped: set[str] = set()
        # Map a real (QUIC) stream id -> a dense, strictly-positive synthetic
        # id. The collector treats stream_id == 0 as "no stream / ghost", but
        # QUIC's first client bidi stream is legitimately 0, so we remap real
        # stream ids onto 1, 2, 3, ... Request and response for the same QUIC
        # stream share one synthetic id (and therefore one flow).
        self._qsid_map: dict[int, int] = {}
        self._qsid_next: int = 1
        # QUIC stream plumbing (see QuicStreamFlowMixin): the single HTTP/3
        # control flow, real stream id -> flow_id, and the newest stream event
        # (needed to create flows for chunks still buffered at finalize).
        self.h3_control_flow_id: Optional[str] = None
        self.quic_stream_flows: dict[int, str] = {}
        self.quic_last_event = None
        # HTTP/2 plumbing (see Http2StreamFlowMixin): stream id -> flow_id
        # routes (LRU, outlive the flow's completion), the newest control-frame
        # flow, and the newest record per direction (stamps flush leftovers).
        self.h2_stream_flows: OrderedDict[int, str] = OrderedDict()
        self.h2_control_flow_id: Optional[str] = None
        self.h2_last_chunk: dict[str, FlowChunk] = {}
        # Fresh flows opened for late stream payload (not the active flow);
        # completed with the control flow when the connection is finalized.
        self.h2_late_stream_flow_ids: list[str] = []

    def map_qsid(self, real_qsid: int) -> int:
        """Return the dense positive synthetic id for a real QUIC stream id."""
        sid = self._qsid_map.get(real_qsid)
        if sid is None:
            sid = self._qsid_next
            self._qsid_next += 1
            self._qsid_map[real_qsid] = sid
        return sid



    def can_parse(self, data: bytes) -> bool:
        return False
