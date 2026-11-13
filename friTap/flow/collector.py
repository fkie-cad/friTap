"""Thread-safe flow collector that groups SSL events into flows."""

import copy
import logging
import re
import threading
import time
import weakref
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Callable, NamedTuple, Optional

if TYPE_CHECKING:
    from .models import FlowSummary

from friTap.caller_stack_shapes import compact_caller_stack
from friTap.connection_index import ConnectionKeyAliases, resolve_connection_key
from friTap.constants import direction_for_function
from friTap.events import (
    ERROR_SEVERITY_WARNING,
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

from .attribution import (
    CHROMIUM_FAMILY_KINDS,
    SOURCE_NATIVE_STACK,
    chromium_internal_candidate,
    chromium_internal_host_update,
    direct_attribution,
    inherited_attribution,
    merge_attribution,
    module_basename,
    sdk_name,
    transport_attribution,
)
from .caller_stack_stash import CallerStackStash, StashedCallerStack
from .h2_flow import Http2StreamFlowMixin
from .layer_pipeline import MESSAGE_TRANSPORTS, LayerPipeline
from .models import Flow, FlowChunk, FlowEventType, FlowState
from .quic_flow import QuicStreamFlowMixin
from .request_context_join import (
    MATCH_SLACK_SECONDS,
    RequestContextStore,
    absolute_request_url,
    normalize_request_key,
)
from .synthetic_endpoint_upgrade import observed_endpoint_map, upgrade_flow_endpoints

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
# Bounds on flows waiting for a request context that arrives after them (oldest dropped first).
MAX_REQUEST_JOIN_KEYS = 1024
MAX_REQUEST_JOIN_FLOWS_PER_KEY = 16
# Cap on the module -> load-path map fed by LibraryDetectedEvent (the agent
# announces each TLS module once, but the names are target-controlled).
MAX_MODULE_PATHS = 256

# Decrypted-TL transports (Flow.transport values) whose parser is pinned by the
# registry instead of byte-sniffed; every event on them is exactly one packet.
_TRANSPORT_TELEGRAM_E2E = "telegram_e2e"


@dataclass(slots=True)
class _ConnectionAttribution:
    """What a live connection's originators resolved to (see
    ``FlowCollector._connection_attributions``).

    ``caller_stack`` is ``None`` until a caller stack is joined (a record may
    first be created by a per-request originator); ``sdk_names`` gathers the
    names of every originator seen, caller-stack and per-request alike.
    """

    sdk: Optional[dict] = None  # first caller stack's {sdk, vendor, category}
    caller_stack: Optional[dict] = None  # first joined compact caller stack
    sdk_names: set = field(default_factory=set)

    @property
    def mixed(self) -> bool:
        """True when the originators named more than one SDK."""
        return len(self.sdk_names) > 1

    def add_originator(self, sdk: Optional[dict]) -> None:
        """Note *sdk*'s name (an unnamed or missing SDK is ignored)."""
        name = sdk_name(sdk)
        if name is not None:
            self.sdk_names.add(name)


class _Publication(NamedTuple):
    """Staged under the lock by ``_stage_publication``, delivered by ``_publish``."""

    events: list
    request_records: list = []
    request_sink: Optional[Callable[[dict], object]] = None


class _PendingEvents:
    """A pending ``(event_type, flow)`` list plus the ids of its flows, so each
    flow gets at most one extra UPDATED."""

    __slots__ = ("events", "_ids")

    def __init__(self, events: list) -> None:
        self.events = events
        self._ids = {id(flow) for _, flow in events}

    def flows(self) -> list:
        """The distinct flows in *events*, in first-seen order."""
        return list({id(flow): flow for _, flow in self.events}.values())

    def add_updated(self, flow: Flow) -> None:
        if id(flow) not in self._ids:
            self.events.append((FlowEventType.UPDATED, flow))
            self._ids.add(id(flow))


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
        # conn_id -> the first flow sequence of the connection's CURRENT
        # lifetime, recorded whenever its state is created or rebuilt (new
        # connection, idle-reset, LRU-eviction or session end then reuse).
        # _flow_seq is monotonic per conn_id, so "first flow" (the direct-join
        # rule) and "a flow of this lifetime" (sibling fallback) compare against
        # this, not against sequence 0. Outlives the state (a late join may
        # target a finalized connection); only cleared in clear().
        self._lifetime_first_seq: dict[str, int] = {}
        # UPDATED events raised where no pending list is threaded (flow birth
        # inside _make_flow); drained into on_data's pending list. Under _lock.
        self._staged_updates: list = []
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
        # Pending SDK attributions from caller_stack agent messages (opt-in
        # --attribute-sdk) that arrived BEFORE their flow existed. Keyed by the
        # connection 5-tuple (an unordered-endpoint key; see _sdk_tuple_key) —
        # the agent's ssl_session_id is still null (=="0") at the first
        # SSL_read/SSL_write where the backtrace is captured, so the 5-tuple is
        # the stable join key; a real (non-"0") ssl_session_id is kept as a
        # secondary key. Each key maps to a FIFO queue of SDK dicts, drained one
        # per matching flow at birth by _stamp_metadata (mirroring _session_tls)
        # and CONSUMED on use so a later connection reusing the same 5-tuple does
        # not inherit a prior connection's SDK.
        # Also keyed by ("cr", client_random) -- the strongest key, tried first
        # -- and bounded: MAX_STASHED entries, STASH_TTL_SECONDS on self._now()
        # (see caller_stack_stash). Entries are StashedCallerStack, carrying the
        # SDK (or None for an unclassified stack) and the compact caller stack.
        self._sdk_pending: CallerStackStash = CallerStackStash()
        # client_random -> connection_id, set in _record_client_random and popped
        # in _finalize_connection: the O(1) first-choice caller_stack join.
        self._conn_by_client_random: dict[str, str] = {}
        # connection_id -> first SDK / caller stack, so flows born after the join inherit them,
        # even after a sibling was written and released (headless). Written only by
        # _remember_connection_attribution, popped in _finalize_connection.
        self._connection_attributions: dict[str, _ConnectionAttribution] = {}
        # Request-context join (--attribute-sdk); off until the first RequestContextEvent.
        self._request_join_enabled = False
        self._request_contexts = RequestContextStore(self._classify_request_frames)
        # request key -> [(flow first-request host time, flow_id)] of flows
        # still waiting for a context (bounded, oldest key dropped first).
        self._request_join_flows: OrderedDict = OrderedDict()
        # flow_id -> Flow already tried. Weak values: an entry dies with its flow, so a live
        # flow is never retried and cannot take a newer flow's context.
        self._request_join_attempted: weakref.WeakValueDictionary[str, Flow] = (
            weakref.WeakValueDictionary())
        # The chromium-internal bucket is skipped until a Chromium-family transport shows up.
        self._chromium_transport_seen = False
        # Finished contexts staged under the lock for the sink (see
        # set_request_context_sink), emitted after the lock is released.
        self._finished_request_contexts: list = []
        self._request_context_sink: Optional[Callable[[dict], object]] = None
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
        # Module basename -> load path from LibraryDetectedEvent, oldest first,
        # capped at MAX_MODULE_PATHS. Lets the transport classifier see the
        # path (e.g. a Play-services Cronet) for a flow's producing module.
        self._module_paths: OrderedDict[str, str] = OrderedDict()
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
        ``quic.library``). This is only a FALLBACK: data events from the agent's
        plaintext hooks carry the producing module as ``library`` (TCP-TLS and
        QUIC alike), and ``_stamp_detected_library`` prefers it. The last
        announced library is used only for records without one (e.g. hooks
        that cannot name their module), where it may mislabel the flow.
        """
        library = getattr(event, 'library', '') or ''
        publication = self._record_module_path(event)
        if library:
            protocol = getattr(event, 'protocol', 'tls') or 'tls'
            with self._lock:
                self._detected_libraries[protocol] = library
        self._publish(publication)

    def _record_module_path(self, event) -> '_Publication':
        """Remember the event's load path under its module basename AND its
        ``library`` name (the name flows carry), case-insensitively, dropping
        the oldest entry past :data:`MAX_MODULE_PATHS`; then re-classify the
        present flows of those modules (their UPDATED events are returned for
        :meth:`_publish`). Takes the lock."""
        path = str(getattr(event, 'path', '') or '')
        if not path:
            return _Publication([])
        names = (str(getattr(event, 'module', '') or '') or path,
                 str(getattr(event, 'library', '') or ''))
        keys = {self._module_key(name) for name in names} - {""}
        if not keys:
            return _Publication([])
        with self._lock:
            for key in keys:
                self._module_paths.pop(key, None)
                self._module_paths[key] = path
            while len(self._module_paths) > MAX_MODULE_PATHS:
                self._module_paths.popitem(last=False)
            pending: list = []
            self._reclassify_transports(keys, pending)
            return self._stage_publication(pending)

    @staticmethod
    def _module_key(module: str) -> str:
        """The ``_module_paths`` key of *module*: its lower-cased basename."""
        return module_basename(module).lower()

    def _module_path_for(self, library: str) -> str:
        """The recorded load path of *library*, else ``""``. Under lock."""
        return self._module_paths.get(self._module_key(library), '')

    def _reclassify_transports(self, modules: Optional[set], pending: list) -> None:
        """Re-classify the present flows' ``attribution.transport`` with what
        the collector knows now (module paths, capture target): only flows whose
        transport module key is in *modules* (every stamped flow when ``None``).

        P2 stamps the transport once, at flow birth; a module path or capture
        target learned later can change its kind. Only the transport is replaced
        -- originator and source are kept; a ``native-stack`` claim's confidence,
        which derives from the kind, is recomputed via
        :func:`~friTap.flow.attribution.direct_attribution`. Queues one UPDATED
        per changed flow. Under lock.
        """
        for flow in self._flows.values():
            old = (flow.attribution or {}).get("transport")
            if not isinstance(old, dict):
                continue
            if modules is not None and self._module_key(old.get("module", "")) not in modules:
                continue
            layer = flow.layer(flow.transport)
            library = getattr(layer, 'library', '') if layer is not None else ''
            new = transport_attribution(library, self._module_path_for(library),
                                        self._process_name, self._package_name)
            if not new or new.get("kind") == old.get("kind"):
                continue
            attribution = dict(flow.attribution)
            attribution["transport"] = new
            self._note_transport(new)
            if attribution.get("source") == SOURCE_NATIVE_STACK and attribution.get("originator"):
                attribution["confidence"] = direct_attribution(
                    attribution["originator"], new.get("kind", ""))["confidence"]
            flow.attribution = attribution
            pending.append((FlowEventType.UPDATED, flow))

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

    def set_capture_target(self, target: str, process_name: Optional[str] = None) -> None:
        """Record the capture target and derive process/package names.

        The whole target string is used as ``process_name`` unless the caller
        passes the resolved *process_name* (e.g. the target was a numeric PID
        and the attach already knows the process' name). That name is ALSO used
        as ``package_name`` only when it has Android-package shape — dot-separated
        identifier segments (``com.example.app``) — and is not an IP address,
        a numeric PID, a path, or a known native/binary file (``.so``/``.exe``/
        etc.). This avoids misclassifying IPs, PIDs, paths and executables.

        Flows already stamped with a transport are re-classified with the new
        names (see :meth:`_reclassify_transports`).
        """
        target = target or ""
        name = process_name or target
        looks_like_package = self._looks_like_android_package(name)
        pending: list = []
        with self._lock:
            self._capture_target = target
            self._process_name = name
            self._package_name = name if looks_like_package else ""
            self._reclassify_transports(None, pending)
            publication = self._stage_publication(pending)
        self._publish(publication)

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

    def subscribe_to(self, event_bus) -> None:
        """Subscribe the ``on_*`` handlers to *event_bus*: the one wiring every capture
        front end (API, CLI, TUI, ``.tap`` output) shares."""
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
                self._connections[conn_id] = self._start_connection_lifetime(conn_id, event)
                conn = self._connections[conn_id]

            conn.last_activity = event.timestamp
            self._observe_event_time(event.timestamp)
            self._record_client_random(conn, event, pending)
            self._learn_real_endpoints(conn, event, pending)

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

            self._drain_staged_updates(pending)
            publication = self._stage_publication(pending)
            errors_to_emit = self._drain_pending_errors()

        self._publish(publication)
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

    def _start_connection_lifetime(self, conn_id: str, event) -> '_ConnectionState':
        """Fresh state for *conn_id*, recording the first flow sequence of this
        connection-state lifetime (see ``_lifetime_first_seq``). Under lock."""
        self._lifetime_first_seq[conn_id] = self._flow_seq.get(conn_id, 0)
        return self._new_connection_state(conn_id, event)

    def _is_current_lifetime_flow(self, flow: Flow) -> bool:
        """True unless *flow* was minted in an earlier lifetime of its
        connection id (sequence below the current lifetime's first). Under lock."""
        seq = self._flow_sequence_of(flow)
        return seq is None or seq >= self._lifetime_first_seq.get(flow.connection_id, 0)

    @staticmethod
    def _flow_sequence_of(flow: Flow) -> Optional[int]:
        """The sequence of *flow*'s id (see :meth:`_flow_id`), else ``None``."""
        prefix = f"{flow.connection_id}:"
        if not flow.flow_id.startswith(prefix):
            return None
        try:
            return int(flow.flow_id[len(prefix):])
        except ValueError:
            return None

    def _drain_staged_updates(self, pending: list) -> None:
        """Move ``_staged_updates`` onto *pending*, skipping flows already
        queued there. Under lock."""
        queued = {id(flow) for _, flow in pending}
        for event_type, flow in self._staged_updates:
            if id(flow) not in queued:
                pending.append((event_type, flow))
                queued.add(id(flow))
        self._staged_updates.clear()

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
            publication = self._stage_publication(pending)

        self._publish(publication)

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
            publication = self._stage_publication(pending)
            errors_to_emit = self._drain_pending_errors()

        self._publish(publication)
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
            for flow in self._connection_flows(conn_id):
                # Only notify flows that actually changed — a re-RESUMED
                # connection whose flows already carry metadata is a no-op.
                if self._apply_session_metadata(flow, meta):
                    pending.append((FlowEventType.UPDATED, flow))
            publication = self._stage_publication(pending)

        self._publish(publication)

    @staticmethod
    def _sdk_tuple_key(src_addr, src_port, dst_addr, dst_port):
        """Unordered connection-5-tuple key for SDK joins, or ``None``.

        Direction-insensitive: the caller_stack is captured at whichever of the
        first SSL_read/SSL_write runs first, so its src/dst orientation may be
        the reverse of the flow's stored one. Sorting the two endpoints makes
        both resolve to the SAME key. ``None`` when neither endpoint carries an
        address (nothing to join on).
        """
        src = (str(src_addr or ""), int(src_port or 0))
        dst = (str(dst_addr or ""), int(dst_port or 0))
        if not src[0] or not dst[0]:
            return None
        return (src, dst) if src <= dst else (dst, src)

    def _flow_tuple_key(self, flow):
        """The unordered 5-tuple key for *flow*'s stored endpoints (or ``None``)."""
        return self._sdk_tuple_key(
            flow.src_addr, flow.src_port, flow.dst_addr, flow.dst_port)

    @staticmethod
    def _real_sid(sid: str) -> bool:
        """True for a usable ssl_session_id: non-empty and not the null "0".

        At the first SSL_read/SSL_write ``SSL_get_session(ssl)`` is still null,
        so ``getSslSessionId`` returns ``0`` for every freshly-captured
        caller_stack; such ids match no specific connection and are ignored.
        """
        return bool(sid) and sid != "0"

    def on_sdk(self, event) -> None:
        """EventBus subscriber for CallerStackEvent -- attach the caller stack.

        Every caller stack is joined, classified or not: the compact stack is
        stored as ``flow.caller_stack`` and ``flow.sdk`` is set only when the
        router's classifier matched (``event.sdk``). The join tries, in order:

        1. the connection's **client_random** (``_conn_by_client_random``,
           filled by :meth:`_record_client_random`) -- exact and O(1). When
           no live connection has that client_random (its datalog follows, the
           connection was already finalized, or its datalogs never carry the
           cr) the stack falls through to the tuple/sid join -- only when it
           carries a tuple or real sid, so a cr-only stack never scans flows;
        2. the connection **4-tuple** (``_sdk_tuple_key``, direction-insensitive),
           skipping connections known by a different client_random;
        3. a **real** (non-"0") ``ssl_session_id``: at the first
           SSL_read/SSL_write ``SSL_get_session`` is still null, so most stacks
           carry ``"0"``.

        Tuple and session-id matches pick the earliest flow (insertion order)
        that has no caller stack yet, so OS fd/port reuse attributes each stack
        to a distinct connection. The stack then covers every flow of the
        target's connection and is remembered per connection, so flows born
        later (HTTP/2 streams) inherit it. Existing values are never
        overwritten. With no matching flow yet the stack is stashed under the
        first available key and drained at flow birth (or when the
        connection's client_random is learned). One stashed entry is indexed
        under every key the stack has (cr, tuple, sid); whichever drains first
        consumes it. No-op when the event carries
        none of the three keys. Updated flows are notified after the lock.
        """
        join_keys = self._caller_stack_join_keys(event)
        if join_keys is None:
            return
        pending = []
        with self._lock:
            attribution = StashedCallerStack(
                sdk=getattr(event, 'sdk', None) or None,
                caller_stack=compact_caller_stack(event),
                stashed_at=self._now(),
            )
            if not self._join_caller_stack(join_keys, attribution, pending):
                self._sdk_pending.put_under(
                    self._caller_stack_stash_keys(join_keys), attribution, self._now())
            publication = self._stage_publication(pending)
        self._publish(publication)

    def on_request_context(self, event) -> None:
        """EventBus subscriber for RequestContextEvent (``--attribute-sdk``).

        Folds the event into the store and retries flows waiting on each key it newly indexes
        (a context can arrive after its flow). Expiry runs in :meth:`_periodic_sweep`.
        """
        pending: list = []
        with self._lock:
            now = float(getattr(event, 'timestamp', 0.0) or self._now())
            if not self._request_join_enabled:
                self._enable_request_join(now)
            new_keys, finished = self._request_contexts.ingest(event, now)
            self._finished_request_contexts.extend(finished)
            updates = _PendingEvents(pending)
            for key in new_keys:
                self._join_waiting_flows(key, now, updates)
            publication = self._stage_publication(pending)
        self._publish(publication)

    def _enable_request_join(self, now: float) -> None:
        """Turn the join on and index the live flows that already carry a request. Under lock."""
        self._request_join_enabled = True
        cutoff = now - MATCH_SLACK_SECONDS
        updates = _PendingEvents([])
        for flow in self._flows.values():
            if getattr(flow, 'request', None) is None:
                continue
            if flow.started < cutoff:
                # Every context from now on starts too late to match this flow.
                self._mark_request_join_attempted(flow)
            else:
                self._try_request_join(flow, updates)

    def set_request_context_sink(self, sink: Optional[Callable[[dict], object]]) -> None:
        """Register *sink* (e.g. ``TapWriter.write_request_context``) for one ``.tap`` record
        per finished request context, called outside the lock."""
        with self._lock:
            self._request_context_sink = sink

    @staticmethod
    def _classify_request_frames(frames: list) -> Optional[dict]:
        """Classifier result for Java request frames. Lazy import: friTap.flow must not
        import friTap.analysis at module level."""
        key = tuple(frame for frame in frames if isinstance(frame, str) and frame)
        if not key:
            return None
        from friTap.analysis.attribution.sdk import classify_java_frames
        return classify_java_frames(key)

    def _stage_publication(self, pending: list, finish_contexts: bool = False) -> '_Publication':
        """Prepare *pending* for :meth:`_publish` and take the finished request contexts;
        *finish_contexts* finishes the live ones too (flush, clear). Under lock."""
        self._prepare_for_notify(pending)
        if finish_contexts:
            self._finished_request_contexts.extend(self._request_contexts.drain())
        finished, self._finished_request_contexts = self._finished_request_contexts, []
        sink = self._request_context_sink
        records = [context.to_record() for context in finished] if sink is not None else []
        return _Publication(pending, records, sink)

    def _publish(self, publication: '_Publication') -> None:
        """Notify the staged flow events, then hand the request records to the sink.
        Must NOT hold _lock."""
        for event_type, flow in publication.events:
            self._notify(event_type, flow)
        for record in publication.request_records:
            try:
                publication.request_sink(record)
            except Exception:  # noqa: BLE001 - a sink failure must not break capture
                logger.debug("request-context sink failed", exc_info=True)

    def _prepare_for_notify(self, pending: list) -> None:
        """Before notifying: request join first, then the chromium-internal bucket, so only
        flows still without an originator are bucketed. Under lock."""
        if not (self._request_join_enabled or self._chromium_transport_seen):
            return
        updates = _PendingEvents(pending)
        flows = updates.flows()
        if self._request_join_enabled:
            for flow in flows:
                self._try_request_join(flow, updates)
        if self._chromium_transport_seen:
            for flow in flows:
                self._bucket_chromium_internal(flow)

    def _try_request_join(self, flow: Flow, updates: _PendingEvents) -> None:
        """Match *flow* to a context once its request is keyable, else index it to wait;
        tried once per flow. Under lock."""
        if self._request_join_was_attempted(flow):
            return
        key = self._flow_request_key(flow)
        if key is None:
            if self._request_is_final(flow):
                self._mark_request_join_attempted(flow)
            return
        self._mark_request_join_attempted(flow)
        match = self._request_contexts.match(key, flow.started, flow.flow_id)
        if match is None:
            self._wait_for_request_context(key, flow)
        else:
            self._apply_request_match(flow, match, updates)

    def _flow_request_key(self, flow: Flow):
        """Request key of *flow* (authority: Host/``:authority``, else SNI; scheme https),
        else ``None``."""
        request = getattr(flow, 'request', None)
        if request is None or not getattr(request, 'is_request', True):
            return None
        method, target = getattr(request, 'method', ''), getattr(request, 'url', '')
        if not method or not target:
            return None
        return normalize_request_key(absolute_request_url(target, self._flow_host(flow)), method)

    @staticmethod
    def _request_is_final(flow: Flow) -> bool:
        """True once *flow*'s request can no longer change: it is present and
        complete, or the flow itself completed."""
        request = getattr(flow, 'request', None)
        if request is None:
            return False
        return flow.state == FlowState.COMPLETE or bool(getattr(request, 'is_complete', False))

    @staticmethod
    def _flow_sni(flow: Flow) -> str:
        """SNI of *flow*'s TLS layer, else of its QUIC layer, else ``""``."""
        for name in ("tls", "quic"):
            layer = flow.layer(name)
            sni = getattr(layer, 'sni', '') if layer is not None else ''
            if sni:
                return str(sni)
        return ''

    def _bucket_chromium_internal(self, flow: Flow) -> None:
        """Set the chromium-internal bucket if *flow* qualifies. Its event is already
        queued. Under lock."""
        # Candidate first: once any Chromium transport is seen this runs for every chunk.
        if not chromium_internal_candidate(flow):
            return
        update = chromium_internal_host_update(self._flow_host(flow))
        if update is not None:
            self._set_attribution(flow, update)

    def _flow_host(self, flow: Flow) -> str:
        """*flow*'s request Host/``:authority``, else its SNI, else ``""``."""
        request = getattr(flow, 'request', None)
        return str(getattr(request, 'host', '') or '') or self._flow_sni(flow)

    def _request_join_was_attempted(self, flow: Flow) -> bool:
        return self._request_join_attempted.get(flow.flow_id) is flow

    def _mark_request_join_attempted(self, flow: Flow) -> None:
        self._request_join_attempted[flow.flow_id] = flow

    def _wait_for_request_context(self, key, flow: Flow) -> None:
        """Index *flow* under *key* until a context arrives (bounded). Under lock."""
        waiting = self._request_join_flows.setdefault(key, [])
        waiting.append((flow.started, flow.flow_id))
        if len(waiting) > MAX_REQUEST_JOIN_FLOWS_PER_KEY:
            self._warn_cap_once("flows waiting per request key", MAX_REQUEST_JOIN_FLOWS_PER_KEY)
            del waiting[:-MAX_REQUEST_JOIN_FLOWS_PER_KEY]
        self._request_join_flows.move_to_end(key)
        while len(self._request_join_flows) > MAX_REQUEST_JOIN_KEYS:
            self._warn_cap_once("request keys waiting for a context", MAX_REQUEST_JOIN_KEYS)
            self._request_join_flows.popitem(last=False)

    def _join_waiting_flows(self, key, now: float, updates: _PendingEvents) -> None:
        """Retry the flows waiting under *key* (oldest first) after a context indexed it at
        host time *now*. Under lock."""
        waiting = self._request_join_flows.pop(key, None)
        if not waiting:
            return
        # A context indexed at *now* only matches flows that started at most
        # MATCH_SLACK_SECONDS before it; older ones can never match again.
        cutoff = now - MATCH_SLACK_SECONDS
        still_waiting = []
        for flow_time, flow_id in waiting:
            flow = self._flows.get(flow_id)
            if flow is None or flow_time < cutoff:
                continue  # released (already persisted) or too old to match
            match = self._request_contexts.match(key, flow_time, flow_id)
            if match is None:
                still_waiting.append((flow_time, flow_id))
            else:
                self._apply_request_match(flow, match, updates)
        if still_waiting:
            self._request_join_flows[key] = still_waiting

    def _apply_request_match(self, flow: Flow, match, updates: _PendingEvents) -> None:
        """Apply *match*'s claim to *flow* and note its originator on the connection,
        marking the connection's flows when it turns mixed. Under lock."""
        if match.claim is None:
            return
        if self._set_attribution(flow, match.claim):
            updates.add_updated(flow)
        conn_id = flow.connection_id
        was_mixed = self._connection_is_mixed(conn_id)
        self._remember_request_originator(conn_id, match.claim["originator"])
        if not self._connection_is_mixed(conn_id):
            return
        # Siblings are marked once, on the turn to mixed; later ones are marked at birth.
        flows = [] if was_mixed else self._current_lifetime_flows(conn_id)
        if not any(sibling is flow for sibling in flows):
            flows.append(flow)
        self._mark_mixed_flows(conn_id, flows, updates)

    def _remember_request_originator(self, conn_id, sdk: dict) -> None:
        """Record a per-request originator for the mixed check only; never sets
        ``sdk``/``caller_stack``. Under lock."""
        if conn_id not in self._connections:
            return
        self._connection_attributions.setdefault(
            conn_id, _ConnectionAttribution()).add_originator(sdk)

    def _caller_stack_join_keys(self, event):
        """``(client_random, tuple_key, session_id)`` of a CallerStackEvent, or
        ``None`` when it carries none of them (the session id is ``""`` unless
        real)."""
        client_random = str(getattr(event, 'client_random', '') or '')
        sid = str(getattr(event, 'ssl_session_id', '') or '')
        if not self._real_sid(sid):
            sid = ""
        tkey = self._sdk_tuple_key(
            getattr(event, 'src_addr', ''), getattr(event, 'src_port', 0),
            getattr(event, 'dst_addr', ''), getattr(event, 'dst_port', 0))
        if not client_random and tkey is None and not sid:
            return None
        return client_random, tkey, sid

    @staticmethod
    def _caller_stack_stash_keys(join_keys) -> list:
        """Every stash key of a stack: ``("cr", cr)``, the tuple, ``("sid", sid)``."""
        client_random, tkey, sid = join_keys
        keys = [("cr", client_random)] if client_random else []
        if tkey is not None:
            keys.append(tkey)
        if sid:
            keys.append(("sid", sid))
        return keys

    def _join_caller_stack(self, join_keys, attribution, pending: list) -> bool:
        """Attach *attribution* by client_random, then tuple, then session id.
        True when a connection took it. Must be called under ``self._lock``."""
        client_random, tkey, sid = join_keys
        if client_random and self._join_by_client_random(
                client_random, attribution, pending):
            return True
        if tkey is None and not sid:
            return False  # cr-only stack: no O(flows) scan
        target = self._first_unattributed_sdk_flow(tkey, sid, bool(sid), client_random)
        if target is None:
            return False
        self._attribute_connection(target.connection_id, attribution, pending, first=target)
        return True

    def _join_by_client_random(self, client_random: str, attribution,
                               pending: list) -> bool:
        """Attach *attribution* to the connection known by *client_random*.

        False (so the caller stashes it under ``("cr", cr)``) when no connection
        has taught that client_random yet: the agent sends a stack before the
        datalog carrying its cr, and :meth:`_record_client_random` drains the
        stash then. No O(flows) tuple scan for cr-carrying stacks. Under lock.
        """
        conn_id = self._conn_by_client_random.get(client_random)
        if conn_id is None:
            return False
        self._attribute_connection(conn_id, attribution, pending)
        return True

    def _connection_flows(self, conn_id):
        """Yield the present flows of connection *conn_id* in index order. Under lock."""
        for flow_id in self._flow_index.get(conn_id, ()):
            flow = self._flows.get(flow_id)
            if flow is not None:
                yield flow

    def _attribute_connection(self, conn_id, attribution, pending: list,
                              first: Optional[Flow] = None) -> None:
        """Remember *attribution* for *conn_id* and apply it to the connection's
        present flows (*first* included even when unindexed). Under lock.

        Keyed on connection_id, not the 4-tuple, so a later connection reusing
        the tuple -- a distinct connection_id -- is never touched here. Only
        the connection's first flow (see :meth:`_is_first_flow_of_connection`)
        is a direct join -- and only while present: when it was already written
        and released (headless path) every remaining flow inherits (see
        :meth:`_apply_attribution`). The per-connection record is written only
        for a live connection (see :meth:`_remember_connection_attribution`).

        A reused conn_id keeps earlier lifetimes' flows: only the current
        lifetime's flows are touched (see :meth:`_is_current_lifetime_flow`).
        When the tuple/sid join picked an earlier lifetime's flow as *first*,
        the stack belongs to that lifetime, whose bounds are not tracked, so
        it is applied to *first* alone and not remembered for the live one.
        """
        if first is not None and not self._is_current_lifetime_flow(first):
            if self._apply_attribution(first, attribution, direct=False):
                pending.append((FlowEventType.UPDATED, first))
            return
        flows = [first] if first is not None else []
        flows += self._current_lifetime_flows(conn_id, exclude=first)
        # Decided before remembering: the join below counts as "a stack joined".
        direct = [self._is_first_flow_of_connection(flow) for flow in flows]
        self._remember_connection_attribution(conn_id, attribution)
        for flow, is_direct in zip(flows, direct):
            if self._apply_attribution(flow, attribution, direct=is_direct):
                pending.append((FlowEventType.UPDATED, flow))
        self._mark_mixed_flows(conn_id, flows, _PendingEvents(pending))

    def _remember_connection_attribution(self, conn_id, attribution) -> None:
        """Keep a live connection's first SDK and caller stack for later-born
        flows, and mark it mixed when a stack resolves to a different SDK.

        The sole writer of ``_connection_attributions``, so it owns the leak guard:
        a connection no longer in ``_connections`` (session ended, idle-swept,
        LRU-evicted) was already finalized, and nothing would pop an entry
        written now. Under lock.
        """
        if conn_id not in self._connections:
            return
        record = self._connection_attributions.setdefault(conn_id, _ConnectionAttribution())
        if record.caller_stack is None:
            record.caller_stack = attribution.caller_stack
        if attribution.sdk and not record.sdk:
            record.sdk = attribution.sdk
        record.add_originator(attribution.sdk)

    def _connection_is_mixed(self, conn_id) -> bool:
        """True when *conn_id*'s originators (caller stacks and per-request
        contexts) named more than one SDK."""
        record = self._connection_attributions.get(conn_id)
        return record is not None and record.mixed

    def _mark_mixed_flows(self, conn_id, flows, updates: _PendingEvents) -> None:
        """Set ``attribution.mixed`` on *flows* of a mixed connection, queueing
        an UPDATED for each changed flow not already queued. Under lock."""
        if not self._connection_is_mixed(conn_id):
            return
        for flow in flows:
            if self._set_attribution(flow, {"mixed": True}):
                updates.add_updated(flow)

    @classmethod
    def _apply_attribution(cls, flow: Flow, attribution, direct: bool = False) -> bool:
        """Fill *flow*'s empty ``sdk``/``caller_stack`` and, for a classified
        stack, its originator claim (direct or inherited, see
        :mod:`friTap.flow.attribution`); True when anything changed."""
        changed = False
        if attribution.sdk and not getattr(flow, 'sdk', None):
            flow.sdk = attribution.sdk
            changed = True
        if getattr(flow, 'caller_stack', None) is None:
            flow.caller_stack = attribution.caller_stack
            changed = True
        if attribution.sdk:
            changed = cls._set_attribution(
                flow, cls._originator_claim(flow, attribution.sdk, direct)) or changed
        return changed

    @staticmethod
    def _originator_claim(flow: Flow, sdk: dict, direct: bool) -> dict:
        """The direct (per transport kind) or inherited originator claim."""
        if not direct:
            return inherited_attribution(sdk)
        transport = (flow.attribution or {}).get("transport") or {}
        return direct_attribution(sdk, transport.get("kind", ""))

    @staticmethod
    def _set_attribution(flow: Flow, update: dict) -> bool:
        """Merge *update* into ``flow.attribution``; True when it changed."""
        merged = merge_attribution(flow.attribution, update)
        if merged == (flow.attribution or {}):
            return False
        flow.attribution = merged
        return True

    def _first_unattributed_sdk_flow(self, tkey, sid: str, real_sid: bool,
                                     client_random: str = ""):
        """Earliest flow (insertion order) matching the join keys and lacking a
        caller stack, or ``None``. A flow known by a client_random other than
        *client_random* (when given) is skipped. Must be called under ``self._lock``."""
        for flow in self._flows.values():
            if getattr(flow, 'caller_stack', None) is not None:
                continue
            if client_random and not self._flow_may_have_client_random(flow, client_random):
                continue
            if tkey is not None and self._flow_tuple_key(flow) == tkey:
                return flow
            if real_sid and str(flow.ssl_session_id or '') == sid:
                return flow
        return None

    def _flow_may_have_client_random(self, flow: Flow, client_random: str) -> bool:
        """False when *flow*'s connection is known by a different client_random.
        Reads the live connection, else the flow's own ``tls`` layer (without
        creating one). Under lock."""
        known = self._connection_client_random(flow.connection_id)
        if not known:
            tls = flow.layer("tls")
            known = getattr(tls, 'client_random', '') if tls is not None else ''
        return not known or known == client_random

    def _sibling_flows_without_sdk(self, conn_id, exclude):
        """Flows on connection *conn_id* that lack an SDK, excluding *exclude*.

        Must be called under ``self._lock``.
        """
        return self._sibling_flows_missing(conn_id, exclude, 'sdk')

    def _sibling_flows_missing(self, conn_id, exclude, attr: Optional[str]):
        """Flows on connection *conn_id*, excluding *exclude*, whose *attr* is
        falsy (every flow when *attr* is ``None``).

        Backs the per-connection propagation in :meth:`on_sdk` (one caller
        stack covers every flow of its connection, e.g. all HTTP/2 streams).
        Must be called under ``self._lock``.
        """
        siblings = []
        if not conn_id:
            return siblings
        for fid in self._flow_index.get(conn_id, ()):
            flow = self._flows.get(fid)
            if flow is None or flow is exclude:
                continue
            if attr is None or not getattr(flow, attr, None):
                siblings.append(flow)
        return siblings

    def _current_lifetime_flows(self, conn_id, exclude=None) -> list:
        """The present flows of *conn_id*'s current lifetime (see
        :meth:`_is_current_lifetime_flow`) in index order, without *exclude*.
        Under lock."""
        return [flow for flow in self._sibling_flows_missing(conn_id, exclude, None)
                if self._is_current_lifetime_flow(flow)]

    def _connection_sdk(self, conn_id):
        """The SDK resolved for connection *conn_id*, else ``None`` -- so a flow
        born after its connection's caller_stack joined inherits that SDK.

        Prefers the persistent per-connection record (survives a sibling being
        written and released in the headless path); falls back to an attributed
        sibling still present in ``_flows``. Must be called under ``self._lock``.
        """
        return self._connection_attribute(conn_id, 'sdk')

    def _connection_caller_stack(self, conn_id):
        """The caller stack joined to connection *conn_id*, else ``None``
        (same lookup order as :meth:`_connection_sdk`). Under lock."""
        return self._connection_attribute(conn_id, 'caller_stack')

    def _connection_attribute(self, conn_id, attr: str):
        """*conn_id*'s recorded *attr* (see ``_connection_attributions``), else
        the first present sibling's *attr* among the connection's
        current-lifetime flows."""
        if not conn_id:
            return None
        record = self._connection_attributions.get(conn_id)
        recorded = getattr(record, attr) if record is not None else None
        if recorded:
            return recorded
        # Only this lifetime's flows: an idle-reset or reused conn_id keeps
        # the previous lifetime's completed flows in _flows.
        for flow in self._current_lifetime_flows(conn_id):
            value = getattr(flow, attr, None)
            if value:
                return value
        return None

    def _take_pending_sdk(self, flow):
        """Pop and return one stashed :class:`StashedCallerStack` matching
        *flow*, or ``None``.

        Checks the connection's client_random key first, then the flow's
        4-tuple key, then its real session id. Consuming the stash entry (FIFO)
        stops a later connection reusing the same 4-tuple from inheriting this
        one's stack; expired entries are dropped on the collector clock. Must be
        called under ``self._lock``.
        """
        keys = []
        client_random = self._connection_client_random(flow.connection_id)
        if client_random:
            keys.append(("cr", client_random))
        tkey = self._flow_tuple_key(flow)
        if tkey is not None:
            keys.append(tkey)
        sid = str(flow.ssl_session_id or '')
        if self._real_sid(sid):
            keys.append(("sid", sid))
        return self._sdk_pending.take(keys, self._now())

    def _stamp_caller_attribution(self, flow: Flow) -> None:
        """Give a newborn *flow* its stashed caller stack, else the connection's.

        A stash entry is consumed (so a reused 4-tuple does not inherit it) and
        seeds the per-connection record for the connection's later flows; it is a
        direct join only for the connection's first flow (the stack was
        captured at the connection's first SSL_read/SSL_write), otherwise the
        claim is inherited. Without one, the flow inherits the stack/SDK of an
        earlier flow of the same connection -- including one already written
        and released (headless path), via the persistent maps -- with the
        ``connection-fallback`` claim. A mixed connection marks the flow
        ``mixed``. Never clobbers a value already set. Must be called under
        ``self._lock``.
        """
        stashed = self._take_pending_sdk(flow)
        if stashed is not None:
            direct = self._is_first_flow_of_connection(flow)
            was_mixed = self._connection_is_mixed(flow.connection_id)
            self._remember_connection_attribution(flow.connection_id, stashed)
            self._apply_attribution(flow, stashed, direct=direct)
            if not was_mixed:
                # Turned mixed now: mark the connection's present flows too.
                siblings = self._current_lifetime_flows(flow.connection_id, exclude=flow)
                self._mark_mixed_flows(
                    flow.connection_id, siblings, _PendingEvents(self._staged_updates))
        else:
            self._inherit_connection_attribution(flow)
        if self._connection_is_mixed(flow.connection_id):
            self._set_attribution(flow, {"mixed": True})

    def _inherit_connection_attribution(self, flow: Flow) -> None:
        """Give a newborn *flow* its connection's SDK and caller stack, and the
        inherited (``connection-fallback``) originator claim; never overwrites
        a value already set. Under lock."""
        inherited = StashedCallerStack(
            sdk=self._connection_sdk(flow.connection_id),
            caller_stack=self._connection_caller_stack(flow.connection_id),
            stashed_at=self._now(),
        )
        self._apply_attribution(flow, inherited, direct=False)

    def _is_first_flow_of_connection(self, flow: Flow) -> bool:
        """True when *flow* is the first flow minted in its connection's current
        lifetime (the sequence recorded in ``_lifetime_first_seq``, 0 when none
        was, see :meth:`_flow_id`) and no caller stack was joined to the
        connection before -- the one rule for a direct join, at flow birth and
        at a later join alike. Under lock."""
        conn_id = flow.connection_id
        record = self._connection_attributions.get(conn_id)
        if record is not None and record.caller_stack is not None:
            return False
        first_seq = self._lifetime_first_seq.get(conn_id, 0)
        return flow.flow_id == self._flow_id(conn_id, first_seq)

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
            # _module_paths is process-lifetime state (like _detected_libraries
            # and _process_name), so it is kept.
            self._flow_retained_bytes.clear()
            self._truncated_flow_ids.clear()
        self._publish(publication)

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
            publication = self._stage_publication(pending)

        self._publish(publication)
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
            # End of capture: every live request context is finished and
            # handed to the sink (after the join consumed its matches).
            publication = self._stage_publication(completed_events, finish_contexts=True)
            errors_to_emit = self._drain_pending_errors()

        # Notify about removed flows (outside lock)
        for removed_flow in removed_flows:
            self._notify(FlowEventType.REMOVED, removed_flow)
        # Emit COMPLETED for flows this flush finalized (outside lock).
        self._publish(publication)
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

        # Drop the cached TLS metadata and attribution record for this
        # connection to avoid unbounded growth across many short-lived connections.
        self._session_tls.pop(conn.conn_id, None)
        self._connection_attributions.pop(conn.conn_id, None)
        self._forget_client_random(conn)

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

        # 4. Expire finished request contexts (emitted by the entry point)
        self._finished_request_contexts.extend(self._request_contexts.expire(now))

        # 5. Invalidate body caches on completed flows (reconstructed on demand)
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
        conn = self._start_connection_lifetime(conn_id, event)
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

    @staticmethod
    def _flow_id(conn_id: str, seq: int) -> str:
        """The id of *conn_id*'s flow number *seq* (see :meth:`_next_flow_sequence`)."""
        return f"{conn_id}:{seq}"

    def _make_flow(self, conn, event, endpoints: Optional[tuple] = None) -> Flow:
        """Create and index a new Flow for *event*.

        *endpoints* optionally overrides the event's ``(src_addr, src_port,
        dst_addr, dst_port)`` orientation (see :meth:`_oriented_endpoints`).
        """
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

    def _stamp_transport_attribution(self, flow: Flow) -> None:
        """Stamp ``attribution.transport`` from the flow's TLS/QUIC library.

        Classified with the module's recorded load path and the capture
        target's process/package names. No-op for other transports and for a
        flow without a library. Reads the layer without creating it. Under lock.
        """
        if flow.transport not in self._LIBRARY_TRANSPORTS:
            return
        layer = flow.layer(flow.transport)
        library = getattr(layer, 'library', '') if layer is not None else ''
        if not library:
            return
        transport = transport_attribution(
            library, self._module_path_for(library),
            self._process_name, self._package_name)
        if transport:
            self._note_transport(transport)
            flow.attribution = merge_attribution(flow.attribution, {"transport": transport})

    def _note_transport(self, transport: dict) -> None:
        if transport.get("kind") in CHROMIUM_FAMILY_KINDS:
            self._chromium_transport_seen = True

    def _stamp_client_random(self, flow: Flow, event) -> None:
        """Stamp the connection's client_random onto a TLS flow's ``tls`` layer.

        Uses the record's own ``client_random``, else the one already seen on
        the flow's connection (records before the agent learned it carry
        none). Fills an empty value only. TLS flows only: ``flow.tls`` attribute
        access auto-creates the layer (see :meth:`_stamp_detected_library`).
        """
        if flow.transport != "tls" or flow.tls.client_random:
            return
        client_random = (getattr(event, 'client_random', '') or ''
                         or self._connection_client_random(flow.connection_id))
        if client_random:
            flow.tls.client_random = client_random

    def _connection_client_random(self, conn_id: str) -> str:
        """The client_random recorded on *conn_id*'s state, else ``""``."""
        conn = self._connections.get(conn_id)
        return conn.client_random if conn is not None else ""

    def _record_client_random(self, conn: '_ConnectionState', event,
                              pending: Optional[list] = None) -> None:
        """Remember the first client_random seen on *conn* and backfill it
        onto the connection's flows born before it was known. Under lock.

        A connection's early records can lack the client_random (agent layout
        lookup still pending) while later ones carry it; the key aliasing keeps
        them on one connection, and this keeps every flow of it stamped. The
        client_random also becomes the connection's caller_stack join key: it is
        indexed for :meth:`on_sdk` and any stack already stashed under it is
        applied to the connection now.
        """
        client_random = getattr(event, 'client_random', '') or ''
        if not client_random or conn.client_random:
            return
        conn.client_random = client_random
        for flow in self._connection_flows(conn.conn_id):
            self._stamp_client_random(flow, event)
        self._conn_by_client_random[client_random] = conn.conn_id
        self._drain_client_random_stash(conn.conn_id, client_random, pending)

    def _drain_client_random_stash(self, conn_id: str, client_random: str,
                                   pending: Optional[list]) -> None:
        """Apply a caller stack stashed under *client_random* to *conn_id*. Under lock."""
        stashed = self._sdk_pending.take([("cr", client_random)], self._now())
        if stashed is None:
            return
        updated: list = []
        self._attribute_connection(conn_id, stashed, updated)
        if pending is not None:
            for _, flow in updated:
                self._append_progress(pending, flow)

    def _forget_client_random(self, conn: '_ConnectionState') -> None:
        """Drop *conn*'s client_random join entry if it still points at *conn*."""
        if self._conn_by_client_random.get(conn.client_random) == conn.conn_id:
            del self._conn_by_client_random[conn.client_random]

    def _learn_real_endpoints(self, conn: '_ConnectionState', event, pending: list) -> None:
        """Learn the real tuple behind *conn*'s synthetic pin (first one wins)
        and upgrade the connection's synthetic flows to it. Under lock."""
        if conn.real_endpoint_map is not None:
            return
        mapping = observed_endpoint_map(event)
        if mapping is None:
            return
        conn.real_endpoint_map = mapping
        for flow in self._connection_flows(conn.conn_id):
            if upgrade_flow_endpoints(flow, mapping):
                self._append_progress(pending, flow)

    @staticmethod
    def _stamp_synthetic_endpoints(flow: Flow, conn: '_ConnectionState', event) -> None:
        """Flag a flow born on a synthetic pin, upgrading it at once when the
        connection's real tuple is already known."""
        flow.endpoints_synthetic = bool(getattr(event, 'endpoints_synthetic', False))
        mapping = getattr(conn, 'real_endpoint_map', None)
        if mapping is not None:
            upgrade_flow_endpoints(flow, mapping)

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
        self._stamp_transport_attribution(flow)
        self._stamp_client_random(flow, event)
        # Backfill handshake metadata cached from an earlier SESSION_STARTED/
        # RESUMED for this connection (handshake arrives before the first data
        # event, so _stamp_tls_metadata found no flow to stamp at that time).
        # Transport-aware: stamps flow.tls or flow.quic per flow.transport.
        # Only fills fields that are still empty so we never clobber later data.
        cached_meta = self._session_tls.get(flow.connection_id)
        if cached_meta:
            self._apply_session_metadata(flow, cached_meta)
        # Backfill a caller stack (and its SDK, if classified) captured before
        # this flow existed, or inherit the connection's (see
        # _stamp_caller_attribution).
        self._stamp_caller_attribution(flow)
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
        # First client_random seen on this connection's records ("" until the
        # agent stamps one); stamped onto every TLS flow of the connection.
        self.client_random: str = ""
        # Synthetic -> real endpoint map learned from the first record that
        # carried observed_* under a synthetic pin (option 5); None until then.
        self.real_endpoint_map: Optional[dict] = None
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
