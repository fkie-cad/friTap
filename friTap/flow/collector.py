"""Thread-safe flow collector that groups SSL events into flows."""

import copy
import logging
import threading
import time
from typing import Callable, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .models import FlowSummary

from friTap.connection_index import resolve_connection_key
from friTap.constants import SSL_READ
from friTap.events import (
    FlowEvent,
    ErrorEvent,
    ERROR_SEVERITY_WARNING,
    SESSION_ENDED,
    SESSION_DESTROYED,
)
from friTap.parsers.base import (
    BaseParser,
    ParserFailure,
    SafeParserAdapter,
    unwrap_parser,
)
from friTap.parsers.bhttp import parse_bhttp
from friTap.parsers.hexdump import HexdumpParser
from friTap.parsers.http2 import Http2Parser, is_h2_control_frame_data
from friTap.parsers.registry import get_default_registry

from .models import Flow, FlowEventType, FlowState, FlowChunk

logger = logging.getLogger(__name__)

# If no data arrives for this many seconds and then resumes, treat as new connection.
IDLE_THRESHOLD = 30.0

# Buffer this many bytes before committing to HexdumpParser fallback.
# Ensures HTTP/2 (9-byte frame header) and HTTP/3 (varint) have enough data for detection.
PARSER_DETECTION_BUFFER_SIZE = 256

# Run periodic maintenance sweep every N data events.
_SWEEP_INTERVAL = 500

# Read-function names used to determine direction.
# Superset of SSL_READ from constants — includes _ex variants and platform names.
_READ_FUNCTIONS = SSL_READ | frozenset({
    'SSL_read_ex', 'PR_Recv', 'SSLRead',
})


class FlowCollector:
    """Thread-safe flow collector that groups SSL events into flows."""

    def __init__(self, event_bus=None, show_control_frames: bool = True):
        self._lock = threading.Lock()
        self._flows: dict[str, Flow] = {}  # flow_id -> Flow
        self._connections: dict[str, _ConnectionState] = {}  # conn_id -> state
        self._callbacks: list[Callable] = []
        self._event_bus = event_bus
        self._show_control_frames = show_control_frames
        # HTTP/2 stream-level index: (conn_id, stream_id) -> flow_id
        self._h2_stream_flows: dict[tuple[str, int], str] = {}
        # Orphan request index: dst_key -> [(timestamp, flow_id), ...]
        self._orphan_requests: dict[str, list[tuple[float, str]]] = {}
        self._event_count = 0
        # ErrorEvents staged by SafeParserAdapter via _on_parser_failure;
        # populated under _lock and drained by entry-point methods after the
        # lock is released so EventBus.emit cannot deadlock against TUI
        # subscribers that may need to read collector state.
        self._pending_errors: list[ErrorEvent] = []

    def _wrap_parser(
        self,
        parser: BaseParser,
        conn: Optional['_ConnectionState'] = None,
    ) -> BaseParser:
        """Wrap *parser* in a SafeParserAdapter unless already wrapped.

        All parsers that get assigned to ``conn.parser`` go through this
        helper so a malformed stream can never crash the collector. When
        a connection state is supplied, the per-connection failure
        callback also resets the active flow's ``detected_protocol`` so
        the UI does not keep claiming HTTP/1.1 (or whatever the dead
        parser asserted) while raw bytes are now flowing untyped.
        """
        if parser is None or isinstance(parser, SafeParserAdapter):
            return parser
        if conn is None:
            return SafeParserAdapter(parser, on_failure=self._on_parser_failure)

        def _on_failure_with_conn(failure: ParserFailure) -> None:
            self._on_parser_failure(failure)
            flow_id = conn.active_flow_id
            if flow_id and flow_id in self._flows:
                self._flows[flow_id].detected_protocol = "unknown"

        return SafeParserAdapter(parser, on_failure=_on_failure_with_conn)

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
        # Build connection ID using tiered key resolution (session_token → normalized 4-tuple)
        conn_id = resolve_connection_key(
            event.src_addr, event.src_port,
            event.dst_addr, event.dst_port,
            session_token=getattr(event, 'ssl_session_id', ''),
            client_random=getattr(event, 'client_random', ''),
        )

        pending = []

        with self._lock:
            # Get or create connection state
            if conn_id not in self._connections:
                self._connections[conn_id] = _ConnectionState(conn_id)

            conn = self._connections[conn_id]

            # Time-gap heuristic: if idle too long, reset connection state
            if conn.last_activity > 0 and (event.timestamp - conn.last_activity) > IDLE_THRESHOLD:
                self._finalize_connection(conn, conn.last_activity, pending)
                # Reset to fresh state
                self._connections[conn_id] = _ConnectionState(conn_id)
                conn = self._connections[conn_id]

            conn.last_activity = event.timestamp

            # Prefer event.direction; fall back to function-name heuristic
            direction = getattr(event, 'direction', '') or self._get_direction(event.function)

            # Create chunk
            chunk = FlowChunk(
                data=event.data,
                direction=direction,
                timestamp=event.timestamp,
                function=event.function
            )

            # Parser detection with buffering retry
            if conn.parser is None:
                # Buffer chunks until we have enough data for reliable detection
                conn.pending_chunks.append(chunk)
                conn.pending_bytes += len(event.data)

                try:
                    registry = get_default_registry()
                    combined = b"".join(c.data for c in conn.pending_chunks)
                    detected = registry.detect(combined)
                except Exception:
                    logger.debug("Parser detection failed", exc_info=True)
                    detected = HexdumpParser()

                # Check if we got a real parser or just the fallback
                is_fallback = isinstance(detected, HexdumpParser)

                if not is_fallback or conn.pending_bytes >= PARSER_DETECTION_BUFFER_SIZE:
                    # Commit to parser and feed all buffered chunks
                    conn.parser = self._wrap_parser(detected, conn)
                    for pending_chunk in conn.pending_chunks:
                        results = conn.parser.feed(pending_chunk.data, pending_chunk.direction)
                        results = self._filter_control_frames(results)
                        if results:
                            for result in results:
                                flow = self._create_or_update_flow(conn, pending_chunk, result, event, pending)
                                pending.append((FlowEventType.UPDATED, flow))
                        else:
                            flow = self._get_or_create_active_flow(conn, event, pending)
                            self._append_chunk(flow, pending_chunk)
                            pending.append((FlowEventType.UPDATED, flow))
                    # Stamp detected_protocol on the active flow when the parser
                    # matched a real protocol but produced no ParseResult yet
                    # (e.g. HTTP/2 SETTINGS-only prelude).
                    if (not is_fallback
                            and conn.active_flow_id
                            and conn.active_flow_id in self._flows):
                        active = self._flows[conn.active_flow_id]
                        if not active.detected_protocol:
                            active.detected_protocol = conn.parser.PROTOCOL
                    # Propagate trailing data from buffered-chunk parsing
                    if conn.active_flow_id and conn.active_flow_id in self._flows:
                        self._propagate_trailing_data(conn.parser, self._flows[conn.active_flow_id])
                    conn.pending_chunks = []
                    conn.pending_bytes = 0
                else:
                    # Still buffering — create/update flow with chunk but don't feed parser yet
                    flow = self._get_or_create_active_flow(conn, event, pending)
                    self._append_chunk(flow, chunk)
                    pending.append((FlowEventType.UPDATED, flow))
            else:
                # Parser already committed — try upgrade if on fallback
                if isinstance(unwrap_parser(conn.parser), HexdumpParser):
                    self._try_parser_upgrade(conn, event.data)

                # Feed directly
                results = conn.parser.feed(event.data, direction)

                if results:
                    results = self._filter_control_frames(results)
                    flow = None
                    for result in results:
                        flow = self._create_or_update_flow(conn, chunk, result, event, pending)
                        pending.append((FlowEventType.UPDATED, flow))
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
                        pending.append((FlowEventType.UPDATED, flow))

            self._event_count += 1
            if self._event_count % _SWEEP_INTERVAL == 0:
                self._periodic_sweep(pending)

            errors_to_emit = self._drain_pending_errors()

        for event_type, flow in pending:
            self._notify(event_type, flow)
        self._emit_errors(errors_to_emit)

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
            else:
                flow.ohttp_inner_response = result

            pending.append((FlowEventType.UPDATED, flow))

        for event_type, flow in pending:
            self._notify(event_type, flow)

    def on_session_event(self, event) -> None:
        """EventBus subscriber for SessionEvent -- handle connection lifecycle."""
        if event.event_type not in (SESSION_ENDED, SESSION_DESTROYED):
            return

        conn_id = getattr(event, 'connection_id', '')
        if not conn_id:
            return

        pending = []
        errors_to_emit: list = []
        with self._lock:
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
            self._connections.clear()
            self._h2_stream_flows.clear()
            self._orphan_requests.clear()

    def flush(self) -> None:
        """Flush all parsers and finalize active flows."""
        removed_flows: list[Flow] = []
        with self._lock:
            for conn in self._connections.values():
                # Commit parser for connections still in the buffering phase
                if conn.parser is None and conn.pending_chunks:
                    self._commit_pending(conn)

                if conn.parser:
                    self._flush_parser_to_flow(conn)

            # Merge orphan request-only + response-only flows by destination
            removed_flows = self._merge_remaining_orphans()

            # Mark all active flows as complete
            for flow in self._flows.values():
                if flow.state == FlowState.ACTIVE:
                    flow.state = FlowState.COMPLETE
                    flow.ended = time.time()

            self._orphan_requests.clear()
            errors_to_emit = self._drain_pending_errors()

        # Notify about removed flows (outside lock)
        for removed_flow in removed_flows:
            self._notify(FlowEventType.REMOVED, removed_flow)
        self._emit_errors(errors_to_emit)

    def _merge_remaining_orphans(self) -> list[Flow]:
        """Match request-only with response-only flows by destination. Must be called under lock.

        Returns list of removed Flow objects (for REMOVED notifications).
        """
        request_only: list[tuple[str, str]] = []   # (flow_id, dst_key)
        response_only: list[tuple[str, str]] = []   # (flow_id, dst_key)

        for fid, flow in self._flows.items():
            if flow.request is not None and flow.response is None:
                request_only.append((fid, f"{flow.dst_addr}:{flow.dst_port}"))
            elif flow.response is not None and flow.request is None:
                response_only.append((fid, f"{flow.dst_addr}:{flow.dst_port}"))

        # Build lookup: dst_key -> first request-only flow_id
        req_by_dst: dict[str, str] = {}
        for fid, dst_key in request_only:
            if dst_key not in req_by_dst:
                req_by_dst[dst_key] = fid

        # Merge: attach response to request flow, remove response-only flow
        removed: list[Flow] = []
        for resp_fid, dst_key in response_only:
            if dst_key not in req_by_dst:
                continue
            req_fid = req_by_dst.pop(dst_key)
            req_flow = self._flows.get(req_fid)
            resp_flow = self._flows.get(resp_fid)
            if not req_flow or not resp_flow:
                continue
            if abs(resp_flow.started - req_flow.started) > IDLE_THRESHOLD:
                continue
            req_flow.response = resp_flow.response
            req_flow.chunks.extend(resp_flow.chunks)
            req_flow._total_bytes += resp_flow._total_bytes
            if resp_flow.ended > req_flow.ended:
                req_flow.ended = resp_flow.ended
            del self._flows[resp_fid]
            removed.append(resp_flow)

        return removed

    def _finalize_connection(self, conn: '_ConnectionState', ended: float,
                              pending: list) -> None:
        """Flush parser and mark the active flow as complete. Must be called under lock."""
        # Commit parser for connections still in the buffering phase
        if conn.parser is None and conn.pending_chunks:
            self._commit_pending(conn)

        if conn.parser:
            self._flush_parser_to_flow(conn)
        if conn.active_flow_id and conn.active_flow_id in self._flows:
            flow = self._flows[conn.active_flow_id]
            if flow.state == FlowState.ACTIVE:
                flow.state = FlowState.COMPLETE
                flow.ended = ended
                pending.append((FlowEventType.COMPLETED, flow))

        # Clean up H2 stream index entries for this connection
        stale_streams = [key for key in self._h2_stream_flows
                         if key[0] == conn.conn_id]
        for key in stale_streams:
            del self._h2_stream_flows[key]

    def _periodic_sweep(self, pending: list) -> None:
        """Periodic maintenance: clean stale indices, idle connections, body caches.

        Must be called under lock.
        """
        now = time.time()

        # 1. Sweep orphan requests: prune entries older than IDLE_THRESHOLD
        #    or referencing flows that no longer exist
        stale_keys = []
        for dst_key, candidates in self._orphan_requests.items():
            valid = [(ts, fid) for ts, fid in candidates
                     if (now - ts) <= IDLE_THRESHOLD and fid in self._flows]
            if valid:
                candidates[:] = valid
            else:
                stale_keys.append(dst_key)
        for k in stale_keys:
            del self._orphan_requests[k]

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

    @staticmethod
    def _append_chunk(flow: Flow, chunk: FlowChunk) -> None:
        """Append a chunk to a flow and update the cached byte total."""
        flow.chunks.append(chunk)
        flow._total_bytes += len(chunk.data)
        flow.invalidate_body_cache()

    @staticmethod
    def _attach_response(flow: Flow, result, chunk: FlowChunk, timestamp: float) -> None:
        """Attach a response ParseResult to a flow and optionally mark complete."""
        flow.response = result
        FlowCollector._append_chunk(flow, chunk)
        if result.is_complete:
            flow.state = FlowState.COMPLETE
            flow.ended = timestamp

    def _commit_pending(self, conn: '_ConnectionState') -> None:
        """Commit a parser and feed pending chunks for a buffering-phase connection.

        Called by flush() and _finalize_connection() when a connection still
        has uncommitted pending_chunks.  Must be called under lock.
        """
        try:
            registry = get_default_registry()
            # Only concatenate enough bytes for detection (parsers only check first bytes)
            prefix = bytearray()
            for c in conn.pending_chunks:
                prefix += c.data
                if len(prefix) >= PARSER_DETECTION_BUFFER_SIZE:
                    break
            conn.parser = self._wrap_parser(registry.detect(bytes(prefix)), conn)
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

    def _flush_parser_to_flow(self, conn: '_ConnectionState') -> None:
        """Flush the committed parser and assign results to the active flow.

        Must be called under lock.
        """
        try:
            results = conn.parser.flush()
        except Exception:
            return
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

    @staticmethod
    def _propagate_trailing_data(parser, flow: Flow) -> None:
        """Move trailing data from a parser instance to a Flow. Must be called under lock."""
        td = getattr(parser, 'trailing_data', None)
        if td is None:
            return
        flow.trailing_bytes = td
        flow.trailing_protocol = getattr(parser, 'trailing_protocol', '')
        flow.trailing_parse = getattr(parser, 'trailing_sub_parse', None)
        parser.trailing_data = None

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

    def _try_parser_upgrade(self, conn: '_ConnectionState', data: bytes) -> bool:
        """Attempt to upgrade from HexdumpParser if data starts a known protocol.

        Returns True if parser was upgraded, False otherwise.
        Must be called under lock.
        """
        if not isinstance(unwrap_parser(conn.parser), HexdumpParser):
            return False
        try:
            registry = get_default_registry()
            detected = registry.detect(data)
        except Exception:
            return False
        if isinstance(detected, HexdumpParser):
            return False
        conn.parser = self._wrap_parser(detected, conn)
        return True

    def _get_direction(self, function: str) -> str:
        """Determine direction from function name."""
        func_base = function.split('(')[0].strip() if '(' in function else function.strip()
        if func_base in _READ_FUNCTIONS or 'read' in func_base.lower() or 'recv' in func_base.lower():
            return "read"
        return "write"

    def _create_or_update_flow(self, conn, chunk, result, event, pending):
        """Create new flow or update existing based on parse result."""
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
            conn.flow_sequence += 1
            # Index by HTTP/2 stream_id for response correlation
            if stream_id > 0:
                self._h2_stream_flows[(conn.conn_id, stream_id)] = flow.flow_id
            # Register in orphan index for destination-keyed matching
            dst_key = f"{event.dst_addr}:{event.dst_port}"
            self._orphan_requests.setdefault(dst_key, []).append(
                (event.timestamp, flow.flow_id)
            )
            pending.append((FlowEventType.CREATED, flow))
            return flow
        else:
            # Response — try stream-level match first (HTTP/2 multiplexing)
            if stream_id > 0:
                stream_key = (conn.conn_id, stream_id)
                matched_flow_id = self._h2_stream_flows.get(stream_key)
                if matched_flow_id and matched_flow_id in self._flows:
                    self._attach_response(self._flows[matched_flow_id], result, chunk, event.timestamp)
                    # Remove stream mapping when response is complete
                    if result.is_complete:
                        self._h2_stream_flows.pop(stream_key, None)
                    return self._flows[matched_flow_id]

            # Fall back to active flow on this connection
            if conn.active_flow_id and conn.active_flow_id in self._flows:
                flow = self._flows[conn.active_flow_id]
                self._attach_response(flow, result, chunk, event.timestamp)
                return flow
            else:
                # Response without request — try orphan index match
                matched = self._match_orphan_request(event)
                if matched:
                    self._attach_response(matched, result, chunk, event.timestamp)
                    return matched
                # No match — create orphan flow
                flow = self._make_flow(conn, event)
                self._attach_response(flow, result, chunk, event.timestamp)
                conn.active_flow_id = flow.flow_id
                conn.flow_sequence += 1
                pending.append((FlowEventType.CREATED, flow))
                return flow

    def _match_orphan_request(self, event) -> Optional[Flow]:
        """Find a recent request-only flow to the same destination."""
        dst_key = f"{event.dst_addr}:{event.dst_port}"
        candidates = self._orphan_requests.get(dst_key)
        if not candidates:
            return None
        now = event.timestamp
        # Prune stale entries (always, not only when matched)
        valid = [(ts, fid) for ts, fid in candidates
                 if (now - ts) <= IDLE_THRESHOLD and fid in self._flows]
        candidates[:] = valid
        if not valid:
            return None
        # Pick the closest in time
        _, flow_id = min(valid, key=lambda x: abs(now - x[0]))
        flow = self._flows.get(flow_id)
        if flow and flow.request is not None and flow.response is None:
            candidates[:] = [(ts, fid) for ts, fid in candidates if fid != flow_id]
            return flow
        return None

    def _get_or_create_active_flow(self, conn, event, pending):
        """Get current active flow or create a new one."""
        if conn.active_flow_id and conn.active_flow_id in self._flows:
            flow = self._flows[conn.active_flow_id]
            if flow.state == FlowState.ACTIVE:
                return flow
        flow = self._make_flow(conn, event)
        conn.active_flow_id = flow.flow_id
        conn.flow_sequence += 1
        pending.append((FlowEventType.CREATED, flow))
        return flow

    def _make_flow(self, conn, event) -> Flow:
        flow_id = f"{conn.conn_id}:{conn.flow_sequence}"
        flow = Flow(
            flow_id=flow_id,
            connection_id=conn.conn_id,
            src_addr=event.src_addr,
            src_port=event.src_port,
            dst_addr=event.dst_addr,
            dst_port=event.dst_port,
            ssl_session_id=getattr(event, 'ssl_session_id', ''),
            started=event.timestamp,
        )
        self._flows[flow_id] = flow
        return flow

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


class _ConnectionState:
    """Internal per-connection tracking."""
    def __init__(self, conn_id: str):
        self.conn_id = conn_id
        self.parser = None  # BaseParser instance
        self.active_flow_id: Optional[str] = None
        self.flow_sequence: int = 0
        self.last_activity: float = 0.0
        self.pending_chunks: list[FlowChunk] = []  # buffered before parser committed
        self.pending_bytes: int = 0  # total bytes in pending_chunks



    def can_parse(self, data: bytes) -> bool:
        return False
