"""Parser lifecycle and chunk retention for :class:`FlowCollector`.

The host class owns the state; methods run under its lock unless noted.
Collector constants are read through ``_collector()`` at call time so patches take effect.
"""

import logging
from typing import Optional

from friTap.events import ERROR_SEVERITY_WARNING, ErrorEvent
from friTap.parsers.base import (
    MAX_PARSER_RESETS,
    BaseParser,
    ParserFailure,
    SafeParserAdapter,
    unwrap_parser,
)
from friTap.parsers.hexdump import HexdumpParser
from friTap.parsers.registry import get_default_registry

from .collector_state import _ConnectionState
from .collector_state import collector_module as _collector
from .models import Flow, FlowChunk

# The collector's logger, so existing log filters and levels keep matching.
logger = logging.getLogger("friTap.flow.collector")


class ParserFlowMixin:
    """Wraps, detects, commits, upgrades and flushes connection parsers; keeps per-flow chunks within ``MAX_FLOW_CHUNK_BYTES``."""

    def _wrap_parser(
        self,
        parser: BaseParser,
        conn: Optional['_ConnectionState'] = None,
    ) -> BaseParser:
        """Wrap *parser* in a SafeParserAdapter unless already wrapped, so a malformed stream cannot crash the collector.

        With *conn*, ``flow_transport`` is stamped and, once the adapter gives up for
        good, the active flow's ``detected_protocol`` becomes "unknown".
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

        on_failure runs BEFORE the adapter resets or disables itself, so the outcome
        is read from its reset budget (``MAX_PARSER_RESETS``).
        """
        return adapter.disabled or adapter.reset_count >= MAX_PARSER_RESETS

    def _mark_active_flow_unknown(self, conn: '_ConnectionState') -> None:
        """Label *conn*'s active flow "unknown" (its parser is gone). Under lock."""
        flow = self._flows.get(conn.active_flow_id or "")
        if flow is not None:
            flow.detected_protocol = "unknown"

    def _on_parser_failure(self, failure: ParserFailure) -> None:
        """SafeParserAdapter callback: stage an ErrorEvent. Runs under the lock, so the
        entry point emits ``_pending_errors`` after releasing it (emitting here could deadlock subscribers).
        """
        self._pending_errors.append(ErrorEvent(
            error=f"Parser {failure.parser_name} failed",
            description=f"{failure.exc_class}: {failure.exc_message}",
            stack=failure.traceback_text,
            severity=ERROR_SEVERITY_WARNING,
        ))

    def _stamp_detected_protocol(self, conn: '_ConnectionState') -> bool:
        """Stamp the parser's PROTOCOL on the active flow if it recognized any; True when no further stamping is needed."""
        active = self._flows.get(conn.active_flow_id) if conn.active_flow_id else None
        if active is None:
            return False
        return self._stamp_protocol_on(active, conn)

    @staticmethod
    def _stamp_protocol_on(flow: Flow, conn: '_ConnectionState') -> bool:
        """Fill *flow*'s empty ``detected_protocol`` from *conn*'s parser; False while nothing is recognized yet."""
        if conn.parser is None or not conn.parser.recognized_any():
            return False
        if not flow.detected_protocol:
            flow.detected_protocol = conn.parser.PROTOCOL
        return True

    def _filter_control_frames(self, results: list) -> list:
        """Remove control-frame results when show_control_frames is disabled."""
        if self._show_control_frames:
            return results
        return [r for r in results if not r.is_control_frame]

    def _append_chunk(self, flow: Flow, chunk: Optional[FlowChunk]) -> None:
        """Append a chunk to a flow and update the cached byte total.

        The total always grows; the chunk is retained only within
        :data:`MAX_FLOW_CHUNK_BYTES` (:meth:`_retain_chunk_bytes`). ``None`` is a no-op.
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

        The first refusal marks the flow truncated and logs a warning; later chunks are dropped silently.
        """
        flow_id = flow.flow_id
        if flow_id in self._truncated_flow_ids:
            return False
        retained = self._flow_retained_bytes.get(flow_id, 0) + size
        if retained > _collector().MAX_FLOW_CHUNK_BYTES:
            self._truncated_flow_ids.add(flow_id)
            flow.truncated = True
            logger.warning(
                "Flow %s exceeded %d retained bytes; further payload is counted "
                "but not retained", flow_id, _collector().MAX_FLOW_CHUNK_BYTES)
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
        """Attach a response to a flow; complete it when ``is_complete`` (via :meth:`_complete_flow`, since the TapWriter writes only on COMPLETED)."""

        flow.response = result
        self._append_chunk(flow, chunk)
        if result.is_complete:
            self._complete_flow(flow, timestamp, pending)

    def _commit_pending(self, conn: '_ConnectionState') -> None:
        """Commit a parser and feed pending chunks for a buffering-phase connection. Under lock."""
        try:
            # Detection only needs the first bytes; do not join everything.
            prefix = bytearray()
            for c in conn.pending_chunks:
                prefix += c.data
                if len(prefix) >= _collector().PARSER_DETECTION_BUFFER_SIZE:
                    break
            conn.parser = self._wrap_parser(
                self._detect_parser(conn, bytes(prefix)), conn)
        except Exception:
            conn.parser = self._wrap_parser(HexdumpParser(), conn)

        flow = None
        if conn.active_flow_id and conn.active_flow_id in self._flows:
            flow = self._flows[conn.active_flow_id]

        for pending_chunk in conn.pending_chunks:
            # SafeParserAdapter.feed never raises; this guards an unwrapped parser.
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
        """Flush the committed parser and assign results to the active flow; *pending* collects events of flows opened for HTTP/2 leftovers. Under lock."""
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
        """Move trailing data from a parser to a Flow. Under lock.

        The "trailing" layer mirrors ``flow.trailing_parse``; the trailing_* fields stay the source of truth.
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
        old_trailing = getattr(conn.parser, 'trailing_data', None)
        from friTap.parsers.websocket import WebSocketParser
        if "websocket" in upgrade.lower():
            conn.parser = self._wrap_parser(WebSocketParser(), conn)
        # Local try/except: a malformed trailing frame must not mark the new parser failed.
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
        """Upgrade from HexdumpParser if *data* starts a known protocol; True if upgraded. Under lock."""
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
