"""QUIC stream-aware flow plumbing for :class:`FlowCollector` (HTTP/3).

QUIC multiplexes many streams over one connection. Each HTTP/3 request lives
on its own bidirectional stream, while unidirectional streams (``id & 0x2``)
carry connection-level data: the control stream (SETTINGS) and the QPACK
encoder/decoder streams. The collector's generic byte path knows nothing about
streams, so this mixin keeps QUIC stream events apart:

* every chunk keeps its REAL stream id (``FlowChunk.stream_id``) and is fed to
  the parser with it, so buffered chunks never lose their stream;
* parser detection never concatenates bytes of different streams;
* results are remapped onto the collector's dense positive stream ids
  (``_ConnectionState.map_qsid``) and routed to their own stream's flow, even
  when a chunk of another stream unblocked them;
* result-less chunks of unidirectional streams land in ONE control flow per
  connection (or are dropped when control frames are hidden), result-less
  chunks of a request stream land in that stream's flow.

Events that are not QUIC stream events (no real stream id, app-api decoded
headers, neqo's already de-framed body bytes) keep the legacy path untouched.
The host class must provide the FlowCollector helpers used here and must call
these methods under its lock.
"""

import dataclasses
import logging
from typing import Optional

from friTap.parsers.base import unwrap_parser
from friTap.parsers.hexdump import HexdumpParser
from friTap.parsers.http3 import Http3Parser
from friTap.parsers.registry import get_default_registry

from .models import FlowChunk, FlowEventType

logger = logging.getLogger(__name__)

_TRANSPORT_QUIC = "quic"

# Bit 0x2 of a QUIC stream id marks a unidirectional stream (RFC 9000 2.1).
_UNI_STREAM_BIT = 0x2

# neqo hands over DE-FRAMED HTTP/3 body bytes on h3 stream ids; feeding them to
# the frame parser would misparse them, so these keep the legacy path.
_NEQO_BODY_FUNCTIONS = ("read_response_data", "send_request_body")

# Unidirectional stream kind that carries responses (server push), not control.
_PUSH_STREAM_KIND = "push"


class QuicStreamFlowMixin:
    """Routes real-stream-id QUIC chunks into per-stream HTTP/3 flows."""

    # ------------------------------------------------------------------
    # Classification
    # ------------------------------------------------------------------

    @staticmethod
    def _quic_stream_id(event) -> Optional[int]:
        """The event's real QUIC stream id, or None when absent/sentinel (-1)."""
        sid = getattr(event, 'stream_id', None)
        if isinstance(sid, int) and not isinstance(sid, bool) and sid >= 0:
            return sid
        return None

    @staticmethod
    def _is_neqo_body_event(event) -> bool:
        """True for neqo hooks that deliver de-framed body bytes."""
        function = getattr(event, 'function', '') or ''
        return any(name in function for name in _NEQO_BODY_FUNCTIONS)

    def _is_quic_stream_event(self, conn, event) -> bool:
        """True if *event* carries raw QUIC stream bytes with a real stream id."""
        return (conn.transport == _TRANSPORT_QUIC
                and getattr(event, 'http3_headers', None) is None
                and self._quic_stream_id(event) is not None
                and not self._is_neqo_body_event(event))

    def _chunk_stream_id(self, conn, event,
                         is_quic_stream: Optional[bool] = None) -> Optional[int]:
        """Stream id to store on the event's FlowChunk (QUIC stream events only).

        *is_quic_stream* is the caller's already computed
        :meth:`_is_quic_stream_event` verdict; evaluated here when omitted.
        """
        if is_quic_stream is None:
            is_quic_stream = self._is_quic_stream_event(conn, event)
        return self._quic_stream_id(event) if is_quic_stream else None

    @staticmethod
    def _is_stream_aware(parser) -> bool:
        """True if *parser* keys its results by the real stream id it was fed."""
        return isinstance(unwrap_parser(parser), Http3Parser)

    def _quic_stream_kind(self, conn, sid: int) -> str:
        """Parser-reported stream kind, falling back to ``uni``/``bidi``."""
        stream_kind = getattr(unwrap_parser(conn.parser), 'stream_kind', None)
        kind = None
        if callable(stream_kind):
            try:
                kind = stream_kind(sid)
            except Exception:
                logger.debug("stream_kind(%s) raised", sid, exc_info=True)
        if kind:
            return str(kind).lower()
        return "uni" if sid & _UNI_STREAM_BIT else "bidi"

    def _is_quic_control_stream(self, conn, sid: int) -> bool:
        """True for unidirectional streams other than push streams."""
        if not sid & _UNI_STREAM_BIT:
            return False
        return _PUSH_STREAM_KIND not in self._quic_stream_kind(conn, sid)

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    def _handle_quic_stream_chunk(self, conn, chunk, event, pending) -> None:
        """Buffer, detect, feed and route one QUIC stream chunk. Under lock."""
        conn.quic_last_event = event
        if conn.parser is None:
            conn.pending_chunks.append(chunk)
            conn.pending_bytes += len(chunk.data)
            if self._ensure_quic_parser(conn, [chunk]):
                self._feed_quic_pending(conn, event, pending)
            return
        self._try_parser_upgrade(conn, chunk.data)
        self._process_quic_chunk(conn, chunk, event, pending)

    def _process_quic_chunk(self, conn, chunk, event, pending) -> None:
        """Feed *chunk*, dispatch its results, and place the chunk itself."""
        pairs = self._feed_quic(conn, chunk)
        placed = self._dispatch_quic_results(conn, chunk, pairs, event, pending)
        if not placed:
            self._route_resultless_quic_chunk(conn, chunk, event, pending)

    def _feed_quic_pending(self, conn, event, pending) -> None:
        """Feed every buffered chunk, in arrival order, to the committed parser."""
        chunks = conn.pending_chunks
        conn.pending_chunks = []
        conn.pending_bytes = 0
        for chunk in chunks:
            self._process_quic_chunk(conn, chunk, event, pending)

    # ------------------------------------------------------------------
    # Detection
    # ------------------------------------------------------------------

    def _ensure_quic_parser(self, conn, candidates: list, force: bool = False) -> bool:
        """Commit a parser once a candidate chunk's stream is recognised.

        Detection runs per (stream, direction) byte run, never across streams.
        A Hexdump fallback is committed only once enough bytes are buffered
        (or when *force* is set at finalize). Returns True when committed.
        """
        from .collector import PARSER_DETECTION_BUFFER_SIZE

        detected = self._detect_quic_parser(conn, candidates)
        if (isinstance(detected, HexdumpParser) and not force
                and conn.pending_bytes < PARSER_DETECTION_BUFFER_SIZE):
            return False
        conn.parser = self._wrap_parser(detected, conn)
        return True

    def _detect_quic_parser(self, conn, candidates: list):
        """First non-Hexdump parser detected on a candidate's stream bytes."""
        for chunk in candidates:
            try:
                detected = get_default_registry().detect(
                    self._quic_stream_prefix(conn, chunk), transport=conn.transport)
            except Exception:
                logger.debug("QUIC parser detection failed", exc_info=True)
                continue
            if not isinstance(detected, HexdumpParser):
                return detected
        return HexdumpParser()

    @staticmethod
    def _quic_stream_prefix(conn, chunk) -> bytes:
        """Buffered bytes of *chunk*'s own stream and direction only."""
        from .collector import PARSER_DETECTION_BUFFER_SIZE

        prefix = bytearray()
        for buffered in conn.pending_chunks:
            if (buffered.stream_id == chunk.stream_id
                    and buffered.direction == chunk.direction):
                prefix += buffered.data
                if len(prefix) >= PARSER_DETECTION_BUFFER_SIZE:
                    break
        return bytes(prefix)

    # ------------------------------------------------------------------
    # Feeding and dispatch
    # ------------------------------------------------------------------

    def _feed_quic(self, conn, chunk) -> list:
        """Feed *chunk* with its real stream id -> ``[(real_sid, result)]``.

        Results of a stream-aware parser are remapped onto the collector's
        dense positive stream ids; other parsers' results belong to the chunk's
        own stream and are passed through unchanged (legacy behaviour).
        """
        results = self._filter_control_frames(
            conn.parser.feed(chunk.data, chunk.direction, stream_id=chunk.stream_id))
        if not self._is_stream_aware(conn.parser):
            return [(chunk.stream_id, result) for result in results]
        return [(result.stream_id,
                 dataclasses.replace(result, stream_id=conn.map_qsid(result.stream_id)))
                for result in results]

    def _dispatch_quic_results(self, conn, chunk, pairs, event, pending) -> bool:
        """Route each result to its stream's flow. True if *chunk* was placed."""
        placed = False
        for real_sid, result in pairs:
            if self._is_quic_control_stream(conn, real_sid):
                self._apply_control_result(conn, result, event, pending)
            elif real_sid == chunk.stream_id and not placed:
                flow = self._create_or_update_flow(conn, chunk, result, event, pending)
                self._remember_quic_stream_flow(conn, real_sid, flow)
                self._append_progress(pending, flow)
                placed = True
            else:
                self._apply_result_without_chunk(conn, real_sid, result, event, pending)
        return placed

    def _apply_control_result(self, conn, result, event, pending) -> None:
        """Label the control flow with a control-frame result (e.g. SETTINGS).

        Non-control results on a control stream are misparsed connection-level
        bytes and never become request flows.
        """
        if not result.is_control_frame:
            return
        flow = self._quic_control_flow(conn, event, pending)
        if flow is not None and flow.request is None:
            flow.request = result

    def _apply_result_without_chunk(self, conn, real_sid, result, event, pending) -> None:
        """Apply a result for another stream than the chunk that produced it.

        Happens when e.g. a QPACK encoder-stream chunk unblocks a HEADERS
        block of a request stream. Without a flow for that stream yet, an
        empty placeholder chunk carries the result through the normal path.
        """
        flow_id = self._h2_stream_flows.get((conn.conn_id, result.stream_id))
        flow = self._flows.get(flow_id) if flow_id else None
        if flow is None:
            placeholder = FlowChunk(
                data=b"", direction="write" if result.is_request else "read",
                timestamp=event.timestamp, function=getattr(event, 'function', ''),
                stream_id=real_sid)
            flow = self._create_or_update_flow(conn, placeholder, result, event, pending)
            self._remember_quic_stream_flow(conn, real_sid, flow)
        else:
            self._set_stream_result(conn, flow, result, event.timestamp, pending)
        self._append_progress(pending, flow)

    def _set_stream_result(self, conn, flow, result, timestamp, pending) -> None:
        """Store *result* as the request or response of *flow*."""
        if result.is_request:
            flow.request = result
            return
        flow.response = result
        if result.is_complete:
            self._complete_flow(flow, timestamp, pending)
            self._h2_stream_flows.pop((conn.conn_id, result.stream_id), None)

    # ------------------------------------------------------------------
    # Result-less chunks
    # ------------------------------------------------------------------

    def _route_resultless_quic_chunk(self, conn, chunk, event, pending) -> None:
        """Place a chunk that produced no result of its own stream."""
        if self._is_quic_control_stream(conn, chunk.stream_id):
            flow = self._quic_control_flow(conn, event, pending)
        else:
            flow = self._quic_stream_flow(conn, chunk, event, pending)
        if flow is None:
            return  # control frames hidden: connection-level bytes dropped
        self._append_chunk(flow, chunk)
        self._append_progress(pending, flow)

    def _quic_control_flow(self, conn, event, pending):
        """The connection's single HTTP/3 control flow, or None when hidden."""
        if not self._show_control_frames:
            return None
        flow = self._flows.get(conn.h3_control_flow_id or "")
        if flow is not None:
            return flow
        flow = self._open_quic_flow(conn, event, pending)
        conn.h3_control_flow_id = flow.flow_id
        return flow

    def _quic_stream_flow(self, conn, chunk, event, pending):
        """The flow of *chunk*'s request stream, opening one when unknown."""
        flow = self._flows.get(conn.quic_stream_flows.get(chunk.stream_id, ""))
        if flow is not None:
            return flow
        if not self._is_stream_aware(conn.parser):
            return self._get_or_create_active_flow(conn, event, pending)
        flow = self._open_quic_flow(conn, event, pending, chunk.direction)
        self._remember_quic_stream_flow(conn, chunk.stream_id, flow)
        return flow

    def _open_quic_flow(self, conn, event, pending, direction: str = "write"):
        """Create a device->server oriented flow that is NOT the active flow."""
        flow = self._make_flow(conn, event, self._oriented_endpoints(event, direction))
        flow.detected_protocol = getattr(conn.parser, 'PROTOCOL', '') or ''
        pending.append((FlowEventType.CREATED, flow))
        return flow

    def _remember_quic_stream_flow(self, conn, real_sid: int, flow) -> None:
        """Index *flow* under its real and its dense (collector) stream id.

        ``quic_stream_flows`` survives the flow's completion so late DATA of
        the stream still finds its flow instead of opening a stray one.
        """
        conn.quic_stream_flows[real_sid] = flow.flow_id
        if self._is_stream_aware(conn.parser):
            self._h2_stream_flows.setdefault(
                (conn.conn_id, conn.map_qsid(real_sid)), flow.flow_id)

    # ------------------------------------------------------------------
    # Finalize
    # ------------------------------------------------------------------

    @staticmethod
    def _is_quic_connection(conn) -> bool:
        """True if *conn* carries the QUIC transport."""
        return conn.transport == _TRANSPORT_QUIC

    def _complete_quic_stream_flows(self, conn, ended: float, pending: list) -> None:
        """Commit, flush and complete every QUIC stream/control flow of *conn*."""
        if not self._is_quic_connection(conn):
            return
        self._flush_quic_connection(conn, pending)
        for flow in self._quic_owned_flows(conn):
            self._complete_flow(flow, ended, pending)

    def _flush_quic_connection(self, conn, pending: list) -> None:
        """Commit still-buffered stream chunks and flush the parser per stream.

        Runs before the legacy commit/flush, which would otherwise feed the
        buffered chunks without stream ids and hand every stream's partial
        result to the connection's active flow. QUIC connections only: callers
        check :meth:`_is_quic_connection` first.
        """
        self._commit_quic_pending(conn, pending)
        self._flush_quic_parser(conn)

    def _commit_quic_pending(self, conn, pending: list) -> None:
        """Force-commit a parser for still-buffered QUIC stream chunks."""
        event = conn.quic_last_event
        if conn.parser is not None or event is None:
            return
        if not any(chunk.stream_id is not None for chunk in conn.pending_chunks):
            return
        self._ensure_quic_parser(conn, list(conn.pending_chunks), force=True)
        self._feed_quic_pending(conn, event, pending)

    def _flush_quic_parser(self, conn) -> None:
        """Fill missing request/response of stream flows from the parser flush."""
        if not (conn.quic_stream_flows and self._is_stream_aware(conn.parser)):
            return
        try:
            results = conn.parser.flush()
        except Exception:
            logger.debug("QUIC parser flush raised", exc_info=True)
            return
        for result in results:
            flow = self._flows.get(conn.quic_stream_flows.get(result.stream_id, ""))
            if flow is None or not (result.method or result.status_code):
                continue
            field = "request" if result.is_request else "response"
            if getattr(flow, field) is None:
                setattr(flow, field, dataclasses.replace(
                    result, stream_id=conn.map_qsid(result.stream_id)))

    def _quic_owned_flows(self, conn) -> list:
        """The control flow plus every stream flow of *conn*, deduplicated."""
        flow_ids = [conn.h3_control_flow_id, *conn.quic_stream_flows.values()]
        unique_ids = dict.fromkeys(fid for fid in flow_ids if fid)
        return [self._flows[fid] for fid in unique_ids if fid in self._flows]
