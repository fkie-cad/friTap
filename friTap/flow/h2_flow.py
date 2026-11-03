"""Frame-exact HTTP/2 flow attribution for :class:`~.collector.FlowCollector`.

A decrypted TLS record is not an HTTP/2 unit: one record carries frames of
several multiplexed streams, and one frame (a 16 KiB DATA frame, a large
HEADERS block) spans several records. Attaching whole records to whichever
flow produced a ParseResult in that feed — and every result-less record to the
connection's "active" flow — scattered a stream's DATA over unrelated flows
and broke the frame alignment :meth:`Flow._extract_h2_body` relies on (it walks
a flow's per-direction bytes as one frame sequence from offset 0), so bodies
came out empty or partial.

Instead the parser reports every frame it consumed
(:meth:`~friTap.parsers.http2.Http2Parser.take_frame_log`) and this mixin gives
each stream's flow exactly its own complete frames. Every flow's per-direction
bytes are thereby a frame-aligned sequence again — no ``.tap`` format change.
"""

from __future__ import annotations

import logging
from dataclasses import replace
from types import SimpleNamespace
from typing import Optional

from friTap.parsers.base import unwrap_parser
from friTap.parsers.http2 import Http2Parser

from .models import Flow, FlowChunk, FlowEventType, FlowState

logger = logging.getLogger(__name__)

# Per-connection cap on remembered stream -> flow routes (oldest dropped). A
# dropped route only matters for a late frame of a long-finished stream.
_MAX_ROUTED_H2_STREAMS = 1024

# Key of connection-level bytes (stream-0 frames, connection preface).
_CONNECTION_KEY = 0

# Frame types carrying stream payload (DATA, HEADERS, PUSH_PROMISE,
# CONTINUATION). A late one opens a fresh flow for its stream; any other late
# frame (RST_STREAM, WINDOW_UPDATE, PRIORITY) joins the control flow.
_STREAM_PAYLOAD_FRAME_TYPES = frozenset({0x0, 0x1, 0x5, 0x9})


class Http2StreamFlowMixin:
    """Routes each HTTP/2 frame to the flow of the stream it belongs to."""

    # ------------------------------------------------------------------
    # Classification
    # ------------------------------------------------------------------

    @staticmethod
    def _is_h2_connection(conn) -> bool:
        """True while *conn* runs an HTTP/2 parser that has not failed."""
        return (isinstance(unwrap_parser(conn.parser), Http2Parser)
                and not getattr(conn.parser, 'failed', False))

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    def _process_h2_chunk(self, conn, chunk: FlowChunk, event, pending: list) -> None:
        """Feed one plaintext record and attribute its frames. Under lock."""
        h2 = unwrap_parser(conn.parser)
        h2.enable_frame_log()
        results = self._filter_control_frames(
            conn.parser.feed(chunk.data, chunk.direction))
        frames = h2.take_frame_log()
        if getattr(conn.parser, 'failed', False):
            # The parser just died mid-record: keep its raw bytes the legacy
            # way (whole record on the active flow) from here on.
            self._attach_whole_chunk(conn, chunk, event, pending)
            return
        conn.h2_last_chunk[chunk.direction] = chunk
        pieces = self._h2_pieces(frames, results, chunk)
        for result in results:
            piece = pieces.pop(result.stream_id, None)
            flow = self._apply_h2_result(conn, result, piece, event, pending)
            self._append_progress(pending, flow)
        for key, piece in pieces.items():
            self._attach_h2_piece(conn, key, piece, event, pending)
        if conn.protocol_stamp_pending:
            conn.protocol_stamp_pending = not self._stamp_detected_protocol(conn)

    def _attach_whole_chunk(self, conn, chunk: FlowChunk, event, pending: list) -> None:
        """Legacy placement: the whole record on the connection's active flow."""
        flow = self._get_or_create_active_flow(conn, event, pending)
        self._append_chunk(flow, chunk)
        self._append_progress(pending, flow)

    # ------------------------------------------------------------------
    # Grouping
    # ------------------------------------------------------------------

    @staticmethod
    def _h2_pieces(frames: list, results: list, chunk: FlowChunk) -> dict:
        """Group this feed's frames into one FlowChunk per destination key.

        The key is the frame's stream id. Connection-level frames go to the
        control result when the feed produced one; otherwise they ride with
        the record's first stream frame (as they did when whole records were
        attached), else stay under :data:`_CONNECTION_KEY`.
        """
        if any(result.stream_id == _CONNECTION_KEY for result in results):
            connection_key = _CONNECTION_KEY
        else:
            connection_key = next(
                (sid for _direction, sid, _raw in frames if sid), _CONNECTION_KEY)
        grouped: dict[int, bytearray] = {}
        for _direction, stream_id, raw in frames:
            grouped.setdefault(stream_id or connection_key, bytearray()).extend(raw)
        return {key: replace(chunk, data=bytes(data)) for key, data in grouped.items()}

    # ------------------------------------------------------------------
    # Results
    # ------------------------------------------------------------------

    def _apply_h2_result(self, conn, result, piece: Optional[FlowChunk],
                         event, pending: list) -> Flow:
        """Create/update the result's flow, attaching its stream's frames once."""
        if result.is_control_frame and not result.is_request:
            return self._attach_h2_control_response(conn, result, piece, event, pending)
        flow = self._create_or_update_flow(conn, piece, result, event, pending)
        self._stamp_protocol_on(flow, conn)
        if result.is_control_frame:
            conn.h2_control_flow_id = flow.flow_id
        elif result.stream_id:
            self._remember_h2_stream_flow(conn, result.stream_id, flow)
        return flow

    def _attach_h2_control_response(self, conn, result, piece: Optional[FlowChunk],
                                    event, pending: list) -> Flow:
        """Answer the connection's control flow with a server control frame.

        The generic response path attached it to the active (request) flow,
        completing that request with a SETTINGS "response" before its real
        response arrived; the real one then landed on an already-written flow
        and was lost from the ``.tap``. A control flow that already holds a
        response gets a fresh sibling (not made the active flow). Because it
        is never the active flow, the protocol label is stamped here directly
        (a GOAWAY-only connection would otherwise stay unlabelled).
        """
        flow = self._open_h2_control_flow(conn, event, pending)
        self._attach_response(flow, result, piece, event.timestamp, pending)
        return flow

    def _open_h2_control_flow(self, conn, event, pending: list) -> Flow:
        """The connection's still-open control flow, created when needed.

        Open means ACTIVE without a response: it has not been written yet and
        will be at completion (response, idle finalize, flush). Labelled
        HTTP/2 here since it is usually not the active flow.
        """
        flow = self._flows.get(conn.h2_control_flow_id or "")
        if flow is None or flow.state != FlowState.ACTIVE or flow.response is not None:
            flow = self._make_flow(conn, event)
            pending.append((FlowEventType.CREATED, flow))
            conn.h2_control_flow_id = flow.flow_id
        self._stamp_protocol_on(flow, conn)
        return flow

    def _complete_h2_side_flows(self, conn, ended: float, pending: list) -> None:
        """Complete *conn*'s control and late-stream flows (not the active flow).

        Called when the connection is finalized (idle gap, sweep, eviction),
        so late frames parked there reach the writers then, not only at flush.
        """
        side_ids = [conn.h2_control_flow_id, *conn.h2_late_stream_flow_ids]
        for flow_id in side_ids:
            flow = self._flows.get(flow_id or "")
            if flow is not None:
                self._complete_flow(flow, ended, pending)
        conn.h2_late_stream_flow_ids.clear()

    # ------------------------------------------------------------------
    # Result-less frames
    # ------------------------------------------------------------------

    def _attach_h2_piece(self, conn, key: int, piece: FlowChunk,
                         event, pending: list) -> None:
        """Place frames whose stream produced no result in this feed."""
        flow = self._h2_destination(conn, key, piece.data, event, pending)
        if flow is None:
            return  # connection-level bytes while control frames are hidden
        self._stamp_protocol_on(flow, conn)
        self._append_chunk(flow, piece)
        self._append_progress(pending, flow)

    def _h2_destination(self, conn, key: int, data: bytes,
                        event, pending: list) -> Optional[Flow]:
        """The flow of stream *key*; the active flow for an unknown stream.

        An unknown stream (e.g. its HEADERS predate the capture) is pinned to
        the flow that received its first frame, so its frames stay together.
        Routes outlive the flow's completion, so a late frame (a client
        RST_STREAM after the server's END_STREAM, a WINDOW_UPDATE) is still
        recognized; see :meth:`_h2_late_frame_destination`.
        """
        if key == _CONNECTION_KEY:
            if not self._show_control_frames:
                return None
            return self._get_or_create_active_flow(conn, event, pending)
        flow = self._flows.get(conn.h2_stream_flows.get(key, ""))
        if flow is None:
            flow = self._get_or_create_active_flow(conn, event, pending)
            self._remember_h2_stream_flow(conn, key, flow)
        elif flow.state != FlowState.ACTIVE:
            return self._h2_late_frame_destination(conn, key, data, event, pending)
        return flow

    def _h2_late_frame_destination(self, conn, key: int, data: bytes,
                                   event, pending: list) -> Optional[Flow]:
        """Where frames of an already completed (written) stream flow go.

        Appending to the completed flow would never reach the ``.tap`` (it was
        handed to the writers at completion, and completed flows are not
        reopened). Stream payload opens a fresh flow for stream *key*; pure
        control frames join the connection's open control flow, like other
        control traffic — dropped while control frames are hidden.
        """
        if key != _CONNECTION_KEY and self._carries_stream_payload(data):
            return self._open_h2_late_stream_flow(conn, key, event, pending)
        if not self._show_control_frames:
            return None
        return self._open_h2_control_flow(conn, event, pending)

    @staticmethod
    def _carries_stream_payload(data: bytes) -> bool:
        """True when any frame in *data* (complete frames, the last possibly
        truncated) is a DATA/HEADERS/PUSH_PROMISE/CONTINUATION frame."""
        offset = 0
        while offset + 4 <= len(data):
            if data[offset + 3] in _STREAM_PAYLOAD_FRAME_TYPES:
                return True
            offset += 9 + int.from_bytes(data[offset:offset + 3], "big")
        return False

    def _open_h2_late_stream_flow(self, conn, key: int, event, pending: list) -> Flow:
        """A fresh flow for stream *key*, now its route, labelled HTTP/2.

        It is not the active flow, so the connection's finalize completes it
        (see :meth:`_complete_h2_side_flows`); flush completes it otherwise.
        """
        flow = self._make_flow(conn, event)
        pending.append((FlowEventType.CREATED, flow))
        self._remember_h2_stream_flow(conn, key, flow)
        conn.h2_late_stream_flow_ids.append(flow.flow_id)
        self._stamp_protocol_on(flow, conn)
        return flow

    @staticmethod
    def _remember_h2_stream_flow(conn, stream_id: int, flow: Flow) -> None:
        """Route stream *stream_id* of *conn* to *flow* (bounded, LRU)."""
        routes = conn.h2_stream_flows
        routes[stream_id] = flow.flow_id
        routes.move_to_end(stream_id)
        while len(routes) > _MAX_ROUTED_H2_STREAMS:
            routes.popitem(last=False)

    # ------------------------------------------------------------------
    # Flush
    # ------------------------------------------------------------------

    def _attach_h2_leftovers(self, conn, pending: Optional[list] = None) -> None:
        """Place bytes the parser still held at flush (truncated last frame).

        Must run right after ``conn.parser.flush()``. They go to their
        stream's flow (else the active flow) stamped like the newest record of
        their direction; without either they are dropped. If that flow already
        completed they take the late-frame route instead (CREATED events of
        flows opened for them go to *pending*).
        """
        h2 = unwrap_parser(conn.parser)
        if not isinstance(h2, Http2Parser):
            return
        pending = [] if pending is None else pending
        for direction, stream_id, raw in h2.take_frame_log():
            template = conn.h2_last_chunk.get(direction)
            flow = (self._flows.get(conn.h2_stream_flows.get(stream_id, ""))
                    or self._flows.get(conn.active_flow_id or ""))
            if template is not None and flow is not None:
                flow = self._h2_leftover_destination(
                    conn, flow, stream_id, replace(template, data=raw), pending)
            if template is None or flow is None:
                logger.debug("Dropping %d unattributed HTTP/2 bytes at flush", len(raw))
                continue
            self._append_chunk(flow, replace(template, data=raw))

    def _h2_leftover_destination(self, conn, flow: Flow, stream_id: int,
                                 piece: FlowChunk, pending: list) -> Optional[Flow]:
        """*flow* while it is open, else the late-frame destination."""
        if flow.state == FlowState.ACTIVE:
            return flow
        event = self._h2_event_like(flow, piece)
        return self._h2_late_frame_destination(conn, stream_id, piece.data, event, pending)

    @staticmethod
    def _h2_event_like(flow: Flow, chunk: FlowChunk) -> SimpleNamespace:
        """The event fields a new flow is built from, taken from *flow*'s
        endpoints and *chunk* (flush has no event of its own)."""
        return SimpleNamespace(
            timestamp=chunk.timestamp, direction=chunk.direction,
            function=chunk.function, protocol=flow.transport,
            src_addr=flow.src_addr, src_port=flow.src_port,
            dst_addr=flow.dst_addr, dst_port=flow.dst_port,
            ssl_session_id=flow.ssl_session_id)
