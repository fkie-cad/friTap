"""Map captured QUIC DatalogEvents onto synthetic QUIC datagrams for -p writers.

Each QUIC stream record goes through :class:`SyntheticQuicWriter`; every
datagram it emits comes back as a DatalogEvent copy carrying the record's
real tuple (client = the app's local side), so the -p handlers write it with
their usual UDP framing. Everything else is left to the legacy path.

Handlers call :meth:`QuicPcapBridge.route`, :meth:`~QuicPcapBridge.close_on_destroyed`
and :meth:`~QuicPcapBridge.close_all` with their own record writer
(``write_record(record, timestamp=None)``) and secrets writer (``write_secrets(lines)``).
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field, replace
from typing import Callable, Dict, List, Optional, Tuple

from ..capture_time import arrival_time
from ..constants import DIRECTION_READ, DIRECTION_WRITE, direction_for_function
from ..events import SESSION_DESTROYED
from . import quic_synthetic
from .bounded_lru import BoundedLRU
from .quic_synthetic import CLIENT, SERVER, SyntheticOutput

_logger = logging.getLogger("friTap.output.quic_pcap")

QUIC_PAYLOAD_STREAM = "stream"
QUIC_PAYLOAD_BODY = "body"
_QUIC_PAYLOADS = (QUIC_PAYLOAD_STREAM, QUIC_PAYLOAD_BODY)

INSTALL_NOTICE = "install fritap[quic-pcap] for Wireshark-viewable HTTP/3"

# Real tuples remembered for open synthetic connections (needed at close).
DEFAULT_MAX_TRACKED_CONNECTIONS = 1024

#: One side of a connection: (printable addr, raw addr, port).
_Side = Tuple[str, object, int]

#: ``write_record(record, timestamp=None)`` and ``write_secrets(lines)`` of a handler.
RecordWriter = Callable[..., None]
SecretsWriter = Callable[[List[str]], None]

# Stream ids the synthetic writer can never carry need no offset tracking.
_MAX_TRACKED_STREAM_ID = quic_synthetic.MAX_STREAMS_PER_TYPE * 4


@dataclass
class QuicPcapOutput:
    """Synthetic datagrams as writable records, plus new synthetic key log lines."""

    records: list = field(default_factory=list)
    keylog_lines: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class _ConnectionTuple:
    local: _Side
    remote: _Side
    ss_family: str


@dataclass
class _ConnectionState:
    """What one open connection needs: its tuple, record templates and stream positions."""

    tup: _ConnectionTuple
    #: Per sending side, a payload-free record carrying that side's tuple.
    templates: Dict[str, object]
    #: (stream_id, side) -> next stream offset not yet written.
    next_offsets: Dict[Tuple[int, str], int] = field(default_factory=dict)
    gap_logged: bool = False


def is_quic_stream_record(event) -> bool:
    """True for a UDP record that carries data of a real QUIC stream."""
    stream_id = getattr(event, "stream_id", None)
    if getattr(event, "transport", "tcp") != "udp" or isinstance(stream_id, bool):
        return False
    if not isinstance(stream_id, int) or stream_id < 0:
        return False
    return (getattr(event, "quic_payload", "") in _QUIC_PAYLOADS
            or bool(getattr(event, "http3_headers", None)))


def record_side(event) -> str:
    """Synthetic endpoint that sent *event*: the app's local side is the client."""
    direction = direction_for_function(getattr(event, "function", ""), getattr(event, "direction", ""))
    return SERVER if direction == DIRECTION_READ else CLIENT


def _side(event, prefix: str) -> _Side:
    return (getattr(event, prefix + "_addr"), getattr(event, prefix + "_addr_raw"),
            getattr(event, prefix + "_port"))


def _connection_tuple(event) -> _ConnectionTuple:
    src, dst = _side(event, "src"), _side(event, "dst")
    local, remote = (dst, src) if record_side(event) == SERVER else (src, dst)
    return _ConnectionTuple(local, remote, event.ss_family)


def _side_template(event, tup: _ConnectionTuple, side: str):
    # Built once per connection and side; holding no payload keeps it small.
    src, dst = (tup.local, tup.remote) if side == CLIENT else (tup.remote, tup.local)
    return replace(
        event, data=b"", function="",
        direction=DIRECTION_WRITE if side == CLIENT else DIRECTION_READ,
        src_addr=src[0], src_addr_raw=src[1], src_port=src[2],
        dst_addr=dst[0], dst_addr_raw=dst[1], dst_port=dst[2],
        ss_family=tup.ss_family, stream_id=-1, quic_payload="", http3_headers=None,
        endpoints_synthetic=False,
        # Datagrams are stamped with their own time; an inherited arrival
        # time would override it.
        received_at=None,
    )


def _datagram_record(template, payload: bytes, now: float):
    return replace(template, data=payload, timestamp=now)


class QuicPcapBridge:
    """Per-handler adapter between DatalogEvents and a SyntheticQuicWriter."""

    def __init__(self, writer=None, available: Optional[Callable[[], bool]] = None,
                 notice: Optional[Callable[[str], None]] = None,
                 max_tracked: int = DEFAULT_MAX_TRACKED_CONNECTIONS) -> None:
        self._available = (available or quic_synthetic.is_available)()
        self._writer = writer if writer is not None else (
            quic_synthetic.SyntheticQuicWriter() if self._available else None)
        self._notice = notice or _logger.info
        self._notice_shown = False
        # Never track more than the writer keeps open: the bridge then always
        # evicts (and closes) first, so both LRUs hold the same connections.
        writer_cap = getattr(self._writer, "max_connections", None)
        cap = min(max_tracked, writer_cap) if isinstance(writer_cap, int) else max_tracked
        self._connections: "BoundedLRU[str, _ConnectionState]" = BoundedLRU(cap)
        # Reentrant: route() holds it across translate() and the writes, so a
        # connection's offsets, aioquic feed and file order form one atomic step.
        # Order is always bridge lock -> writer lock; the writer never calls back.
        self._lock = threading.RLock()

    @property
    def active(self) -> bool:
        return self._writer is not None

    def wants_empty_record(self, event) -> bool:
        """A header-only record (no data) is still writable when synthesised."""
        return self.active and is_quic_stream_record(event) and bool(getattr(event, "http3_headers", None))

    def should_write(self, event) -> bool:
        """Whether a handler should write *event* at all."""
        return bool(event.data) or self.wants_empty_record(event)

    # --- handler entry points -------------------------------------------------

    def route(self, event, write_record: RecordWriter, write_secrets: SecretsWriter) -> None:
        """Write *event* as synthetic QUIC datagrams when possible, else as it is."""
        with self._lock:
            evicted, synthetic = self._translate(event)
            self._emit(evicted, write_record, write_secrets)
            if synthetic is not None:
                self._emit(synthetic, write_record, write_secrets)
            elif event.data:
                write_record(event)

    def close_on_destroyed(self, event, write_record: RecordWriter, write_secrets: SecretsWriter) -> None:
        """Write the CONNECTION_CLOSE of a connection whose session was destroyed."""
        if event.event_type == SESSION_DESTROYED and event.session_id:
            with self._lock:
                self._emit(self.close_connection(event.session_id, event.timestamp), write_record, write_secrets)

    def close_all(self, write_record: RecordWriter, write_secrets: SecretsWriter,
                  now: Optional[float] = None) -> None:
        """Close every connection still open (end of capture)."""
        now = time.time() if now is None else now
        with self._lock:
            for conn_key in self._connections.keys():
                self._emit(self.close_connection(conn_key, now), write_record, write_secrets)

    # --- translation ------------------------------------------------------------

    def translate(self, event) -> Optional[QuicPcapOutput]:
        """Synthetic records for *event*, or None to write it the legacy way.

        Close records of a connection evicted to make room come first.
        """
        evicted, synthetic = self._translate(event)
        if synthetic is None:
            return evicted if evicted.records else None
        return QuicPcapOutput(records=evicted.records + synthetic.records,
                              keylog_lines=evicted.keylog_lines + synthetic.keylog_lines)

    def _translate(self, event) -> Tuple[QuicPcapOutput, Optional[QuicPcapOutput]]:
        """(close records of evicted connections, synthetic records or None for legacy)."""
        evicted = QuicPcapOutput()
        if not is_quic_stream_record(event):
            return evicted, None
        if not self.active:
            self._show_install_notice_once()
            return evicted, None
        now = arrival_time(event)
        with self._lock:
            state = self._state_for(event, now, evicted)
            data = self._unwritten_bytes(state, event)
            if data is None:
                # Retransmitted bytes already written once: nothing new to show.
                return evicted, QuicPcapOutput()
            # Fed under the same lock as the offset bookkeeping above, so
            # aioquic sees a stream's chunks in the order their offsets were taken.
            output = self._feed(event, data, now)
        # Nothing re-encapsulated (e.g. over budget): keep the bytes visible as bare UDP.
        if not output.packets:
            return evicted, None
        return evicted, self._as_records(state, output, now)

    def close_connection(self, conn_key: str, now: float) -> QuicPcapOutput:
        """CONNECTION_CLOSE datagrams for a destroyed connection (if it is open)."""
        with self._lock:
            state = self._connections.pop(conn_key)
            if state is None or not self.active:
                return QuicPcapOutput()
            return self._as_records(state, self._writer.close(conn_key, now), now)

    def _feed(self, event, data: bytes, now: float) -> SyntheticOutput:
        key, side = event.ssl_session_id, record_side(event)
        if event.quic_payload == QUIC_PAYLOAD_STREAM:
            return self._writer.feed_stream(key, side, event.stream_id, data, event.fin, now)
        return self._writer.feed_headers_body(
            key, side, event.stream_id, event.http3_headers, data or None, event.fin, now)

    def _state_for(self, event, now: float, evicted: QuicPcapOutput) -> _ConnectionState:
        tup = _connection_tuple(event)
        state = self._connections.get(event.ssl_session_id)
        if state is None or state.tup != tup:
            templates = {side: _side_template(event, tup, side) for side in (CLIENT, SERVER)}
            state = _ConnectionState(tup, templates, state.next_offsets if state else {})
            for old_key, old_state in self._connections.put(event.ssl_session_id, state):
                self._close_evicted(old_key, old_state, now, evicted)
        return state

    def _close_evicted(self, conn_key, state: _ConnectionState, now: float, out: QuicPcapOutput) -> None:
        # Forgetting the offsets must also end the synthetic connection: else
        # close_all() never closes it and a returning connection would re-feed
        # retransmitted bytes into the still-open one.
        closed = self._as_records(state, self._writer.close(conn_key, now), now)
        out.records.extend(closed.records)
        out.keylog_lines.extend(closed.keylog_lines)

    def _unwritten_bytes(self, state: _ConnectionState, event) -> Optional[bytes]:
        """The record's bytes past what this stream already carried; None if nothing is new."""
        data = event.data or b""
        offset = event.stream_offset
        if (event.quic_payload != QUIC_PAYLOAD_STREAM or offset is None
                or event.stream_id >= _MAX_TRACKED_STREAM_ID):
            return data
        key = (event.stream_id, record_side(event))
        expected = state.next_offsets.get(key)
        state.next_offsets[key] = max(expected or 0, offset + len(data))
        if expected is None or offset == expected:
            return data
        if offset > expected:
            # The synthetic stream just continues; aioquic numbers its own offsets.
            self._log_gap_once(state, event, expected)
            return data
        fresh = data[expected - offset:]
        return fresh if fresh or event.fin else None

    @staticmethod
    def _log_gap_once(state: _ConnectionState, event, expected: int) -> None:
        if state.gap_logged:
            return
        state.gap_logged = True
        _logger.debug("synthetic QUIC: %r stream %d jumps from offset %d to %d; missing bytes skipped",
                      event.ssl_session_id, event.stream_id, expected, event.stream_offset)

    @staticmethod
    def _as_records(state: _ConnectionState, output: SyntheticOutput, now: float) -> QuicPcapOutput:
        records = [_datagram_record(state.templates[side], payload, now) for side, payload in output.packets]
        return QuicPcapOutput(records=records, keylog_lines=list(output.keylog_lines))

    @staticmethod
    def _emit(output: QuicPcapOutput, write_record: RecordWriter, write_secrets: SecretsWriter) -> None:
        # Secrets first: Wireshark reads DSBs in file order, and a sidecar must
        # be complete whenever its packets are.
        if output.keylog_lines:
            write_secrets(output.keylog_lines)
        for record in output.records:
            write_record(record, timestamp=record.timestamp)

    def _show_install_notice_once(self) -> None:
        if self._notice_shown:
            return
        self._notice_shown = True
        self._notice(INSTALL_NOTICE)
