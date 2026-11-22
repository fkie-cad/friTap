"""Connection-state lifecycle for :class:`FlowCollector`.

The host class owns the state; methods run under its lock unless noted.
Collector constants are read through ``_collector()`` at call time so patches take effect.
"""

import logging
from typing import Optional

from .collector_state import (
    _ConnectionState,
    _merge_connection_attribution,
    _merge_pop,
    _merge_session_meta,
)
from .collector_state import collector_module as _collector
from .models import Flow, FlowEventType, FlowState
from .synthetic_endpoint_upgrade import (
    observed_endpoint_map,
    provisional_endpoint_map,
    provisional_sides,
    upgrade_flow_endpoints,
)

# The collector's logger, so existing log filters and levels keep matching.
logger = logging.getLogger("friTap.flow.collector")


class ConnectionLifecycleMixin:
    """Lifetimes, idle and LRU eviction, finalize, the periodic sweep, and connection re-keying with endpoint upgrades."""

    def _start_connection_lifetime(self, conn_id: str, event) -> '_ConnectionState':
        """Fresh state for *conn_id*, recording the first flow sequence of this lifetime (``_lifetime_first_seq``). Under lock."""
        self._lifetime_first_seq[conn_id] = self._flow_seq.get(conn_id, 0)
        return self._new_connection_state(conn_id, event)

    def _is_current_lifetime_flow(self, flow: Flow) -> bool:
        """True unless *flow* was minted in an earlier lifetime of its connection id (sequence below the current first). Under lock."""
        seq = self._flow_sequence_of(flow)
        return seq is None or seq >= self._lifetime_first_seq.get(flow.connection_id, 0)

    @staticmethod
    def _new_connection_state(conn_id: str, event) -> '_ConnectionState':
        """Fresh per-connection state carrying the event's transport."""
        transport = getattr(event, 'protocol', 'tls') or 'tls'
        return _ConnectionState(conn_id, transport=transport)

    @staticmethod
    def _is_exempt_from_idle(conn: '_ConnectionState') -> bool:
        """Secret-Chat connections keep their open request across idle gaps: a reply routinely arrives minutes later, and an idle reset/sweep would finalize the request-only flow and break pairing."""
        return conn.transport == _collector()._TRANSPORT_TELEGRAM_E2E

    def _is_idle_gap(self, conn: '_ConnectionState', timestamp: float) -> bool:
        """True if *conn* sat idle longer than IDLE_THRESHOLD before *timestamp*."""
        if conn.last_activity <= 0 or self._is_exempt_from_idle(conn):
            return False
        return (timestamp - conn.last_activity) > _collector().IDLE_THRESHOLD

    def _lifecycle_conn_id(self, event, conn_id: str) -> str:
        """Map a SessionEvent's key onto the live connection it aliases. Under lock."""
        return self._key_aliases.lookup(
            conn_id,
            getattr(event, 'src_addr', ''), getattr(event, 'src_port', 0),
            getattr(event, 'dst_addr', ''), getattr(event, 'dst_port', 0),
            self._connections.__contains__,
        )

    def _finalize_connection(self, conn: '_ConnectionState', ended: float,
                              pending: list) -> None:
        """Flush parser and mark the active flow as complete. Must be called under lock."""
        self._complete_quic_stream_flows(conn, ended, pending)
        if conn.parser is None and conn.pending_chunks:
            self._commit_pending(conn)

        if conn.parser:
            self._flush_parser_to_flow(conn, pending)
        if conn.active_flow_id and conn.active_flow_id in self._flows:
            self._complete_flow(self._flows[conn.active_flow_id], ended, pending)
        self._complete_h2_side_flows(conn, ended, pending)

        stale_streams = [key for key in self._h2_stream_flows
                         if key[0] == conn.conn_id]
        for key in stale_streams:
            del self._h2_stream_flows[key]

        # Bound growth across many short-lived connections.
        self._session_tls.pop(conn.conn_id, None)
        self._connection_attributions.pop(conn.conn_id, None)
        self._forget_client_random(conn)

    def _periodic_sweep(self, pending: list) -> None:
        """Periodic maintenance: clean stale indices, idle connections, body caches. Under lock."""
        now = self._now()

        # 1. Orphan requests older than IDLE_THRESHOLD or whose flow is gone.
        for key, candidates in list(self._orphan_requests.items()):
            valid = [(ts, fid) for ts, fid in candidates
                     if (now - ts) <= _collector().IDLE_THRESHOLD and fid in self._flows]
            self._replace_orphan_candidates(key, valid)

        # 2. H2 stream entries of finalized connections or completed/missing flows.
        stale_streams = [
            key for key, fid in self._h2_stream_flows.items()
            if key[0] not in self._connections
            or fid not in self._flows
            or self._flows[fid].state == FlowState.COMPLETE
        ]
        for key in stale_streams:
            del self._h2_stream_flows[key]

        # 3. Connections idle for 2x IDLE_THRESHOLD (never got SESSION_ENDED).
        idle_threshold = 2 * _collector().IDLE_THRESHOLD
        idle_conn_ids = [
            cid for cid, conn in self._connections.items()
            if conn.last_activity > 0 and (now - conn.last_activity) > idle_threshold
            and not self._is_exempt_from_idle(conn)
        ]
        for conn_id in idle_conn_ids:
            conn = self._connections[conn_id]
            self._finalize_connection(conn, conn.last_activity, pending)
            del self._connections[conn_id]

        # 4. Expire finished request contexts (emitted by the entry point).
        #    Not under the event clock: the combined pass replays QUIC after TLS,
        #    so "now" can run past contexts QUIC flows still need.
        if not self._use_event_clock:
            self._finished_request_contexts.extend(self._request_contexts.expire(now))

        # 5. Body caches of completed flows (rebuilt on demand).
        for flow in self._flows.values():
            if flow.state == FlowState.COMPLETE and flow._body_cache:
                flow._body_cache.clear()

    def _touch_connection(self, conn_id: str, event, pending: list) -> '_ConnectionState':
        """Return *conn_id*'s state (created if new), marked most recently used; creating one past MAX_TRACKED_CONNECTIONS evicts the LRU. Under lock."""
        conn = self._connections.get(conn_id)
        if conn is not None:
            self._connections.move_to_end(conn_id)
            return conn
        conn = self._start_connection_lifetime(conn_id, event)
        self._connections[conn_id] = conn
        while len(self._connections) > _collector().MAX_TRACKED_CONNECTIONS:
            self._evict_oldest_connection(pending)
        return conn

    def _evict_oldest_connection(self, pending: list) -> None:
        """Finalize and forget the least recently used connection, like the idle sweep (flows completed, COMPLETED queued on *pending*, before its state goes). Under lock."""
        _conn_id, conn = self._connections.popitem(last=False)
        self._warn_cap_once("connections", _collector().MAX_TRACKED_CONNECTIONS)
        self._finalize_connection(conn, conn.last_activity or self._now(), pending)

    def _warn_cap_once(self, what: str, cap: int) -> None:
        """Log one warning the first time the *what* cap trips."""
        if what in self._caps_warned:
            return
        self._caps_warned.add(what)
        logger.warning(
            "Flow collector tracks more than %d %s; evicting the least "
            "recently used (possible connection-id flood)", cap, what)

    def _may_promote_connection(self, owner: str, record_key: str) -> bool:
        """Whether the live connection *owner* may be re-keyed under *record_key*: only while it has no
        client_random, and never onto a key ever used as a connection id (flow ids and lifetimes never mix). Under lock."""
        conn = self._connections.get(owner)
        return (conn is not None and not conn.client_random
                and record_key not in self._connections
                and record_key not in self._flow_seq)

    def _rename_connection(self, conn: '_ConnectionState', new_id: str,
                           pending: list) -> None:
        """Move all per-connection state of *conn* to *new_id* and queue an UPDATED per renamed flow.

        Flow ids keep their old prefix (subscribers know them by it); key aliases were already renamed by the index. Under lock.
        """
        old_id = conn.conn_id
        del self._connections[old_id]
        conn.conn_id = new_id
        self._connections[new_id] = conn
        self._merge_renamed_state(old_id, new_id)
        cached_meta = self._session_tls.get(new_id)
        for flow in self._connection_flows(new_id):
            flow.connection_id = new_id
            if cached_meta:
                self._apply_session_metadata(flow, cached_meta)
            pending.append((FlowEventType.UPDATED, flow))

    def _merge_renamed_state(self, old_id: str, new_id: str) -> None:
        """Fold *old_id*'s per-connection tables into *new_id*'s, merging (not overwriting): *new_id* may already hold
        entries (e.g. a SESSION_STARTED keyed by the client_random before promotion). Under lock."""
        _merge_pop(self._session_tls, old_id, new_id,
                   lambda new, old: _merge_session_meta(old, new))
        _merge_pop(self._connection_attributions, old_id, new_id,
                   _merge_connection_attribution)
        # new_id never minted flows (_may_promote_connection), so the merged
        # counter below is old_id's and the lifetime baseline must be too.
        _merge_pop(self._lifetime_first_seq, old_id, new_id, lambda new, old: old)
        _merge_pop(self._flow_index, old_id, new_id, lambda new, old: old + new)
        # The old counter stays too: its flow ids are still in use.
        self._flow_seq[new_id] = max(self._flow_seq.get(old_id, 0),
                                     self._flow_seq.get(new_id, 0))
        for key in [k for k in self._h2_stream_flows if k[0] == old_id]:
            self._h2_stream_flows.setdefault((new_id, key[1]), self._h2_stream_flows.pop(key))

    def _learn_real_endpoints(self, conn: '_ConnectionState', event, pending: list) -> None:
        """Learn the real tuple behind *conn*'s synthetic pin (first one wins)
        and upgrade the connection's synthetic flows to it. Under lock."""
        if conn.real_endpoint_map is not None:
            return
        mapping = observed_endpoint_map(event) or self._provisional_endpoint_map(conn, event)
        if mapping is None:
            return
        conn.real_endpoint_map = mapping
        for flow in self._connection_flows(conn.conn_id):
            if upgrade_flow_endpoints(flow, mapping):
                self._append_progress(pending, flow)

    @staticmethod
    def _provisional_endpoint_map(conn: '_ConnectionState', event) -> Optional[dict]:
        """Remember an agent-guessed (provisional) tuple of *conn*; on the first
        real record after one, the map from those guesses to the real tuple."""
        sides = provisional_sides(event)
        if sides is None:
            return provisional_endpoint_map(conn.provisional_sides, event) if conn.provisional_sides else None
        # Bounded: the guess only varies with the best-effort observed peer.
        if (sides not in conn.provisional_sides
                and len(conn.provisional_sides) < _collector()._MAX_PROVISIONAL_SIDES):
            conn.provisional_sides.append(sides)
        return None

    @staticmethod
    def _stamp_synthetic_endpoints(flow: Flow, conn: '_ConnectionState', event) -> None:
        """Flag a flow born on a synthetic pin, upgrading it at once when the
        connection's real tuple is already known."""
        flow.endpoints_synthetic = bool(getattr(event, 'endpoints_synthetic', False))
        mapping = getattr(conn, 'real_endpoint_map', None)
        if mapping is not None:
            upgrade_flow_endpoints(flow, mapping)
