"""Caller-stack (``--attribute-sdk``) attribution for :class:`FlowCollector`.

The host class owns the state; methods run under its lock unless noted. Collector
constants are read through ``_collector()`` at call time so patches take effect.
"""

from typing import Optional

from friTap.caller_stack_shapes import compact_caller_stack

from .attribution import inherited_attribution, merge_attribution
from .caller_stack_stash import StashedCallerStack
from .collector_state import _ConnectionAttribution, _ConnectionState, _PendingEvents
from .collector_state import collector_module as _collector
from .models import Flow, FlowEventType


class CallerStackAttributionMixin:
    """Joins caller stacks to connections (client_random, 4-tuple, session id) and stamps SDK + originator claim on their flows."""

    @staticmethod
    def _sdk_tuple_key(src_addr, src_port, dst_addr, dst_port):
        """Unordered connection 5-tuple key for SDK joins, or ``None`` without addresses.

        Sorted because the caller stack may be captured on the read or write side.
        """
        src = (str(src_addr or ""), int(src_port or 0))
        dst = (str(dst_addr or ""), int(dst_port or 0))
        if not src[0] or not dst[0]:
            return None
        return (src, dst) if src <= dst else (dst, src)

    def _flow_tuple_key(self, flow):
        """Unordered 5-tuple key for *flow*'s endpoints (or ``None``)."""
        return self._sdk_tuple_key(
            flow.src_addr, flow.src_port, flow.dst_addr, flow.dst_port)

    @staticmethod
    def _real_sid(sid: str) -> bool:
        """True for a usable ssl_session_id: non-empty and not the null "0" (SSL_get_session is null at the first read/write)."""
        return bool(sid) and sid != "0"

    def on_sdk(self, event) -> None:
        """EventBus subscriber for CallerStackEvent: attach the caller stack.

        Stores the compact stack as ``flow.caller_stack`` (``flow.sdk`` only when the
        router classified it). Join order:

        1. **client_random** (``_conn_by_client_random``), exact and O(1); falls
           through to 2/3 only if the stack carries a tuple or real sid, so a
           cr-only stack never scans flows;
        2. the unordered **4-tuple**, skipping connections known by a different
           client_random;
        3. a **real** (non-"0") ``ssl_session_id``.

        Tuple/sid matches take the earliest flow without a caller stack, so fd/port
        reuse attributes each stack to a distinct connection. Existing values are
        never overwritten. Unmatched stacks are stashed under every key they carry;
        whichever drains first consumes the entry. Updated flows are notified after the lock.
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

    def _caller_stack_join_keys(self, event):
        """``(client_random, tuple_key, session_id)`` of a CallerStackEvent, or ``None`` when it carries none (sid is ``""`` unless real)."""
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
        """Attach *attribution* by client_random, then tuple, then session id; True when a connection took it. Under lock."""
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

        False when none has it yet (the stack often precedes its datalog);
        :meth:`_record_client_random` drains the stash later. Under lock.
        """
        conn_id = self._conn_by_client_random.get(client_random)
        if conn_id is None:
            return False
        self._attribute_connection(conn_id, attribution, pending)
        return True

    def _attribute_connection(self, conn_id, attribution, pending: list,
                              first: Optional[Flow] = None) -> None:
        """Remember *attribution* for *conn_id* and apply it to its present flows (*first* included even when unindexed). Under lock.

        Keyed on connection_id, so a later connection reusing the 4-tuple is never
        touched. Only the first flow is a direct join; the rest inherit. If *first*
        belongs to an earlier lifetime, it alone gets the stack and nothing is remembered.
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
        """Keep a live connection's first SDK/caller stack for later-born flows and note the originator for the mixed check.

        Sole writer of ``_connection_attributions``, so it owns the leak guard: a
        connection no longer in ``_connections`` was finalized and nothing would pop
        an entry written now. Under lock.
        """
        if conn_id not in self._connections:
            return
        record = self._connection_attributions.setdefault(conn_id, _ConnectionAttribution())
        record.adopt_missing(attribution)
        record.add_originator(attribution.sdk)

    def _connection_is_mixed(self, conn_id) -> bool:
        """True when *conn_id*'s originators (caller stacks and request contexts) named more than one SDK."""
        record = self._connection_attributions.get(conn_id)
        return record is not None and record.mixed

    def _mark_mixed_flows(self, conn_id, flows, updates: _PendingEvents) -> None:
        """Set ``attribution.mixed`` on *flows* of a mixed connection, queueing an UPDATED per changed flow. Under lock."""
        if not self._connection_is_mixed(conn_id):
            return
        for flow in flows:
            if self._set_attribution(flow, {"mixed": True}):
                updates.add_updated(flow)

    @classmethod
    def _apply_attribution(cls, flow: Flow, attribution, direct: bool = False) -> bool:
        """Fill *flow*'s empty ``sdk``/``caller_stack`` and, for a classified stack, its originator claim; True when anything changed."""
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
        return _collector().direct_attribution(sdk, transport.get("kind", ""))

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
        """Earliest flow matching the join keys and lacking a caller stack, or ``None``.

        A flow known by a client_random other than *client_random* is skipped. Under lock.
        """
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

        Reads the live connection, else the flow's own tls/quic layer (without creating one). Under lock.
        """
        known = self._connection_client_random(flow.connection_id)
        if not known and flow.transport in self._LIBRARY_TRANSPORTS:
            layer = flow.layer(flow.transport)
            known = getattr(layer, 'client_random', '') if layer is not None else ''
        return not known or known == client_random

    def _sibling_flows_without_sdk(self, conn_id, exclude):
        """Flows on connection *conn_id* that lack an SDK, excluding *exclude*. Under lock."""
        return self._sibling_flows_missing(conn_id, exclude, 'sdk')

    def _sibling_flows_missing(self, conn_id, exclude, attr: Optional[str]):
        """Flows on *conn_id*, excluding *exclude*, whose *attr* is falsy (every flow when ``None``). Under lock."""
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
        """Present flows of *conn_id*'s current lifetime (:meth:`_is_current_lifetime_flow`), in index order, without *exclude*. Under lock."""
        return [flow for flow in self._sibling_flows_missing(conn_id, exclude, None)
                if self._is_current_lifetime_flow(flow)]

    def _connection_sdk(self, conn_id):
        """The SDK resolved for *conn_id*, else ``None``. Under lock."""
        return self._connection_attribute(conn_id, 'sdk')

    def _connection_caller_stack(self, conn_id):
        """The caller stack joined to *conn_id*, else ``None``. Under lock."""
        return self._connection_attribute(conn_id, 'caller_stack')

    def _connection_attribute(self, conn_id, attr: str):
        """*conn_id*'s recorded *attr*, else the first current-lifetime sibling's."""
        if not conn_id:
            return None
        record = self._connection_attributions.get(conn_id)
        recorded = getattr(record, attr) if record is not None else None
        if recorded:
            return recorded
        # Current lifetime only: a reset or reused conn_id keeps old completed flows in _flows.
        for flow in self._current_lifetime_flows(conn_id):
            value = getattr(flow, attr, None)
            if value:
                return value
        return None

    def _take_pending_sdk(self, flow):
        """Pop one stashed :class:`StashedCallerStack` matching *flow* (client_random, 4-tuple, real sid), or ``None``.

        Consuming it stops a later connection reusing the 4-tuple from inheriting it. Under lock.
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

        A consumed stash entry seeds the connection record and is a direct join only
        for the connection's first flow (captured at its first read/write). Otherwise
        the flow inherits (``connection-fallback``). Never clobbers a set value. Under lock.
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
        """Give a newborn *flow* its connection's SDK, caller stack and inherited claim; never overwrites. Under lock."""
        inherited = StashedCallerStack(
            sdk=self._connection_sdk(flow.connection_id),
            caller_stack=self._connection_caller_stack(flow.connection_id),
            stashed_at=self._now(),
        )
        self._apply_attribution(flow, inherited, direct=False)

    def _is_first_flow_of_connection(self, flow: Flow) -> bool:
        """True when *flow* is the first minted in its connection's current lifetime (``_lifetime_first_seq``, see :meth:`_flow_id`) and no caller stack was joined before: the one rule for a direct join. Under lock."""
        conn_id = flow.connection_id
        record = self._connection_attributions.get(conn_id)
        if record is not None and record.caller_stack is not None:
            return False
        first_seq = self._lifetime_first_seq.get(conn_id, 0)
        return self._flow_sequence_of(flow) == first_seq

    def _stamp_client_random(self, flow: Flow, event) -> None:
        """Stamp the connection's client_random onto a TLS/QUIC flow's layer (fills an empty value only).

        Uses the record's own value, else the one seen on the connection (early
        records lack it). Attribute access auto-creates the layer.
        """
        if flow.transport not in self._LIBRARY_TRANSPORTS:
            return
        layer = getattr(flow, flow.transport)
        if layer.client_random:
            return
        client_random = (getattr(event, 'client_random', '') or ''
                         or self._connection_client_random(flow.connection_id))
        if client_random:
            layer.client_random = client_random

    def _connection_client_random(self, conn_id: str) -> str:
        """The client_random recorded on *conn_id*'s state, else ``""``."""
        conn = self._connections.get(conn_id)
        return conn.client_random if conn is not None else ""

    def _record_client_random(self, conn: '_ConnectionState', event,
                              pending: Optional[list] = None) -> None:
        """Remember the first client_random seen on *conn* and backfill it onto earlier flows. Under lock.

        Early records can lack it while the agent's layout lookup is pending. It is
        also the caller_stack join key: indexed for :meth:`on_sdk`, and a stack
        already stashed under it is applied now.
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
