"""Request-context join for :class:`FlowCollector` (``--attribute-sdk``).

The host class owns the state; methods run under its lock unless noted.
Collector constants are read through ``_collector()`` at call time so patches take effect.
"""

from typing import Callable, Optional

from .attribution import chromium_internal_candidate, chromium_internal_host_update
from .collector_state import _ConnectionAttribution, _PendingEvents
from .collector_state import collector_module as _collector
from .models import Flow, FlowState
from .request_context_join import (
    MATCH_SLACK_SECONDS,
    absolute_request_url,
    normalize_request_key,
)


class RequestContextJoinMixin:
    """Matches flows to per-request Java contexts by request key and time, and
    buckets Chromium-internal flows."""

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

    def reserve_request_contexts(self, count: int) -> None:
        """Let the request-context store hold *count* contexts (offline replay)."""
        with self._lock:
            self._request_contexts.reserve(count)

    @property
    def evicted_request_contexts(self) -> int:
        """Request contexts dropped by the store's size bound so far."""
        return self._request_contexts.evicted

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
        max_flows = _collector().MAX_REQUEST_JOIN_FLOWS_PER_KEY
        max_keys = _collector().MAX_REQUEST_JOIN_KEYS
        waiting = self._request_join_flows.setdefault(key, [])
        waiting.append((flow.started, flow.flow_id))
        if len(waiting) > max_flows:
            self._warn_cap_once("flows waiting per request key", max_flows)
            del waiting[:-max_flows]
        self._request_join_flows.move_to_end(key)
        while len(self._request_join_flows) > max_keys:
            self._warn_cap_once("request keys waiting for a context", max_keys)
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
