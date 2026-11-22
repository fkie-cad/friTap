"""Orphan request/response pairing for :class:`FlowCollector`.

The host class owns the state; methods run under its lock unless noted.
Collector constants are read through ``_collector()`` at call time so patches take effect.
"""

from typing import Optional

from .collector_state import collector_module as _collector
from .layer_pipeline import MESSAGE_TRANSPORTS
from .models import Flow, FlowState


class OrphanFlowMixin:
    """Indexes request-only flows by server endpoint and pairs leftover halves at flush."""

    @staticmethod
    def _is_orphan_merge_candidate(flow: Flow) -> bool:
        """True when *flow* may take part in orphan merging; message-stream transports (MTProto, Secret Chats) are excluded because their records are independent TL messages."""
        return (getattr(flow, "transport", "") or "") not in MESSAGE_TRANSPORTS

    def _merge_remaining_orphans(self) -> list[Flow]:
        """Pair leftover request-only and response-only flows. Under lock.

        1. By ``connection_id``: same-connection halves pair unambiguously.
        2. By destination ``host:port``, only when exactly one request-only flow
           remains for it (several concurrent connections would make it a guess).

        Pairs more than IDLE_THRESHOLD apart never merge. Returns the removed response flows.
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

        # Request-only flows still free to absorb a response; consumed as matched so no request is claimed twice.
        avail_req: set[str] = set(request_only)

        def _merge(resp_fid: str, req_fid: str) -> bool:
            req_flow = self._flows.get(req_fid)
            resp_flow = self._flows.get(resp_fid)
            if not req_flow or not resp_flow:
                return False
            if abs(resp_flow.started - req_flow.started) > _collector().IDLE_THRESHOLD:
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

        # Pass 1: exact pairing by connection_id.
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

        # Pass 2: dst-keyed fallback, only when unambiguous.
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

    @staticmethod
    def _oriented_endpoints(event, direction: str = "") -> tuple:
        """``(src_addr, src_port, dst_addr, dst_port)`` oriented device -> server.

        A received (read) packet is swapped; *direction* overrides ``event.direction``.
        """
        if (direction or getattr(event, 'direction', '')) == "read":
            return (event.dst_addr, event.dst_port,
                    event.src_addr, event.src_port)
        return (event.src_addr, event.src_port,
                event.dst_addr, event.dst_port)

    @classmethod
    def _orphan_key(cls, event, direction: str = "") -> str:
        """``host:port`` of the REMOTE (server) endpoint of *event*.

        Keyed on the server, not the raw ``dst`` of a read: with one UDP socket shared
        by several QUIC servers that would attach server A's datagram to B's request.
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
        # Prune stale entries even when nothing matches.
        valid = [(ts, fid) for ts, fid in candidates
                 if (now - ts) <= _collector().IDLE_THRESHOLD and fid in self._flows]
        self._replace_orphan_candidates(key, valid)
        if not valid:
            return None
        _, flow_id = min(valid, key=lambda x: abs(now - x[0]))
        flow = self._flows.get(flow_id)
        if flow and flow.request is not None and flow.response is None:
            self._replace_orphan_candidates(
                key, [(ts, fid) for ts, fid in valid if fid != flow_id])
            return flow
        return None

    def _register_orphan_request(self, key: str, timestamp: float,
                                 flow_id: str) -> None:
        """Index a request-only flow under its server *key*. Under lock."""
        self._orphan_requests.setdefault(key, []).append((timestamp, flow_id))
        self._orphan_requests.move_to_end(key)
        self._orphan_request_total += 1
        while self._orphan_request_total > _collector().MAX_ORPHAN_REQUESTS:
            self._evict_oldest_orphan_request()

    def _evict_oldest_orphan_request(self) -> None:
        """Drop the oldest entry of the least-recently-used key. Under lock.

        Only the index entry goes; the flow stays on its connection and is still paired by the flush-time merge.
        """
        key, candidates = next(iter(self._orphan_requests.items()))
        self._warn_cap_once("orphan requests", _collector().MAX_ORPHAN_REQUESTS)
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
