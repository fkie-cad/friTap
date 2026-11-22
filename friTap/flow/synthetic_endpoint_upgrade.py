"""Upgrade a flow's synthetic (option 5) endpoints to the real ones.

An fd-less connection is pinned to a synthetic ``198.18.0.0/15`` tuple by the
router's EndpointPinner; later records carry the real tuple as ``observed_*``.
These helpers map synthetic endpoints to real ones orientation-independently and
rewrite the flow's src/dst and local/remote fields; the connection key is untouched.

A QUIC record whose tuple the agent had to guess arrives flagged
``endpoints_synthetic`` without ``observed_*``. Such a *provisional* tuple is
mapped side by side (local to local, peer to peer) onto the connection's first
real record.
"""

from __future__ import annotations

from typing import Iterable, Optional, Tuple

from ..connection_index import has_usable_endpoints
from ..synthetic_endpoints import is_provisional, record_sides

#: ``{(synthetic_addr, synthetic_port): (real_addr, real_port)}``.
EndpointMap = dict
#: ``((local_addr, local_port), (peer_addr, peer_port))`` of one record.
RecordSides = Tuple[tuple, tuple]


def observed_endpoint_map(event) -> Optional[EndpointMap]:
    """The synthetic -> real endpoint map an event teaches, or ``None``.

    The event's ``src``/``dst`` (the pin) and ``observed_src``/``observed_dst``
    (the real socket) share one orientation, so each side maps to its peer.
    """
    if not getattr(event, "endpoints_synthetic", False):
        return None
    real_src = getattr(event, "observed_src_addr", "") or ""
    real_dst = getattr(event, "observed_dst_addr", "") or ""
    if not real_src or not real_dst:
        return None
    return {
        (event.src_addr, event.src_port): (real_src, event.observed_src_port),
        (event.dst_addr, event.dst_port): (real_dst, event.observed_dst_port),
    }


def _mapped(mapping: EndpointMap, addr, port) -> tuple:
    """The real endpoint for ``(addr, port)``, or itself when not mapped."""
    return mapping.get((addr, port), (addr, port))


def upgrade_flow_endpoints(flow, mapping: EndpointMap) -> bool:
    """Rewrite a synthetic *flow*'s endpoints through *mapping* once.

    Returns True when the flow was upgraded (and its flag cleared). A flow
    whose endpoints the map does not cover stays synthetic.
    """
    if not getattr(flow, "endpoints_synthetic", False):
        return False
    if (flow.src_addr, flow.src_port) not in mapping:
        return False
    flow.src_addr, flow.src_port = _mapped(mapping, flow.src_addr, flow.src_port)
    flow.dst_addr, flow.dst_port = _mapped(mapping, flow.dst_addr, flow.dst_port)
    flow.local_addr, flow.local_port = _mapped(mapping, flow.local_addr, flow.local_port)
    flow.remote_addr, flow.remote_port = _mapped(mapping, flow.remote_addr, flow.remote_port)
    flow.endpoints_synthetic = False
    return True


def provisional_sides(event) -> Optional[RecordSides]:
    """The sides of an agent-guessed tuple (flagged synthetic, no ``observed_*``), else ``None``."""
    return record_sides(event) if is_provisional(event) else None


def provisional_endpoint_map(provisional: Iterable[RecordSides], event) -> Optional[EndpointMap]:
    """Map every provisional side onto *event*'s real side of the same role.

    ``None`` unless *event* carries a usable real (unflagged) tuple.
    """
    if getattr(event, "endpoints_synthetic", False):
        return None
    if not has_usable_endpoints(event.src_addr, event.src_port, event.dst_addr, event.dst_port):
        return None
    real_local, real_peer = record_sides(event)
    mapping: EndpointMap = {}
    for local, peer in provisional:
        mapping[local] = real_local
        mapping[peer] = real_peer
    return mapping or None
