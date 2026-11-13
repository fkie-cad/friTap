"""Upgrade a flow's synthetic (option 5) endpoints to the real ones.

An fd-less connection is pinned to a synthetic ``198.18.0.0/15`` tuple by the
router's :class:`~friTap.endpoint_pinner.EndpointPinner`. When a later record of
the connection sees the real socket, the router keeps the pin (one TCP stream in
the pcap) and carries the real tuple as ``observed_*`` on the
``DatalogEvent``. The collector uses these helpers to map each synthetic
endpoint to its real one, orientation-independently, and rewrite the flow's
src/dst and local/remote fields. The connection key is never touched.
"""

from __future__ import annotations

from typing import Optional

#: ``{(synthetic_addr, synthetic_port): (real_addr, real_port)}``.
EndpointMap = dict


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
