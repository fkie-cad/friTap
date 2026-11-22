"""Capture timestamps of agent records.

A record the agent held before sending (``held_ms``) is back-dated for flows,
but packet writers keep its arrival time: records reach the pcap in arrival
order, so back-dated packet times would go out of order.
"""

from __future__ import annotations

from typing import Optional, Tuple


def held_capture_times(held_ms: object, received_at: float) -> Tuple[float, Optional[float]]:
    """(capture time, arrival time or None when the record was not held)."""
    if isinstance(held_ms, bool) or not isinstance(held_ms, (int, float)) or held_ms <= 0:
        return received_at, None
    return max(0.0, received_at - held_ms / 1000.0), received_at


def arrival_time(event) -> float:
    """When the host received *event*: the time a packet writer must stamp."""
    received_at = getattr(event, "received_at", None)
    return event.timestamp if received_at is None else received_at
