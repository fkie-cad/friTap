"""Hold QUIC records with an agent-guessed tuple until their real tuple is known.

Written as-is, a guessed tuple (``endpoints_synthetic`` without ``observed_*``,
e.g. Chrome's 0-RTT first write) forms a separate fake UDP conversation in the
pcap. Held records are released, rewritten to the connection's first real
tuple, in arrival order; at close (or past the bounds) they are released
unchanged. TCP records are handled by the endpoint pinner instead.
"""

from __future__ import annotations

import threading
from collections import OrderedDict
from dataclasses import replace
from typing import Dict, List, Optional, Tuple

from ..connection_index import has_usable_endpoints
from ..synthetic_endpoints import is_provisional, record_sides

DEFAULT_MAX_HELD_PER_CONNECTION = 64
DEFAULT_MAX_HELD_CONNECTIONS = 256
#: Real tuples remembered for connections that had provisional records.
DEFAULT_MAX_REAL_TUPLES = 4096

#: One side of a connection: (printable addr, raw addr, port).
_Side = Tuple[str, object, int]


def _side(event, side: str) -> _Side:
    return getattr(event, side + "_addr"), getattr(event, side + "_addr_raw"), getattr(event, side + "_port")


def _with_real_tuple(event, real: Tuple[_Side, _Side, str]):
    """A copy of *event* carrying the real tuple *real* in its own orientation."""
    local, peer, ss_family = real
    src, dst = (peer, local) if event.direction == "read" else (local, peer)
    return replace(event, src_addr=src[0], src_addr_raw=src[1], src_port=src[2],
                   dst_addr=dst[0], dst_addr_raw=dst[1], dst_port=dst[2],
                   ss_family=ss_family, endpoints_synthetic=False)


class ProvisionalEndpointHold:
    """Per-connection hold for provisional UDP records (thread-safe, bounded)."""

    def __init__(self, max_held_per_connection: int = DEFAULT_MAX_HELD_PER_CONNECTION,
                 max_held_connections: int = DEFAULT_MAX_HELD_CONNECTIONS,
                 max_real_tuples: int = DEFAULT_MAX_REAL_TUPLES) -> None:
        self._max_per_connection = max_held_per_connection
        self._max_connections = max_held_connections
        self._max_real = max_real_tuples
        self._held: Dict[str, list] = {}
        self._real: "OrderedDict[str, Tuple[_Side, _Side, str]]" = OrderedDict()
        self._lock = threading.Lock()

    def admit(self, event) -> List:
        """The records to write now for *event* (possibly none, possibly several)."""
        key = getattr(event, "ssl_session_id", "") or ""
        if getattr(event, "transport", "tcp") != "udp" or not key:
            return [event]
        with self._lock:
            if is_provisional(event):
                return self._admit_provisional(key, event)
            return self._admit_real(key, event)

    def drain(self) -> List:
        """Every record still held, unchanged, in arrival order per connection."""
        with self._lock:
            held, self._held = self._held, {}
        return [event for events in held.values() for event in events]

    def _admit_provisional(self, key: str, event) -> List:
        real = self._real.get(key)
        if real is not None:
            return [_with_real_tuple(event, real)]
        held = self._held.get(key)
        if held is None:
            if len(self._held) >= self._max_connections:
                return [event]
            held = self._held[key] = []
        return self._hold(key, held, event)

    def _hold(self, key: str, held: list, event) -> List:
        held.append(event)
        if len(held) > self._max_per_connection:
            return self._held.pop(key)
        return []

    def _admit_real(self, key: str, event) -> List:
        held = self._held.pop(key, None)
        if held is None:
            return [event]
        real = self._real_tuple(event)
        if real is None:
            # Not a usable tuple either: queue it behind the held ones to keep order.
            self._held[key] = held
            return self._hold(key, held, event)
        self._remember_real(key, real)
        return [_with_real_tuple(h, real) if is_provisional(h) else h for h in held] + [event]

    @staticmethod
    def _real_tuple(event) -> Optional[Tuple[_Side, _Side, str]]:
        if getattr(event, "endpoints_synthetic", False):
            return None
        if not has_usable_endpoints(event.src_addr, event.src_port, event.dst_addr, event.dst_port):
            return None
        local, peer = record_sides(event, _side)
        return local, peer, event.ss_family

    def _remember_real(self, key: str, real: Tuple[_Side, _Side, str]) -> None:
        self._real[key] = real
        self._real.move_to_end(key)
        if len(self._real) > self._max_real:
            self._real.popitem(last=False)
