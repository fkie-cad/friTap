"""Sticky per-connection endpoint pinning for TLS records keyed by client_random.

One TLS connection (one ``client_random``) must stay in ONE TCP stream in the
pcap and the live sinks, even when only some of its records carry a socket
tuple. :class:`EndpointPinner` pins the FIRST tuple a client_random is seen
with -- the real one when the record has it, else a synthetic one from
:func:`~friTap.synthetic_endpoints.synthetic_tuple` -- and re-emits that pin
for every later record of the connection.

A real tuple learned after a synthetic pin is never emitted in place of the
pin (that would split the stream); it is returned as ``observed`` and recorded
once in the mapping table (:meth:`EndpointPinner.mappings`), which the pcap
finalize path uses to rewrite synthetic streams to their real tuples.

Pins are stored in (client, server) orientation; a write record is
client -> server, a read record server -> client. Each pin caches its read-
and write-oriented :class:`ResolvedEndpoints`, so a pin hit without a new real
tuple allocates nothing.
"""

from __future__ import annotations

import ipaddress
import logging
import threading
from collections import OrderedDict
from dataclasses import dataclass, replace
from typing import Any, Dict, List, Optional

from .connection_index import has_usable_endpoints
from .synthetic_endpoints import is_default_fd_placeholder, synthetic_tuple

#: Pins kept before the least-recently-used connection is forgotten.
DEFAULT_PIN_CAPACITY = 4096
#: Synthetic pins kept in the mapping table (unlike pins, never evicted: the
#: pcap rewrite needs every one). Pins past the cap still work, but their
#: streams are not rewritten; they are counted in ``mapping_overflow_count``.
DEFAULT_MAPPING_CAPACITY = 65536
#: Real pins remembered after LRU eviction, so a long-lived connection's next
#: fd-less record re-pins to its real tuple instead of a new synthetic one
#: (which would split it over two TCP streams). Oldest dropped past the cap,
#: counted in ``evicted_real_overflow_count``.
DEFAULT_EVICTED_REAL_CAPACITY = 65536
_SYNTHETIC_FAMILY = "AF_INET"


@dataclass(frozen=True)
class PinnedEndpoint:
    """One side of a connection: printable address, port, raw (pcap) address."""
    addr: str
    port: int
    raw: Any


@dataclass(frozen=True)
class EndpointPair:
    """A connection's endpoints in (client, server) orientation."""
    client: PinnedEndpoint
    server: PinnedEndpoint
    ss_family: str
    synthetic: bool = False


@dataclass(frozen=True)
class RecordEndpoints:
    """A record's endpoints in its own (src, dst) orientation."""
    src_addr: str
    src_port: int
    dst_addr: str
    dst_port: int
    src_addr_raw: Any
    dst_addr_raw: Any
    ss_family: str


@dataclass(frozen=True)
class ResolvedEndpoints(RecordEndpoints):
    """The endpoints to emit, plus the real ones observed under a synthetic pin."""
    synthetic: bool = False
    observed: Optional[RecordEndpoints] = None


@dataclass(frozen=True)
class MappingEntry:
    """A synthetic pin and the first real tuple learned for it (``None`` if none)."""
    client_random: str
    synthetic: EndpointPair
    real: Optional[EndpointPair] = None


def _as_pair(endpoints: RecordEndpoints, is_read: bool) -> EndpointPair:
    """*endpoints* re-oriented to (client, server); reads travel server -> client."""
    src = PinnedEndpoint(endpoints.src_addr, endpoints.src_port, endpoints.src_addr_raw)
    dst = PinnedEndpoint(endpoints.dst_addr, endpoints.dst_port, endpoints.dst_addr_raw)
    client, server = (dst, src) if is_read else (src, dst)
    return EndpointPair(client=client, server=server, ss_family=endpoints.ss_family)


def _synthetic_endpoint(ip: int, port: int) -> PinnedEndpoint:
    return PinnedEndpoint(str(ipaddress.IPv4Address(ip)), port, ip)


def _resolved(pin: EndpointPair, is_read: bool) -> ResolvedEndpoints:
    """*pin* oriented as a record of the given direction, flagged when synthetic."""
    src, dst = (pin.server, pin.client) if is_read else (pin.client, pin.server)
    return ResolvedEndpoints(src.addr, src.port, dst.addr, dst.port,
                             src.raw, dst.raw, pin.ss_family, synthetic=pin.synthetic)


class _PinState:
    """A pin plus its two cached record orientations."""
    __slots__ = ("pair", "as_write", "as_read", "conflict_logged")

    def __init__(self, pair: EndpointPair) -> None:
        self.pair = pair
        self.as_write = _resolved(pair, is_read=False)
        self.as_read = _resolved(pair, is_read=True)
        self.conflict_logged = False

    def resolved(self, is_read: bool) -> ResolvedEndpoints:
        return self.as_read if is_read else self.as_write


def synthetic_pair(client_random: str) -> EndpointPair:
    """The synthetic :class:`EndpointPair` of a normalized *client_random*."""
    tup = synthetic_tuple(client_random)
    return EndpointPair(
        client=_synthetic_endpoint(tup.client_ip, tup.client_port),
        server=_synthetic_endpoint(tup.server_ip, tup.server_port),
        ss_family=_SYNTHETIC_FAMILY,
        synthetic=True,
    )


def _real_endpoints(endpoints: Optional[RecordEndpoints]) -> Optional[RecordEndpoints]:
    """*endpoints* when they are a usable real tuple (not missing/zero/``-ed``)."""
    if endpoints is None:
        return None
    tuple4 = (endpoints.src_addr, endpoints.src_port, endpoints.dst_addr, endpoints.dst_port)
    if not has_usable_endpoints(*tuple4) or is_default_fd_placeholder(*tuple4):
        return None
    return endpoints


def _same_tuple(a: EndpointPair, b: EndpointPair) -> bool:
    """Equal client/server address+port (raw spelling and family ignored)."""
    return ((a.client.addr, a.client.port, a.server.addr, a.server.port)
            == (b.client.addr, b.client.port, b.server.addr, b.server.port))


def _record_matches(pin: EndpointPair, record: RecordEndpoints, is_read: bool) -> bool:
    """:func:`_same_tuple` of *pin* and *record* without building a pair."""
    src, dst = (pin.server, pin.client) if is_read else (pin.client, pin.server)
    return ((record.src_addr, record.src_port, record.dst_addr, record.dst_port)
            == (src.addr, src.port, dst.addr, dst.port))


class EndpointPinner:
    """Sticky first-tuple pin per client_random (LRU-bounded, thread-safe)."""

    def __init__(self, capacity: int = DEFAULT_PIN_CAPACITY,
                 mapping_capacity: int = DEFAULT_MAPPING_CAPACITY,
                 evicted_real_capacity: int = DEFAULT_EVICTED_REAL_CAPACITY) -> None:
        self._capacity = capacity
        self._mapping_capacity = mapping_capacity
        self._evicted_real_capacity = evicted_real_capacity
        self._pins: "OrderedDict[str, _PinState]" = OrderedDict()
        # client_random -> real pin evicted from ``_pins`` (bounded, oldest first).
        self._evicted_real: "OrderedDict[str, EndpointPair]" = OrderedDict()
        self._evicted_real_overflow = 0
        # client_random -> first real pair (None until learned). Never evicted
        # with the pins: the pcap rewrite needs every synthetic stream, and an
        # evicted connection re-pins to the same (derivable) synthetic tuple.
        self._mappings: Dict[str, Optional[EndpointPair]] = {}
        self._mapping_overflow = 0
        self._conflicts = 0
        self._lock = threading.Lock()
        self._logger = logging.getLogger("friTap.endpoint_pinner")

    @property
    def conflict_count(self) -> int:
        """Later real tuples that disagreed with the pinned/mapped one."""
        return self._conflicts

    @property
    def evicted_real_overflow_count(self) -> int:
        """Evicted real pins forgotten because the fallback table was full."""
        return self._evicted_real_overflow

    @property
    def mapping_overflow_count(self) -> int:
        """Synthetic pins left out of :meth:`mappings` because the table was full."""
        return self._mapping_overflow

    def mappings(self) -> List[MappingEntry]:
        """Every synthetic pin with its first learned real tuple, in pin order."""
        with self._lock:
            items = list(self._mappings.items())
        return [MappingEntry(cr, synthetic_pair(cr), real) for cr, real in items]

    def learned_real(self, client_random: str,
                     direction_is_read: bool) -> Optional[RecordEndpoints]:
        """The real tuple learned for a synthetic pin, oriented as a record of
        the given direction (``None`` when none was learned)."""
        with self._lock:
            real = self._mappings.get(client_random)
        return _resolved(real, direction_is_read) if real is not None else None

    def resolve(self, client_random: str, transport: str, direction_is_read: bool,
                event_endpoints: Optional[RecordEndpoints]) -> Optional[ResolvedEndpoints]:
        """The endpoints to emit for a record, or ``None`` when pinning does not apply.

        Applies only to ``tcp`` records with a (normalized) *client_random*.
        """
        if transport != "tcp" or not client_random:
            return None
        real = _real_endpoints(event_endpoints)
        with self._lock:
            state = self._pin_for(client_random, real, direction_is_read)
            observed = self._observe(client_random, state, real, direction_is_read)
        resolved = state.resolved(direction_is_read)
        return replace(resolved, observed=real) if observed else resolved

    def _pin_for(self, client_random: str, real: Optional[RecordEndpoints],
                 is_read: bool) -> _PinState:
        state = self._pins.get(client_random)
        if state is not None:
            self._pins.move_to_end(client_random)
            return state
        state = _PinState(self._new_pin(client_random, real, is_read))
        self._pins[client_random] = state
        if len(self._pins) > self._capacity:
            self._remember_evicted(*self._pins.popitem(last=False))
        return state

    def _remember_evicted(self, client_random: str, state: _PinState) -> None:
        """Keep an evicted REAL pin (synthetic ones are derivable); drop the oldest past the cap."""
        if state.pair.synthetic:
            return
        self._evicted_real[client_random] = state.pair
        if len(self._evicted_real) > self._evicted_real_capacity:
            self._evicted_real.popitem(last=False)
            self._evicted_real_overflow += 1

    def _new_pin(self, client_random: str, real: Optional[RecordEndpoints],
                 is_read: bool) -> EndpointPair:
        """A synthetic pin survives eviction, so does an evicted real pin;
        otherwise the record's real tuple, else synthetic."""
        if client_random in self._mappings:
            return synthetic_pair(client_random)
        evicted = self._evicted_real.pop(client_random, None)
        if evicted is not None:
            return evicted
        if real is not None:
            return _as_pair(real, is_read)
        self._remember_synthetic(client_random)
        return synthetic_pair(client_random)

    def _remember_synthetic(self, client_random: str) -> None:
        """Add a mapping row for a new synthetic pin, or count the overflow."""
        if len(self._mappings) < self._mapping_capacity:
            self._mappings[client_random] = None
            return
        if self._mapping_overflow == 0:
            self._logger.warning(
                "synthetic endpoint table full (%d); later fd-less connections "
                "keep their synthetic tuple in the -p pcap", self._mapping_capacity)
        self._mapping_overflow += 1

    def _observe(self, client_random: str, state: _PinState,
                 real: Optional[RecordEndpoints], is_read: bool) -> bool:
        """Record a real tuple seen against the pin; True when it travels as ``observed``."""
        pin = state.pair
        if real is None or (not pin.synthetic and _record_matches(pin, real, is_read)):
            return False
        real_pair = _as_pair(real, is_read)
        if not pin.synthetic:
            self._note_conflict(client_random, pin, real_pair)
            return False
        if client_random not in self._mappings:
            return True  # overflowed pin: still observed, nothing to record
        known = self._mappings[client_random]
        if known is None:
            self._mappings[client_random] = real_pair
        elif not _same_tuple(known, real_pair):
            self._note_conflict(client_random, known, real_pair)
        return True
    def _note_conflict(self, client_random: str, kept: EndpointPair,
                       seen: EndpointPair) -> None:
        """Count a disagreeing real tuple; log it once per connection at debug."""
        self._conflicts += 1
        state = self._pins.get(client_random)
        if state is None or state.conflict_logged:
            return
        state.conflict_logged = True
        self._logger.debug(
            "client_random %s...: keeping %s:%d -> %s:%d, ignoring later tuple %s:%d -> %s:%d",
            client_random[:16], kept.client.addr, kept.client.port, kept.server.addr,
            kept.server.port, seen.client.addr, seen.client.port, seen.server.addr,
            seen.server.port)

    def clear(self) -> None:
        with self._lock:
            self._pins.clear()
            self._mappings.clear()
            self._evicted_real.clear()
            self._evicted_real_overflow = 0
            self._mapping_overflow = 0
            self._conflicts = 0
