#!/usr/bin/env python3

"""
Session-scoped connection tracking: key/socket dedup, connection keys and aliases.
"""

from __future__ import annotations

import functools
import threading
from collections import OrderedDict
from dataclasses import dataclass
from typing import Callable, Dict, Optional, Set, Tuple

from .synthetic_endpoints import is_synthetic_ip

# Dummy session ID prefix from the agent (DUMMY_SESSION_ID_* in
# agent/tls/definitions/shared_constants.ts): match such connections by client_random.
DUMMY_SESSION_ID_BASE = "59FD71B7B90202F359D89E66AE4E61247954E28431F6C6AC46625D472FF7633"

# NSS dummy session ID returned when the SSL layer lookup fails.
NSS_DUMMY_SESSION_ID = "3E8ABF58649A1A1C58824D704173BA9AAFA2DA33B45FFEA341D218B29BBACF8F"


def normalize_4tuple(src_addr: str, src_port: int,
                     dst_addr: str, dst_port: int) -> str:
    """Canonical endpoint pair; endpoints are sorted so both sides yield the same key."""
    ep1 = f"{src_addr}:{src_port}"
    ep2 = f"{dst_addr}:{dst_port}"
    lo, hi = (ep1, ep2) if ep1 < ep2 else (ep2, ep1)
    return f"{lo}-{hi}"


def normalize_addr(addr: str) -> str:
    """Canonicalize an IP literal (strip IPv6 brackets and zone id, compress via :mod:`ipaddress`).

    Non-IP input (hostnames, empty) is returned unchanged. Needed because
    tshark passes (``follow,tls`` vs ``-T ek``) spell IPv6 differently.
    Memoized for strings: it runs for every event and the parse dominates keying cost.
    """
    if isinstance(addr, str):
        return _normalize_addr_cached(addr)
    return _normalize_addr_uncached(addr)


def _normalize_addr_uncached(addr: str) -> str:
    """:func:`normalize_addr` without memoization."""
    if not addr:
        return addr
    a = addr.strip()
    if a.startswith("[") and a.endswith("]"):
        a = a[1:-1]
    if "%" in a:  # drop IPv6 zone id
        a = a.split("%", 1)[0]
    try:
        import ipaddress
        return str(ipaddress.ip_address(a))
    except ValueError:
        return a


_normalize_addr_cached = functools.lru_cache(maxsize=4096)(_normalize_addr_uncached)


def canonical_4tuple(src_addr: str, src_port: int,
                     dst_addr: str, dst_port: int) -> str:
    """:func:`normalize_4tuple` over canonicalized addresses (perspective- and spelling-independent)."""
    return normalize_4tuple(normalize_addr(src_addr), src_port,
                            normalize_addr(dst_addr), dst_port)


# The only protocol whose endpoint-tier key stays ``net:<4tuple>`` (see resolve_connection_key).
_LEGACY_NET_PROTOCOL = "tls"


def resolve_connection_key(
    src_addr: str,
    src_port: int,
    dst_addr: str,
    dst_port: int,
    session_token: str = "",
    client_random: str = "",
    protocol: str = "tls",
) -> str:
    """Deterministic connection key with tiered fallback.

    1. ``cr:<proto>:<client_random>`` (unique per connection, not reused on resumption)
    2. ``sid:<proto>:<session token>``
    3. ``net:<4tuple>`` for TLS (stable format for ``.tap`` flow ids), else
       ``net:<proto>:<canonical_4tuple>`` so other protocols never fold into a
       TLS flow sharing the 4-tuple.

    An empty/None ``protocol`` is coerced to ``"tls"`` here, the one owner of the
    key format; callers must stamp the same protocol on lifecycle and data events.
    """
    protocol = str(protocol or "tls")
    if client_random:
        return f"cr:{protocol}:{client_random}"
    if session_token and not session_token.startswith(DUMMY_SESSION_ID_BASE) and session_token != NSS_DUMMY_SESSION_ID:
        return f"sid:{protocol}:{session_token}"
    if protocol == _LEGACY_NET_PROTOCOL:
        return f"net:{normalize_4tuple(src_addr, src_port, dst_addr, dst_port)}"
    return f"net:{protocol}:{canonical_4tuple(src_addr, src_port, dst_addr, dst_port)}"


# Protocols whose session token names exactly one connection (QUIC: the agent
# keys by QuicConnection pointer plus ``#gen`` on reuse). A TLS session id does not qualify.
_CONNECTION_SCOPED_SESSION_PROTOCOLS = frozenset({"quic"})


def connection_scoped_session_key(session_token: str, protocol: str,
                                  record_key: str = "") -> str:
    """The ``sid:<proto>:`` key of *session_token* when it names a single connection, else ``""``.

    *record_key* is the record's own key; reused when it is already the ``sid:`` key.
    """
    if str(protocol or "") not in _CONNECTION_SCOPED_SESSION_PROTOCOLS:
        return ""
    if record_key.startswith("sid:"):
        return record_key
    key = resolve_connection_key("", 0, "", 0, session_token=session_token,
                                 protocol=protocol)
    return key if key.startswith("sid:") else ""


def promotes_to_client_random_key(record_key: str, owner_key: str) -> bool:
    """True when a connection owned by *owner_key* should be re-keyed to *record_key*.

    Only a QUIC ``sid:quic:`` owner (e.g. 0-RTT data before the handshake was
    bound) is promoted to a ``cr:quic:`` key.
    """
    return (owner_key.startswith("sid:quic:")
            and record_key.startswith("cr:quic:"))


_UNSPECIFIED_ADDRS = frozenset({"", "0.0.0.0", "::", "[::]"})


def has_usable_endpoints(src_addr: str, src_port: int,
                         dst_addr: str, dst_port: int) -> bool:
    """True when a record carries a real 4-tuple.

    Unresolved sockets (empty/unspecified address, port 0) and synthetic
    ``198.18.0.0/15`` tuples can only be keyed by session token or client_random.
    The ``-ed`` placeholder (127.0.0.1:1234 <-> :2345) counts as usable: it is the
    only tuple there is when no client_random replaced it.
    """
    try:
        ports_ok = int(src_port or 0) > 0 and int(dst_port or 0) > 0
    except (TypeError, ValueError):
        return False
    return (ports_ok
            and _is_real_address(src_addr)
            and _is_real_address(dst_addr))


def _is_real_address(addr) -> bool:
    """Specified address outside the synthetic range."""
    return (str(addr or "").strip() not in _UNSPECIFIED_ADDRS
            and not is_synthetic_ip(addr))


def _is_client_random_key(key: str) -> bool:
    """Tier-1 ``cr:`` key."""
    return key.startswith("cr:")


class ConnectionKeyAliases:
    """Folds the different keys one live connection is seen under into one.

    :func:`resolve_connection_key` is pure, so a connection whose records carry a
    session id only part of the time resolves to two keys (TLS 1.3 legacy mode:
    the session id appears after NewSessionTicket, so ``SSL_write`` keys as
    ``net:`` and ``SSL_read`` as ``sid:``).

    The first key seen on a usable live 4-tuple owns the connection; later
    ``net:``/``sid:`` keys on it alias to the owner. Records without addresses
    resolve through the aliases.

    ``cr:`` keys alias to a live non-``cr:`` owner (early records lacked the
    client_random), otherwise they claim the 4-tuple. A different ``cr:`` key on
    the same 4-tuple is a new connection reusing the port and takes it over.
    Not thread-safe: callers hold their own lock.
    """

    def __init__(self, capacity: int = 16384) -> None:
        self._capacity = capacity
        self._owner_by_endpoint: "OrderedDict[str, str]" = OrderedDict()
        self._alias_to_owner: "OrderedDict[str, str]" = OrderedDict()
        # Non-cr: owner -> the cr: key folded into it (a second, different one is a new connection).
        self._client_random_key_of_owner: "OrderedDict[str, str]" = OrderedDict()
        #: The old owner key when the last :meth:`resolve` promoted it, else None.
        self.promoted_from: Optional[str] = None

    def resolve(self, key: str, src_addr: str, src_port: int, dst_addr: str,
                dst_port: int, protocol: str, is_live, session_key: str = "",
                may_promote: Optional[Callable[[str, str], bool]] = None) -> str:
        """Canonical connection key for a record whose pure key is *key*.

        *is_live(key)* reports whether a connection key is still tracked; a
        finished owner no longer captures new records on its 4-tuple.
        *session_key* (see :func:`connection_scoped_session_key`) names the
        record's connection outright, so the 4-tuple is not consulted.

        When *key* would fold into a live owner that
        :func:`promotes_to_client_random_key` allows and *may_promote(owner,
        key)* agrees, the owner is renamed to *key* instead, *key* is returned
        and :attr:`promoted_from` names the old owner.
        """
        self.promoted_from = None
        if session_key:
            return self._resolve_by_session(key, session_key, is_live, may_promote)
        if not has_usable_endpoints(src_addr, src_port, dst_addr, dst_port):
            return self.canonical(key)
        endpoint_key = resolve_connection_key(
            src_addr, src_port, dst_addr, dst_port, protocol=protocol)
        owner = self._owner_by_endpoint.get(endpoint_key)
        if self._may_alias(key, owner, is_live):
            if self._promote(key, owner, may_promote):
                return key
            self._remember(self._alias_to_owner, key, owner)
            if _is_client_random_key(key):
                self._remember(self._client_random_key_of_owner, owner, key)
            return owner
        self._remember(self._owner_by_endpoint, endpoint_key, key)
        self._alias_to_owner.pop(key, None)
        return key

    def _resolve_by_session(self, key: str, session_key: str, is_live,
                            may_promote: Optional[Callable[[str, str], bool]] = None) -> str:
        """Join *key* to the live connection of *session_key*, else start one under *key*.

        A late client_random folds into the ``sid:`` owner; a new ``#gen`` is a new connection.
        """
        owner = self.canonical(session_key)
        if is_live(owner):
            if self._promote(key, owner, may_promote):
                return key
            # Per-record path: only write when the alias changes, not on every record.
            if key != owner and self._alias_to_owner.get(key) != owner:
                self._remember(self._alias_to_owner, key, owner)
            return owner
        self._alias_to_owner.pop(key, None)
        if key != session_key:
            self._remember(self._alias_to_owner, session_key, key)
        return key

    def _promote(self, key: str, owner: str,
                 may_promote: Optional[Callable[[str, str], bool]]) -> bool:
        """Rename the live *owner* to *key* when allowed; True when it did."""
        # String checks first: non-QUIC records never reach the callback.
        if (may_promote is None or key == owner
                or not promotes_to_client_random_key(key, owner)
                or not may_promote(owner, key)):
            return False
        self.rename(owner, key)
        self.promoted_from = owner
        return True

    def _may_alias(self, key: str, owner: Optional[str], is_live) -> bool:
        """Whether *key* folds into the live 4-tuple *owner*.

        Distinct ``cr:`` keys are distinct connections (port reuse): never folded into a
        ``cr:`` owner, nor a non-``cr:`` owner that already absorbed another.
        """
        if owner is None or owner == key or not is_live(owner):
            return False
        if not _is_client_random_key(key):
            return True
        if _is_client_random_key(owner):
            return False
        return self._client_random_key_of_owner.get(owner, key) == key

    def lookup(self, key: str, src_addr: str, src_port: int, dst_addr: str,
               dst_port: int, is_live) -> str:
        """Read-only :meth:`resolve` (lifecycle events must not claim a 4-tuple)."""
        canonical = self.canonical(key)
        if _is_client_random_key(key) or is_live(canonical):
            return canonical
        if key.startswith("sid:") and has_usable_endpoints(
                src_addr, src_port, dst_addr, dst_port):
            protocol = key.split(":", 2)[1]
            owner = self._owner_by_endpoint.get(resolve_connection_key(
                src_addr, src_port, dst_addr, dst_port, protocol=protocol))
            if owner is not None and is_live(owner):
                return owner
        return canonical

    def canonical(self, key: str) -> str:
        """The owner key *key* was aliased to, else *key* itself."""
        return self._alias_to_owner.get(key, key)

    def rename(self, old: str, new: str) -> None:
        """Make *new* the owner of *old*'s connection: its aliases and 4-tuple claims move. Idempotent."""
        if old == new:
            return
        self._alias_to_owner.pop(new, None)
        for table in (self._alias_to_owner, self._owner_by_endpoint):
            for key in [k for k, owner in table.items() if owner == old]:
                table[key] = new
        # Only non-cr: owners track a folded client_random; a cr: owner is its own.
        self._client_random_key_of_owner.pop(old, None)
        self._remember(self._alias_to_owner, old, new)

    def clear(self) -> None:
        self._owner_by_endpoint.clear()
        self._alias_to_owner.clear()
        self._client_random_key_of_owner.clear()
        self.promoted_from = None

    def _remember(self, table: "OrderedDict[str, str]", key: str, value: str) -> None:
        table[key] = value
        table.move_to_end(key)
        while len(table) > self._capacity:
            table.popitem(last=False)


@dataclass
class ConnectionInfo:
    """Metadata for a tracked connection."""
    src_addr: str = ""
    src_port: int = 0
    dst_addr: str = ""
    dst_port: int = 0
    ss_family: str = "AF_INET"
    ssl_session_id: str = ""
    protocol: str = "tls"
    bytes_read: int = 0
    bytes_written: int = 0


class ConnectionIndex:
    """Session-scoped connection and key deduplication tracker.

    Thread-safe. Created per-session, destroyed when session ends.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._seen_keys: Set[str] = set()
        self._traced_sockets: Set[Tuple[str, int, str, int]] = set()
        self._connections: Dict[str, ConnectionInfo] = {}
        self._client_random_map: Dict[str, str] = {}

    def is_new_key(self, key_data: str) -> bool:
        """True the first time *key_data* is seen. Thread-safe."""
        with self._lock:
            if key_data in self._seen_keys:
                return False
            self._seen_keys.add(key_data)
            return True

    def is_new_socket(self, src_addr: str, src_port: int,
                       dst_addr: str, dst_port: int) -> bool:
        """True the first time the socket tuple is seen. Thread-safe."""
        key = (src_addr, src_port, dst_addr, dst_port)
        with self._lock:
            if key in self._traced_sockets:
                return False
            self._traced_sockets.add(key)
            return True

    def get_or_create_connection(
        self,
        src_addr: str,
        src_port: int,
        dst_addr: str,
        dst_port: int,
        **kwargs,
    ) -> Tuple[str, ConnectionInfo]:
        """Return ``(connection_id, info)``, creating the entry if needed.

        The id includes ssl_session_id when it is real (non-dummy), to tell
        multiplexed connections on one socket tuple apart.
        """
        ssl_session_id = kwargs.get("ssl_session_id", "")
        base_key = f"{src_addr}:{src_port}-{dst_addr}:{dst_port}"
        if ssl_session_id and not ssl_session_id.startswith(DUMMY_SESSION_ID_BASE) and ssl_session_id != NSS_DUMMY_SESSION_ID:
            key = f"{base_key}:{ssl_session_id}"
        else:
            key = base_key
        with self._lock:
            if key not in self._connections:
                self._connections[key] = ConnectionInfo(
                    src_addr=src_addr,
                    src_port=src_port,
                    dst_addr=dst_addr,
                    dst_port=dst_port,
                    **kwargs,
                )
            return key, self._connections[key]

    def register_client_random(self, client_random: str, connection_id: str) -> None:
        """Map a client_random to a connection_id; empty values are ignored. Thread-safe."""
        if not client_random:
            return
        with self._lock:
            self._client_random_map[client_random] = connection_id

    def get_connection_by_client_random(self, client_random: str) -> Optional[str]:
        """The connection_id for *client_random*, or ``None``. Thread-safe."""
        if not client_random:
            return None
        with self._lock:
            return self._client_random_map.get(client_random)

    @property
    def key_count(self) -> int:
        """Number of unique keys seen."""
        with self._lock:
            return len(self._seen_keys)

    @property
    def connection_count(self) -> int:
        """Number of tracked connections."""
        with self._lock:
            return len(self._connections)

    @property
    def socket_count(self) -> int:
        """Number of traced sockets."""
        with self._lock:
            return len(self._traced_sockets)

    def remove_connection(self, connection_id: str) -> None:
        """Remove a connection and its client_random mappings; unknown ids are ignored. Thread-safe."""
        with self._lock:
            self._connections.pop(connection_id, None)
            stale = [cr for cr, cid in self._client_random_map.items()
                     if cid == connection_id]
            for cr in stale:
                del self._client_random_map[cr]

    def clear(self) -> None:
        """Clear all tracking state."""
        with self._lock:
            self._seen_keys.clear()
            self._traced_sockets.clear()
            self._connections.clear()
            self._client_random_map.clear()
