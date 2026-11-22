"""Tiny size-bounded LRU mapping shared by the synthetic-QUIC output modules."""

from __future__ import annotations

from collections import OrderedDict
from typing import Generic, Hashable, List, Optional, Tuple, TypeVar

K = TypeVar("K", bound=Hashable)
V = TypeVar("V")


class BoundedLRU(Generic[K, V]):
    """Mapping that keeps at most *cap* entries, forgetting the least recently used.

    Not thread-safe: callers already serialise access under their own lock.
    """

    # Not flow.replay._LRUCache: put() reports evictions and the cap is clamped to >= 1.

    def __init__(self, cap: int) -> None:
        self._cap = max(1, int(cap))
        self._entries: "OrderedDict[K, V]" = OrderedDict()

    def __len__(self) -> int:
        return len(self._entries)

    def __contains__(self, key: object) -> bool:
        return key in self._entries

    def __getitem__(self, key: K) -> V:
        return self._entries[key]

    def keys(self) -> List[K]:
        return list(self._entries)

    def get(self, key: K, default: Optional[V] = None) -> Optional[V]:
        """The value for *key* (marking it recently used), else *default*."""
        if key not in self._entries:
            return default
        self._entries.move_to_end(key)
        return self._entries[key]

    def put(self, key: K, value: V) -> List[Tuple[K, V]]:
        """Store *key* as most recently used; return the entries evicted for it."""
        self._entries[key] = value
        self._entries.move_to_end(key)
        evicted = []
        while len(self._entries) > self._cap:
            evicted.append(self._entries.popitem(last=False))
        return evicted

    def pop(self, key: K, default: Optional[V] = None) -> Optional[V]:
        return self._entries.pop(key, default)
