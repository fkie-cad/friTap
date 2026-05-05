"""Shared key deduplication utility for output handlers."""

import threading
from collections import OrderedDict


class KeyDeduplicator:
    """Thread-safe deduplicator for keylog entries with optional LRU eviction."""

    def __init__(self, max_size: int = 10_000):
        self._seen: OrderedDict[str, None] = OrderedDict()
        self._max_size = max_size
        self._lock = threading.Lock()

    def is_new(self, key: str) -> bool:
        """Return True if this key has not been seen before, and record it."""
        with self._lock:
            if key in self._seen:
                return False
            if len(self._seen) >= self._max_size:
                # Evict oldest 10% to avoid per-insert eviction overhead
                for _ in range(self._max_size // 10):
                    self._seen.popitem(last=False)
            self._seen[key] = None
            return True

    def unmark(self, keys) -> None:
        """Remove keys from tracking so they can be re-queued on error recovery."""
        with self._lock:
            for k in keys:
                self._seen.pop(k, None)

    def clear(self) -> None:
        """Reset all seen keys."""
        with self._lock:
            self._seen.clear()
