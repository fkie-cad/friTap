"""Shared key deduplication utility for output handlers."""


class KeyDeduplicator:
    """Thread-safe-ish deduplicator for keylog entries."""

    def __init__(self):
        self._seen: set[str] = set()

    def is_new(self, key: str) -> bool:
        """Return True if this key has not been seen before, and record it."""
        if key in self._seen:
            return False
        self._seen.add(key)
        return True

    def clear(self) -> None:
        """Reset all seen keys."""
        self._seen.clear()
