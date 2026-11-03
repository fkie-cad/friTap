"""Circuit breaker for repeated decoder-worker failures."""

from __future__ import annotations

import time
from collections import deque


class CircuitBreaker:
    """Opens after more than *max_failures* failures within *window* seconds.

    While open (for *cooldown* seconds) :meth:`is_open` is True and no worker
    is started. Not thread-safe by itself; the supervisor holds its lock.
    """

    def __init__(self, max_failures: int = 5, window: float = 60.0,
                 cooldown: float = 60.0, clock=time.monotonic) -> None:
        self.max_failures = max_failures
        self.window = window
        self.cooldown = cooldown
        self._clock = clock
        self._failures: deque[float] = deque()
        self._open_until: float | None = None

    def record_failure(self) -> bool:
        """Count one failure; True when this failure opened the breaker."""
        now = self._clock()
        self._failures.append(now)
        self._forget_before(now - self.window)
        if len(self._failures) > self.max_failures and self._open_until is None:
            self._open_until = now + self.cooldown
            return True
        return False

    def is_open(self) -> bool:
        """True while the cooldown runs; closes (and forgets history) after it."""
        if self._open_until is None:
            return False
        if self._clock() < self._open_until:
            return True
        self.reset()
        return False

    def reset(self) -> None:
        """Close the breaker and clear the failure history."""
        self._open_until = None
        self._failures.clear()

    def _forget_before(self, cutoff: float) -> None:
        while self._failures and self._failures[0] < cutoff:
            self._failures.popleft()
