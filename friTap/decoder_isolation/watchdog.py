"""Deadline watchdog for decoder-worker requests.

A blocking ``recv_bytes`` cannot be interrupted portably, and a compromised
worker could send a frame header and then stall. One persistent daemon
thread therefore enforces each request's deadline by invoking a kill
callback; the killed worker's pipe reaches EOF and the blocked call returns.
"""

from __future__ import annotations

import threading
import time
from typing import Callable


class Watchdog:
    """Calls *on_expire* when an armed deadline passes before :meth:`disarm`."""

    def __init__(self, on_expire: Callable[[], None]) -> None:
        self._on_expire = on_expire
        self._cond = threading.Condition()
        self._deadline: float | None = None
        self._fired = False
        self._stopped = False
        self._thread = threading.Thread(target=self._run, name="fritap-decoder-watchdog",
                                        daemon=True)
        self._thread.start()

    def arm(self, seconds: float) -> None:
        """Start a deadline *seconds* from now (replaces any armed one)."""
        with self._cond:
            self._deadline = time.monotonic() + seconds
            self._fired = False
            self._cond.notify()

    def disarm(self) -> bool:
        """Cancel the deadline; True when it had already fired."""
        with self._cond:
            self._deadline = None
            fired, self._fired = self._fired, False
            return fired

    def stop(self) -> None:
        """End the watchdog thread."""
        with self._cond:
            self._stopped = True
            self._cond.notify()
        self._thread.join(timeout=2)

    def _run(self) -> None:
        with self._cond:
            while not self._stopped:
                if self._wait_for_expiry():
                    self._fired = True
                    self._deadline = None
                    self._fire()

    def _wait_for_expiry(self) -> bool:
        """Block until the armed deadline passes (True) or state changes (False)."""
        if self._deadline is None:
            self._cond.wait()
            return False
        remaining = self._deadline - time.monotonic()
        if remaining > 0:
            self._cond.wait(remaining)
            return False
        return True

    def _fire(self) -> None:
        try:
            self._on_expire()
        except Exception:
            pass
