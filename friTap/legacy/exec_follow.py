"""Bookkeeping that lets friTap follow every instrumented process across exec().

``SSL_Logger`` instruments the spawned or attached target and, with
``--enable_child_gating``, its gated children. Each of those processes can
``exec()`` a new image under the same pid. Frida ends the old image's session
with ``process-replaced`` and, when child gating is on for that session, reports
the new image as a child of origin ``"exec"`` held suspended. Both events can
arrive in either order, per pid.

* :class:`ProcessTracker` remembers which pids friTap instruments, whether each
  one's session gates its children, and counts those two events per pid.
* :class:`HeldExecWatchdog` finds an exec'd image Frida holds without announcing
  it (see its docstring), so it can be instrumented and resumed like any other.
* :class:`ResumeWorker` resumes gated processes off Frida's event thread.
"""

from __future__ import annotations

import dataclasses
import logging
import queue
import threading
import time
from collections.abc import Callable, Iterable, Mapping
from typing import Any

logger = logging.getLogger("friTap.exec_follow")


@dataclasses.dataclass
class TrackedProcess:
    """One instrumented process: the main target or an instrumented child."""

    pid: int
    is_main: bool  # its loss ends the capture; a child's never does
    gated: bool  # its session gates children, so an exec() arrives as one
    session: Any = None
    replaced: int = 0  # 'process-replaced' detaches seen
    images: int = 0  # exec'd images seen

    @property
    def awaiting_image(self) -> bool:
        return self.replaced > self.images


class ProcessTracker:
    """Thread-safe ``pid -> TrackedProcess`` map.

    Detach callbacks, Frida's event thread, the instrument worker and timers all
    use it, so every method takes the lock and returns plain values.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._processes: dict[int, TrackedProcess] = {}

    def track(self, pid: int, *, session: Any, is_main: bool, gated: bool) -> None:
        """Record *pid* as instrumented through *session*. Re-tracking a pid (its
        exec'd image) keeps the event counters: the old image's detach and the
        new image may be counted on either side of it."""
        with self._lock:
            entry = self._processes.get(pid)
            if entry is None:
                self._processes[pid] = TrackedProcess(pid, is_main, gated, session)
                return
            entry.is_main, entry.gated, entry.session = is_main, gated, session

    def forget(self, pid: int, session: Any = None) -> bool:
        """Stop tracking *pid*. With *session*, only while that session is still
        the pid's current one: a late detach of an image that already exec()ed
        must not drop the image that replaced it."""
        with self._lock:
            entry = self._processes.get(pid)
            if entry is None or (session is not None and entry.session is not session):
                return False
            del self._processes[pid]
            return True

    def get(self, pid: int) -> TrackedProcess | None:
        with self._lock:
            entry = self._processes.get(pid)
            return dataclasses.replace(entry) if entry is not None else None

    def is_tracked(self, pid: int) -> bool:
        with self._lock:
            return pid in self._processes

    def note_replaced(self, pid: int) -> bool:
        """Count a 'process-replaced'; True while its exec'd image is still due."""
        with self._lock:
            entry = self._processes.get(pid)
            if entry is None:
                return False
            entry.replaced += 1
            return entry.awaiting_image

    def note_image(self, pid: int) -> None:
        with self._lock:
            entry = self._processes.get(pid)
            if entry is not None:
                entry.images += 1

    def awaiting_image(self, pid: int) -> bool:
        with self._lock:
            entry = self._processes.get(pid)
            return entry is not None and entry.awaiting_image

    def pids(self) -> set[int]:
        with self._lock:
            return set(self._processes)


@dataclasses.dataclass
class _WatchState:
    path: str | None = None  # learnt on the first poll
    changed_at: float | None = None


class HeldExecWatchdog:
    """Find exec'd images that Frida holds without ever announcing them.

    Seen with Frida 17.24.3 on macOS: a gated process that closes Frida's file
    descriptors between fork() and exec() -- Python's ``subprocess`` with the
    default ``close_fds=True`` does -- stalls ~25 s in exec() (Frida's D-Bus
    timeout), and its new image then waits at Frida's exec breakpoint with no
    'child-added' and no detach. Its parent waits for it, so the capture would
    hang forever. Frida can still attach to and resume that image.

    So the executable path of every watched (gated) pid is polled, by pid, which
    costs a few milliseconds. A path that changed without an exec announcement
    for ``grace`` seconds is such a held image and is handed to ``on_held``.
    The path, not the name, is compared: a process may rename itself without
    exec() (``setproctitle``), but its executable only changes on exec().

    While nothing changes, the poll interval doubles up to ``max_interval`` to
    spare the backend; a pending change, a held image, ``watch()`` or
    ``note_exec()`` drops it back to ``interval``. ``watch()`` and ``note_exec()``
    also poll at once, so a path is (re-)learnt before the next exec().
    """

    def __init__(self, query_paths: Callable[[list[int]], Mapping[int, str]],
                 on_held: Callable[[int, str], None], interval: float = 1.0,
                 grace: float = 2.0, clock: Callable[[], float] = time.monotonic,
                 max_interval: float = 5.0) -> None:
        self._query_paths = query_paths
        self._on_held = on_held
        self._interval = interval
        self._max_interval = max(interval, max_interval)
        self._backoff_reset = False
        self._grace = grace
        self._clock = clock
        self._lock = threading.Lock()
        self._watched: dict[int, _WatchState] = {}
        self._stop = threading.Event()
        self._wake = threading.Event()  # set by watch(), note_exec() and stop()
        self._thread: threading.Thread | None = None
        self._unsupported = False

    def watch(self, pid: int) -> None:
        with self._lock:
            if self._unsupported or self._stop.is_set():
                return
            self._watched[pid] = _WatchState()
            self._backoff_reset = True
            self._start_locked()
        self._wake.set()

    def forget(self, pid: int) -> None:
        with self._lock:
            self._watched.pop(pid, None)

    def note_exec(self, pid: int) -> None:
        """An exec of *pid* was announced: re-learn its path on the next poll."""
        with self._lock:
            if pid in self._watched:
                self._watched[pid] = _WatchState()
                self._backoff_reset = True
        self._wake.set()

    def watched(self) -> set[int]:
        with self._lock:
            return set(self._watched)

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()
        with self._lock:
            self._watched.clear()

    def poll_once(self) -> bool:
        """One poll: report every pid whose image changed unannounced.

        Returns whether anything happened: an image was reported or a path
        change is still within its grace period.
        """
        pids = sorted(self.watched())
        if not pids:
            return False
        paths = self._query(pids)
        if paths is None:
            return False
        held = self._update(pids, paths, self._clock())
        for pid, path in held:
            logger.debug("pid %s exec()ed %s without an announcement", pid, path)
            self._on_held(pid, path)
        return bool(held) or self._change_pending()

    def _change_pending(self) -> bool:
        with self._lock:
            return any(state.changed_at is not None for state in self._watched.values())

    def _next_interval(self, current: float, active: bool) -> float:
        """Base cadence after activity, otherwise double up to the cap."""
        with self._lock:
            reset, self._backoff_reset = self._backoff_reset, False
        if active or reset:
            return self._interval
        return min(current * 2, self._max_interval)

    def _query(self, pids: list[int]) -> Mapping[int, str] | None:
        try:
            paths = self._query_paths(pids)
        except NotImplementedError:
            logger.debug("backend cannot list process paths; held exec images "
                         "will not be detected")
            with self._lock:
                self._unsupported = True
                self._watched.clear()
            return None
        except Exception:  # noqa: BLE001 - a failed poll is retried next time
            logger.debug("process path poll failed", exc_info=True)
            return None
        return paths if isinstance(paths, Mapping) else {}

    def _update(self, pids: Iterable[int], paths: Mapping[int, str],
                now: float) -> list[tuple[int, str]]:
        held = []
        with self._lock:
            for pid in pids:
                state = self._watched.get(pid)
                if state is None:
                    continue
                path = paths.get(pid)
                if not isinstance(path, str):
                    del self._watched[pid]  # the process is gone
                elif state.path is None or path == state.path:
                    self._watched[pid] = _WatchState(path=path)
                elif state.changed_at is None:
                    state.changed_at = now
                elif now - state.changed_at >= self._grace:
                    held.append((pid, path))
                    self._watched[pid] = _WatchState(path=path)
        return held

    def _start_locked(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._run, name="fritap-exec-watchdog",
                                        daemon=True)
        self._thread.start()

    def _run(self) -> None:
        wait = self._interval
        while True:
            self._wake.wait(wait)
            self._wake.clear()
            if self._stop.is_set():
                return
            wait = self._next_interval(wait, self.poll_once())
            with self._lock:
                if not self._watched:
                    self._thread = None
                    return


class ResumeWorker:
    """Resume gated pids one after another on a single background thread.

    Gating callbacks run on Frida's event thread, where a synchronous resume
    deadlocks it, so every resume is handed here instead of to a new thread per
    process. The thread starts on demand and retires after ``idle_timeout``
    seconds without work. Callers keep each pid in their own suspended-pid
    bookkeeping until ``resume`` returned, so a teardown racing this worker
    still resumes it.
    """

    def __init__(self, resume: Callable[[int], None], idle_timeout: float = 1.0) -> None:
        self._resume = resume
        self._idle_timeout = idle_timeout
        self._queue: queue.SimpleQueue[int] = queue.SimpleQueue()
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None

    def submit(self, pid: int) -> None:
        with self._lock:
            self._queue.put(pid)
            if self._thread is None:
                self._thread = threading.Thread(target=self._run, name="fritap-resume",
                                                daemon=True)
                self._thread.start()

    def _run(self) -> None:
        while (pid := self._next_pid()) is not None:
            try:
                self._resume(pid)
            except Exception:  # noqa: BLE001 - one failed resume must not stop the rest
                logger.debug("resume of pid %s failed", pid, exc_info=True)

    def _next_pid(self) -> int | None:
        """The next queued pid, or None (thread retired) after an idle timeout."""
        while True:
            try:
                return self._queue.get(timeout=self._idle_timeout)
            except queue.Empty:
                with self._lock:
                    if self._queue.empty():
                        self._thread = None
                        return None
