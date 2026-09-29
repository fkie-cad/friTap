#!/usr/bin/env python3

"""Ctrl+C / stop responsiveness of the memory-scan poll loop.

Device-confirmed bug: with ``--memory-scan-interval <= 0.3s`` the poll loop ran
``scanOnce()`` back-to-back and, together with Frida's message-dispatch thread,
saturated the GIL. CPython only runs the ``signal.signal(SIGINT, ...)`` handler on
the main thread when that thread can win the GIL, so the handler was starved —
friTap "ignored" 20+ SIGINTs and had to be SIGKILLed.

The fix serves the inter-scan wait as short interruptible slices on the stop
Event (:data:`MS_STOP_POLL_SECONDS`), always leaves one GIL-releasing gap per
cycle (:data:`MS_MIN_YIELD_SECONDS`), and re-checks stop before each scan — while
preserving the exponential backoff (:data:`MS_BACKOFF_FACTOR` /
:data:`MS_BACKOFF_CAP_SECONDS`) and every output.

These tests are hermetic (no device / Frida): the loop is driven with a stubbed
``scanOnce`` and a real stop Event, using small intervals so the suite stays fast
and deterministic (no multi-second sleeps).
"""

from __future__ import annotations

import threading
import time

from friTap.memory_scanning import MemoryScanEngine
from friTap.memory_scanning.engine import (
    MS_BACKOFF_CAP_SECONDS,
    MS_MIN_YIELD_SECONDS,
    MS_STOP_POLL_SECONDS,
)

JOIN_TIMEOUT = 3.0


class _ScriptedRpc:
    """Minimal ``scanOnce`` stub returning a scripted ``emitted`` count.

    Each call pops the next scripted value (0 once the script is exhausted), so a
    test can drive the loop's backoff/reset branches deterministically without a
    real agent. ``calls`` records the wall-clock time of every scan for cadence
    assertions.
    """

    def __init__(self, emitted_seq=None, on_scan=None):
        self._seq = list(emitted_seq) if emitted_seq is not None else []
        self._on_scan = on_scan
        self.calls: list[float] = []

    def scanOnce(self):
        self.calls.append(time.monotonic())
        if self._on_scan is not None:
            self._on_scan()
        emitted = self._seq.pop(0) if self._seq else 0
        return {"emitted": emitted, "durationMs": 0}


# --------------------------------------------------------------------------- #
# (a) A stop mid-wait exits promptly even for a huge interval
# --------------------------------------------------------------------------- #


def test_stop_mid_wait_exits_far_sooner_than_a_large_interval():
    """A large interval must not hold teardown hostage: stop is observed fast."""
    eng = MemoryScanEngine(interval=100.0)  # a full cycle would sleep ~100s
    reached_wait = threading.Event()
    # emitted=1 keeps the wait pinned at the (huge) base interval, so exiting
    # quickly can only be because the wait itself is interruptible.
    rpc = _ScriptedRpc(on_scan=reached_wait.set)

    thread = threading.Thread(target=eng._poll_loop, args=(rpc,), daemon=True)
    thread.start()
    try:
        assert reached_wait.wait(JOIN_TIMEOUT), "poll loop never ran a scan"
        # Give the loop a beat to enter the inter-scan wait, then request stop.
        time.sleep(0.05)
        eng._stop.set()
        thread.join(timeout=JOIN_TIMEOUT)
        assert not thread.is_alive(), "loop hung on the 100s wait after stop"
    finally:
        eng._stop.set()
        thread.join(timeout=JOIN_TIMEOUT)


def test_wait_between_scans_returns_true_immediately_when_stopped():
    eng = MemoryScanEngine(interval=5.0)
    eng._stop.set()
    start = time.monotonic()
    assert eng._wait_between_scans(5.0) is True
    assert time.monotonic() - start < 0.5


def test_wait_between_scans_elapses_and_returns_false_when_not_stopped():
    eng = MemoryScanEngine(interval=1.0)
    start = time.monotonic()
    assert eng._wait_between_scans(0.2) is False
    elapsed = time.monotonic() - start
    assert 0.15 <= elapsed < 1.0


# --------------------------------------------------------------------------- #
# (b) A normal interval still scans at roughly the configured cadence
# --------------------------------------------------------------------------- #


def test_scans_at_roughly_configured_cadence_for_a_normal_interval():
    eng = MemoryScanEngine(interval=0.1)
    rpc = _ScriptedRpc()  # emitted defaults to 0; interval > backoff floor here
    # emitted=0 would grow the wait via backoff; keep it at base by always emitting.
    rpc = _ScriptedRpc(emitted_seq=[1] * 100)

    thread = threading.Thread(target=eng._poll_loop, args=(rpc,), daemon=True)
    thread.start()
    try:
        time.sleep(0.45)
        eng._stop.set()
        thread.join(timeout=JOIN_TIMEOUT)
    finally:
        eng._stop.set()
        thread.join(timeout=JOIN_TIMEOUT)
    # ~0.1s cadence over ~0.45s -> about 4-5 scans; wide slack for CI jitter.
    assert 3 <= len(rpc.calls) <= 8, f"unexpected scan count: {len(rpc.calls)}"


# --------------------------------------------------------------------------- #
# (c) Backoff (and its reset + cap + min-yield floor) still applies
# --------------------------------------------------------------------------- #


def _record_waits(eng: MemoryScanEngine, stop_after: int) -> list:
    """Replace ``_wait_between_scans`` with a non-blocking recorder.

    Records each requested wait and returns ``True`` (i.e. "stopped") once
    *stop_after* waits have been seen, so ``_poll_loop`` can be driven
    synchronously with no real sleeping.
    """
    recorded: list = []

    def fake_wait(seconds: float) -> bool:
        recorded.append(seconds)
        return len(recorded) >= stop_after

    eng._wait_between_scans = fake_wait  # type: ignore[method-assign]
    return recorded


def test_backoff_grows_geometrically_and_resets_on_a_new_key():
    eng = MemoryScanEngine(interval=1.0)
    recorded = _record_waits(eng, stop_after=5)
    # scans: empty, empty, empty, EMITTED (reset), empty
    rpc = _ScriptedRpc(emitted_seq=[0, 0, 0, 1, 0])
    eng._poll_loop(rpc)
    assert recorded == [2.0, 4.0, 8.0, 1.0, 2.0]


def test_backoff_is_capped_at_the_ceiling():
    eng = MemoryScanEngine(interval=40.0)
    recorded = _record_waits(eng, stop_after=3)
    rpc = _ScriptedRpc(emitted_seq=[0, 0, 0])  # never emits -> keeps growing
    eng._poll_loop(rpc)
    assert recorded == [MS_BACKOFF_CAP_SECONDS] * 3
    assert all(w <= MS_BACKOFF_CAP_SECONDS for w in recorded)


def test_tiny_interval_is_floored_to_a_minimum_yield():
    eng = MemoryScanEngine(interval=0.01)  # smaller than the yield floor
    recorded = _record_waits(eng, stop_after=2)
    rpc = _ScriptedRpc(emitted_seq=[1, 1])  # stay at base interval
    eng._poll_loop(rpc)
    assert recorded == [MS_MIN_YIELD_SECONDS, MS_MIN_YIELD_SECONDS]


# --------------------------------------------------------------------------- #
# Stop-before-scan guard
# --------------------------------------------------------------------------- #


def test_stop_before_first_scan_runs_no_scan():
    eng = MemoryScanEngine(interval=0.1)
    eng._stop.set()
    rpc = _ScriptedRpc(emitted_seq=[1, 1, 1])
    eng._poll_loop(rpc)
    assert rpc.calls == []


def test_wait_slices_are_bounded_by_the_poll_granularity():
    """The wait is served in slices no larger than MS_STOP_POLL_SECONDS."""
    eng = MemoryScanEngine(interval=1.0)
    slices: list = []
    real_wait = eng._stop.wait

    def spy(timeout=None):  # noqa: ANN001
        slices.append(timeout)
        return real_wait(timeout)

    eng._stop.wait = spy  # type: ignore[method-assign]
    eng._wait_between_scans(0.35)
    assert slices, "no wait slices recorded"
    assert all(s <= MS_STOP_POLL_SECONDS + 1e-9 for s in slices)
