#!/usr/bin/env python3
"""A target that crashes on friTap's own detach must be reported, not end clean.

Live defect (Pixel 5 / Chrome 158): an early attach left ART in a broken state
and Chrome aborted ~0.6 s after friTap's detach ("attempting to detach while
still running code"). on_detach ignores events once teardown runs and frida
sends none after session.detach(), so friTap exited 0 with a clean detach log.
"""

import logging
import types

import pytest

from friTap.exit_codes import EXIT_OK, EXIT_TARGET_DETACHED
from friTap.legacy.ssl_logger_core import SSL_Logger
from friTap.legacy.ssl_logger_teardown import TeardownMixin

ART_DETACH_ABORT = ("Thread[16,tid=17633,Runnable,Thread*=0xb40000780726d050,peer=0x22c0928,"
                    "\"Thread-5\"] attempting to detach while still running code")


class _ListHandler(logging.Handler):
    def __init__(self):
        super().__init__(logging.DEBUG)
        self.records = []

    def emit(self, record):
        self.records.append(record)


class _Backend:
    """enumerate_processes() returns the pid lists given, one per call (last repeats)."""

    def __init__(self, *pid_lists, error=None):
        self.pid_lists = list(pid_lists)
        self.error = error
        self.calls = 0

    def enumerate_processes(self, device):
        self.calls += 1
        if self.error is not None:
            raise self.error
        pids = self.pid_lists.pop(0) if len(self.pid_lists) > 1 else self.pid_lists[0]
        return [types.SimpleNamespace(pid=p, name="x") for p in pids]


def _make_logger(backend, enrich=(None, None), evidence=None):
    obj = SSL_Logger.__new__(SSL_Logger)
    obj.logger = logging.getLogger("test.crash_after_detach")
    obj.logger.setLevel(logging.DEBUG)
    obj.logger.propagate = False
    handler = _ListHandler()
    obj.logger.handlers = [handler]
    obj.pid = 1234
    obj.device = object()
    obj._backend = backend
    obj._android_target_cached = True
    obj._main_session_detached = True
    obj._crash_reported = False
    obj._pending_crash = None
    obj._event_bus = types.SimpleNamespace(emit=lambda *a, **k: None)
    obj.POST_DETACH_POLL_SECONDS = 0

    def fake_enrich(crash, writer):
        obj._android_crash_evidence = evidence
        return enrich

    obj._enrich_crash_log_android = fake_enrich
    obj._enrich_crash_log_ios = lambda crash, writer: (None, None)
    obj._enrich_crash_log_macos = lambda crash, writer: (None, None)
    return obj, handler


@pytest.fixture(autouse=True)
def _no_debug_log(monkeypatch):
    monkeypatch.setattr("friTap.fritap_utility.open_debug_log", lambda *a, **k: None)
    monkeypatch.setattr("friTap.fritap_utility.attach_file_handlers", lambda *a, **k: None)
    monkeypatch.setattr("friTap.fritap_utility.get_debug_log_writer", lambda *a, **k: None)


def _messages(handler, level):
    return [r.getMessage() for r in handler.records if r.levelno == level]


def test_art_abort_right_after_detach_is_reported_as_a_crash():
    # Alive on the first poll, gone on the second: the baseline timing.
    backend = _Backend([1234, 1], [1])
    obj, handler = _make_logger(backend, enrich=("SIGSEGV", ART_DETACH_ABORT))

    obj._report_crash_after_detach()

    errors = _messages(handler, logging.ERROR)
    assert any("1234 crashed during or right after friTap's detach" in m
               and "attempting to detach while still running code" in m for m in errors), errors
    assert obj._exit_status == EXIT_TARGET_DETACHED
    assert obj._crash_reported is True


def test_target_that_survives_the_detach_is_not_reported():
    backend = _Backend([1234])
    obj, handler = _make_logger(backend)
    obj.POST_DETACH_WATCH_SECONDS = 0

    obj._report_crash_after_detach()

    assert backend.calls == 1
    assert not _messages(handler, logging.ERROR) and not _messages(handler, logging.WARNING)
    assert obj._exit_status == EXIT_OK
    assert obj._crash_reported is False


def test_target_gone_without_crash_evidence_is_a_warning_only():
    obj, handler = _make_logger(_Backend([1]))

    obj._report_crash_after_detach()

    warnings = _messages(handler, logging.WARNING)
    assert any("1234 exited during or right after friTap's detach" in m for m in warnings)
    assert not _messages(handler, logging.ERROR)
    assert obj._exit_status == EXIT_OK


def test_android_evidence_without_a_signal_still_counts_as_a_crash():
    obj, handler = _make_logger(_Backend([1]), evidence=("tombstone", "/data/tombstones/tombstone_03"))

    obj._report_crash_after_detach()

    assert any("tombstone: /data/tombstones/tombstone_03" in m
               for m in _messages(handler, logging.ERROR))
    assert obj._exit_status == EXIT_TARGET_DETACHED


@pytest.mark.parametrize("attr, value", [
    ("_android_target_cached", False),   # not Android
    ("_main_session_detached", False),   # friTap never detached (target gone, wedged unload)
    ("_target_gone", True),              # death already reported by on_detach
    ("_crash_reported", True),
    ("pid", None),
])
def test_no_watch_unless_friTap_detached_from_a_live_android_target(attr, value):
    backend = _Backend([1])
    obj, handler = _make_logger(backend)
    setattr(obj, attr, value)

    obj._report_crash_after_detach()

    assert backend.calls == 0
    assert not handler.records or not _messages(handler, logging.ERROR)


def test_failed_liveness_check_reports_nothing():
    obj, handler = _make_logger(_Backend(error=RuntimeError("device gone")))

    obj._report_crash_after_detach()

    assert not _messages(handler, logging.ERROR) and not _messages(handler, logging.WARNING)
    assert obj._exit_status == EXIT_OK


def test_teardown_detach_step_is_followed_by_the_survival_check(monkeypatch):
    calls = []
    monkeypatch.setattr(TeardownMixin, "_detach_with_cli_timeout",
                        lambda self: calls.append("detach"))
    obj = SSL_Logger.__new__(SSL_Logger)
    obj._report_crash_after_detach = lambda: calls.append("check")

    obj._detach_with_cli_timeout()

    assert calls == ["detach", "check"]


# --- the CLI main thread must let a --duration teardown reach the check ------
# Live: with --duration, cleanup() runs on the timer thread and sets _done_event
# BEFORE the detach step; wait_for_completion() then os._exit()ed at once, so the
# detach and the survival check never ran (no goodbye line either).

def test_main_thread_waits_for_a_teardown_running_elsewhere():
    obj = SSL_Logger.__new__(SSL_Logger)
    obj._cleanup_done = True
    obj.TEARDOWN_FINISH_GRACE_SECONDS = 5.0
    import threading
    threading.Timer(0.2, obj._teardown_finished.set).start()
    import time
    t0 = time.monotonic()
    obj._let_running_teardown_finish()
    waited = time.monotonic() - t0
    assert 0.15 <= waited < 4.0


def test_main_thread_wait_is_bounded_and_skipped_without_a_teardown():
    import time
    obj = SSL_Logger.__new__(SSL_Logger)
    obj.TEARDOWN_FINISH_GRACE_SECONDS = 0.2
    t0 = time.monotonic()
    obj._let_running_teardown_finish()          # no cleanup started: no wait
    assert time.monotonic() - t0 < 0.1
    obj._cleanup_done = True
    obj._let_running_teardown_finish()          # never finishes: bounded
    assert 0.15 <= time.monotonic() - t0 < 2.0


def test_only_the_cleanup_that_ran_the_steps_marks_the_teardown_finished(monkeypatch):
    def fake_cleanup(self, *a, **k):
        if self._cleanup_done:
            return
        self._cleanup_done = True

    monkeypatch.setattr(TeardownMixin, "cleanup", fake_cleanup)
    obj = SSL_Logger.__new__(SSL_Logger)
    obj._cleanup_done = True                    # another thread is mid-teardown
    obj.cleanup()
    assert not obj._teardown_finished.is_set()

    fresh = SSL_Logger.__new__(SSL_Logger)
    fresh._cleanup_done = False
    fresh.cleanup(live=False)
    assert fresh._teardown_finished.is_set()
