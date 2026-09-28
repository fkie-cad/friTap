"""Unit tests for CaptureController's explicit capture-state machine.

Regression cover for the "stop didn't stop / pressing again re-started the
capture" bug: the Enter toggle used to key off ``SSL_Logger.running`` alone, so a
press after a (self-terminated or teardown-in-flight) stop silently launched a
brand-new attach. The controller now tracks IDLE / RUNNING / STOPPING / STOPPED
and gates start/stop on it.

Lightweight stubs — instantiating the real Textual app is impractical here.
"""

from __future__ import annotations

import types
from unittest.mock import MagicMock

import pytest


def _make_controller():
    pytest.importorskip("textual")
    from friTap.tui.capture_controller import CaptureController

    activity: list = []
    pushed: list = []

    class _ActivityLog:
        def log_error(self, m): activity.append(("error", m))
        def log_info(self, m): activity.append(("info", m))
        def log_warning(self, m): activity.append(("warning", m))
        def log_session(self, m): activity.append(("session", m))

    class _StatusBar:
        capture_mode = ""
        def update_capture(self, *a, **kw): pass
        def update_target(self, *a, **kw): pass

    class _App:
        def push_screen(self, screen, callback=None): pushed.append(screen)
        def notify(self, *a, **kw): pass
        def call_from_thread(self, fn, *a, **kw): return fn(*a, **kw)

    class _State:
        target = ""
        target_display = ""

    screen = types.SimpleNamespace()
    screen.app = _App()
    screen._get_activity_log = lambda: _ActivityLog()
    screen._get_status_bar = lambda: _StatusBar()
    screen._get_state = lambda: _State()
    screen._wizard_guard = lambda: False
    screen.run_worker = MagicMock()

    controller = CaptureController(screen)
    return controller, activity, pushed


def test_starts_idle():
    controller, _a, _p = _make_controller()
    assert controller._capture_state == controller.STATE_IDLE


def test_stop_from_running_moves_to_stopping_and_requests_stop():
    controller, activity, _p = _make_controller()
    controller._capture_state = controller.STATE_RUNNING
    controller._ssl_logger = MagicMock(running=True)

    controller.action_stop_capture()

    assert controller._capture_state == controller.STATE_STOPPING
    controller._ssl_logger.request_stop.assert_called_once()
    assert any("Stopping capture" in m for kind, m in activity if kind == "info")


def test_second_stop_press_while_stopping_is_a_noop():
    controller, _a, _p = _make_controller()
    controller._capture_state = controller.STATE_STOPPING
    controller._ssl_logger = MagicMock(running=False)

    controller.action_stop_capture()

    # Still stopping; must NOT request_stop again or restart anything.
    assert controller._capture_state == controller.STATE_STOPPING
    controller._ssl_logger.request_stop.assert_not_called()


def test_toggle_when_stopped_does_not_restart():
    controller, activity, _p = _make_controller()
    controller._capture_state = controller.STATE_STOPPED

    controller.action_toggle_capture()

    # No new session started; a restart hint is shown instead.
    controller._screen.run_worker.assert_not_called()
    assert controller._capture_state == controller.STATE_STOPPED
    assert any("restart the wizard" in m for _k, m in activity)


def test_toggle_when_running_stops():
    controller, _a, _p = _make_controller()
    controller._capture_state = controller.STATE_RUNNING
    controller._ssl_logger = MagicMock(running=True)

    controller.action_toggle_capture()

    assert controller._capture_state == controller.STATE_STOPPING
    controller._ssl_logger.request_stop.assert_called_once()


def test_start_guard_blocks_when_already_running():
    controller, _a, pushed = _make_controller()
    controller._capture_state = controller.STATE_RUNNING

    controller.action_start_capture()

    # Warned, and did NOT proceed to start a worker.
    controller._screen.run_worker.assert_not_called()
    assert pushed  # an AlertModal was pushed


def test_start_guard_blocks_when_stopped_until_restart():
    controller, activity, _p = _make_controller()
    controller._capture_state = controller.STATE_STOPPED

    controller.action_start_capture()

    controller._screen.run_worker.assert_not_called()
    assert any("restart the wizard" in m for _k, m in activity)


def test_reset_capture_state_returns_to_idle():
    controller, _a, _p = _make_controller()
    controller._capture_state = controller.STATE_STOPPED
    controller.reset_capture_state()
    assert controller._capture_state == controller.STATE_IDLE


def test_toggle_when_stopping_only_asks_to_wait():
    controller, activity, _p = _make_controller()
    controller._capture_state = controller.STATE_STOPPING
    controller._ssl_logger = MagicMock(running=False)

    controller.action_toggle_capture()

    assert activity == [("info", "Stopping capture — please wait…")]
    controller._ssl_logger.request_stop.assert_not_called()
    assert controller._capture_state == controller.STATE_STOPPING


def test_toggle_when_stopped_emits_exactly_the_restart_hint():
    from friTap.tui.capture_controller import CAPTURE_STOPPED_RESTART_HINT

    controller, activity, pushed = _make_controller()
    controller._capture_state = controller.STATE_STOPPED

    controller.action_toggle_capture()

    assert activity == [("info", CAPTURE_STOPPED_RESTART_HINT)]
    assert not pushed


def test_memory_scan_keylog_files_dedupes_shared_sidecar(tmp_path, monkeypatch):
    controller, _a, _p = _make_controller()
    controller._ssl_logger = MagicMock()
    tls = tmp_path / "ms.keylog"
    mt = tmp_path / "ms.mtproto.keylog"
    tls.write_text("CLIENT_RANDOM aa bb\n")
    mt.write_text("MTPROTO_AUTH_KEY aa bb\n")
    mapping = {"tls": str(tls), "mtproto": str(mt), "telegram": str(mt),
               "missing": str(tmp_path / "nope.keylog")}
    import friTap.memory_scanning as ms
    monkeypatch.setattr(ms, "memory_scan_protocol_keylogs", lambda _cfg: mapping)

    assert controller._memory_scan_keylog_files() == {"tls": str(tls), "mtproto": str(mt)}
    assert controller._memory_scan_keylog_paths() == [str(tls), str(mt)]


def _memscan_controller(mapping, monkeypatch, session_start):
    controller, _a, _p = _make_controller()
    controller._ssl_logger = MagicMock()
    controller._ssl_logger._session_start_time = session_start
    import friTap.memory_scanning as ms
    monkeypatch.setattr(ms, "memory_scan_protocol_keylogs", lambda _cfg: mapping)
    return controller


def test_memory_scan_keylog_files_skips_sidecar_from_earlier_run(tmp_path, monkeypatch):
    """A derived-name sidecar last written before this session is stale: not listed."""
    import os
    import time
    stale = tmp_path / "ms.mtproto.keylog"
    stale.write_text("MTPROTO_AUTH_KEY old old\n")
    old = time.time() - 3600
    os.utime(stale, (old, old))
    fresh = tmp_path / "ms.keylog"
    fresh.write_text("CLIENT_RANDOM aa bb\n")
    controller = _memscan_controller(
        {"tls": str(fresh), "mtproto": str(stale)}, monkeypatch, time.time() - 60)

    assert controller._memory_scan_keylog_files() == {"tls": str(fresh)}


def test_memory_scan_keylog_files_skips_empty_sidecar(tmp_path, monkeypatch):
    import time
    empty = tmp_path / "ms.mtproto.keylog"
    empty.write_text("")
    controller = _memscan_controller({"mtproto": str(empty)}, monkeypatch, time.time() - 60)

    assert controller._memory_scan_keylog_files() == {}


def test_memory_scan_keylog_files_is_total():
    controller, _a, _p = _make_controller()
    controller._ssl_logger = None  # no config -> lookup raises internally

    assert controller._memory_scan_keylog_files() == {}
    assert controller._memory_scan_keylog_paths() == []
