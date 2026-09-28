"""Regression tests for stopping/restarting a capture while it is in flight.

T1 — pressing ``r`` (restart wizard) while a capture was RUNNING/STOPPING reset
the controller to IDLE and opened the wizard immediately, while the old worker
was still tearing down. Its late ``_on_session_ended`` then wiped the wizard's
selections / pushed the old results over it, or tore down a NEW session's
logger. The restart is now deferred until the old session has ended, and a
stale session's end report is ignored.

T2 — ``start_capture`` enters RUNNING before the worker builds SSL_Logger; a
stop in that window had no logger to ``request_stop`` and the capture then ran
forever. The stop is now recorded and honoured by the worker.

Lightweight stubs — instantiating the real Textual app is impractical here.
"""

from __future__ import annotations

import types
from unittest.mock import MagicMock, patch

import pytest

pytest.importorskip("textual")


def _make_screen_stub():
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

    class _MenuPanel:
        def batch_update(self):
            class _CM:
                def __enter__(self): return self
                def __exit__(self, *a): return False
            return _CM()

    state = types.SimpleNamespace(
        target="com.example.app", target_display="Example", spawn=True,
        pcap_path="", keylog_path="", json_path="", live=False, live_mode="",
        full_capture=False, device_type="", protocol="tls",
    )

    class _App:
        def push_screen(self, screen, callback=None): pushed.append((screen, callback))
        def notify(self, *a, **kw): pass
        def call_from_thread(self, fn, *a, **kw): return fn(*a, **kw)

    screen = types.SimpleNamespace()
    screen.app = _App()
    screen._get_activity_log = lambda: _ActivityLog()
    screen._get_status_bar = lambda: _StatusBar()
    screen._get_menu_panel = lambda: _MenuPanel()
    screen._get_state = lambda: state
    screen._wizard_guard = lambda: False
    screen._activate_legacy_view = lambda: None
    screen._update_flow_title = lambda: None
    screen.query_one = MagicMock(side_effect=Exception("not in test"))
    screen.run_worker = MagicMock()
    screen.start_decrypt_to_flow_multi = MagicMock()
    return screen, state, activity, pushed


def _make_controller():
    from friTap.tui.capture_controller import CaptureController
    screen, state, activity, pushed = _make_screen_stub()
    controller = CaptureController(screen)
    controller._tui_handler = MagicMock(key_count=0)
    return controller, state, activity, pushed


def _logger_stub(**overrides):
    stub = types.SimpleNamespace(
        _event_bus=MagicMock(), _tui_mode=False, _output_handlers=[],
        _detected_libraries=["dummy"], full_capture=False, mobile=False,
        pcap_name="", live=False, socket_trace=False, debug_output=False,
        running=True,
    )

    def _request_stop():
        stub.running = False

    stub.request_stop = MagicMock(side_effect=_request_stop)
    for name in ("connect_live", "start_fritap_session", "finish_fritap",
                 "pcap_cleanup", "cleanup"):
        setattr(stub, name, MagicMock())
    for key, value in overrides.items():
        setattr(stub, key, value)
    return stub


def _run_worker_with(controller, ssl_logger_stub):
    controller._pending_config = MagicMock(debug_output=False)
    with patch("friTap.ssl_logger.SSL_Logger", return_value=ssl_logger_stub):
        controller._run_session()


def _enter_starting_window(controller):
    """What start_capture leaves behind before the worker built SSL_Logger."""
    controller._capture_state = controller.STATE_RUNNING
    controller._session_generation += 1
    controller._stop_requested = False
    controller._ssl_logger = None


def _dismiss_all(pushed):
    i = 0
    while i < len(pushed):
        _screen, callback = pushed[i]
        i += 1
        if callback is not None:
            callback(None)


def _main_screen_stub(controller):
    from friTap.tui.screens.main_screen import MainScreen
    fake = types.SimpleNamespace(
        _capture=controller, _replay_ctrl=None,
        _restart_wizard_now=MagicMock(),
    )
    fake._ssl_logger = controller.ssl_logger
    return MainScreen, fake


# ---------------------------------------------------------------------------
# T2 — stop during the "starting" window
# ---------------------------------------------------------------------------

def test_start_capture_bumps_generation_and_clears_stop_request():
    controller, state, _a, _p = _make_controller()
    controller._stop_requested = True
    controller._screen._get_menu_panel = MagicMock()
    with patch("friTap.tui.handlers.TuiOutputHandler"), \
         patch.object(controller, "build_config", return_value=MagicMock()):
        controller.start_capture(state)
    assert controller._session_generation == 1
    assert controller._stop_requested is False
    assert controller._capture_state == controller.STATE_RUNNING


def test_stop_while_starting_records_the_request():
    controller, _s, _a, _p = _make_controller()
    _enter_starting_window(controller)

    controller.action_stop_capture()

    assert controller._capture_state == controller.STATE_STOPPING
    assert controller._stop_requested is True


def test_worker_honours_stop_requested_before_logger_existed():
    controller, _s, _a, _p = _make_controller()
    _enter_starting_window(controller)
    controller.action_stop_capture()
    stub = _logger_stub()

    _run_worker_with(controller, stub)

    stub.request_stop.assert_called_once()
    stub.connect_live.assert_not_called()
    stub.start_fritap_session.assert_not_called()
    stub.finish_fritap.assert_called_once()
    stub.cleanup.assert_called_once()
    assert controller._capture_state == controller.STATE_STOPPED


def test_worker_without_stop_request_runs_the_session():
    controller, _s, _a, _p = _make_controller()
    _enter_starting_window(controller)
    stub = _logger_stub(running=False)

    _run_worker_with(controller, stub)

    stub.request_stop.assert_not_called()
    stub.connect_live.assert_called_once()
    stub.start_fritap_session.assert_called_once()
    assert controller._capture_state == controller.STATE_STOPPED


def test_stop_if_capturing_stops_during_starting_window():
    controller, _s, _a, _p = _make_controller()
    _enter_starting_window(controller)
    main_screen_cls, fake = _main_screen_stub(controller)

    main_screen_cls.stop_if_capturing(fake)

    assert controller._stop_requested is True
    assert controller._capture_state == controller.STATE_STOPPING


def test_stop_if_capturing_is_noop_when_idle():
    controller, _s, _a, _p = _make_controller()
    main_screen_cls, fake = _main_screen_stub(controller)

    main_screen_cls.stop_if_capturing(fake)

    assert controller._capture_state == controller.STATE_IDLE
    assert controller._stop_requested is False


# ---------------------------------------------------------------------------
# T1 — restart while a capture is in flight
# ---------------------------------------------------------------------------

def test_restart_when_idle_opens_wizard_immediately():
    controller, _s, _a, _p = _make_controller()
    main_screen_cls, fake = _main_screen_stub(controller)

    main_screen_cls.action_restart_wizard(fake)

    fake._restart_wizard_now.assert_called_once()


@pytest.mark.parametrize("in_flight_state", ["running", "stopping"])
def test_restart_while_in_flight_is_deferred(in_flight_state):
    controller, _s, activity, _p = _make_controller()
    controller._capture_state = in_flight_state
    controller._ssl_logger = _logger_stub()
    main_screen_cls, fake = _main_screen_stub(controller)

    main_screen_cls.action_restart_wizard(fake)

    fake._restart_wizard_now.assert_not_called()
    assert controller._capture_state == controller.STATE_STOPPING
    assert ("info", "Stopping capture before restart…") in activity


def test_restart_while_running_requests_stop():
    controller, _s, _a, _p = _make_controller()
    controller._capture_state = controller.STATE_RUNNING
    stub = _logger_stub()
    controller._ssl_logger = stub
    main_screen_cls, fake = _main_screen_stub(controller)

    main_screen_cls.action_restart_wizard(fake)

    stub.request_stop.assert_called_once()


def test_deferred_restart_runs_after_session_ended_and_results_dismissed(tmp_path):
    controller, state, activity, pushed = _make_controller()
    keylog = tmp_path / "keys.log"
    keylog.write_text("CLIENT_RANDOM aa bb\n")
    state.keylog_path = str(keylog)
    controller._capture_state = controller.STATE_RUNNING
    controller._ssl_logger = _logger_stub()
    restart = MagicMock()

    controller.restart_when_stopped(restart)
    restart.assert_not_called()

    def _restart_sees_reset_state():
        # The old session's reset has already happened: nothing the wizard
        # sets afterwards can be wiped by it.
        assert state.target == ""
        assert controller._capture_state == controller.STATE_STOPPED
    restart.side_effect = _restart_sees_reset_state

    controller._on_session_ended({}, generation=controller._session_generation)
    assert pushed, "results modal expected"
    restart.assert_not_called()  # not while the results modal is up

    _dismiss_all(pushed)
    restart.assert_called_once()
    assert not any("press r" in m for kind, m in activity if kind == "info")


def test_deferred_restart_without_modals_runs_immediately():
    controller, _s, _a, pushed = _make_controller()
    controller._capture_state = controller.STATE_STOPPING
    restart = MagicMock()
    controller.restart_when_stopped(restart)

    controller._on_session_ended({})

    assert pushed == []
    restart.assert_called_once()
    assert controller._restart_after_stop is None


def test_second_restart_press_while_pending_only_asks_to_wait():
    controller, _s, activity, _p = _make_controller()
    controller._capture_state = controller.STATE_RUNNING
    stub = _logger_stub()
    controller._ssl_logger = stub
    controller.restart_when_stopped(MagicMock())
    activity.clear()

    controller.restart_when_stopped(MagicMock())

    stub.request_stop.assert_called_once()
    assert activity == [("info", "Stopping capture — please wait…")]


def test_stale_session_end_does_not_touch_current_session():
    controller, state, _a, pushed = _make_controller()
    controller._session_generation = 2
    controller._capture_state = controller.STATE_RUNNING
    current_logger = _logger_stub()
    controller._ssl_logger = current_logger

    controller._on_session_ended({}, generation=1)

    assert controller._ssl_logger is current_logger
    assert controller._capture_state == controller.STATE_RUNNING
    assert state.target == "com.example.app"
    assert pushed == []


def test_worker_teardown_uses_its_own_logger_not_a_newer_one():
    controller, _s, _a, _p = _make_controller()
    _enter_starting_window(controller)
    old_logger = _logger_stub(running=False)
    new_logger = _logger_stub()

    def _newer_session_takes_over():
        controller._session_generation += 1
        controller._capture_state = controller.STATE_RUNNING
        controller._ssl_logger = new_logger
    old_logger.start_fritap_session.side_effect = _newer_session_takes_over

    _run_worker_with(controller, old_logger)

    old_logger.finish_fritap.assert_called_once()
    new_logger.finish_fritap.assert_not_called()
    new_logger.cleanup.assert_not_called()
    assert controller._ssl_logger is new_logger
    assert controller._capture_state == controller.STATE_RUNNING
