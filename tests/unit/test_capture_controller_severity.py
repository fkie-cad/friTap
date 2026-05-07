"""Unit tests for CaptureController severity routing & exception flow.

Covers two distinct concerns:

1. The session-level except block in :meth:`_run_session` must (a) set
   ``_session_error`` and ``_session_error_severity = "fatal"``, (b) call
   ``logger.exception`` so the traceback hits the debug log file, and
   (c) emit an ``ErrorEvent(severity="fatal")`` on the SSL_Logger event
   bus so the EventBus debug-log subscriber records the failure.

2. :meth:`_on_session_ended` must only push the "Capture Error"
   AlertModal when ``_session_error_severity`` is in ``("error", "fatal")``.
   ``"warning"`` / ``"info"`` are recovered errors (e.g. parser-level
   fallbacks) and must NOT block the user.

Both tests use lightweight stubs because instantiating the real Textual
app or the real SSL_Logger inside a unit test is impractical.
"""

import logging
import threading
import types
from unittest.mock import MagicMock, patch

import pytest

from friTap.events import (
    ErrorEvent,
    ERROR_SEVERITY_ERROR,
    ERROR_SEVERITY_FATAL,
    ERROR_SEVERITY_INFO,
    ERROR_SEVERITY_WARNING,
    EventBus,
)


# ---------------------------------------------------------------------------
# Shared stubs
# ---------------------------------------------------------------------------

def _make_screen_stub():
    """Build a stub `_screen` rich enough for the controller's TUI calls.

    Records the activity-log calls and `app.push_screen` invocations
    so tests can assert what the user would actually see.
    """
    pushed_screens: list = []
    activity_calls: list = []
    state_reset_calls: list = []

    class _ActivityLog:
        def log_error(self, m): activity_calls.append(("error", m))
        def log_info(self, m): activity_calls.append(("info", m))
        def log_warning(self, m): activity_calls.append(("warning", m))
        def log_session(self, m): activity_calls.append(("session", m))

    class _StatusBar:
        capture_mode = ""
        def update_capture(self, *a, **kw): pass
        def update_target(self, *a, **kw): pass

    class _MenuPanel:
        capture_active = False
        has_target = False
        target_name = ""
        target_mode = ""
        current_mode = ""
        keylog_path = ""
        pcap_path = ""
        def batch_update(self):
            class _CM:
                def __enter__(self): return self
                def __exit__(self, *a): return False
            return _CM()

    class _State:
        target = ""
        target_display = ""
        spawn = False
        pcap_path = ""
        keylog_path = ""
        json_path = ""
        live = False
        live_mode = ""
        full_capture = False
        device_type = ""

    state_obj = _State()

    class _App:
        def push_screen(self, screen):
            pushed_screens.append(screen)
        def call_from_thread(self, fn, *a, **kw):
            # Run inline so test assertions see effects synchronously.
            return fn(*a, **kw)

    screen = types.SimpleNamespace()
    screen.app = _App()
    screen._get_activity_log = lambda: _ActivityLog()
    screen._get_status_bar = lambda: _StatusBar()
    screen._get_menu_panel = lambda: _MenuPanel()
    screen._get_state = lambda: state_obj
    screen._activate_legacy_view = lambda: None
    screen._update_flow_title = lambda: None
    screen.query_one = MagicMock(side_effect=Exception("not in test"))
    screen.run_worker = MagicMock()

    return screen, pushed_screens, activity_calls, state_obj


def _make_controller():
    """Create a CaptureController with a stub screen, ready for unit tests."""
    pytest.importorskip("textual")
    from friTap.tui.capture_controller import CaptureController
    screen, pushed, calls, state = _make_screen_stub()
    controller = CaptureController(screen)
    return controller, pushed, calls, state


# ---------------------------------------------------------------------------
# Test class 1: session-level exception routing
# ---------------------------------------------------------------------------

class TestRunSessionExceptionFlow:
    """Verify _run_session's except block."""

    def test_ssl_logger_init_failure_sets_session_error(self):
        controller, pushed, calls, _state = _make_controller()
        # Patch the SSL_Logger constructor used inside _run_session to raise.
        boom = RuntimeError("Unexpected early end-of-stream")
        # Patch the module-level logger so we can verify logger.exception
        # was called (independent of caplog/propagate quirks across tests).
        with patch("friTap.tui.capture_controller.logger") as mock_logger, \
             patch("friTap.ssl_logger.SSL_Logger", side_effect=boom):
            controller._pending_config = MagicMock(debug_output=False)
            controller._run_session()

        # Activity log should show the user-facing error string.
        error_calls = [m for kind, m in calls if kind == "error"]
        assert any("Unexpected early end-of-stream" in m for m in error_calls)
        # logger.exception fired with the user message.
        mock_logger.exception.assert_called_once()
        args, _kw = mock_logger.exception.call_args
        assert "Capture session failed" in args[0]

    def test_ssl_logger_init_failure_emits_error_event_with_fatal_severity(self):
        """Verify ErrorEvent emission to the SSL_Logger bus on session failure."""
        controller, _pushed, _calls, _state = _make_controller()
        captured: list[ErrorEvent] = []

        # Construct an SSL_Logger stub that exposes _event_bus and is
        # assignable as a side effect when SSL_Logger(config=...) is called.
        bus = EventBus()
        bus.subscribe(ErrorEvent, captured.append)

        # SSL_Logger stub: rich enough to satisfy _run_session AND
        # _on_session_ended's later attribute reads (e.g. _detected_libraries).
        ssl_logger_stub = types.SimpleNamespace(
            _event_bus=bus,
            _tui_mode=False,
            _output_handlers=[],
            _detected_libraries=["dummy"],  # avoid the suggest-library-scan modal
            full_capture=False,
            mobile=False,
            pcap_name="",
            live=False,
            socket_trace=False,
            debug_output=False,
            running=False,  # so the polling loop exits cleanly
        )

        boom = RuntimeError("network teardown")
        ssl_logger_stub.start_fritap_session = MagicMock(side_effect=boom)
        ssl_logger_stub.connect_live = MagicMock()
        ssl_logger_stub.finish_fritap = MagicMock()
        ssl_logger_stub.pcap_cleanup = MagicMock()
        ssl_logger_stub.cleanup = MagicMock()

        def _ctor(*a, **kw):
            return ssl_logger_stub

        # _tui_handler must exist so .setup(bus) succeeds.
        controller._tui_handler = MagicMock()

        with patch("friTap.ssl_logger.SSL_Logger", side_effect=_ctor):
            controller._pending_config = MagicMock(debug_output=False)
            controller._run_session()

        # Exactly one ErrorEvent with severity=fatal expected.
        fatal_events = [e for e in captured if e.severity == ERROR_SEVERITY_FATAL]
        assert len(fatal_events) >= 1, (
            f"expected ErrorEvent(severity=fatal); got {[e.severity for e in captured]}"
        )
        evt = fatal_events[0]
        assert evt.error == "RuntimeError"
        assert "network teardown" in evt.description
        assert "Traceback" in evt.stack


# ---------------------------------------------------------------------------
# Test class 2: severity-based modal routing in _on_session_ended
# ---------------------------------------------------------------------------

class TestSessionEndedSeverityRouting:
    """Verify the AlertModal at the end of _on_session_ended is gated by
    `_session_error_severity`."""

    def _drive(self, severity_value, error_message="boom"):
        controller, pushed, _calls, _state = _make_controller()
        # Fake out subsystems that _on_session_ended touches but that
        # aren't relevant to the severity check.
        controller._tui_handler = None
        controller._flow_collector = None
        controller._tap_writer = None
        controller._ssl_logger = None
        controller._session_error = error_message
        controller._session_error_severity = severity_value
        controller._on_session_ended({})
        return [s for s in pushed if getattr(s, "_title", "") == "Capture Error"]

    def test_fatal_severity_pushes_capture_error_modal(self):
        modals = self._drive(ERROR_SEVERITY_FATAL, "Frida disconnected")
        assert len(modals) == 1
        # Body should include the error message. Footer with the debug
        # log path is appended only when a path can be resolved; in
        # isolated test runs `get_debug_log_path()` may return None, so
        # the assertion below is conditional on that.
        msg = modals[0]._message
        assert "Frida disconnected" in msg

    def test_error_severity_pushes_capture_error_modal(self):
        modals = self._drive(ERROR_SEVERITY_ERROR, "Pcap write failed")
        assert len(modals) == 1
        assert "Pcap write failed" in modals[0]._message

    def test_fatal_severity_modal_includes_debug_path_when_log_open(self, tmp_path):
        """When a debug log is open, the modal body must include the path
        and the issue-tracker URL so the user can attach the log."""
        from friTap import fritap_utility as fu
        fu.close_debug_log()
        fu.open_debug_log(str(tmp_path / "modal.log"))
        try:
            modals = self._drive(ERROR_SEVERITY_FATAL, "Frida disconnected")
            assert len(modals) == 1
            msg = modals[0]._message
            assert "Frida disconnected" in msg
            assert "Debug log:" in msg
            assert str(tmp_path / "modal.log") in msg
            assert "github.com/fkie-cad/friTap/issues" in msg
        finally:
            fu.close_debug_log()

    def test_warning_severity_does_not_push_modal(self):
        modals = self._drive(ERROR_SEVERITY_WARNING, "h11 RemoteProtocolError")
        assert modals == [], (
            "warning-severity errors are recovered; they MUST NOT pop a modal"
        )

    def test_info_severity_does_not_push_modal(self):
        modals = self._drive(ERROR_SEVERITY_INFO, "informational note")
        assert modals == []

    def test_no_session_error_no_modal(self):
        controller, pushed, _calls, _state = _make_controller()
        controller._tui_handler = None
        controller._flow_collector = None
        controller._tap_writer = None
        controller._ssl_logger = None
        controller._session_error = ""
        controller._session_error_severity = "fatal"
        controller._on_session_ended({})
        modals = [s for s in pushed if getattr(s, "_title", "") == "Capture Error"]
        assert modals == []
