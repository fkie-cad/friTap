"""Regression tests for starting a manually configured capture from STOPPED (T5).

After a capture ended the controller sits in STOPPED and refused every start
with "press r to restart" — so the manual keybinding workflow (a/s target, 1-6
mode, Enter) no longer worked after the first capture. The ended session clears
target and mode, so allowing a configured start cannot silently re-attach.
"""

from __future__ import annotations

import types
from unittest.mock import MagicMock

import pytest


def _make_controller(**state_fields):
    pytest.importorskip("textual")
    from friTap.tui.capture_controller import CaptureController

    activity: list = []
    pushed: list = []

    class _ActivityLog:
        def log_error(self, m): activity.append(("error", m))
        def log_info(self, m): activity.append(("info", m))
        def log_warning(self, m): activity.append(("warning", m))
        def log_session(self, m): activity.append(("session", m))

    state = types.SimpleNamespace(
        target="", target_display="", keylog_path="", pcap_path="", live=False,
    )
    for key, value in state_fields.items():
        setattr(state, key, value)

    screen = types.SimpleNamespace()
    screen.app = types.SimpleNamespace(
        push_screen=lambda s, callback=None: pushed.append(s),
        notify=lambda *a, **k: None,
    )
    screen._get_activity_log = lambda: _ActivityLog()
    screen._get_state = lambda: state
    screen._wizard_guard = lambda: False

    controller = CaptureController(screen)
    controller.start_capture = MagicMock()
    controller._check_plugin_compatibility = MagicMock()
    return controller, activity, pushed


@pytest.mark.parametrize("mode", [
    {"keylog_path": "k.log"}, {"pcap_path": "c.pcap"}, {"live": True},
])
def test_stopped_with_target_and_mode_starts(mode):
    controller, activity, pushed = _make_controller(target="com.app", **mode)
    controller._capture_state = controller.STATE_STOPPED

    controller.action_toggle_capture()

    controller.start_capture.assert_called_once()
    assert not pushed
    assert not any("restart the wizard" in m for _k, m in activity)


def test_stopped_with_nothing_configured_shows_restart_hint():
    from friTap.tui.capture_controller import CAPTURE_STOPPED_RESTART_HINT

    controller, activity, pushed = _make_controller()
    controller._capture_state = controller.STATE_STOPPED

    controller.action_start_capture()

    controller.start_capture.assert_not_called()
    assert activity == [("info", CAPTURE_STOPPED_RESTART_HINT)]
    assert not pushed


def test_stopped_with_target_but_no_mode_shows_restart_hint():
    controller, activity, _p = _make_controller(target="com.app")
    controller._capture_state = controller.STATE_STOPPED

    controller.action_start_capture()

    controller.start_capture.assert_not_called()
    assert any("restart the wizard" in m for _k, m in activity)


def test_stopping_still_refuses_even_when_configured():
    controller, activity, _p = _make_controller(target="com.app", keylog_path="k.log")
    controller._capture_state = controller.STATE_STOPPING

    controller.action_start_capture()

    controller.start_capture.assert_not_called()
    assert controller._capture_state == controller.STATE_STOPPING
    assert any("restart the wizard" in m for _k, m in activity)


def test_idle_behaviour_unchanged():
    controller, _a, _p = _make_controller(target="com.app", pcap_path="c.pcap")

    controller.action_start_capture()

    controller.start_capture.assert_called_once()
