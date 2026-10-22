"""TUI wiring of the frida-server probe / auto-start.

Frida 17 trap: a USB Android device with NO frida-server still enumerates via
the ADB fallback ("access": "jailed"), so the TUI used to report
"frida-server: running" and the wizard passed, then attach failed "closed".
These tests cover the status mapping, the wizard modal's auto-start, the
menu install action and the capture pre-flight.
"""

from __future__ import annotations

import asyncio
import types
from unittest.mock import MagicMock, patch

import pytest

pytest.importorskip("textual")

from friTap.server_manager.probe import ServerState  # noqa: E402


class _FakeDevice:
    """frida device stub whose probe result is driven by access/process count."""

    def __init__(self, access="full", process_count=300, name="Pixel 7", id="SERIAL1"):
        self._access = access
        self._process_count = process_count
        self.name = name
        self.id = id

    def query_system_parameters(self):
        if self._access is None:
            raise RuntimeError("unreachable")
        return {"access": self._access, "os": {"id": "android"}}

    def enumerate_processes(self):
        return [object()] * self._process_count


DEVICE_FOR_STATE = {
    ServerState.RUNNING: lambda: _FakeDevice(access="full"),
    ServerState.GADGET: lambda: _FakeDevice(access="jailed", process_count=1),
    ServerState.NOT_RUNNING: lambda: _FakeDevice(access="jailed", process_count=300),
    ServerState.UNREACHABLE: lambda: _FakeDevice(access=None),
}


def _android_manager(ensure_running):
    mgr = MagicMock(platform_name="android")
    mgr.ensure_running.side_effect = ensure_running
    return mgr


# ---------------------------------------------------------------------------
# Status bar
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("state, color_role", [
    (ServerState.RUNNING, "success"),
    (ServerState.GADGET, "warning"),
    (ServerState.NOT_RUNNING, "error"),
    (ServerState.UNREACHABLE, "error"),
])
def test_status_bar_renders_each_server_state(state, color_role):
    from friTap.tui.themes import c
    from friTap.tui.widgets.status_bar import StatusBar

    bar = StatusBar()
    bar.check_server_status(DEVICE_FOR_STATE[state]())

    assert bar.server_status == state.value
    assert f"frida-server: [bold {c(color_role)}]{state.value}[/]" in bar.render()


def test_status_bar_hides_server_status_when_unset():
    from friTap.tui.widgets.status_bar import StatusBar

    assert "frida-server" not in StatusBar().render()


def test_status_bar_check_ignores_jailed_enumeration():
    """The ADB fallback enumerates hundreds of processes — still not running."""
    from friTap.tui.widgets.status_bar import StatusBar

    bar = StatusBar()
    bar.check_server_status(DEVICE_FOR_STATE[ServerState.NOT_RUNNING](), backend=MagicMock())
    assert bar.server_status == "not running"


# ---------------------------------------------------------------------------
# MainScreen status check + install action
# ---------------------------------------------------------------------------

def _main_screen_stub():
    status_bar = types.SimpleNamespace(device_name="Pixel 7", device_type="[U]", server_status="")
    status_bar.update_device = lambda n, t, s="": setattr(status_bar, "server_status", s)
    menu = types.SimpleNamespace(server_running=False)
    logs: list = []
    log = types.SimpleNamespace(
        log_info=lambda m: logs.append(("info", m)),
        log_success=lambda m: logs.append(("success", m)),
        log_error=lambda m: logs.append(("error", m)),
    )
    stub = types.SimpleNamespace(
        app=types.SimpleNamespace(call_from_thread=lambda fn, *a: fn(*a)),
        _get_state=lambda: types.SimpleNamespace(device_type="usb", device_id="SERIAL1"),
        _get_status_bar=lambda: status_bar,
        _get_menu_panel=lambda: menu,
        _get_activity_log=lambda: log,
    )
    from friTap.tui.screens.main_screen import MainScreen
    stub._show_server_state = lambda st: MainScreen._show_server_state(stub, st)
    return stub, status_bar, menu, logs


@pytest.mark.parametrize("state, capable", [
    (ServerState.RUNNING, True),
    (ServerState.GADGET, True),
    (ServerState.NOT_RUNNING, False),
    (ServerState.UNREACHABLE, False),
])
def test_main_screen_server_check_maps_probe_state(state, capable):
    from friTap.tui.screens.main_screen import MainScreen

    stub, status_bar, menu, _logs = _main_screen_stub()
    backend = MagicMock()
    backend.get_device.return_value = DEVICE_FOR_STATE[state]()
    with patch("friTap.backends.get_backend", return_value=backend):
        MainScreen._check_server_status(stub)

    assert status_bar.server_status == state.value
    assert menu.server_running is capable
    backend.check_connectivity.assert_not_called()


def test_main_screen_install_uses_ensure_running_state():
    from friTap.tui.screens.main_screen import MainScreen

    stub, status_bar, menu, logs = _main_screen_stub()
    mgr = _android_manager(lambda device, callback=None: ServerState.RUNNING)
    backend = MagicMock()
    backend.get_device.return_value = DEVICE_FOR_STATE[ServerState.NOT_RUNNING]()
    with patch("friTap.backends.get_backend", return_value=backend), \
         patch("friTap.server_manager.factory.get_server_manager", return_value=mgr):
        MainScreen._do_install_server(stub, "SERIAL1")

    mgr.ensure_running.assert_called_once()
    assert status_bar.server_status == "running"
    assert menu.server_running is True


def test_main_screen_install_failure_logs_error_and_keeps_status():
    from friTap.tui.screens.main_screen import MainScreen

    stub, status_bar, menu, logs = _main_screen_stub()

    def _fail(device, callback=None):
        raise RuntimeError("device is not rooted")

    backend = MagicMock()
    backend.get_device.return_value = DEVICE_FOR_STATE[ServerState.NOT_RUNNING]()
    with patch("friTap.backends.get_backend", return_value=backend), \
         patch("friTap.server_manager.factory.get_server_manager",
               return_value=_android_manager(_fail)):
        MainScreen._do_install_server(stub, "SERIAL1")

    assert any(k == "error" and "not rooted" in m for k, m in logs)
    assert menu.server_running is False


# ---------------------------------------------------------------------------
# Wizard ServerCheckModal (Textual pilot)
# ---------------------------------------------------------------------------

def _run_modal(device, mgr, *, press=None, wait_for_result=True):
    """Push ServerCheckModal; return (dismiss result, modal, status text)."""
    from textual.widgets import Static

    from friTap.tui.app import FriTapApp
    from friTap.tui.modals.server_check_modal import ServerCheckModal

    out: dict = {}

    async def _main():
        app = FriTapApp()
        async with app.run_test(size=(100, 30)) as pilot:
            modal = ServerCheckModal(device_id="SERIAL1", device_name="Pixel 7")
            await app.push_screen(modal, callback=lambda v: out.setdefault("result", v))
            for _ in range(100):
                await pilot.pause(0.05)
                if "result" in out or (not wait_for_result and modal.phase == "prompt"):
                    break
            if press and "result" not in out:
                await pilot.click(f"#{press}")
                for _ in range(100):
                    await pilot.pause(0.05)
                    if "result" in out or modal.phase == "prompt":
                        break
            out["modal"] = modal
            out["phase"] = modal.phase
            if "result" not in out:  # a dismissed modal has no widgets left
                out["status"] = str(modal.query_one("#status-message", Static).render())
                out["buttons_shown"] = modal.query_one("#action-buttons").display

    with patch("friTap.tui.modals.server_check_modal.ServerCheckModal._lookup_device",
               return_value=device), \
         patch("friTap.server_manager.factory.get_server_manager", return_value=mgr):
        asyncio.run(_main())
    return out


def test_modal_dismisses_ok_when_server_running():
    mgr = _android_manager(lambda *a, **k: pytest.fail("must not start"))
    out = _run_modal(DEVICE_FOR_STATE[ServerState.RUNNING](), mgr)
    assert out.get("result") == "ok"
    mgr.ensure_running.assert_not_called()


def test_modal_auto_starts_on_android_not_running_then_ok():
    calls = []

    def _ensure(device, callback=None):
        callback("Starting frida-server ...")
        calls.append(device)
        return ServerState.RUNNING

    out = _run_modal(DEVICE_FOR_STATE[ServerState.NOT_RUNNING](), _android_manager(_ensure))
    assert len(calls) == 1  # no click needed
    assert out.get("result") == "ok"


def test_modal_ensure_running_failure_shows_error_and_buttons():
    def _fail(device, callback=None):
        raise RuntimeError("Pixel 7 is not rooted")

    out = _run_modal(
        DEVICE_FOR_STATE[ServerState.NOT_RUNNING](), _android_manager(_fail),
        wait_for_result=False,
    )
    assert "result" not in out
    assert out["phase"] == "prompt"
    assert "not rooted" in out["status"]
    assert out["buttons_shown"] is True


def test_modal_non_android_not_running_keeps_manual_prompt():
    mgr = MagicMock(platform_name="ios")
    out = _run_modal(DEVICE_FOR_STATE[ServerState.NOT_RUNNING](), mgr, wait_for_result=False)
    assert "result" not in out
    assert out["phase"] == "prompt"
    mgr.ensure_running.assert_not_called()


def test_modal_install_button_reports_ok_only_after_ensure_running():
    """Install on a non-Android device: install(), then ensure_running()."""
    mgr = MagicMock(platform_name="ios")
    mgr.ensure_running.return_value = ServerState.RUNNING
    out = _run_modal(DEVICE_FOR_STATE[ServerState.NOT_RUNNING](), mgr, press="btn-install")
    mgr.install.assert_called_once()
    mgr.ensure_running.assert_called_once()
    assert out.get("result") == "ok"


def test_modal_install_button_failure_is_not_ok():
    mgr = MagicMock(platform_name="ios")
    mgr.ensure_running.side_effect = RuntimeError("did not become reachable")
    out = _run_modal(DEVICE_FOR_STATE[ServerState.NOT_RUNNING](), mgr, press="btn-install")
    assert "result" not in out
    assert "did not become reachable" in out["status"]


# ---------------------------------------------------------------------------
# Capture pre-flight
# ---------------------------------------------------------------------------

def _make_controller():
    from friTap.tui.capture_controller import CaptureController

    logs: list = []
    shown: list = []

    class _Log:
        def __getattr__(self, level):
            return lambda m: logs.append((level, m))

    screen = types.SimpleNamespace(
        app=types.SimpleNamespace(call_from_thread=lambda fn, *a, **k: fn(*a, **k)),
        _get_activity_log=lambda: _Log(),
        _show_server_state=shown.append,
        run_worker=MagicMock(),
        _get_status_bar=MagicMock,
        _get_state=MagicMock,
        query_one=MagicMock(side_effect=Exception("not in test")),
    )
    controller = CaptureController(screen)
    controller._preflight_target = ("SERIAL1", "Pixel 7")
    return controller, logs, shown


def _run_session(controller, device, mgr):
    """Run _run_session with SSL_Logger stubbed; return the SSL_Logger mock."""
    ssl_logger = MagicMock(running=False)
    ssl_cls = MagicMock(return_value=ssl_logger)
    controller._pending_config = MagicMock(debug_output=False)
    controller._tui_handler = MagicMock()
    with patch.object(type(controller), "_lookup_frida_device", return_value=device), \
         patch("friTap.server_manager.factory.get_server_manager", return_value=mgr), \
         patch("friTap.ssl_logger.SSL_Logger", ssl_cls), \
         patch.object(controller, "_on_session_ended") as ended, \
         patch.object(controller, "_gather_result_stats", return_value={}), \
         patch.object(controller, "_close_debug_log"):
        controller._run_session()
    controller.session_ended_mock = ended
    return ssl_cls, ssl_logger


def test_preflight_running_does_not_start_server():
    controller, _logs, shown = _make_controller()
    mgr = _android_manager(lambda *a, **k: pytest.fail("must not start"))

    ssl_cls, ssl_logger = _run_session(controller, DEVICE_FOR_STATE[ServerState.RUNNING](), mgr)

    mgr.ensure_running.assert_not_called()
    ssl_cls.assert_called_once()
    ssl_logger.start_fritap_session.assert_called_once()
    assert shown == [ServerState.RUNNING]


def test_preflight_not_running_starts_server_then_session_proceeds():
    controller, logs, shown = _make_controller()

    def _ensure(device, callback=None):
        callback("Installing frida-server 17.0.0 ...")
        return ServerState.RUNNING

    mgr = _android_manager(_ensure)
    ssl_cls, ssl_logger = _run_session(controller, DEVICE_FOR_STATE[ServerState.NOT_RUNNING](), mgr)

    mgr.ensure_running.assert_called_once()
    ssl_logger.start_fritap_session.assert_called_once()
    assert shown == [ServerState.RUNNING]
    infos = [m for lvl, m in logs if lvl == "log_info"]
    assert any("starting it via AndroidFridaManager" in m and "Pixel 7" in m for m in infos)
    assert "Installing frida-server 17.0.0 ..." in infos
    assert controller._session_error == ""


def test_preflight_failure_reports_error_and_never_attaches():
    controller, logs, shown = _make_controller()

    def _fail(device, callback=None):
        raise RuntimeError("Pixel 7 is not rooted")

    ssl_cls, _ssl_logger = _run_session(
        controller, DEVICE_FOR_STATE[ServerState.NOT_RUNNING](), _android_manager(_fail),
    )

    ssl_cls.assert_not_called()  # no SSL_Logger -> no attach
    assert controller._session_error == (
        "frida-server is not running on Pixel 7 and could not be started: "
        "Pixel 7 is not rooted"
    )
    assert any(lvl == "log_error" and "could not be started" in m for lvl, m in logs)
    controller.session_ended_mock.assert_called_once()
    assert shown == []


def test_preflight_skipped_for_local_device():
    controller, _logs, shown = _make_controller()
    controller._preflight_target = None  # what start_capture sets for local
    with patch.object(type(controller), "_lookup_frida_device") as lookup:
        controller._ensure_frida_server()
    lookup.assert_not_called()
    assert shown == []


def test_preflight_disabled_flag_skips_probe():
    controller, _logs, _shown = _make_controller()
    controller.server_preflight_enabled = False
    with patch.object(type(controller), "_lookup_frida_device") as lookup:
        controller._ensure_frida_server()
    lookup.assert_not_called()


@pytest.mark.parametrize("device_type, expected", [
    ("local", None),
    ("usb", ("SERIAL1", "Pixel 7")),
    ("remote", ("SERIAL1", "Pixel 7")),
])
def test_start_capture_snapshots_preflight_target(device_type, expected):
    controller, _logs, _shown = _make_controller()
    controller._preflight_target = "sentinel"
    state = types.SimpleNamespace(device_type=device_type, device_id="SERIAL1",
                                  device_name="Pixel 7", spawn=False, target="app",
                                  target_display="app", protocol="tls")
    screen = controller._screen
    screen._get_status_bar = lambda: MagicMock()
    screen._get_menu_panel = lambda: MagicMock()
    with patch.object(controller, "build_config", return_value=MagicMock()), \
         patch("friTap.tui.handlers.TuiOutputHandler"):
        controller.start_capture(state)
    assert controller._preflight_target == expected


# ---------------------------------------------------------------------------
# Factory cache
# ---------------------------------------------------------------------------

def test_factory_reuses_android_manager_per_serial():
    from friTap.server_manager import factory

    with patch.dict(factory._ANDROID_MANAGERS, clear=True):
        a1 = factory.get_server_manager(_FakeDevice(id="A"))
        a2 = factory.get_server_manager(_FakeDevice(id="A"))
        b = factory.get_server_manager(_FakeDevice(id="B"))
    assert a1 is a2
    assert a1 is not b
