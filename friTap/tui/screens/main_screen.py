#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Main screen for friTap TUI -- single split-pane layout.

Replaces the 5-screen sequential flow with a permanent main screen.
Left panel: StatusBar + MenuPanel. Right panel: ActivityLog.
Device/process selection via modals.
"""

from __future__ import annotations

import sys
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ..app import AppState

try:
    from textual.app import ComposeResult
    from textual.binding import Binding
    from textual.screen import Screen
    from textual.widgets import Header, Footer, Static
    from textual.containers import Horizontal, Vertical
    TEXTUAL_AVAILABLE = True
except ImportError:
    TEXTUAL_AVAILABLE = False

if TEXTUAL_AVAILABLE:
    from ..widgets.activity_log import ActivityLog
    from ..widgets.status_bar import StatusBar
    from ..widgets.menu_panel import MenuPanel
    from ..modals.device_modal import DeviceSelectModal
    from ..modals.process_modal import ProcessSelectModal
    from ..modals.spawn_modal import SpawnInputModal
    from ..modals.help_modal import HelpScreen
    from ..modals.alert_modal import AlertModal
    from ..modals.capture_mode_modal import CaptureModeModal
    from ..modals.protocol_modal import ProtocolSelectModal
    from ..wizard import CaptureWizard
    from ..capture_controller import CaptureController
    from ..mode_controller import ModeController

    class MainScreen(Screen):
        """Single-screen split-pane layout for friTap TUI."""

        def __init__(self, **kwargs) -> None:
            super().__init__(**kwargs)
            self._wizard = CaptureWizard(self)
            self._capture = CaptureController(self)
            self._mode_ctrl = ModeController(self)

        # ----------------------------------------------------------
        # Layout
        # ----------------------------------------------------------

        def compose(self) -> ComposeResult:
            yield Header(show_clock=True)
            with Horizontal(id="main-split"):
                with Vertical(id="left-panel"):
                    yield StatusBar(id="status-bar")
                    yield MenuPanel(id="menu-panel")
                with Vertical(id="right-panel"):
                    yield Static("[bold #4ade80]friTap Console[/]", id="activity-title")
                    yield ActivityLog(id="activity-log")
            yield Footer()

        def on_mount(self) -> None:
            """Initialize the screen with welcome message and device info."""
            state = self._get_state()

            # Show welcome banner
            activity = self.query_one("#activity-log", ActivityLog)
            try:
                from friTap.about import __version__
                activity.show_welcome(version=__version__)
            except ImportError:
                activity.show_welcome()

            # Initialize status bar with local device
            status = self.query_one("#status-bar", StatusBar)
            platform_name = {"darwin": "macOS", "win32": "Windows"}.get(
                sys.platform, "Linux"
            )
            status.update_device(platform_name, "[L]")

            # Launch guided setup wizard
            self._start_wizard()

        # ----------------------------------------------------------
        # State helpers
        # ----------------------------------------------------------

        def _get_state(self) -> "AppState":
            """Return the shared AppState from the app."""
            return self.app.app_state

        def _get_activity_log(self) -> ActivityLog:
            return self.query_one("#activity-log", ActivityLog)

        def _get_status_bar(self) -> StatusBar:
            return self.query_one("#status-bar", StatusBar)

        def _get_menu_panel(self) -> MenuPanel:
            return self.query_one("#menu-panel", MenuPanel)

        # ----------------------------------------------------------
        # Background checks
        # ----------------------------------------------------------

        def _check_server_status(self) -> None:
            """Check frida-server status in a worker thread (USB/remote only)."""
            state = self._get_state()
            if state.device_type == "local" or not state.device_id:
                return
            try:
                from friTap.backends import get_backend
                device = get_backend().get_device(mobile=state.device_id)
                device.enumerate_processes()
                server_status = "running"
            except Exception:
                server_status = "not running"
            is_running = server_status == "running"
            def _update_ui():
                status = self._get_status_bar()
                status.update_device(status.device_name, status.device_type, server_status)
                self._get_menu_panel().server_running = is_running
            self.app.call_from_thread(_update_ui)

        # ----------------------------------------------------------
        # Wizard delegation
        # ----------------------------------------------------------

        def _wizard_guard(self) -> bool:
            """Return True if wizard is active (blocks manual actions)."""
            return self._wizard.guard()

        def _start_wizard(self) -> None:
            """Launch the guided setup wizard."""
            self._wizard.start()

        @property
        def _wizard_active(self) -> bool:
            return self._wizard.active

        @_wizard_active.setter
        def _wizard_active(self, value: bool) -> None:
            self._wizard.active = value

        # ----------------------------------------------------------
        # Capture delegation
        # ----------------------------------------------------------

        @property
        def _ssl_logger(self):
            return self._capture.ssl_logger

        @property
        def _tui_handler(self):
            return self._capture.tui_handler

        @property
        def _capture_mode(self) -> str:
            return self._capture.capture_mode

        @_capture_mode.setter
        def _capture_mode(self, value: str) -> None:
            self._capture.capture_mode = value

        def _build_config(self, state):
            return self._capture.build_config(state)

        def _start_capture(self, state) -> None:
            self._capture.start_capture(state)

        def action_start_capture(self) -> None:
            self._capture.action_start_capture()

        def action_stop_capture(self) -> None:
            self._capture.action_stop_capture()

        def action_toggle_capture(self) -> None:
            self._capture.action_toggle_capture()

        def action_escape_action(self) -> None:
            self._capture.action_escape_action()

        # ----------------------------------------------------------
        # Device selection
        # ----------------------------------------------------------

        def action_device_select(self) -> None:
            """Open the device selection modal."""
            if self._wizard_guard():
                return
            state = self._get_state()

            def _on_result(device_id: Optional[str]) -> None:
                if device_id is None:
                    return
                self._apply_device_selection(device_id)

            self.app.push_screen(
                DeviceSelectModal(current_device_id=state.device_id),
                callback=_on_result,
            )

        _DEVICE_TYPE_TAGS = {"local": "[L]", "usb": "[U]"}

        _PLATFORM_MAP = {"darwin": "macos", "win32": "windows"}

        def _apply_device_selection(self, device_id: str) -> None:
            """Apply the selected device to AppState and update UI."""
            state = self._get_state()
            state.device_id = device_id

            try:
                from friTap.backends import get_backend
                device = get_backend().get_device(mobile=device_id)
                state.device_name = device.name
                state.device_type = device.type if device.type in ("local", "usb") else "remote"
                type_tag = self._DEVICE_TYPE_TAGS.get(state.device_type, "[R]")

                if state.device_type == "local":
                    state.device_platform = self._PLATFORM_MAP.get(sys.platform, "linux")
                elif state.device_type == "usb":
                    try:
                        params = device.query_system_parameters()
                        os_info = params.get("os", {})
                        state.device_platform = (
                            os_info.get("id", "unknown")
                            if isinstance(os_info, dict)
                            else "unknown"
                        )
                    except Exception:
                        state.device_platform = "unknown"
                else:
                    state.device_platform = "unknown"

                status = self._get_status_bar()
                status.update_device(device.name, type_tag)
                status.server_status = ""

                self._get_activity_log().log_success(f"Device selected: {type_tag} {device.name}")

                menu = self._get_menu_panel()
                menu.server_running = (state.device_type == "local")

                if state.device_type != "local" and not self._wizard_active:
                    self.run_worker(self._check_server_status, thread=True)

            except Exception as e:
                self._get_activity_log().log_error(f"Failed to select device: {e}")

        # ----------------------------------------------------------
        # Process attach / spawn
        # ----------------------------------------------------------

        def _apply_target(self, display_name: str, frida_target: str, is_spawn: bool) -> None:
            """Apply target selection to state and update UI widgets."""
            state = self._get_state()
            mode = "spawn" if is_spawn else "attach"
            mode_tag = mode.upper()

            state.target = frida_target
            state.target_display = display_name
            state.spawn = is_spawn
            self._get_status_bar().update_target(display_name, mode_tag)
            menu = self._get_menu_panel()
            menu.has_target = True
            menu.target_name = display_name
            menu.target_mode = mode
            self._get_activity_log().log_info(
                f"Target: [bold #d4945a]{display_name}[/] [{mode_tag}]"
            )

        def _guard_target_change(self) -> bool:
            """Return True if target change should be blocked."""
            if self._wizard_guard():
                return True
            if self._ssl_logger and self._ssl_logger.running:
                self._get_activity_log().log_warning("Stop capture before changing target.")
                return True
            return False

        def action_attach(self) -> None:
            """Open the process selection modal."""
            if self._guard_target_change():
                return

            state = self._get_state()

            def _on_result(result) -> None:
                if result is None:
                    return
                display_name, frida_target, is_pid = result
                self._apply_target(display_name, frida_target, is_spawn=False)

            self.app.push_screen(
                ProcessSelectModal(
                    device_id=state.device_id,
                    device_type=state.device_type,
                ),
                callback=_on_result,
            )

        def action_spawn(self) -> None:
            """Open the spawn input modal."""
            if self._guard_target_change():
                return

            def _on_result(target: Optional[str]) -> None:
                if target is None:
                    return
                self._apply_target(target, target, is_spawn=True)

            self.app.push_screen(SpawnInputModal(), callback=_on_result)

        # ----------------------------------------------------------
        # Capture mode presets
        # ----------------------------------------------------------

        def action_set_mode_1(self) -> None:
            """Full capture (keys + pcap)."""
            self._mode_ctrl.set_mode(1)

        def action_set_mode_2(self) -> None:
            """Key extraction only."""
            self._mode_ctrl.set_mode(2)

        def action_set_mode_3(self) -> None:
            """Plaintext pcap."""
            self._mode_ctrl.set_mode(3)

        def action_set_mode_4(self) -> None:
            """Live Wireshark pipe."""
            self._mode_ctrl.set_mode(4)

        def action_set_mode_5(self) -> None:
            """Live Wireshark with auto-decrypt (PCAPNG+DSB)."""
            self._mode_ctrl.set_mode(5)

        def _apply_mode(self, mode_id: str, display: str, config: dict) -> None:
            """Apply a capture mode from the modal result."""
            state = self._get_state()
            state.keylog_path = config.get("keylog", "")
            state.pcap_path = config.get("pcap", "")
            state.live = config.get("live", False)
            state.full_capture = config.get("full_capture", False)

            self._capture_mode = mode_id
            self._get_status_bar().update_capture("IDLE", display)
            menu = self._get_menu_panel()
            menu.current_mode = mode_id
            menu.keylog_path = state.keylog_path
            menu.pcap_path = state.pcap_path
            self._get_activity_log().log_info(f"Capture mode: [bold]{display}[/]")
            if state.keylog_path:
                self._get_activity_log().log_info(f"  -> Keys: {state.keylog_path}")
            if state.pcap_path:
                self._get_activity_log().log_info(f"  -> PCAP: {state.pcap_path}")

        # ----------------------------------------------------------
        # Log management
        # ----------------------------------------------------------

        def action_clear_log(self) -> None:
            """Clear the activity log."""
            self._get_activity_log().clear()

        def action_copy_log(self) -> None:
            """Copy activity log to clipboard."""
            log = self._get_activity_log()
            text = log.get_plain_text()
            if text:
                self.app.copy_to_clipboard(text)
                log.log_success(f"Copied {log.get_line_count()} lines to clipboard")
            else:
                log.log_warning("Nothing to copy -- log is empty.")

        # ----------------------------------------------------------
        # Setup / server management
        # ----------------------------------------------------------

        def action_install_server(self) -> None:
            """Install frida-server on the selected device."""
            if self._wizard_guard():
                return
            state = self._get_state()
            if self._get_menu_panel().server_running:
                self._get_activity_log().log_info("frida-server is already running.")
                return
            if state.device_type == "local":
                self._get_activity_log().log_warning("Local device does not need frida-server.")
                return

            if not state.device_id:
                self._get_activity_log().log_warning("Select a device first (press [bold]d[/]).")
                return

            self._get_activity_log().log_info("Installing frida-server...")
            self.run_worker(lambda: self._do_install_server(state.device_id), thread=True)

        def _do_install_server(self, device_id: str) -> None:
            """Background worker for frida-server installation."""
            try:
                from friTap.backends import get_backend
                device = get_backend().get_device(mobile=device_id)
                from friTap.server_manager.factory import get_server_manager
                mgr = get_server_manager(device)

                self.app.call_from_thread(
                    lambda: self._get_activity_log().log_info(
                        f"Installing frida-server for {device.name} ({mgr.platform_name})..."
                    )
                )

                def _progress(msg: str) -> None:
                    self.app.call_from_thread(
                        lambda: self._get_activity_log().log_info(msg)
                    )

                mgr.install(device, callback=_progress)

                self.app.call_from_thread(
                    lambda: self._get_activity_log().log_info("Starting frida-server...")
                )
                mgr.start(device)

                def _on_install_success():
                    self._get_activity_log().log_success("frida-server installed and started!")
                    self._get_menu_panel().server_running = True
                    self._get_status_bar().server_status = "running"
                self.app.call_from_thread(_on_install_success)
            except Exception as e:
                self.app.call_from_thread(
                    lambda: self._get_activity_log().log_error(f"Install failed: {e}")
                )

        # ----------------------------------------------------------
        # Options toggles
        # ----------------------------------------------------------

        def action_verbose_toggle(self) -> None:
            """Toggle verbose mode."""
            state = self._get_state()
            state.verbose = not state.verbose
            menu = self._get_menu_panel()
            menu.verbose = state.verbose
            label = "ON" if state.verbose else "OFF"
            self._get_activity_log().log_info(f"Verbose: {label}")

        def action_experimental_toggle(self) -> None:
            """Toggle experimental mode."""
            state = self._get_state()
            # Store experimental in a simple attribute
            if not hasattr(state, '_experimental'):
                state._experimental = False
            state._experimental = not state._experimental
            menu = self._get_menu_panel()
            menu.experimental = state._experimental
            label = "ON" if state._experimental else "OFF"
            self._get_activity_log().log_info(f"Experimental: {label}")

        def action_protocol_select(self) -> None:
            """Open the protocol selection modal."""
            if self._wizard_guard():
                return
            state = self._get_state()

            def _on_result(protocol: Optional[str]) -> None:
                if protocol is None:
                    return
                state.protocol = protocol
                self._get_status_bar().protocol = protocol
                self._get_activity_log().log_info(f"Protocol: {protocol.upper()}")

            self.app.push_screen(ProtocolSelectModal(), callback=_on_result)

        # ----------------------------------------------------------
        # Help
        # ----------------------------------------------------------

        def action_show_help(self) -> None:
            """Show the help overlay."""
            self.app.push_screen(HelpScreen())
