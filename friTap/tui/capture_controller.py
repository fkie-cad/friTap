#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Capture controller -- manages the capture lifecycle extracted from MainScreen.

Handles config building, session start/stop, background worker management,
and post-session UI cleanup.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..tui.app import AppState

try:
    from textual.widgets import Static
    TEXTUAL_AVAILABLE = True
except ImportError:
    TEXTUAL_AVAILABLE = False


class CaptureController:
    """Manages capture lifecycle -- extracted from MainScreen."""

    def __init__(self, screen) -> None:
        self._screen = screen
        self._ssl_logger = None
        self._tui_handler = None
        self._capture_mode: str = ""

    # ----------------------------------------------------------
    # Public properties
    # ----------------------------------------------------------

    @property
    def ssl_logger(self):
        return self._ssl_logger

    @property
    def tui_handler(self):
        return self._tui_handler

    @property
    def capture_mode(self) -> str:
        return self._capture_mode

    @capture_mode.setter
    def capture_mode(self, value: str) -> None:
        self._capture_mode = value

    # ----------------------------------------------------------
    # Actions
    # ----------------------------------------------------------

    def _warn(self, modal_message: str, log_message: str) -> None:
        """Show a warning alert modal and log the message."""
        from ..modals.alert_modal import AlertModal

        self._screen.app.push_screen(AlertModal(message=modal_message, title="Warning"))
        self._screen._get_activity_log().log_warning(log_message)

    def action_start_capture(self) -> None:
        """Build config, create SSL_Logger, wire handler, start session."""
        state = self._screen._get_state()

        if not state.target:
            self._warn(
                "No target selected.\nPress [bold]a[/] to attach or [bold]s[/] to spawn.",
                "No target selected. Press [bold]a[/] to attach or [bold]s[/] to spawn.",
            )
            return

        if self._ssl_logger and self._ssl_logger.running:
            self._warn(
                "Capture already running.\nPress [bold]Enter[/] to stop first.",
                "Capture already running. Press [bold]Enter[/] or [bold]Esc[/] to stop first.",
            )
            return

        if not state.keylog_path and not state.pcap_path and not state.live:
            self._warn(
                "No capture mode set.\nPress [bold]1[/]-[bold]4[/] to select a mode.",
                "No capture mode set. Press [bold]1[/]-[bold]4[/] to select a mode.",
            )
            return

        self.start_capture(state)

    def action_stop_capture(self) -> None:
        """Stop the active capture session."""
        if self._ssl_logger and self._ssl_logger.running:
            self._screen._get_activity_log().log_info("Stopping capture...")
            try:
                self._ssl_logger.finish_fritap()
            except Exception as e:
                self._screen._get_activity_log().log_error(f"Error stopping: {e}")
            finally:
                self._ssl_logger.running = False
        else:
            self._screen._get_activity_log().log_warning("No capture running.")

    def action_toggle_capture(self) -> None:
        """Toggle capture: start if idle, stop if running."""
        if self._screen._wizard_guard():
            return
        if self._ssl_logger and self._ssl_logger.running:
            self.action_stop_capture()
        else:
            self.action_start_capture()

    def action_escape_action(self) -> None:
        """Esc stops capture if running, otherwise does nothing."""
        if self._screen._wizard_guard():
            return
        if self._ssl_logger and self._ssl_logger.running:
            self.action_stop_capture()

    # ----------------------------------------------------------
    # Config & session
    # ----------------------------------------------------------

    def build_config(self, state):
        """Build a FriTapConfig from AppState."""
        from friTap.config import FriTapConfig, DeviceConfig, OutputConfig, HookingConfig

        device = DeviceConfig(spawn=state.spawn)
        if state.device_type == "usb":
            device.mobile = state.device_id if state.device_id else True
        elif state.device_type == "remote":
            device.host = state.device_id or None

        output = OutputConfig(
            pcap=state.pcap_path or None,
            keylog=state.keylog_path or None,
            json_output=state.json_path or None,
            verbose=state.verbose,
            live=state.live,
            full_capture=state.full_capture,
        )

        return FriTapConfig(
            target=state.target,
            device=device,
            output=output,
            hooking=HookingConfig(),
            protocol=getattr(state, 'protocol', 'tls'),
        )

    def start_capture(self, state) -> None:
        """Build config, create SSL_Logger, wire TUI handler, start."""
        from friTap.ssl_logger import SSL_Logger
        from friTap.tui.handlers import TuiOutputHandler

        config = self.build_config(state)
        self._ssl_logger = SSL_Logger(config=config)

        # Wire TUI output handler
        self._tui_handler = TuiOutputHandler(self._screen.app)
        self._tui_handler.setup(self._ssl_logger._event_bus)
        self._ssl_logger._output_handlers.append(self._tui_handler)

        # Update UI state
        mode_display = self._capture_mode or "Custom"
        self._screen._get_status_bar().update_capture("CAPTURING", mode_display)
        menu = self._screen._get_menu_panel()
        menu.capture_active = True
        menu.target_name = state.target_display or state.target

        log = self._screen._get_activity_log()
        mode_action = "Spawning" if state.spawn else "Attaching to"
        log.log_info(f"{mode_action}: [bold #d4945a]{state.target_display or state.target}[/]...")

        # Update console title with CAPTURING badge
        try:
            title = self._screen.query_one("#activity-title", Static)
            title.update("[bold #4ade80]friTap Console[/]  [bold green on #1a3a1a] CAPTURING [/]")
        except Exception:
            pass

        # CRITICAL: Do NOT call install_signal_handler() -- it calls os._exit(0)
        self._screen.run_worker(self._run_session, thread=True)

    def _run_session(self) -> None:
        """Run the SSL_Logger session in a background thread."""
        try:
            self._ssl_logger.start_fritap_session()
            while self._ssl_logger.running:
                time.sleep(0.2)
        except Exception as e:
            self._screen.app.call_from_thread(
                lambda: self._screen._get_activity_log().log_error(str(e))
            )
        finally:
            self._screen.app.call_from_thread(self._on_session_ended)

    def _on_session_ended(self) -> None:
        """Called when the capture session ends (on Textual thread)."""
        from ..modals.alert_modal import AlertModal

        state = self._screen._get_state()

        # Save paths BEFORE resetting
        result_paths = {}
        if state.keylog_path:
            result_paths["Key log"] = state.keylog_path
        if state.pcap_path:
            result_paths["PCAP"] = state.pcap_path
        target_display = state.target_display or state.target or "unknown"

        # Reset AppState (preserve device info)
        state.target = ""
        state.target_display = ""
        state.spawn = False
        state.pcap_path = ""
        state.keylog_path = ""
        state.json_path = ""
        state.live = False
        state.full_capture = False

        # Reset status bar
        status = self._screen._get_status_bar()
        status.update_capture("STOPPED")
        status.update_target("", "")
        status.capture_mode = ""

        # Reset menu panel
        menu = self._screen._get_menu_panel()
        menu.capture_active = False
        menu.has_target = False
        menu.target_name = ""
        menu.target_mode = ""
        menu.current_mode = ""
        menu.keylog_path = ""
        menu.pcap_path = ""

        self._capture_mode = ""

        self._screen._get_activity_log().log_session("Capture session ended")

        # Revert console title
        try:
            title = self._screen.query_one("#activity-title", Static)
            title.update("[bold #4ade80]friTap Console[/]")
        except Exception:
            pass

        # Show results summary
        if result_paths:
            lines = [f"Capture of [bold]{target_display}[/] completed.\n"]
            for label, path in result_paths.items():
                lines.append(f"  {label}: [bold]{path}[/]")
            self._screen.app.push_screen(
                AlertModal(message="\n".join(lines), title="Capture Results", severity="info")
            )
