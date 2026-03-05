#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Main TUI application for friTap.

Launch with `fritap` (no arguments) for the interactive experience.
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ..events import EventBus

try:
    from textual.app import App
    from textual.binding import Binding
    TEXTUAL_AVAILABLE = True
except ImportError:
    TEXTUAL_AVAILABLE = False


@dataclass
class AppState:
    """Shared state across TUI screens."""

    # Mode
    mode: str = "capture"  # "capture", "inspect", "patterns"

    # Target
    target: str = ""
    target_display: str = ""   # Human-readable name for UI (e.g. "Chrome")
    spawn: bool = False
    device_type: str = "local"  # "local", "usb", "remote"
    device_id: str = ""        # Frida device ID (e.g. "emulator-5554")
    device_name: str = ""      # Human-readable name (e.g. "Pixel 6")
    device_platform: str = ""  # "android", "ios", "linux", "macos", "windows"

    # Output config
    pcap_path: str = ""
    keylog_path: str = ""
    json_path: str = ""
    verbose: bool = False
    live: bool = False
    full_capture: bool = False
    protocol: str = "tls"  # "tls", "ipsec", "ssh", "auto"

    # Runtime
    session: Optional[object] = None
    event_bus: Optional["EventBus"] = None


if TEXTUAL_AVAILABLE:
    from .screens.main_screen import MainScreen

    class FriTapApp(App):
        """The friTap interactive TUI application."""

        TITLE = "friTap"
        SUB_TITLE = "Real-time key extraction and traffic decryption"
        CSS_PATH = "css/fritap.tcss"
        ENABLE_COMMAND_PALETTE = False

        BINDINGS = [
            Binding("q", "quit", "Quit", show=True),
            Binding("d", "device_select", "Device", show=False),
            Binding("a", "attach", "Attach", show=False),
            Binding("s", "spawn", "Spawn", show=False),
            Binding("1", "set_mode_1", "Full Capture", show=False),
            Binding("2", "set_mode_2", "Keys Only", show=False),
            Binding("3", "set_mode_3", "Plaintext PCAP", show=False),
            Binding("4", "set_mode_4", "Live Wireshark", show=False),
            Binding("5", "set_mode_5", "Live PCAPNG", show=False),
            Binding("enter", "toggle_capture", "Start/Stop", show=False),
            Binding("escape", "escape_action", "Stop/Close", show=False),
            Binding("c", "clear_log", "Clear Console", show=False),
            Binding("i", "install_server", "Install Frida", show=False),
            Binding("v", "verbose_toggle", "Verbose", show=False),
            Binding("e", "experimental_toggle", "Experimental", show=False),
            Binding("p", "protocol_select", "Protocol", show=False),
            Binding("question_mark", "show_help", "Help", show=True),
            Binding("y", "copy_log", "Copy Log", show=False),
        ]

        def on_mount(self) -> None:
            """Start with the main screen."""
            self.app_state = AppState()
            self.push_screen(MainScreen())

        # -------------------------------------------------------
        # Action delegation to MainScreen
        # -------------------------------------------------------

        def _main_screen(self) -> Optional[MainScreen]:
            """Return the MainScreen if it's the active screen."""
            try:
                for screen in self.screen_stack:
                    if isinstance(screen, MainScreen):
                        return screen
            except Exception:
                pass
            return None

        def _delegate(self, action_name: str) -> None:
            """Forward an action to MainScreen by name."""
            ms = self._main_screen()
            if ms:
                getattr(ms, action_name)()

        def action_device_select(self) -> None:
            self._delegate("action_device_select")

        def action_attach(self) -> None:
            self._delegate("action_attach")

        def action_spawn(self) -> None:
            self._delegate("action_spawn")

        def action_set_mode_1(self) -> None:
            self._delegate("action_set_mode_1")

        def action_set_mode_2(self) -> None:
            self._delegate("action_set_mode_2")

        def action_set_mode_3(self) -> None:
            self._delegate("action_set_mode_3")

        def action_set_mode_4(self) -> None:
            self._delegate("action_set_mode_4")

        def action_set_mode_5(self) -> None:
            self._delegate("action_set_mode_5")

        def action_toggle_capture(self) -> None:
            self._delegate("action_toggle_capture")

        def action_escape_action(self) -> None:
            self._delegate("action_escape_action")

        def action_clear_log(self) -> None:
            self._delegate("action_clear_log")

        def action_install_server(self) -> None:
            self._delegate("action_install_server")

        def action_verbose_toggle(self) -> None:
            self._delegate("action_verbose_toggle")

        def action_experimental_toggle(self) -> None:
            self._delegate("action_experimental_toggle")

        def action_protocol_select(self) -> None:
            self._delegate("action_protocol_select")

        def action_show_help(self) -> None:
            self._delegate("action_show_help")

        def action_copy_log(self) -> None:
            self._delegate("action_copy_log")


    def run_tui() -> None:
        """Entry point to launch the TUI."""
        if not TEXTUAL_AVAILABLE:
            import sys
            print("Error: The TUI requires the 'textual' package.")
            print("Install it with: pip install fritap[tui]  or  pip install textual>=0.80.0")
            sys.exit(1)
        app = FriTapApp()
        app.run()

else:
    def run_tui() -> None:
        import sys
        print("Error: The TUI requires the 'textual' package.")
        print("Install it with: pip install fritap[tui]  or  pip install textual>=0.80.0")
        sys.exit(1)
