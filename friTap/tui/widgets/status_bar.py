#!/usr/bin/env python3

"""
StatusBar widget for friTap TUI.

Displays a single-line overview of the current capture session state:
device info, server status, target, capture mode, and capture status.
"""

from __future__ import annotations

try:
    from textual.reactive import reactive
    from textual.widgets import Static
    TEXTUAL_AVAILABLE = True
except ImportError:
    TEXTUAL_AVAILABLE = False

from friTap.server_manager.probe import ServerState, probe_frida_server
from friTap.tui.themes import c

# Theme color per frida-server status (ServerState values).
SERVER_STATUS_COLORS = {
    ServerState.RUNNING.value: "success",
    ServerState.GADGET.value: "warning",
    ServerState.NOT_RUNNING.value: "error",
    ServerState.UNREACHABLE.value: "error",
}

if TEXTUAL_AVAILABLE:

    class StatusBar(Static):
        """Single-line status bar showing device, target, and capture state."""

        capture_state: reactive[str] = reactive("")
        device_name: reactive[str] = reactive("Local")
        device_type: reactive[str] = reactive("[L]")
        server_status: reactive[str] = reactive("")
        target_app: reactive[str] = reactive("")
        target_mode: reactive[str] = reactive("")
        capture_mode: reactive[str] = reactive("")
        protocol: reactive[str] = reactive("tls")

        def render(self) -> str:
            """Build the status line from reactive properties."""
            parts = []

            # Device
            parts.append(f"Device: {self.device_type} {self.device_name}")

            # frida-server status (only show when set — USB/remote devices)
            server_color = SERVER_STATUS_COLORS.get(self.server_status)
            if server_color:
                parts.append(
                    f"frida-server: [bold {c(server_color)}]{self.server_status}[/]"
                )

            # Target
            if self.target_app:
                mode_tag = f" [{self.target_mode}]" if self.target_mode else ""
                parts.append(f"Target: [bold {c('target')}]{self.target_app}[/]{mode_tag}")

            # Capture mode
            if self.capture_mode:
                parts.append(self.capture_mode)

            # Protocol (only show when non-default)
            if self.protocol and self.protocol != "tls":
                parts.append(f"Protocol: [bold]{self.protocol.upper()}[/]")

            # State — only show when actively capturing or just stopped
            state = self.capture_state
            if state == "CAPTURING":
                parts.append(f"[bold {c('success')}]CAPTURING[/]")
            elif state == "STOPPED":
                parts.append(f"[bold {c('error')}]STOPPED[/]")

            return " | ".join(parts)

        def update_device(self, name: str, type_tag: str, server_status: str = "") -> None:
            """Update device-related reactive properties."""
            self.device_name = name
            self.device_type = type_tag
            if server_status:
                self.server_status = server_status

        def update_target(self, app_name: str, mode: str = "") -> None:
            """Update target-related reactive properties."""
            self.target_app = app_name
            self.target_mode = mode

        def update_capture(self, state: str, mode: str = "") -> None:
            """Update capture state and mode."""
            self.capture_state = state
            if mode:
                self.capture_mode = mode

        def check_server_status(self, device=None, backend=None) -> None:
            """Probe frida-server on *device* and show the resulting state.

            Uses the attach-capability probe instead of enumeration: on
            frida 17 a server-less USB device still enumerates via ADB.
            *backend* is kept for signature compatibility and is unused.
            """
            if device is None:
                return
            self.server_status = probe_frida_server(device).value
