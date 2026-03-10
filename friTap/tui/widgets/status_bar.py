#!/usr/bin/env python3
# -*- coding: utf-8 -*-

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
            if self.server_status == "running":
                parts.append("frida-server: [bold green]running[/]")
            elif self.server_status == "not running":
                parts.append("frida-server: [bold red]not running[/]")

            # Target
            if self.target_app:
                mode_tag = f" [{self.target_mode}]" if self.target_mode else ""
                parts.append(f"Target: [bold #d4945a]{self.target_app}[/]{mode_tag}")

            # Capture mode
            if self.capture_mode:
                parts.append(self.capture_mode)

            # Protocol (only show when non-default)
            if self.protocol and self.protocol != "tls":
                parts.append(f"Protocol: [bold]{self.protocol.upper()}[/]")

            # State — only show when actively capturing or just stopped
            state = self.capture_state
            if state == "CAPTURING":
                parts.append("[bold green]CAPTURING[/]")
            elif state == "STOPPED":
                parts.append("[bold red]STOPPED[/]")

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
            """Check if frida-server is reachable on the device."""
            if device is None:
                return
            if backend is not None:
                reachable = backend.check_connectivity(device)
            else:
                try:
                    device.enumerate_processes()
                    reachable = True
                except Exception:
                    reachable = False
            self.server_status = "running" if reachable else "not running"
