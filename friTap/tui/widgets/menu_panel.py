#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
MenuPanel widget for friTap TUI.

Keyboard-driven menu with bracketed key highlights (e.g. ``[d]evice select``).
Actions are grouped by category and contextually enabled/disabled.
"""

from __future__ import annotations

import re
from contextlib import contextmanager
from typing import List, Tuple

try:
    from textual.reactive import reactive
    from textual.containers import ScrollableContainer
    from textual.widgets import Static
    TEXTUAL_AVAILABLE = True
except ImportError:
    TEXTUAL_AVAILABLE = False

# Regex to find [x] bracket patterns
_KEY_RE = re.compile(r"(?<![\\])\[([a-zA-Z0-9?]|Enter)\]")


if TEXTUAL_AVAILABLE:

    class MenuPanel(ScrollableContainer):
        """Keyboard-driven action menu with bracketed key highlights."""

        capture_active: reactive[bool] = reactive(False)
        has_target: reactive[bool] = reactive(False)
        target_name: reactive[str] = reactive("")
        current_mode: reactive[str] = reactive("")
        verbose: reactive[bool] = reactive(False)
        experimental: reactive[bool] = reactive(False)
        target_mode: reactive[str] = reactive("")    # "attach" or "spawn"
        keylog_path: reactive[str] = reactive("")
        pcap_path: reactive[str] = reactive("")
        server_running: reactive[bool] = reactive(False)
        protocol: reactive[str] = reactive("tls")
        _batch_depth: int = 0

        # Static menu sections (Control is built dynamically)
        _STATIC_SECTIONS: List[Tuple[str, List[Tuple[str, str]]]] = [
            ("Target", [
                ("[d]evice select", "always"),
                ("[a]ttach to process", "no_capture"),
                ("[s]pawn application", "no_capture"),
            ]),
            ("Capture Mode", [
                ("[1] full capture (keys + pcap)", "no_capture"),
                ("[2] key extraction only", "no_capture"),
                ("[3] plaintext pcap", "no_capture"),
                ("[4] live wireshark pipe", "no_capture"),
                ("[5] live wireshark (auto-decrypt)", "no_capture"),
            ]),
        ]

        _SETUP_SECTION: List[Tuple[str, str]] = [
            ("[i]nstall & start frida-server", "needs_server"),
        ]

        # Options section is built dynamically by _build_options_section()

        def compose(self):
            yield Static("[bold #38bdf8]friTap Interactive Menu[/]", id="menu-title")
            yield Static("", id="menu-content")

        # All reactive properties trigger the same menu rebuild.
        # Textual calls watch_<name> automatically for each reactive.
        def watch_capture_active(self, _): self._update_menu()
        def watch_has_target(self, _): self._update_menu()
        def watch_target_name(self, _): self._update_menu()
        def watch_current_mode(self, _): self._update_menu()
        def watch_verbose(self, _): self._update_menu()
        def watch_experimental(self, _): self._update_menu()
        def watch_target_mode(self, _): self._update_menu()
        def watch_keylog_path(self, _): self._update_menu()
        def watch_pcap_path(self, _): self._update_menu()
        def watch_server_running(self, _): self._update_menu()
        def watch_protocol(self, _): self._update_menu()

        def on_mount(self) -> None:
            """Render the initial menu."""
            self._update_menu()

        def _build_control_section(self) -> List[Tuple[str, str]]:
            """Build the Control section dynamically based on state."""
            items = []

            # Dynamic Enter item with mode tag
            mode_tag = ""
            if self.target_mode == "attach":
                mode_tag = " [bold #4ade80]\\[Attaching][/]"
            elif self.target_mode == "spawn":
                mode_tag = " [bold #818cf8]\\[Spawning][/]"

            if self.capture_active:
                if self.target_name:
                    items.append((f"[Enter] stop capture of [bold #d4945a]{self.target_name}[/]{mode_tag}", "always"))
                else:
                    items.append(("[Enter] stop capture", "always"))
            else:
                if self.target_name:
                    items.append((f"[Enter] start capture of [bold #d4945a]{self.target_name}[/]{mode_tag}", "has_target"))
                else:
                    items.append(("[Enter] start capture", "has_target"))

            items.append(("[c]lear console", "always"))
            items.append(("[y] copy log", "always"))
            return items

        def _build_options_section(self) -> List[Tuple[str, str, str | None]]:
            """Build the Options section with toggle attribute names."""
            return [
                ("[v]erbose", "always", "verbose"),
                ("[e]xperimental", "always", "experimental"),
                ("[p]rotocol select", "no_capture", None),
                ("[?] help", "always", None),
            ]

        @contextmanager
        def batch_update(self):
            """Defer _update_menu() calls until the context manager exits."""
            self._batch_depth += 1
            try:
                yield
            finally:
                self._batch_depth -= 1
                if self._batch_depth == 0:
                    self._update_menu()

        def _update_menu(self) -> None:
            """Rebuild the full menu content."""
            if self._batch_depth > 0:
                return
            lines: List[str] = []

            # Static sections (Target, Capture Mode)
            for category, items in self._STATIC_SECTIONS:
                lines.append("")
                if category == "Capture Mode" and self.current_mode:
                    mode_labels = {
                        "full": "Full Capture", "keys": "Keys Only",
                        "plaintext": "Plaintext PCAP", "wireshark": "Live Wireshark",
                        "live_pcapng": "Live PCAPNG",
                    }
                    active = mode_labels.get(self.current_mode, "")
                    lines.append(
                        f"[bold #64748b]=== Capture Mode[/] [bold green]► {active}[/][bold #64748b] ===[/]"
                    )
                else:
                    lines.append(f"[bold #64748b]=== {category} ===[/]")
                for text, condition in items:
                    enabled = self._is_enabled(condition)
                    formatted = self._format_item(text, enabled)

                    # Add status indicators for capture mode items
                    indicator = self._get_indicator(text)
                    if indicator:
                        formatted += f"  {indicator}"

                    lines.append(f"  {formatted}")

                # Show output paths below capture mode items
                if category == "Capture Mode" and self.current_mode:
                    if self.keylog_path:
                        lines.append(f"    [#8f9bb3]→ keys: {self.keylog_path}[/]")
                    if self.pcap_path:
                        lines.append(f"    [#8f9bb3]→ pcap: {self.pcap_path}[/]")

            # Control section (dynamic)
            lines.append("")
            lines.append("[bold #64748b]=== Control ===[/]")
            for text, condition in self._build_control_section():
                enabled = self._is_enabled(condition)
                formatted = self._format_item(text, enabled)
                lines.append(f"  {formatted}")

            # Setup section
            lines.append("")
            lines.append("[bold #64748b]=== Setup ===[/]")
            for text, condition in self._SETUP_SECTION:
                enabled = self._is_enabled(condition)
                formatted = self._format_item(text, enabled)
                lines.append(f"  {formatted}")

            # Options section (toggles with inline state)
            lines.append("")
            lines.append("[bold #64748b]=== Options ===[/]")
            for text, condition, toggle_attr in self._build_options_section():
                enabled = self._is_enabled(condition)
                formatted = self._format_item(text, enabled)
                if toggle_attr is not None:
                    is_on = getattr(self, toggle_attr, False)
                    if is_on:
                        indicator = " [bold green]● ON[/]"
                    else:
                        indicator = " [dim]○ off[/]"
                    formatted += indicator
                lines.append(f"  {formatted}")

            try:
                content = self.query_one("#menu-content", Static)
                content.update("\n".join(lines))
            except Exception:
                pass

        def _is_enabled(self, condition: str) -> bool:
            """Check if a menu item should be enabled based on condition name."""
            checks = {
                "always": lambda: True,
                "no_capture": lambda: not self.capture_active,
                "capture_active": lambda: self.capture_active,
                "has_target": lambda: self.has_target and not self.capture_active,
                "needs_server": lambda: not self.capture_active and not self.server_running,
            }
            return checks.get(condition, lambda: True)()

        def _format_item(self, text: str, enabled: bool) -> str:
            """Format a menu item with highlighted bracket keys."""
            if not enabled:
                escaped = _KEY_RE.sub(lambda m: f"\\[{m.group(1)}]", text)
                return f"[#6b7280]{escaped}[/]"

            def _highlight(match: re.Match) -> str:
                key = match.group(1)
                return f"[bold cyan]\\[{key}][/]"

            return _KEY_RE.sub(_highlight, text)

        _INDICATOR_MAP = {
            "full capture": "full",
            "key extraction": "keys",
            "plaintext": "plaintext",
            "auto-decrypt": "live_pcapng",
        }

        _ACTIVE_INDICATOR = "[bold green]  ◄ active[/]"

        def _get_indicator(self, text: str) -> str:
            """Return an optional status indicator for specific items."""
            text_lower = text.lower() if text else ""
            for keyword, mode_id in self._INDICATOR_MAP.items():
                if keyword in text_lower and self.current_mode == mode_id:
                    return self._ACTIVE_INDICATOR
            # "wireshark" without "auto-decrypt" maps to "wireshark" mode
            if "wireshark" in text_lower and "auto-decrypt" not in text_lower and self.current_mode == "wireshark":
                return self._ACTIVE_INDICATOR
            return ""
