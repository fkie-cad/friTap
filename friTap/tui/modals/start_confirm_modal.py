#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Start confirmation modal for friTap TUI wizard.

Shows a summary of all configured settings and asks for
confirmation before starting capture.
"""

from __future__ import annotations

from typing import Optional

try:
    from textual.app import ComposeResult
    from textual.binding import Binding
    from textual.reactive import reactive
    from textual.widgets import Button, Static
    from textual.containers import Vertical, Horizontal
    TEXTUAL_AVAILABLE = True
except ImportError:
    TEXTUAL_AVAILABLE = False

if TEXTUAL_AVAILABLE:
    from .base import FriTapModal

    _TYPE_TAGS = {
        "usb": "U",
        "remote": "R",
        "local": "L",
    }

    class StartConfirmModal(FriTapModal[Optional[bool]]):
        """Confirmation modal displaying capture settings before start."""

        DEFAULT_CSS = """
        StartConfirmModal > #modal-container {
            width: 65;
            height: auto;
            max-height: 70%;
            background: #0d1117;
            border: solid #1e3a5f;
            padding: 1 2;
        }
        StartConfirmModal #summary-block {
            margin: 1 2;
            color: #94a3b8;
        }
        """

        BINDINGS = [
            Binding("v", "toggle_verbose", "Verbose", show=False),
            Binding("e", "toggle_experimental", "Experimental", show=False),
        ]

        verbose: reactive[bool] = reactive(False)
        experimental: reactive[bool] = reactive(False)

        def __init__(self, summary: dict, **kwargs) -> None:
            super().__init__(**kwargs)
            self._summary = summary
            self.verbose = summary.get("verbose", False)
            self.experimental = summary.get("experimental", False)

        def compose(self) -> ComposeResult:
            with Vertical(id="modal-container"):
                yield Static(
                    "[bold #4ade80]Ready to Capture[/]",
                    classes="modal-title",
                )
                yield Static("", id="summary-block")
                yield Static(
                    "[#64748b]Enter: Start  |  v: Verbose  |  e: Experimental  |  Esc: Back[/]",
                    classes="key-hints",
                )
                with Horizontal(classes="button-row"):
                    yield Button(
                        "Start Capture", id="btn-start", variant="primary"
                    )
                    yield Button("Back", id="btn-back", variant="default")

        def on_mount(self) -> None:
            super().on_mount()
            self._refresh_summary()

        def _refresh_summary(self) -> None:
            """Rebuild the summary text and update the widget."""
            text = self._build_summary_text()
            try:
                self.query_one("#summary-block", Static).update(text)
            except Exception:
                pass

        def _build_summary_text(self) -> str:
            """Build the formatted summary block from the summary dict."""
            device_name = self._summary.get("device_name", "Unknown")
            device_type = self._summary.get("device_type", "local")
            target_name = self._summary.get("target_name", "Unknown")
            target_mode = self._summary.get("target_mode", "attach")
            capture_mode_display = self._summary.get(
                "capture_mode_display", "Unknown"
            )
            keylog_path = self._summary.get("keylog_path", "")
            pcap_path = self._summary.get("pcap_path", "")
            live = self._summary.get("live", False)

            type_tag = _TYPE_TAGS.get(device_type, "L")
            target_mode_upper = target_mode.upper()

            verbose_indicator = "[bold green]ON[/]" if self.verbose else "[dim]off[/]"
            experimental_indicator = "[bold green]ON[/]" if self.experimental else "[dim]off[/]"

            lines = [
                f"  Device:        [{type_tag}] {device_name}",
                f"  Target:        {target_name} [{target_mode_upper}]",
                f"  Mode:          {capture_mode_display}",
                f"  Keys:          {keylog_path or '\u2014'}",
                f"  PCAP:          {pcap_path or '\u2014'}",
            ]

            if live:
                lines.append("  Live:          Streaming to Wireshark")

            lines.append("")
            lines.append(f"  Verbose:       {verbose_indicator}")
            lines.append(f"  Experimental:  {experimental_indicator}")

            return "\n".join(lines)

        def watch_verbose(self, value: bool) -> None:
            self._refresh_summary()

        def watch_experimental(self, value: bool) -> None:
            self._refresh_summary()

        def action_toggle_verbose(self) -> None:
            """Toggle verbose flag."""
            self.verbose = not self.verbose

        def action_toggle_experimental(self) -> None:
            """Toggle experimental flag."""
            self.experimental = not self.experimental

        def on_button_pressed(self, event: Button.Pressed) -> None:
            if event.button.id == "btn-start":
                self.dismiss(True)
            elif event.button.id == "btn-back":
                self.dismiss(None)
