#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Capture mode selection modal for friTap TUI.

Presents four capture modes and returns the selected mode string,
or None if the user cancels.
"""

from __future__ import annotations

from typing import Optional

try:
    from textual.app import ComposeResult
    from textual.binding import Binding
    from textual.widgets import Button, OptionList, Static
    from textual.widgets.option_list import Option
    from textual.containers import Vertical, Horizontal
    TEXTUAL_AVAILABLE = True
except ImportError:
    TEXTUAL_AVAILABLE = False

if TEXTUAL_AVAILABLE:
    from .base import FriTapModal

    _MODE_MAP = {0: "full", 1: "keys", 2: "plaintext", 3: "wireshark", 4: "live_pcapng"}

    class CaptureSelectModal(FriTapModal[Optional[str]]):
        """Modal for selecting one of four capture modes."""

        DEFAULT_CSS = """
        CaptureSelectModal > #modal-container {
            width: 65;
            height: auto;
            max-height: 70%;
            background: #0d1117;
            border: solid #1e3a5f;
            padding: 1 2;
        }
        CaptureSelectModal #capture-list {
            height: 10;
            margin: 1 0;
            background: #080c18;
        }
        """

        BINDINGS = [
            Binding("1", "select_full", "Full Capture", show=False),
            Binding("2", "select_keys", "Key Extraction", show=False),
            Binding("3", "select_plaintext", "Plaintext PCAP", show=False),
            Binding("4", "select_wireshark", "Live Wireshark", show=False),
            Binding("5", "select_live_pcapng", "Live PCAPNG", show=False),
        ]

        def compose(self) -> ComposeResult:
            with Vertical(id="modal-container"):
                yield Static(
                    "[bold #38bdf8]Select Capture Mode[/]",
                    classes="modal-title",
                )
                yield OptionList(
                    Option("[1] Full Capture — TLS keys + PCAP file"),
                    Option("[2] Key Extraction Only — Extract TLS session keys"),
                    Option("[3] Plaintext PCAP — Decrypted traffic to PCAP"),
                    Option("[4] Live Wireshark — Stream to Wireshark pipe"),
                    Option("[5] Live Wireshark (auto-decrypt) — PCAPNG with embedded keys"),
                    id="capture-list",
                )
                yield Static(
                    "[#64748b]1-5: Select  |  Enter: Confirm  |  ↑↓: Browse  |  Esc: Back[/]",
                    classes="key-hints",
                )
                with Horizontal(classes="button-row"):
                    yield Button("Select", id="btn-select", variant="primary")
                    yield Button("Cancel", id="btn-cancel", variant="default")

        def _auto_focus(self) -> None:
            """Override base to focus the capture mode list."""
            try:
                self.query_one("#capture-list", OptionList).focus()
            except Exception:
                pass

        def action_select_full(self) -> None:
            self.dismiss("full")

        def action_select_keys(self) -> None:
            self.dismiss("keys")

        def action_select_plaintext(self) -> None:
            self.dismiss("plaintext")

        def action_select_wireshark(self) -> None:
            self.dismiss("wireshark")

        def action_select_live_pcapng(self) -> None:
            self.dismiss("live_pcapng")

        def on_option_list_option_selected(
            self, event: OptionList.OptionSelected
        ) -> None:
            """Enter or double-click on an option selects it."""
            self._select_highlighted()

        def on_button_pressed(self, event: Button.Pressed) -> None:
            if event.button.id == "btn-select":
                self._select_highlighted()
            elif event.button.id == "btn-cancel":
                self.dismiss(None)

        def _select_highlighted(self) -> None:
            """Dismiss with the mode string for the currently highlighted option."""
            option_list = self.query_one("#capture-list", OptionList)
            try:
                highlighted = option_list.highlighted
                if highlighted is not None and highlighted in _MODE_MAP:
                    self.dismiss(_MODE_MAP[highlighted])
                    return
            except Exception:
                pass
            self.dismiss(None)
