#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Capture mode selection modal for friTap TUI.

Presents the available capture modes and returns the selected mode
string, or None if the user cancels.

The "owner" mode (Per-App (UID) Capture) is only offered when the
target device platform is Android or Linux; on other platforms it is
omitted and the remaining modes renumber accordingly.

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
    from friTap.tui.themes import c
    from .base import FriTapModal

    # Ordered (mode_id, label) for every capture mode. "owner" sits directly
    # below "full" and is filtered out at runtime on non-Android/Linux targets.
    _ALL_MODES = [
        ("full", "Full Capture — Decryption keys + PCAP file"),
        (
            "owner",
            "Per-App (UID) Capture — Kernel-scoped keys + PCAP",
        ),
        ("keys", "Key Extraction Only — Extract decryption keys"),
        ("plaintext", "Plaintext PCAP — Decrypted traffic to PCAP"),
        ("wireshark", "Live Wireshark — Stream to Wireshark pipe"),
        ("live_pcapng", "Live Wireshark (auto-decrypt) — PCAPNG with embedded keys"),
    ]

    # Platforms on which the per-app (UID) owner capture is available.
    _OWNER_PLATFORMS = ("android", "linux")

    class CaptureSelectModal(FriTapModal[Optional[str]]):
        """Modal for selecting a capture mode."""

        DEFAULT_CSS = """
        CaptureSelectModal > #modal-container {
            width: 65;
            height: auto;
            max-height: 70%;
            background: $fritap-bg-modal;
            border: solid $fritap-border-default;
            padding: 1 2;
        }
        CaptureSelectModal #capture-list {
            height: 12;
            margin: 1 0;
            background: $surface;
        }
        """

        # Number keys 1-6 all dispatch through a single digit handler so the
        # bindings stay valid regardless of how many modes the platform offers.
        BINDINGS = [
            Binding("1", "select_index('1')", "Mode 1", show=False),
            Binding("2", "select_index('2')", "Mode 2", show=False),
            Binding("3", "select_index('3')", "Mode 3", show=False),
            Binding("4", "select_index('4')", "Mode 4", show=False),
            Binding("5", "select_index('5')", "Mode 5", show=False),
            Binding("6", "select_index('6')", "Mode 6", show=False),
        ]

        def __init__(self, device_platform: str = "", **kwargs) -> None:
            super().__init__(**kwargs)
            self._device_platform = (device_platform or "").lower()
            # Build the visible mode list, dropping "owner" off-platform. The
            # resulting index order drives both the OptionList and _mode_map.
            self._modes = [
                (mode_id, label)
                for mode_id, label in _ALL_MODES
                if mode_id != "owner"
                or self._device_platform in _OWNER_PLATFORMS
            ]
            # OptionList row index -> mode_id (kept in sync with compose order).
            self._mode_map = {
                index: mode_id for index, (mode_id, _) in enumerate(self._modes)
            }

        def compose(self) -> ComposeResult:
            count = len(self._modes)

            with Vertical(id="modal-container"):
                yield Static(
                    f"[bold {c('primary')}]Select Capture Mode[/]",
                    classes="modal-title",
                )
                yield OptionList(
                    *(
                        Option(f"[{index + 1}] {label}")
                        for index, (_, label) in enumerate(self._modes)
                    ),
                    id="capture-list",
                )
                yield Static(
                    f"[{c('text-muted')}]1-{count}: Select  |  Enter: Confirm  |  ↑↓: Browse  |  Esc: Back[/]",
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


        def action_select_index(self, digit: str) -> None:
            """Dismiss with the mode at the given 1-based number key, if present."""
            index = int(digit) - 1
            mode_id = self._mode_map.get(index)
            if mode_id is not None:
                self.dismiss(mode_id)

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

                if highlighted is not None and highlighted in self._mode_map:
                    self.dismiss(self._mode_map[highlighted])

                    return
            except Exception:
                pass
            self.dismiss(None)
