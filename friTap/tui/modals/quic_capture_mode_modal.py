#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
QUIC capture-mode selection modal for friTap TUI.

Lets the user pick the QUIC plaintext-capture boundary used during a
plaintext capture of TLS. Returns the selected mode string
("stream" or "app-api"), or None if the user cancels (ESC).
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

    _MODE_MAP = {0: "stream", 1: "app-api"}

    class QuicCaptureModeModal(FriTapModal[Optional[str]]):
        """Modal for selecting the QUIC plaintext-capture boundary."""

        DEFAULT_CSS = """
        QuicCaptureModeModal > #modal-container {
            width: 70;
            height: auto;
            max-height: 70%;
            background: $fritap-bg-modal;
            border: solid $fritap-border-default;
            padding: 1 2;
        }
        QuicCaptureModeModal #subtitle {
            text-align: center;
            color: $fritap-text-muted;
            margin-bottom: 1;
        }
        QuicCaptureModeModal #quic-mode-list {
            height: auto;
            max-height: 16;
            margin: 1 0;
            background: $surface;
        }
        QuicCaptureModeModal .mode-note {
            color: $fritap-text-muted;
            margin-bottom: 1;
        }
        """

        BINDINGS = [
            Binding("1", "select_stream", "Stream", show=False),
            Binding("2", "select_app_api", "App-API", show=False),
        ]

        def compose(self) -> ComposeResult:
            with Vertical(id="modal-container"):
                yield Static(
                    f"[bold {c('primary')}]QUIC Capture Mode[/]",
                    classes="modal-title",
                )
                yield Static(
                    "Select the QUIC plaintext-capture boundary for this\n"
                    "decrypted (plaintext) capture.",
                    id="subtitle",
                )
                yield OptionList(
                    Option("[1] Stream — lower-boundary QUIC stream hooks (default)"),
                    Option("[2] App-API — decoded HTTP/3 headers, Boundary-4"),
                    id="quic-mode-list",
                )
                yield Static(
                    f"[{c('text-muted')}]App-API is experimental and only works on "
                    f"Chrome / Android Google QUICHE targets.[/]",
                    classes="mode-note",
                )
                yield Static(
                    f"[{c('text-muted')}]1-2: Select  |  Enter: Confirm  |  ↑↓: Browse  |  Esc: Back[/]",
                    classes="key-hints",
                )
                with Horizontal(classes="button-row"):
                    yield Button("Select", id="btn-select", variant="primary")
                    yield Button("Cancel", id="btn-cancel", variant="default")

        def _auto_focus(self) -> None:
            """Override base to focus the QUIC mode list."""
            try:
                self.query_one("#quic-mode-list", OptionList).focus()
            except Exception:
                pass

        def action_select_stream(self) -> None:
            self.dismiss("stream")

        def action_select_app_api(self) -> None:
            self.dismiss("app-api")

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
            option_list = self.query_one("#quic-mode-list", OptionList)
            try:
                highlighted = option_list.highlighted
                if highlighted is not None and highlighted in _MODE_MAP:
                    self.dismiss(_MODE_MAP[highlighted])
                    return
            except Exception:
                pass
            self.dismiss(None)
