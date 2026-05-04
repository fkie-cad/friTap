#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Quit confirmation modal for friTap TUI.

Asks the user to confirm before exiting the application.
"""

from __future__ import annotations

from typing import Optional

try:
    from textual.app import ComposeResult
    from textual.binding import Binding
    from textual.widgets import Button, Static
    from textual.containers import Vertical, Horizontal
    TEXTUAL_AVAILABLE = True
except ImportError:
    TEXTUAL_AVAILABLE = False

if TEXTUAL_AVAILABLE:
    from friTap.tui.themes import c
    from .base import FriTapModal

    class QuitConfirmModal(FriTapModal[Optional[bool]]):
        """Confirmation dialog before quitting friTap."""

        DEFAULT_CSS = """
        QuitConfirmModal > #modal-container {
            width: 55;
            height: auto;
            max-height: 40%;
            background: $fritap-bg-modal;
            border: solid $fritap-border-default;
            padding: 1 2;
        }
        QuitConfirmModal #quit-message {
            margin: 1 0;
            text-align: left;
            padding: 0 1;
        }
        """

        BINDINGS = FriTapModal.BINDINGS + [
            Binding("enter", "confirm_quit", "Quit", show=False),
            Binding("y", "confirm_quit", "Quit", show=False),
            Binding("n", "cancel", "Cancel", show=False),
            Binding("q", "cancel", "Cancel", show=False),
        ]

        def compose(self) -> ComposeResult:
            with Vertical(id="modal-container"):
                yield Static(
                    f"[bold {c('error')}]Quit friTap?[/]",
                    classes="modal-title",
                )
                yield Static(
                    "Are you sure you want to exit?",
                    id="quit-message",
                )
                with Horizontal(classes="button-row"):
                    yield Button("Quit", id="btn-quit", variant="error")
                    yield Button("Cancel", id="btn-cancel", variant="default")
                yield Static(
                    f"[{c('text-muted')}]y/Enter=Quit   n/q/Esc=Cancel[/]",
                    classes="key-hints",
                )

        def on_button_pressed(self, event: Button.Pressed) -> None:
            if event.button.id == "btn-quit":
                self.dismiss(True)
            elif event.button.id == "btn-cancel":
                self.dismiss(None)

        def action_confirm_quit(self) -> None:
            self.dismiss(True)
