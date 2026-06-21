#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Decrypt-confirmation modal for friTap TUI.

Shown after a full-capture + keys session ends, offering to decrypt the
captured pcap with the captured keys into a layered flow view. Returns
True (decrypt) or False (skip).
"""

from __future__ import annotations

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

    class DecryptConfirmModal(FriTapModal[bool]):
        """Modal asking whether to decrypt the captured traffic."""

        DEFAULT_CSS = """
        DecryptConfirmModal > #modal-container {
            width: 60;
            height: auto;
            max-height: 70%;
            background: $fritap-bg-modal;
            border: solid $fritap-border-default;
            padding: 1 2;
        }
        DecryptConfirmModal .modal-body {
            margin: 1 0;
            color: $fritap-text-dim;
            text-align: center;
        }
        """

        BINDINGS = [
            Binding("escape", "cancel", "Skip", show=True),
        ]

        def compose(self) -> ComposeResult:
            with Vertical(id="modal-container"):
                yield Static(
                    f"[bold {c('primary')}]Decrypt captured traffic?[/]",
                    classes="modal-title",
                )
                yield Static(
                    "Decrypt the captured pcap with the captured keys into a "
                    "layered flow view?",
                    classes="modal-body",
                )
                yield Static(
                    f"[{c('text-muted')}]Enter: Decrypt  |  Esc: Skip[/]",
                    classes="key-hints",
                )
                with Horizontal(classes="button-row"):
                    yield Button("Decrypt", id="btn-decrypt", variant="primary")
                    yield Button("Skip", id="btn-skip", variant="default")

        def _auto_focus(self) -> None:
            try:
                self.query_one("#btn-decrypt", Button).focus()
            except Exception:
                pass

        def action_cancel(self) -> None:
            self.dismiss(False)

        def on_button_pressed(self, event: Button.Pressed) -> None:
            if event.button.id == "btn-decrypt":
                self.dismiss(True)
            elif event.button.id == "btn-skip":
                self.dismiss(False)
