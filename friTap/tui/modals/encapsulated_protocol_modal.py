#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Encapsulated protocol decryption modal for friTap TUI.

Lets the user enable or disable decryption of protocols that are
tunnelled inside TLS (e.g. OHTTP / Oblivious HTTP).
Returns a dict mapping protocol name → bool, an empty dict when the user
skips the step, or None when the user cancels (ESC).
"""

from __future__ import annotations

from typing import Dict, Optional

try:
    from textual.app import ComposeResult
    from textual.binding import Binding
    from textual.widgets import Button, Switch, Static, Label
    from textual.containers import Vertical, Horizontal
    TEXTUAL_AVAILABLE = True
except ImportError:
    TEXTUAL_AVAILABLE = False

if TEXTUAL_AVAILABLE:
    from friTap.tui.themes import c
    from .base import FriTapModal

    class EncapsulatedProtocolModal(FriTapModal[Optional[Dict[str, bool]]]):
        """Modal for configuring encapsulated-protocol decryption."""

        BINDINGS = FriTapModal.BINDINGS + [
            Binding("enter", "confirm", "Confirm", priority=True),
            Binding("space", "toggle_protocol", "Toggle", priority=True),
        ]

        DEFAULT_CSS = """
        EncapsulatedProtocolModal > #modal-container {
            width: 64;
            height: auto;
            max-height: 70%;
            background: $fritap-bg-modal;
            border: solid $fritap-border-default;
            padding: 1 2;
        }
        EncapsulatedProtocolModal #subtitle {
            text-align: center;
            color: $fritap-text-muted;
            margin-bottom: 1;
        }
        EncapsulatedProtocolModal .protocol-row {
            height: 3;
            align: left middle;
            margin: 0 0 1 0;
        }
        EncapsulatedProtocolModal .protocol-label {
            width: 1fr;
            color: $fritap-text-secondary;
        }
        EncapsulatedProtocolModal .protocol-desc {
            color: $fritap-text-muted;
            margin-bottom: 1;
        }
        """

        def __init__(self, **kwargs) -> None:
            super().__init__(**kwargs)
            self._ohttp_switch: Optional[Switch] = None

        def compose(self) -> ComposeResult:
            with Vertical(id="modal-container"):
                yield Static(
                    f"[bold {c('primary')}]Encapsulated Protocol Decryption[/]",
                    classes="modal-title",
                )
                yield Static(
                    "friTap can decrypt protocols tunnelled inside TLS.\n"
                    "Enable the protocols you want to inspect.",
                    id="subtitle",
                )
                with Horizontal(classes="protocol-row"):
                    yield Label("OHTTP (Oblivious HTTP)", classes="protocol-label")
                    yield Switch(value=True, id="switch-ohttp")
                yield Static(
                    f"[{c('text-muted')}]Decrypt Oblivious HTTP requests inside TLS streams[/]",
                    classes="protocol-desc",
                )
                yield Static(
                    f"[{c('text-muted')}]Space: Toggle  |  Enter: Confirm  |  Esc: Cancel[/]",
                    classes="key-hints",
                )
                with Horizontal(classes="button-row"):
                    yield Button("Confirm", id="btn-confirm", variant="primary")
                    yield Button("Skip", id="btn-skip", variant="default")

        def _auto_focus(self) -> None:
            try:
                self._ohttp_switch = self.query_one("#switch-ohttp", Switch)
                self._ohttp_switch.focus()
            except Exception:
                pass

        def on_button_pressed(self, event: Button.Pressed) -> None:
            if event.button.id == "btn-confirm":
                self._confirm()
            elif event.button.id == "btn-skip":
                self.dismiss({})

        def action_confirm(self) -> None:
            self._confirm()

        def action_toggle_protocol(self) -> None:
            if self._ohttp_switch is not None:
                self._ohttp_switch.toggle()

        def _confirm(self) -> None:
            ohttp_on = self._ohttp_switch.value if self._ohttp_switch is not None else True
            self.dismiss({"ohttp": bool(ohttp_on)})
