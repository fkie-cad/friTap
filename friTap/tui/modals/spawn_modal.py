#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Spawn input modal for friTap TUI.

Simple input dialog for entering a package name or binary path to spawn.
"""

from __future__ import annotations

from typing import Optional

try:
    from textual.app import ComposeResult
    from textual.widgets import Button, Input, Static
    from textual.containers import Vertical, Horizontal
    TEXTUAL_AVAILABLE = True
except ImportError:
    TEXTUAL_AVAILABLE = False

if TEXTUAL_AVAILABLE:
    from .base import FriTapModal

    class SpawnInputModal(FriTapModal[Optional[str]]):
        """Modal for entering a package name or binary path to spawn."""

        DEFAULT_CSS = """
        SpawnInputModal > #modal-container {
            width: 60;
            height: auto;
            background: #0d1117;
            border: solid #1e3a5f;
            padding: 1 2;
        }
        SpawnInputModal #spawn-input {
            margin: 1 0;
        }
        """

        def compose(self) -> ComposeResult:
            with Vertical(id="modal-container"):
                yield Static("[bold #38bdf8]Spawn Application[/]", classes="modal-title")
                yield Static(
                    "[#8f9bb3]Enter a package name (e.g. com.example.app) "
                    "or path to binary (e.g. /usr/bin/curl)[/]"
                )
                yield Input(
                    placeholder="Package name or /path/to/binary...",
                    id="spawn-input",
                )
                yield Static(
                    "[#64748b]Enter: Spawn  |  Esc: Cancel[/]",
                    classes="key-hints",
                )
                with Horizontal(classes="button-row"):
                    yield Button("Spawn", id="btn-spawn", variant="primary")
                    yield Button("Cancel", id="btn-cancel", variant="default")

        def on_button_pressed(self, event: Button.Pressed) -> None:
            if event.button.id == "btn-spawn":
                self._submit()
            elif event.button.id == "btn-cancel":
                self.dismiss(None)

        def on_input_submitted(self, event: Input.Submitted) -> None:
            """Enter key submits the input."""
            self._submit()

        def _submit(self) -> None:
            """Dismiss with the input value."""
            spawn_input = self.query_one("#spawn-input", Input)
            value = spawn_input.value.strip()
            if value:
                self.dismiss(value)
            else:
                self.notify("Please enter a target to spawn.", severity="warning")
