#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Save .tap file modal dialog."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Optional

try:
    from textual.widgets import Static, Button, Input
    from textual.containers import Horizontal, Vertical
    TEXTUAL_AVAILABLE = True
except ImportError:
    TEXTUAL_AVAILABLE = False

if TEXTUAL_AVAILABLE:
    from .base import FriTapModal
    from ..themes import c

    class SaveTapModal(FriTapModal[Optional[str]]):
        """Modal dialog to choose a filename for saving a .tap capture file."""

        def __init__(self, suggested_name: str = "", **kwargs) -> None:
            super().__init__(**kwargs)
            if not suggested_name:
                ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                suggested_name = f"capture_{ts}.tap"
            self._suggested_name = suggested_name

        def compose(self):
            with Vertical(id="modal-container"):
                yield Static(
                    f"[bold {c('primary')}]Save Capture[/]",
                    classes="modal-title",
                )
                yield Static(
                    f"[{c('text-dim')}]Save the current flow capture to a .tap file.\n"
                    f"You can replay it later with: fritap -r <file>[/]",
                )
                yield Input(
                    value=self._suggested_name,
                    placeholder="capture.tap",
                    id="tap-path-input",
                )
                yield Static(
                    f"[{c('text-muted')}]Enter: Save  |  Esc: Cancel[/]",
                    classes="key-hints",
                )
                with Horizontal(classes="button-row"):
                    yield Button("Save", id="btn-save", variant="primary")
                    yield Button("Cancel", id="btn-cancel", variant="default")

        def on_button_pressed(self, event: Button.Pressed) -> None:
            if event.button.id == "btn-save":
                self._submit()
            elif event.button.id == "btn-cancel":
                self.dismiss(None)

        def _submit(self) -> None:
            value = self.query_one("#tap-path-input", Input).value.strip()
            if not value:
                self.notify("Please enter a file name.", severity="warning")
                return

            # Ensure .tap extension
            path = Path(value)
            if path.suffix != ".tap":
                path = path.with_suffix(".tap")

            self.dismiss(str(path))
