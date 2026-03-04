#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Base modal for friTap TUI dialogs.

Provides ESC to dismiss, Tab/Shift+Tab for focus navigation,
and Enter from Input to submit primary button.
"""

from __future__ import annotations

from typing import Generic, TypeVar

try:
    from textual.binding import Binding
    from textual.screen import ModalScreen
    from textual.widgets import Button, Input
    TEXTUAL_AVAILABLE = True
except ImportError:
    TEXTUAL_AVAILABLE = False

T = TypeVar("T")

if TEXTUAL_AVAILABLE:

    class FriTapModal(ModalScreen[T], Generic[T]):
        """Base modal screen with standard dismiss/focus behavior."""

        DEFAULT_CSS = """
        FriTapModal {
            align: center middle;
            background: rgba(5, 8, 17, 0.85);
        }

        FriTapModal > #modal-container {
            width: 70;
            height: auto;
            max-height: 80%;
            background: #0d1117;
            border: solid #1e3a5f;
            padding: 1 2;
        }

        FriTapModal .modal-title {
            text-align: center;
            text-style: bold;
            color: #38bdf8;
            margin-bottom: 1;
        }

        FriTapModal .button-row {
            height: 3;
            align: center middle;
            margin-top: 1;
        }

        FriTapModal Button {
            margin: 0 1;
        }

        FriTapModal .key-hints {
            text-align: center;
            color: #64748b;
            margin-top: 1;
            height: 1;
        }
        """

        BINDINGS = [
            Binding("escape", "cancel", "Cancel", show=True),
        ]

        def action_cancel(self) -> None:
            """Dismiss the modal with no result."""
            self.dismiss(None)

        def on_mount(self) -> None:
            """Auto-focus the first focusable widget."""
            self._auto_focus()

        def _auto_focus(self) -> None:
            """Focus the first Input or Button found."""
            try:
                self.query(Input).first().focus()
            except Exception:
                try:
                    self.query(Button).first().focus()
                except Exception:
                    pass

        def _find_primary_button(self) -> Button | None:
            """Return the primary button, or the first button if none is primary."""
            try:
                return self.query_one("Button.primary", Button)
            except Exception:
                pass
            try:
                return self.query_one(Button)
            except Exception:
                return None

        def on_input_submitted(self, event: Input.Submitted) -> None:
            """Enter in an Input triggers the primary button."""
            button = self._find_primary_button()
            if button is not None:
                button.press()
