#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Alert modal for friTap TUI.

Dismissible dialog for warnings, errors, and informational messages.
"""

from __future__ import annotations

try:
    from textual.app import ComposeResult
    from textual.widgets import Button, Static
    from textual.containers import Vertical, Horizontal
    TEXTUAL_AVAILABLE = True
except ImportError:
    TEXTUAL_AVAILABLE = False

if TEXTUAL_AVAILABLE:
    from .base import FriTapModal

    class AlertModal(FriTapModal[None]):
        """Dismissible alert dialog for warnings and errors."""

        DEFAULT_CSS = """
        AlertModal > #modal-container {
            width: 60;
            height: auto;
            max-height: 50%;
            background: #0d1117;
            border: solid #1e3a5f;
            padding: 1 2;
        }
        AlertModal #alert-message {
            margin: 1 0;
            text-align: center;
        }
        """

        _SEVERITY_STYLES = {
            "warning": ("#fbbf24", "Warning"),
            "error": ("#ef4444", "Error"),
            "info": ("#38bdf8", "Info"),
        }

        def __init__(
            self,
            message: str,
            title: str = "",
            severity: str = "warning",
            **kwargs,
        ) -> None:
            super().__init__(**kwargs)
            self._message = message
            self._severity = severity
            color, default_title = self._SEVERITY_STYLES.get(
                severity, self._SEVERITY_STYLES["warning"]
            )
            self._title = title or default_title
            self._color = color

        def compose(self) -> ComposeResult:
            with Vertical(id="modal-container"):
                yield Static(
                    f"[bold {self._color}]{self._title}[/]",
                    classes="modal-title",
                )
                yield Static(self._message, id="alert-message")
                yield Static(
                    "[#64748b]Enter: Dismiss  |  Esc: Close[/]",
                    classes="key-hints",
                )
                with Horizontal(classes="button-row"):
                    yield Button("OK", id="btn-ok", variant="primary")

        def on_button_pressed(self, event: Button.Pressed) -> None:
            if event.button.id == "btn-ok":
                self.dismiss(None)
