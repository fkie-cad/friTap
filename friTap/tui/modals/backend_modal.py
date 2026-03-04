#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Backend selection modal for friTap TUI.

Presents available instrumentation backends (Frida, LLDB, GDB)
and returns the selected backend name, or None if the user cancels.
"""

from __future__ import annotations

try:
    from textual.app import ComposeResult
    from textual.screen import ModalScreen
    from textual.widgets import Button, Label
    from textual.containers import Vertical
    TEXTUAL_AVAILABLE = True
except ImportError:
    TEXTUAL_AVAILABLE = False

if TEXTUAL_AVAILABLE:

    class BackendSelectModal(ModalScreen[str | None]):
        """Modal to choose the instrumentation backend."""

        CSS = """
        BackendSelectModal {
            align: center middle;
        }
        #backend-dialog {
            width: 50;
            height: auto;
            max-height: 20;
            border: thick $primary;
            background: $surface;
            padding: 1 2;
        }
        #backend-title {
            text-align: center;
            text-style: bold;
            margin-bottom: 1;
        }
        .backend-btn {
            width: 100%;
            margin-bottom: 1;
        }
        #backend-cancel {
            width: 100%;
            margin-top: 1;
        }
        """

        BINDINGS = [("escape", "cancel", "Cancel")]

        def compose(self) -> ComposeResult:
            with Vertical(id="backend-dialog"):
                yield Label("Select Backend", id="backend-title")
                yield Button(
                    "Frida (default)",
                    id="btn-frida",
                    classes="backend-btn",
                    variant="primary",
                )
                yield Button(
                    "LLDB",
                    id="btn-lldb",
                    classes="backend-btn",
                )
                yield Button(
                    "GDB",
                    id="btn-gdb",
                    classes="backend-btn",
                )
                yield Button(
                    "Cancel",
                    id="backend-cancel",
                    variant="default",
                )

        def on_button_pressed(self, event: Button.Pressed) -> None:
            button_map = {
                "btn-frida": "frida",
                "btn-lldb": "lldb",
                "btn-gdb": "gdb",
                "backend-cancel": None,
            }
            result = button_map.get(event.button.id)
            self.dismiss(result)

        def action_cancel(self) -> None:
            self.dismiss(None)
