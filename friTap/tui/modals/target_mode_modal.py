#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Target mode selection modal for friTap TUI.

Allows the user to choose between attaching to a running process
or spawning a new application with friTap hooks.
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
    from .base import FriTapModal

    _MODE_MAP: dict[int, str] = {
        0: "attach",
        1: "spawn",
    }

    class TargetModeModal(FriTapModal[Optional[str]]):
        """Modal for selecting the target mode (attach or spawn)."""

        DEFAULT_CSS = """
        TargetModeModal > #modal-container {
            width: 70;
            max-height: 80%;
            background: #0d1117;
            border: solid #1e3a5f;
            padding: 1 2;
        }
        TargetModeModal #target-list {
            height: 6;
            margin: 1 0;
            background: #080c18;
        }
        """

        BINDINGS = [
            Binding("a", "select_attach", "Attach", show=True),
            Binding("s", "select_spawn", "Spawn", show=True),
        ]

        def compose(self) -> ComposeResult:
            with Vertical(id="modal-container"):
                yield Static(
                    "[bold #38bdf8]Select Target Mode[/]",
                    classes="modal-title",
                )
                yield OptionList(
                    Option(
                        "Attach to running process",
                        id="attach",
                    ),
                    Option(
                        "Spawn new application",
                        id="spawn",
                    ),
                    id="target-list",
                )
                yield Static(
                    "[#64748b]Enter: Select  |  a: Attach  |  s: Spawn  |  Esc: Cancel[/]",
                    classes="key-hints",
                )
                with Horizontal(classes="button-row"):
                    yield Button("Select", id="btn-select", variant="primary")
                    yield Button("Cancel", id="btn-cancel", variant="default")

        def _auto_focus(self) -> None:
            """Override base to focus the target list."""
            try:
                self.query_one("#target-list", OptionList).focus()
            except Exception:
                pass

        def action_select_attach(self) -> None:
            """Shortcut: select attach mode."""
            self.dismiss("attach")

        def action_select_spawn(self) -> None:
            """Shortcut: select spawn mode."""
            self.dismiss("spawn")

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
            """Dismiss with the currently highlighted target mode."""
            option_list = self.query_one("#target-list", OptionList)
            try:
                highlighted = option_list.highlighted
                if highlighted is not None and highlighted in _MODE_MAP:
                    self.dismiss(_MODE_MAP[highlighted])
                    return
            except Exception:
                pass
            self.dismiss(None)
