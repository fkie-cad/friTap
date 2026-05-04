#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
View mode selection modal for friTap TUI.

Presents display mode options (Legacy View vs Flow View) and returns
the selected mode string, or None if the user cancels.
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

    _VIEW_MODES = [
        ("legacy", "Legacy View \u2014 Classic console log output"),
        ("flow", "Flow View \u2014 Interactive flow list"),
    ]

    class ViewModeModal(FriTapModal[Optional[str]]):
        """Modal for selecting the display mode."""

        DEFAULT_CSS = """
        ViewModeModal > #modal-container {
            width: 60;
            height: auto;
            max-height: 70%;
            background: $fritap-bg-modal;
            border: solid $fritap-border-default;
            padding: 1 2;
        }
        ViewModeModal #view-mode-list {
            height: auto;
            max-height: 10;
            margin: 1 0;
            background: $surface;
        }
        """

        BINDINGS = [
            Binding("escape", "cancel", "Cancel", show=True),
            Binding("1", "select_1", "Legacy View", show=False),
            Binding("2", "select_2", "Flow View", show=False),
        ]

        def compose(self) -> ComposeResult:
            options = [
                Option(f"[{idx + 1}] {label}")
                for idx, (_, label) in enumerate(_VIEW_MODES)
            ]

            with Vertical(id="modal-container"):
                yield Static(
                    f"[bold {c('primary')}]Select Display Mode[/]",
                    classes="modal-title",
                )
                yield OptionList(*options, id="view-mode-list")
                yield Static(
                    f"[{c('text-muted')}]1/2: Quick select  |  Enter: Select  |  Esc: Cancel[/]",
                    classes="key-hints",
                )
                with Horizontal(classes="button-row"):
                    yield Button("Select", id="btn-select", variant="primary")
                    yield Button("Cancel", id="btn-cancel", variant="default")

        def _auto_focus(self) -> None:
            try:
                self.query_one("#view-mode-list", OptionList).focus()
            except Exception:
                pass

        def action_select_1(self) -> None:
            """Quick-select Legacy View."""
            self.dismiss("legacy")

        def action_select_2(self) -> None:
            """Quick-select Flow View."""
            self.dismiss("flow")

        def on_option_list_option_selected(
            self, event: OptionList.OptionSelected
        ) -> None:
            self._select_highlighted()

        def on_button_pressed(self, event: Button.Pressed) -> None:
            if event.button.id == "btn-select":
                self._select_highlighted()
            elif event.button.id == "btn-cancel":
                self.dismiss(None)

        def _select_highlighted(self) -> None:
            option_list = self.query_one("#view-mode-list", OptionList)
            try:
                highlighted = option_list.highlighted
                if highlighted is not None and 0 <= highlighted < len(_VIEW_MODES):
                    mode_name = _VIEW_MODES[highlighted][0]
                    self.dismiss(mode_name)
                    return
            except Exception:
                pass
            self.dismiss(None)
