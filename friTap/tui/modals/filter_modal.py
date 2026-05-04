#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Display filter modal for friTap TUI.

Provides a Wireshark-style display filter dialog with a text input field,
toggle buttons for common filters, and real-time validation feedback.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

try:
    from textual.app import ComposeResult
    from textual.binding import Binding
    from textual.containers import Horizontal, Vertical
    from textual.timer import Timer
    from textual.widgets import Button, Input, Static
    TEXTUAL_AVAILABLE = True
except ImportError:
    TEXTUAL_AVAILABLE = False


@dataclass
class FilterResult:
    """Result returned when the filter modal is dismissed with Apply or Clear."""

    text: str
    text_engine: Any  # FilterEngine | None
    toggle_engine: Any  # FilterEngine | None
    active_toggles: set[str] = field(default_factory=set)


if TEXTUAL_AVAILABLE:
    from friTap.tui.themes import c
    from .base import FriTapModal

    class FilterModal(FriTapModal[Optional[FilterResult]]):
        """Modal dialog for configuring display filters and toggle buttons."""

        # Toggle definitions: (button_id, label, filter_expression)
        TOGGLES: list[tuple[str, str, str]] = [
            ("toggle-http", "HTTP", 'frame.protocol != "unknown"'),
            ("toggle-errors", "Errors", "http.response.code >= 400"),
            ("toggle-ohttp", "OHTTP", "ohttp.present"),
            ("toggle-ipsec", "IPSec", 'frame.protocol == "ipsec"'),
            ("toggle-ssh", "SSH", 'frame.protocol == "ssh"'),
        ]

        DEFAULT_CSS = """
        FilterModal > #modal-container {
            width: 80;
            height: auto;
            max-height: 85%;
        }
        FilterModal #filter-input {
            margin: 1 0;
        }
        FilterModal #filter-input.valid {
            border: tall $success;
        }
        FilterModal #filter-input.invalid {
            border: tall $error;
        }
        FilterModal #filter-status {
            height: 1;
            margin: 0 0 1 0;
        }
        FilterModal #toggle-row {
            height: 1;
            margin: 0 0 1 0;
        }
        FilterModal .filter-toggle {
            min-width: 8;
            height: 1;
            margin: 0 1 0 0;
        }
        FilterModal .filter-toggle.active {
            background: $accent;
            text-style: bold;
        }
        """

        BINDINGS = [
            Binding("escape", "cancel", "Cancel", show=True),
            Binding("f1", "show_help", "Help", show=False),
        ]

        def __init__(
            self,
            current_text: str = "",
            active_toggles: set[str] | None = None,
            **kwargs,
        ) -> None:
            super().__init__(**kwargs)
            self._current_text = current_text
            self._active_toggles: set[str] = set(active_toggles) if active_toggles else set()
            self._text_engine: Any = None  # FilterEngine | None
            self._toggle_engine: Any = None  # FilterEngine | None
            self._debounce_timer: Timer | None = None

        def compose(self) -> ComposeResult:
            with Vertical(id="modal-container"):
                yield Static(
                    f"[bold {c('primary')}]Display Filter[/]",
                    classes="modal-title",
                )
                yield Input(
                    placeholder='e.g., http.response.code >= 400',
                    id="filter-input",
                )
                yield Static("", id="filter-status")
                with Horizontal(id="toggle-row"):
                    for btn_id, label, _ in self.TOGGLES:
                        yield Button(label, id=btn_id, classes="filter-toggle")
                yield Static(
                    f"[{c('text-muted')}]Enter: Apply  |  F1/?: Help  |  Esc: Cancel[/]",
                    classes="key-hints",
                )
                with Horizontal(classes="button-row"):
                    yield Button("Apply", id="btn-apply", variant="primary")
                    yield Button("Clear", id="btn-clear", variant="default")
                    yield Button("?", id="btn-help", variant="default")
                    yield Button("Cancel", id="btn-cancel", variant="default")

        def on_mount(self) -> None:
            """Restore previous filter state on mount."""
            inp = self.query_one("#filter-input", Input)
            if self._current_text:
                inp.value = self._current_text
            # Activate previously active toggle buttons
            for tid in self._active_toggles:
                try:
                    btn = self.query_one(f"#{tid}", Button)
                    btn.add_class("active")
                except Exception:
                    pass
            # Rebuild the toggle engine from restored state
            if self._active_toggles:
                self._rebuild_toggle_engine()
            inp.focus()

        # -- Input handling ---------------------------------------------------

        def on_input_changed(self, event: Input.Changed) -> None:
            """Debounce filter input -- lenient validation after 250ms."""
            if event.input.id != "filter-input":
                return
            if self._debounce_timer is not None:
                self._debounce_timer.stop()
            self._debounce_timer = self.set_timer(0.25, self._validate_lenient)

        def on_input_submitted(self, event: Input.Submitted) -> None:
            """Strict validation and apply on Enter."""
            if event.input.id != "filter-input":
                return
            # Prevent the base class from pressing the primary button --
            # we handle Enter ourselves with strict validation.
            event.prevent_default()
            event.stop()
            if self._debounce_timer is not None:
                self._debounce_timer.stop()
                self._debounce_timer = None
            self._apply_strict()

        def _validate_lenient(self) -> None:
            """Run lenient validation on the current input text."""
            from friTap.filter import FilterEngine

            self._debounce_timer = None
            inp = self.query_one("#filter-input", Input)
            status = self.query_one("#filter-status", Static)
            text = inp.value.strip()

            if not text:
                self._text_engine = None
                inp.remove_class("valid", "invalid")
                status.update("")
                return

            result = FilterEngine.try_create_lenient(text)
            if result is None:
                # Incomplete but plausible input
                self._text_engine = None
                inp.remove_class("valid", "invalid")
                status.update(f"[dim]typing...[/]")
            elif isinstance(result, str):
                # Error
                self._text_engine = None
                inp.remove_class("valid")
                inp.add_class("invalid")
                msg = result if len(result) <= 60 else result[:57] + "..."
                status.update(f"[red]{msg}[/]")
            else:
                # Valid engine
                self._text_engine = result
                inp.remove_class("invalid")
                inp.add_class("valid")
                status.update(f"[{c('success')}]valid[/]")

        def _apply_strict(self) -> None:
            """Strict validation and dismiss with result on success."""
            from friTap.filter import FilterEngine

            inp = self.query_one("#filter-input", Input)
            status = self.query_one("#filter-status", Static)
            text = inp.value.strip()

            if not text:
                # Empty text filter is valid -- dismiss with current toggles
                self._text_engine = None
                status.update(f"[dim]Applying...[/]")
                self._dismiss_with_result()
                return

            result = FilterEngine.try_create(text)
            if isinstance(result, str):
                # Validation error
                self._text_engine = None
                inp.remove_class("valid")
                inp.add_class("invalid")
                msg = result if len(result) <= 60 else result[:57] + "..."
                status.update(f"[red]{msg}[/]")
                return

            # Valid engine
            self._text_engine = result
            inp.remove_class("invalid")
            inp.add_class("valid")
            status.update(f"[dim]Applying...[/]")
            self._dismiss_with_result()

        # -- Toggle handling --------------------------------------------------

        def on_button_pressed(self, event: Button.Pressed) -> None:
            btn_id = event.button.id

            if btn_id == "btn-apply":
                self._apply_strict()
                return

            if btn_id == "btn-clear":
                self._clear_all()
                return

            if btn_id == "btn-help":
                self._push_help()
                return

            if btn_id == "btn-cancel":
                self.dismiss(None)
                return

            # Check if it's a toggle button
            is_toggle = any(tid == btn_id for tid, _, _ in self.TOGGLES)
            if not is_toggle:
                return

            # Toggle the button state
            if btn_id in self._active_toggles:
                self._active_toggles.discard(btn_id)
                event.button.remove_class("active")
            else:
                self._active_toggles.add(btn_id)
                event.button.add_class("active")

            self._rebuild_toggle_engine()

        def _rebuild_toggle_engine(self) -> None:
            """Build a combined FilterEngine from all active toggles."""
            from friTap.filter import FilterEngine

            if not self._active_toggles:
                self._toggle_engine = None
                return

            exprs: list[str] = []
            for tid, _, expr in self.TOGGLES:
                if tid in self._active_toggles:
                    exprs.append(f"({expr})")

            if not exprs:
                self._toggle_engine = None
                return

            combined = " and ".join(exprs)
            try:
                self._toggle_engine = FilterEngine(combined)
            except Exception:
                self._toggle_engine = None

        # -- Clear / Help / Dismiss -------------------------------------------

        def _clear_all(self) -> None:
            """Clear input and all toggles, then dismiss with empty result."""
            inp = self.query_one("#filter-input", Input)
            inp.value = ""
            inp.remove_class("valid", "invalid")

            for tid, _, _ in self.TOGGLES:
                try:
                    btn = self.query_one(f"#{tid}", Button)
                    btn.remove_class("active")
                except Exception:
                    pass

            self._active_toggles.clear()
            self._text_engine = None
            self._toggle_engine = None

            self.dismiss(FilterResult(
                text="",
                text_engine=None,
                toggle_engine=None,
                active_toggles=set(),
            ))

        def action_show_help(self) -> None:
            """Show the filter help modal (F1 binding)."""
            self._push_help()

        def _push_help(self) -> None:
            """Push the filter help modal screen."""
            from .filter_help_modal import FilterHelpScreen
            self.app.push_screen(FilterHelpScreen())

        def _dismiss_with_result(self) -> None:
            """Dismiss the modal with the current filter state."""
            inp = self.query_one("#filter-input", Input)
            self.dismiss(FilterResult(
                text=inp.value.strip(),
                text_engine=self._text_engine,
                toggle_engine=self._toggle_engine,
                active_toggles=set(self._active_toggles),
            ))
