#!/usr/bin/env python3

"""
Key-extraction-method modal for friTap TUI ("Key Extraction Method").

Lets the wizard user choose how secrets are recovered:

* **Intercepting** -- hook TLS/crypto functions (the default, and the only
  method before this step existed);
* **Memory scanning** -- recover secrets from process memory (``--memory-scan``).

Both may be selected; at least one must be. Capture modes that need the hooks
(plaintext / live Wireshark) lock Intercepting on.

Returns ``{"intercept": bool, "memory_scan": bool}``, or ``None`` when the user
presses Esc (back).

The selection logic lives in :class:`ExtractionMethodSelection`, which is
Textual-free so it can be unit-tested without a running app.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional


@dataclass
class ExtractionMethodSelection:
    """Pure toggle state for the extraction-method modal."""

    intercept: bool = True
    memory_scan: bool = False
    intercept_locked: bool = False

    def __post_init__(self) -> None:
        if self.intercept_locked:
            self.intercept = True

    def set_intercept(self, value: bool) -> None:
        """Toggle Intercepting; a locked Intercepting cannot be turned off."""
        if self.intercept_locked:
            return
        self.intercept = value

    def set_memory_scan(self, value: bool) -> None:
        self.memory_scan = value

    def is_valid(self) -> bool:
        """At least one method must be selected."""
        return self.intercept or self.memory_scan

    def result(self) -> Dict[str, bool]:
        return {"intercept": self.intercept, "memory_scan": self.memory_scan}


try:
    from textual.app import ComposeResult
    from textual.binding import Binding
    from textual.containers import Horizontal, Vertical
    from textual.widgets import Button, Label, Static, Switch
    TEXTUAL_AVAILABLE = True
except ImportError:
    TEXTUAL_AVAILABLE = False

if TEXTUAL_AVAILABLE:
    from friTap.tui.themes import c

    from .alert_modal import AlertModal
    from .base import FriTapModal

    _INTERCEPT_SWITCH_ID = "switch-intercept"
    _MEMORY_SCAN_SWITCH_ID = "switch-memory-scan"

    class ExtractionMethodModal(FriTapModal[Optional[Dict[str, bool]]]):
        """Modal for choosing intercepting and/or memory scanning."""

        BINDINGS = FriTapModal.BINDINGS + [
            Binding("enter", "confirm", "Confirm", priority=True),
            Binding("space", "toggle_focused", "Toggle", priority=True),
        ]

        DEFAULT_CSS = """
        ExtractionMethodModal > #modal-container {
            width: 70;
            height: auto;
            max-height: 90%;
            overflow-y: auto;
            background: $fritap-bg-modal;
            border: solid $fritap-border-default;
            padding: 1 2;
        }
        ExtractionMethodModal .key-hints {
            margin-top: 0;
        }
        ExtractionMethodModal #subtitle {
            text-align: center;
            color: $fritap-text-muted;
            margin-bottom: 1;
        }
        ExtractionMethodModal .method-row {
            height: 3;
            align: left middle;
        }
        ExtractionMethodModal .method-label {
            width: 1fr;
            color: $fritap-text-secondary;
        }
        """

        def __init__(
            self,
            intercept: bool = True,
            memory_scan: bool = False,
            intercept_locked: bool = False,
            **kwargs,
        ) -> None:
            super().__init__(**kwargs)
            self._selection = ExtractionMethodSelection(
                intercept=intercept,
                memory_scan=memory_scan,
                intercept_locked=intercept_locked,
            )

        def _method_label(self, name: str, description: str) -> str:
            return f"[bold]{name}[/]\n[{c('text-muted')}]{description}[/]"

        def compose(self) -> ComposeResult:
            intercept_description = (
                "hook TLS/crypto functions (required by this capture mode)"
                if self._selection.intercept_locked else
                "hook TLS/crypto functions (default)"
            )
            with Vertical(id="modal-container"):
                yield Static(
                    f"[bold {c('primary')}]Key Extraction Method[/]",
                    classes="modal-title",
                )
                yield Static("Choose how secrets are recovered (one or both).", id="subtitle")
                with Horizontal(classes="method-row"):
                    yield Label(
                        self._method_label("Intercepting", intercept_description),
                        classes="method-label",
                    )
                    yield Switch(
                        value=self._selection.intercept,
                        id=_INTERCEPT_SWITCH_ID,
                        disabled=self._selection.intercept_locked,
                    )
                with Horizontal(classes="method-row"):
                    yield Label(
                        self._method_label(
                            "Memory scanning", "recover secrets from process memory"
                        ),
                        classes="method-label",
                    )
                    yield Switch(value=self._selection.memory_scan, id=_MEMORY_SCAN_SWITCH_ID)
                yield Static(
                    f"[{c('text-muted')}]Space: Toggle  |  Enter: Confirm  |  Esc: Back[/]",
                    classes="key-hints",
                )
                with Horizontal(classes="button-row"):
                    yield Button("Confirm", id="btn-confirm", variant="primary")
                    yield Button("Back", id="btn-back", variant="default")

        def _auto_focus(self) -> None:
            """Focus the first enabled switch so Space toggles right away."""
            for switch in self.query(Switch):
                if not switch.disabled:
                    switch.focus()
                    return

        # -- selection handling -------------------------------------------

        def on_switch_changed(self, event: Switch.Changed) -> None:
            if event.switch.id == _INTERCEPT_SWITCH_ID:
                self._selection.set_intercept(event.value)
            elif event.switch.id == _MEMORY_SCAN_SWITCH_ID:
                self._selection.set_memory_scan(event.value)

        def action_toggle_focused(self) -> None:
            focused = self.focused
            if isinstance(focused, Switch):
                focused.toggle()
            elif isinstance(focused, Button):
                focused.press()

        # -- confirm / back -------------------------------------------------

        def on_button_pressed(self, event: Button.Pressed) -> None:
            if event.button.id == "btn-confirm":
                self._confirm()
            elif event.button.id == "btn-back":
                self.dismiss(None)

        def action_confirm(self) -> None:
            focused = self.focused
            if isinstance(focused, Button):
                focused.press()
                return
            self._confirm()

        def _confirm(self) -> None:
            if not self._selection.is_valid():
                self.app.push_screen(
                    AlertModal(
                        message="Select at least one method (or press Esc to go back).",
                        title="Key Extraction Method",
                        severity="warning",
                    )
                )
                return
            self.dismiss(self._selection.result())
