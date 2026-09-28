#!/usr/bin/env python3

"""
Custom-cipher selection modal for friTap TUI ("Custom Encryption").

Shows an "All supported custom ciphers" switch followed by one switch per
registered custom cipher (handlers with ``category ==
"custom_cipher"``, e.g. RC4). Selection semantics ("option B"):

* checking a cipher row switches "All" off — only the checked rows are used;
* re-checking "All" clears every cipher row;
* "All" off with no row checked means no custom cipher.

The "All" switch starts on only with ``required=True``. In the optional
follow-up (after picking TLS/SSH/...) it starts off, so pressing Enter without
toggling anything is the same as Skip.

Returns a ``list[str]`` of cipher names ("All" expands to every registered
cipher), ``[]`` for Skip / nothing selected, or ``None`` when the user presses
Esc (back). With ``required=True`` (opened from the "Custom Encryption" entry)
there is no Skip button and confirming with nothing selected only warns.

The selection logic lives in :class:`CipherSelection`, which is Textual-free so
it can be unit-tested without a running app.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, NamedTuple, Optional, Set


class CustomCipherEntry(NamedTuple):
    """One selectable custom cipher (from the protocol registry)."""

    name: str
    display_name: str
    description: str


def menu_label(display_name: str, description: str, fallback: Optional[str] = None) -> str:
    """Menu label ``"Name — description"``; without a description, *fallback*
    (or just the name when no fallback is given)."""
    if description:
        return f"{display_name} — {description}"
    return fallback if fallback is not None else display_name


def available_custom_ciphers() -> List[CustomCipherEntry]:
    """Return the registered custom ciphers in :func:`custom_cipher_names` order.

    Empty when this build registers no custom cipher.
    """
    from friTap.protocols.registry import custom_cipher_handlers

    return [
        CustomCipherEntry(
            name=handler.name,
            display_name=getattr(handler, "display_name", handler.name),
            description=getattr(handler, "description", ""),
        )
        for handler in custom_cipher_handlers()
    ]


@dataclass
class CipherSelection:
    """Pure option-B toggle state for the custom-cipher modal."""

    ciphers: List[str]
    all_selected: bool = True
    checked: Set[str] = field(default_factory=set)

    def set_all(self, value: bool) -> None:
        """Toggle "All"; turning it on clears every individual cipher row."""
        self.all_selected = value
        if value:
            self.checked.clear()

    def set_cipher(self, name: str, value: bool) -> None:
        """Toggle one cipher row; checking a row turns "All" off."""
        if value:
            self.checked.add(name)
            self.all_selected = False
        else:
            self.checked.discard(name)

    def is_checked(self, name: str) -> bool:
        return name in self.checked

    def result(self) -> List[str]:
        """Selected cipher names in registry order ([] when nothing is selected)."""
        if self.all_selected:
            return list(self.ciphers)
        return [name for name in self.ciphers if name in self.checked]


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

    _ALL_SWITCH_ID = "switch-all"
    _CIPHER_SWITCH_PREFIX = "switch-cipher-"

    class CustomCipherModal(FriTapModal[Optional[List[str]]]):
        """Modal for selecting custom-cipher key extraction (RC4, ...)."""

        BINDINGS = FriTapModal.BINDINGS + [
            Binding("enter", "confirm", "Confirm", priority=True),
            Binding("space", "toggle_focused", "Toggle", priority=True),
        ]

        DEFAULT_CSS = """
        CustomCipherModal > #modal-container {
            width: 70;
            height: auto;
            max-height: 90%;
            overflow-y: auto;
            background: $fritap-bg-modal;
            border: solid $fritap-border-default;
            padding: 1 2;
        }
        CustomCipherModal .key-hints {
            margin-top: 0;
        }
        CustomCipherModal #subtitle {
            text-align: center;
            color: $fritap-text-muted;
            margin-bottom: 1;
        }
        CustomCipherModal .cipher-row {
            height: 3;
            align: left middle;
        }
        CustomCipherModal .cipher-label {
            width: 1fr;
            color: $fritap-text-secondary;
        }
        CustomCipherModal .cipher-row.-dimmed {
            opacity: 50%;
        }
        CustomCipherModal .cipher-separator {
            color: $fritap-text-muted;
            height: 1;
        }
        """

        def __init__(
            self,
            required: bool = False,
            ciphers: Optional[List[CustomCipherEntry]] = None,
            **kwargs,
        ) -> None:
            super().__init__(**kwargs)
            self._required = required
            self._entries = list(ciphers) if ciphers is not None else available_custom_ciphers()
            self._selection = CipherSelection(
                [entry.name for entry in self._entries],
                all_selected=required,
            )

        def compose(self) -> ComposeResult:
            subtitle = (
                "Select the custom ciphers to extract keys for."
                if self._required else
                "Optionally also extract keys of custom ciphers (or Skip)."
            )
            with Vertical(id="modal-container"):
                yield Static(
                    f"[bold {c('primary')}]Custom Encryption[/]",
                    classes="modal-title",
                )
                yield Static(subtitle, id="subtitle")
                with Horizontal(classes="cipher-row"):
                    yield Label("All supported custom ciphers", classes="cipher-label")
                    yield Switch(value=self._selection.all_selected, id=_ALL_SWITCH_ID)
                yield Static("─" * 60, classes="cipher-separator")
                for entry in self._entries:
                    row_classes = "cipher-row -dimmed" if self._selection.all_selected else "cipher-row"
                    with Horizontal(classes=row_classes, id=f"row-{entry.name}"):
                        yield Label(menu_label(entry.display_name, entry.description), classes="cipher-label")
                        yield Switch(value=False, id=f"{_CIPHER_SWITCH_PREFIX}{entry.name}")
                yield Static(
                    f"[{c('text-muted')}]Space: Toggle  |  Enter: Confirm  |  Esc: Back[/]",
                    classes="key-hints",
                )
                with Horizontal(classes="button-row"):
                    yield Button("Confirm", id="btn-confirm", variant="primary")
                    if not self._required:
                        yield Button("Skip", id="btn-skip", variant="default")

        def _auto_focus(self) -> None:
            try:
                self.query_one(f"#{_ALL_SWITCH_ID}", Switch).focus()
            except Exception:
                pass

        # -- selection handling -------------------------------------------

        def on_switch_changed(self, event: Switch.Changed) -> None:
            switch_id = event.switch.id or ""
            if switch_id == _ALL_SWITCH_ID:
                self._selection.set_all(event.value)
            elif switch_id.startswith(_CIPHER_SWITCH_PREFIX):
                self._selection.set_cipher(switch_id[len(_CIPHER_SWITCH_PREFIX):], event.value)
            else:
                return
            self._sync_switches()

        def _sync_switches(self) -> None:
            """Reflect the selection state in the widgets without re-triggering events."""
            with self.prevent(Switch.Changed):
                self.query_one(f"#{_ALL_SWITCH_ID}", Switch).value = self._selection.all_selected
                for entry in self._entries:
                    switch = self.query_one(f"#{_CIPHER_SWITCH_PREFIX}{entry.name}", Switch)
                    switch.value = self._selection.is_checked(entry.name)
                    row = self.query_one(f"#row-{entry.name}", Horizontal)
                    row.set_class(self._selection.all_selected, "-dimmed")

        def action_toggle_focused(self) -> None:
            focused = self.focused
            if isinstance(focused, Switch):
                focused.toggle()
            elif isinstance(focused, Button):
                focused.press()

        # -- confirm / skip -------------------------------------------------

        def on_button_pressed(self, event: Button.Pressed) -> None:
            if event.button.id == "btn-confirm":
                self._confirm()
            elif event.button.id == "btn-skip":
                self.dismiss([])

        def action_confirm(self) -> None:
            focused = self.focused
            if isinstance(focused, Button):
                focused.press()
                return
            self._confirm()

        def _confirm(self) -> None:
            selected = self._selection.result()
            if self._required and not selected:
                self.app.push_screen(
                    AlertModal(
                        message="Select at least one custom cipher (or press Esc to go back).",
                        title="Custom Encryption",
                        severity="warning",
                    )
                )
                return
            self.dismiss(selected)
