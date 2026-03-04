#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Protocol selection modal for friTap TUI.

Presents available protocols and returns the selected protocol string,
or None if the user cancels. Builds the protocol list dynamically from
the ProtocolRegistry when provided, with custom protocol plugins
shown as "[N] DisplayName (plugin)".
"""

from __future__ import annotations

from typing import Optional

try:
    from textual.app import ComposeResult
    from textual.widgets import Button, OptionList, Static
    from textual.widgets.option_list import Option
    from textual.containers import Vertical, Horizontal
    TEXTUAL_AVAILABLE = True
except ImportError:
    TEXTUAL_AVAILABLE = False

if TEXTUAL_AVAILABLE:
    from .base import FriTapModal

    # Built-in protocols (always present, fixed order)
    _BUILTIN_PROTOCOLS = [
        ("tls", "TLS/SSL — Standard TLS/SSL interception (default)"),
        ("ipsec", "IPSec — IPSec/IKE key extraction"),
        ("ssh", "SSH — SSH session key extraction"),
    ]

    # Auto-detect always last among built-ins
    _AUTO_ENTRY = ("auto", "Auto — Auto-detect from loaded libraries")

    class ProtocolSelectModal(FriTapModal[Optional[str]]):
        """Modal for selecting the target protocol."""

        DEFAULT_CSS = """
        ProtocolSelectModal > #modal-container {
            width: 60;
            height: auto;
            max-height: 70%;
            background: #0d1117;
            border: solid #1e3a5f;
            padding: 1 2;
        }
        ProtocolSelectModal #protocol-list {
            height: auto;
            max-height: 16;
            margin: 1 0;
            background: #080c18;
        }
        """

        def __init__(
            self,
            registry=None,
            **kwargs,
        ) -> None:
            super().__init__(**kwargs)
            self._protocol_entries: list[tuple[str, str]] = []
            self._build_entries(registry)

        def _build_entries(self, registry) -> None:
            """Build the protocol entry list from built-ins + registry."""
            self._protocol_entries = list(_BUILTIN_PROTOCOLS)

            # Add custom protocols from registry (if any)
            if registry is not None:
                builtin_names = {name for name, _ in _BUILTIN_PROTOCOLS}
                builtin_names.add("auto")
                for handler in registry.get_all():
                    if handler.name not in builtin_names:
                        label = f"{handler.display_name} (plugin)"
                        self._protocol_entries.append((handler.name, label))

            # Auto-detect always at the end
            self._protocol_entries.append(_AUTO_ENTRY)

        def compose(self) -> ComposeResult:
            options = [
                Option(f"[{idx + 1}] {label}")
                for idx, (_, label) in enumerate(self._protocol_entries)
            ]

            with Vertical(id="modal-container"):
                yield Static(
                    "[bold #38bdf8]Select Protocol[/]",
                    classes="modal-title",
                )
                yield OptionList(*options, id="protocol-list")
                yield Static(
                    "[#64748b]Enter: Select  |  Up/Down: Browse  |  Esc: Cancel[/]",
                    classes="key-hints",
                )
                with Horizontal(classes="button-row"):
                    yield Button("Select", id="btn-select", variant="primary")
                    yield Button("Cancel", id="btn-cancel", variant="default")

        def _auto_focus(self) -> None:
            try:
                self.query_one("#protocol-list", OptionList).focus()
            except Exception:
                pass

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
            option_list = self.query_one("#protocol-list", OptionList)
            try:
                highlighted = option_list.highlighted
                if highlighted is not None and 0 <= highlighted < len(self._protocol_entries):
                    protocol_name = self._protocol_entries[highlighted][0]
                    self.dismiss(protocol_name)
                    return
            except Exception:
                pass
            self.dismiss(None)
