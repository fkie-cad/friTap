#!/usr/bin/env python3

"""
Protocol selection modal for friTap TUI.

Presents available protocols and returns the selected protocol string,
or None if the user cancels. Builds the protocol list dynamically from
the ProtocolRegistry (the default registry when none is passed): registry
protocols are shown as "[N] DisplayName — description" (or "(plugin)" when
they have no description), and custom ciphers (RC4, ...) are grouped under a
single "Custom Encryption" entry.
"""

from __future__ import annotations

from typing import Optional

try:
    from textual.app import ComposeResult
    from textual.containers import Horizontal, Vertical
    from textual.widgets import Button, OptionList, Static
    from textual.widgets.option_list import Option
    TEXTUAL_AVAILABLE = True
except ImportError:
    TEXTUAL_AVAILABLE = False

if TEXTUAL_AVAILABLE:
    from friTap.tui.themes import c

    from .base import FriTapModal

    # User-visible built-in protocols (always PUBLIC; fixed order). Version-
    # specific or not-yet-announced ("upcoming") protocols are deliberately NOT
    # hardcoded here: they are surfaced via the ProtocolRegistry and filtered by
    # `handler.upcoming` in _build_entries(). So a protocol that is stripped from
    # this build (absent from the registry) or marked upcoming (e.g. a code-only
    # feature) never appears in the TUI — the picker stays in step with the build
    # and reveals nothing about a non-shipped protocol.
    _BUILTIN_PROTOCOLS = [
        ("tls", "TLS/SSL — TLS/SSL interception (default)"),
        ("ssh", "SSH — SSH session key extraction"),
        ("mtproto", "MTProto — Telegram key extraction (Android)"),
        ("telegram", "Telegram — MTProto + E2E key extraction (Android)"),
    ]

    # Auto-detect always last among built-ins
    _AUTO_ENTRY = ("auto", "Auto — Auto-detect from loaded libraries")

    def _registry_label(handler) -> str:
        """Menu label for a registry protocol: its description when it has one."""
        from .custom_cipher_modal import menu_label

        display_name = getattr(handler, "display_name", handler.name)
        return menu_label(
            display_name, getattr(handler, "description", ""), f"{display_name} (plugin)"
        )

    def _custom_encryption_entry(ciphers=None) -> Optional[tuple[str, str]]:
        """The grouped "Custom Encryption" entry, or None when no custom cipher
        is registered in this build. The individual ciphers are picked in the
        follow-up :class:`CustomCipherModal`, so the label names none of them.
        *ciphers* defaults to :func:`available_custom_ciphers`."""
        from friTap.protocols.registry import CUSTOM_GROUP

        if ciphers is None:
            from .custom_cipher_modal import available_custom_ciphers
            ciphers = available_custom_ciphers()
        if not ciphers:
            return None
        return (CUSTOM_GROUP, "Custom Encryption — custom cipher key extraction")

    class ProtocolSelectModal(FriTapModal[Optional[str]]):
        """Modal for selecting the target protocol."""

        DEFAULT_CSS = """
        ProtocolSelectModal > #modal-container {
            width: 65;
            height: auto;
            max-height: 70%;
            background: $fritap-bg-modal;
            border: solid $fritap-border-default;
            padding: 1 2;
        }
        ProtocolSelectModal #protocol-list {
            height: auto;
            max-height: 16;
            margin: 1 0;
            background: $surface;
        }
        """

        def __init__(
            self,
            registry=None,
            ciphers=None,
            **kwargs,
        ) -> None:
            super().__init__(**kwargs)
            self._protocol_entries: list[tuple[str, str]] = []
            if registry is None:
                from friTap.protocols.registry import create_default_registry
                registry = create_default_registry()
            self._build_entries(registry, ciphers)

        def _build_entries(self, registry, ciphers=None) -> None:
            """Build the protocol entry list from built-ins + registry."""
            self._protocol_entries = list(_BUILTIN_PROTOCOLS)

            # Add any further registered protocols (custom plugins, or future
            # built-ins that ship in this build). Hidden: anything already shown
            # as a built-in, and any "upcoming" (code-only) protocol whose handler
            # is registered but not yet meant to be user-visible (e.g. the full
            # build's not-yet-announced protocols). The public build simply has no
            # such handler registered, so this loop never sees it.
            if registry is not None:
                builtin_names = {name for name, _ in _BUILTIN_PROTOCOLS}
                builtin_names.add("auto")
                for handler in registry.get_all():
                    if handler.name in builtin_names:
                        continue
                    if getattr(handler, "upcoming", False):
                        continue
                    # Custom ciphers (e.g. RC4) are offered via the grouped
                    # "Custom Encryption" entry / follow-up modal, not standalone.
                    if getattr(handler, "category", "protocol") == "custom_cipher":
                        continue
                    self._protocol_entries.append((handler.name, _registry_label(handler)))

            custom_entry = _custom_encryption_entry(ciphers)
            if custom_entry is not None:
                self._protocol_entries.append(custom_entry)

            # Auto-detect always at the end
            self._protocol_entries.append(_AUTO_ENTRY)

        def compose(self) -> ComposeResult:
            options = [
                Option(f"[{idx + 1}] {label}")
                for idx, (_, label) in enumerate(self._protocol_entries)
            ]

            with Vertical(id="modal-container"):
                yield Static(
                    f"[bold {c('primary')}]Select Protocol[/]",
                    classes="modal-title",
                )
                yield OptionList(*options, id="protocol-list")
                yield Static(
                    f"[{c('text-muted')}]Enter: Select  |  Up/Down: Browse  |  Esc: Cancel[/]",
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
