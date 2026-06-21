#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Open-pcap modal for friTap TUI.

Lets the user open an existing pcap together with one or more keylog files
and decrypt them into a layered flow view. Returns a dict of paths/options,
or None if the user cancels.
"""

from __future__ import annotations

from typing import Optional

try:
    from textual.app import ComposeResult
    from textual.widgets import Button, Input, Static
    from textual.containers import Vertical, Horizontal
    TEXTUAL_AVAILABLE = True
except ImportError:
    TEXTUAL_AVAILABLE = False

if TEXTUAL_AVAILABLE:
    from friTap.tui.themes import c
    from .base import FriTapModal

    class OpenPcapModal(FriTapModal[Optional[dict]]):
        """Modal for selecting a pcap + keylog files to decrypt offline."""

        DEFAULT_CSS = """
        OpenPcapModal > #modal-container {
            width: 70;
            height: auto;
            max-height: 80%;
            background: $fritap-bg-modal;
            border: solid $fritap-border-default;
            padding: 1 2;
        }
        OpenPcapModal .path-label {
            margin-top: 1;
            color: $fritap-text-secondary;
        }
        OpenPcapModal .modal-description {
            margin: 1 0;
            color: $fritap-text-dim;
            text-align: center;
        }
        OpenPcapModal Input {
            margin-bottom: 1;
        }
        """

        def __init__(
            self,
            default_pcap: str = "",
            default_keylog: str = "",
            default_protocol: str = "tls",
            **kwargs,
        ) -> None:
            super().__init__(**kwargs)
            self._default_pcap = default_pcap
            self._default_keylog = default_keylog
            self._default_protocol = default_protocol or "tls"
            self._proto_names = self._discover_protocol_names()

        def _discover_protocol_names(self) -> list[str]:
            """Names of friTap-owned offline decryptors (signal, mtproto, ...)."""
            try:
                from friTap.offline.registry import get_offline_decryptor_registry
                return get_offline_decryptor_registry().names()
            except Exception:
                return []

        def compose(self) -> ComposeResult:
            extra = ", ".join(self._proto_names)
            valid = "tls" + (", " + extra if extra else "")
            with Vertical(id="modal-container"):
                yield Static(
                    f"[bold {c('primary')}]Open PCAP & Decrypt[/]",
                    classes="modal-title",
                )
                yield Static(
                    "Decrypt an existing pcap with keylog files into a "
                    "layered flow view.",
                    classes="modal-description",
                )

                yield Static(f"[{c('text-secondary')}]PCAP file:[/]", classes="path-label")
                yield Input(
                    value=self._default_pcap,
                    placeholder="Path to .pcap or .pcapng...",
                    id="pcap-input",
                )

                yield Static(f"[{c('text-secondary')}]TLS key log file:[/]", classes="path-label")
                yield Input(
                    value=self._default_keylog,
                    placeholder="Path to TLS keylog (SSLKEYLOGFILE format)...",
                    id="keylog-input",
                )

                yield Static(
                    f"[{c('text-secondary')}]Per-protocol key log (optional):[/]",
                    classes="path-label",
                )
                yield Input(
                    value="",
                    placeholder="Path to e.g. Signal/MTProto keylog (optional)...",
                    id="proto-keylog-input",
                )

                yield Static(
                    f"[{c('text-secondary')}]Protocol (valid: {valid}):[/]",
                    classes="path-label",
                )
                yield Input(
                    value=self._default_protocol,
                    placeholder="tls",
                    id="protocol-input",
                )

                yield Static(
                    f"[{c('text-secondary')}]Output .tap file (optional):[/]",
                    classes="path-label",
                )
                yield Input(
                    value="",
                    placeholder="Defaults to <pcap stem>.tap...",
                    id="tap-input",
                )

                yield Static(
                    f"[{c('text-muted')}]Enter: Accept  |  Tab: Edit fields  |  Esc: Cancel[/]",
                    classes="key-hints",
                )
                with Horizontal(classes="button-row"):
                    yield Button("Accept", id="btn-accept", variant="primary")
                    yield Button("Cancel", id="btn-cancel", variant="default")

        def _auto_focus(self) -> None:
            try:
                self.query_one("#pcap-input", Input).focus()
            except Exception:
                pass

        def on_button_pressed(self, event: Button.Pressed) -> None:
            if event.button.id == "btn-accept":
                self._submit()
            elif event.button.id == "btn-cancel":
                self.dismiss(None)

        def _value(self, widget_id: str) -> str:
            try:
                return self.query_one(widget_id, Input).value.strip()
            except Exception:
                return ""

        def _submit(self) -> None:
            """Collect input values and dismiss with a result dict."""
            pcap = self._value("#pcap-input")
            if not pcap:
                # Nothing to decrypt without a pcap — keep the modal open.
                try:
                    self.query_one("#pcap-input", Input).focus()
                except Exception:
                    pass
                return
            result = {
                "pcap": pcap,
                "keylog": self._value("#keylog-input"),
                "proto_keylog": self._value("#proto-keylog-input"),
                "protocol": self._value("#protocol-input") or "tls",
                "tap": self._value("#tap-input"),
            }
            self.dismiss(result)
