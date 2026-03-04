#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Capture mode configuration modal for friTap TUI.

Shown when the user presses 1-4 to select a capture mode.
Displays mode info and editable output paths.
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
    from .base import FriTapModal

    _MODE_DESCRIPTIONS = {
        "full": "Capture TLS keys and write a PCAP file with decrypted traffic.",
        "keys": "Extract TLS session keys only (no traffic capture).",
        "plaintext": "Write decrypted plaintext traffic to a PCAP file.",
        "wireshark": "Stream decrypted traffic live to Wireshark via named pipe.",
        "live_pcapng": "Stream PCAPNG with embedded decryption keys directly to Wireshark.",
    }

    class CaptureModeModal(FriTapModal[Optional[dict]]):
        """Modal for configuring capture mode output paths."""

        DEFAULT_CSS = """
        CaptureModeModal > #modal-container {
            width: 65;
            height: auto;
            max-height: 70%;
            background: #0d1117;
            border: solid #1e3a5f;
            padding: 1 2;
        }
        CaptureModeModal .path-label {
            margin-top: 1;
            color: #94a3b8;
        }
        CaptureModeModal .mode-description {
            margin: 1 0;
            color: #8f9bb3;
            text-align: center;
        }
        CaptureModeModal Input {
            margin-bottom: 1;
        }
        """

        def __init__(
            self,
            mode_id: str,
            mode_display: str,
            default_keylog: str = "",
            default_pcap: str = "",
            is_live: bool = False,
            **kwargs,
        ) -> None:
            super().__init__(**kwargs)
            self._mode_id = mode_id
            self._mode_display = mode_display
            self._default_keylog = default_keylog
            self._default_pcap = default_pcap
            self._is_live = is_live

        def compose(self) -> ComposeResult:
            description = _MODE_DESCRIPTIONS.get(self._mode_id, "")
            with Vertical(id="modal-container"):
                yield Static(
                    f"[bold #38bdf8]Configure: {self._mode_display}[/]",
                    classes="modal-title",
                )
                if description:
                    yield Static(description, classes="mode-description")

                if self._default_keylog:
                    yield Static("[#94a3b8]Key log file:[/]", classes="path-label")
                    yield Input(
                        value=self._default_keylog,
                        placeholder="Path for key log file...",
                        id="keylog-input",
                    )

                if self._default_pcap:
                    yield Static("[#94a3b8]PCAP file:[/]", classes="path-label")
                    yield Input(
                        value=self._default_pcap,
                        placeholder="Path for PCAP file...",
                        id="pcap-input",
                    )

                if self._is_live:
                    yield Static(
                        "[#818cf8]Live mode: traffic will be streamed to Wireshark.[/]",
                        classes="mode-description",
                    )

                yield Static(
                    "[#64748b]Enter: Accept  |  Tab: Edit paths  |  Esc: Cancel[/]",
                    classes="key-hints",
                )
                with Horizontal(classes="button-row"):
                    yield Button("Accept", id="btn-accept", variant="primary")
                    yield Button("Cancel", id="btn-cancel", variant="default")

        def on_button_pressed(self, event: Button.Pressed) -> None:
            if event.button.id == "btn-accept":
                self._submit()
            elif event.button.id == "btn-cancel":
                self.dismiss(None)

        def _submit(self) -> None:
            """Collect input values and dismiss with result dict."""
            result = {
                "live": self._is_live,
                "full_capture": self._mode_id == "full",
            }

            try:
                keylog_input = self.query_one("#keylog-input", Input)
                result["keylog"] = keylog_input.value.strip()
            except Exception:
                result["keylog"] = ""

            try:
                pcap_input = self.query_one("#pcap-input", Input)
                result["pcap"] = pcap_input.value.strip()
            except Exception:
                result["pcap"] = ""

            self.dismiss(result)
