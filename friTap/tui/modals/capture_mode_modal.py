#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Capture mode configuration modal for friTap TUI.

Shown when the user presses 1-5 to select a capture mode.
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
        "full": "Capture TLS keys and write a PCAPNG file with decrypted traffic.",
        "keys": "Extract TLS session keys only (no traffic capture).",
        "plaintext": "Write decrypted plaintext traffic to a PCAPNG file.",
        "wireshark": "Stream decrypted plaintext traffic live to Wireshark — no keylog needed.",
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
            self._ws_found: bool | None = None
            if is_live:
                from ...fritap_utility import find_wireshark_binary
                self._ws_found = find_wireshark_binary() is not None

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
                    yield Static("[#94a3b8]Output file (PCAP/PCAPNG):[/]", classes="path-label")
                    yield Input(
                        value=self._default_pcap,
                        placeholder="Path for capture file (.pcap or .pcapng)...",
                        id="pcap-input",
                    )

                if self._is_live:
                    if self._mode_id == "live_pcapng":
                        yield Static(
                            "[#818cf8]Keys are embedded in the PCAPNG stream — no file paths needed.\n"
                            "Wireshark receives a single stream with both traffic and decryption keys.[/]",
                            classes="mode-description",
                        )
                    else:
                        yield Static(
                            "[#818cf8]Decrypted plaintext streams directly to Wireshark via a named pipe.\n"
                            "No keylog file needed — traffic is already decrypted.[/]",
                            classes="mode-description",
                        )
                    if self._ws_found:
                        yield Static(
                            "[#4ade80]Wireshark found — will auto-launch when capture starts.[/]",
                            classes="mode-description",
                        )
                    else:
                        yield Static(
                            "[#f59e0b]Wireshark not found in PATH — you will need to connect manually.[/]",
                            classes="mode-description",
                        )

                has_inputs = bool(self._default_keylog or self._default_pcap)
                hint_parts = ["Enter: Accept"]
                if has_inputs:
                    hint_parts.append("Tab: Edit paths")
                hint_parts.append("Esc: Cancel")
                yield Static(
                    f"[#64748b]{'  |  '.join(hint_parts)}[/]",
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
            if self._is_live:
                result["live_mode"] = self._mode_id

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
