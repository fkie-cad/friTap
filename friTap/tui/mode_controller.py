#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Data-driven capture mode controller for friTap TUI.

Replaces five nearly identical ``action_set_mode_N`` methods in
MainScreen with a single data-driven dispatcher that maps a mode
number (1-5) to a ``CaptureMode`` definition and opens the
corresponding ``CaptureModeModal``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .screens.main_screen import MainScreen


@dataclass(frozen=True)
class CaptureMode:
    """Definition of a capture-mode preset."""

    mode_id: str
    display: str
    callback_display: str = ""
    default_keylog: str = ""
    default_pcap: str = ""
    is_live: bool = False

    @property
    def apply_display(self) -> str:
        """Display name used in _apply_mode (may differ from modal title)."""
        return self.callback_display or self.display


# All available capture modes keyed by shortcut number.
# ``callback_display`` overrides ``display`` in _apply_mode when the
# two intentionally differ (e.g. mode 2: modal says "Key Extraction
# Only" but status bar shows "Keys Only").
CAPTURE_MODES = {
    1: CaptureMode(
        "full",
        "Full Capture",
        default_keylog="keys.log",
        default_pcap="capture.pcap",
    ),
    2: CaptureMode(
        "keys",
        "Key Extraction Only",
        callback_display="Keys Only",
        default_keylog="keys.log",
    ),
    3: CaptureMode(
        "plaintext",
        "Plaintext PCAP",
        default_pcap="plaintext.pcap",
    ),
    4: CaptureMode(
        "wireshark",
        "Live Wireshark",
        default_keylog="keys.log",
        is_live=True,
    ),
    5: CaptureMode(
        "live_pcapng",
        "Live Wireshark (auto-decrypt)",
        is_live=True,
    ),
}


class ModeController:
    """Handles capture-mode selection for *MainScreen*.

    Centralises the guard-check -> alert -> push-modal -> apply-mode
    sequence so that each ``action_set_mode_N`` becomes a one-liner.
    """

    def __init__(self, screen: "MainScreen") -> None:
        self._screen = screen

    def set_mode(self, mode_number: int) -> None:
        """Open the capture-mode modal for *mode_number* (1-5)."""
        screen = self._screen

        if screen._wizard_guard():
            return

        if screen._ssl_logger and screen._ssl_logger.running:
            from .modals.alert_modal import AlertModal

            screen.app.push_screen(
                AlertModal("Stop capture before changing mode.")
            )
            return

        mode = CAPTURE_MODES.get(mode_number)
        if mode is None:
            return

        def _on_result(result):
            if result is None:
                return
            screen._apply_mode(mode.mode_id, mode.apply_display, result)

        from .modals.capture_mode_modal import CaptureModeModal

        screen.app.push_screen(
            CaptureModeModal(
                mode_id=mode.mode_id,
                mode_display=mode.display,
                default_keylog=mode.default_keylog,
                default_pcap=mode.default_pcap,
                is_live=mode.is_live,
            ),
            callback=_on_result,
        )
