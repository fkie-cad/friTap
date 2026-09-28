#!/usr/bin/env python3

"""
Decrypt-progress modal for friTap TUI.

A non-dismissible spinner shown while an offline pcap->tap decrypt runs, so the
conversion never looks hung. The worker updates its status line via
:meth:`update_status` and dismisses it on completion/error.
"""

from __future__ import annotations

try:
    from textual.app import ComposeResult
    from textual.containers import Vertical
    from textual.widgets import LoadingIndicator, Static
    TEXTUAL_AVAILABLE = True
except ImportError:
    TEXTUAL_AVAILABLE = False

if TEXTUAL_AVAILABLE:
    from friTap.tui.themes import c

    from .base import FriTapModal

    class DecryptProgressModal(FriTapModal[None]):
        """Non-dismissible progress spinner for the offline decrypt worker."""

        DEFAULT_CSS = """
        DecryptProgressModal > #modal-container {
            width: 60;
            height: auto;
            max-height: 40%;
            background: $fritap-bg-modal;
            border: solid $fritap-border-default;
            padding: 1 2;
        }
        DecryptProgressModal LoadingIndicator {
            height: 1;
            margin: 1 0;
        }
        DecryptProgressModal #decrypt-status {
            text-align: center;
            margin-top: 1;
        }
        """

        def __init__(self, message: str = "Decrypting captured traffic…", **kwargs) -> None:
            super().__init__(**kwargs)
            self._message = message
            self._finished = False

        def compose(self) -> ComposeResult:
            with Vertical(id="modal-container"):
                yield Static(
                    f"[bold {c('primary')}]Decrypting[/]",
                    classes="modal-title",
                )
                yield LoadingIndicator()
                yield Static(self._message, id="decrypt-status")

        def action_cancel(self) -> None:
            """Ignore ESC: the decrypt worker owns this modal's lifetime."""
            return

        def _auto_focus(self) -> None:
            """No focusable widget; nothing to focus."""
            return

        def finish(self) -> None:
            """Close the spinner without ever closing a different screen.

            ``Screen.dismiss`` pops the app's TOP screen, whatever it is. If
            another screen was pushed above the spinner (quit confirmation,
            an alert), dismissing directly would close that screen and strand
            this non-dismissible spinner. So: close now only when the spinner
            is the active screen; otherwise mark it finished and let
            :meth:`on_screen_resume` close it once it is back on top.
            """
            if self._finished:
                return
            self._finished = True
            if self.is_active:
                self._close()

        def on_screen_resume(self) -> None:
            """Close a spinner that finished while covered by another screen."""
            if self._finished and self.is_active:
                self._close()

        def _close(self) -> None:
            try:
                self.dismiss(None)
            except Exception:
                pass

        def update_status(self, message: str) -> None:
            """Replace the status line (called from the UI thread)."""
            try:
                self.query_one("#decrypt-status", Static).update(message)
            except Exception:
                pass
