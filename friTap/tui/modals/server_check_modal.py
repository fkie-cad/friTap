#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Server check modal for friTap TUI wizard.

Checks whether frida-server is running on the selected device
and optionally installs it via the server manager.
"""

from __future__ import annotations

from typing import Optional

try:
    from textual.app import ComposeResult
    from textual.reactive import reactive
    from textual.widgets import Button, Static
    from textual.containers import Vertical, Horizontal
    TEXTUAL_AVAILABLE = True
except ImportError:
    TEXTUAL_AVAILABLE = False

if TEXTUAL_AVAILABLE:
    from .base import FriTapModal

    class ServerCheckModal(FriTapModal[Optional[str]]):
        """Modal that checks frida-server status and offers installation."""

        DEFAULT_CSS = """
        ServerCheckModal > #modal-container {
            width: 65;
            height: auto;
            max-height: 70%;
            background: #0d1117;
            border: solid #1e3a5f;
            padding: 1 2;
        }
        ServerCheckModal #status-message {
            margin: 1 0;
            text-align: center;
            color: #94a3b8;
        }
        ServerCheckModal #prompt-message {
            margin: 1 0;
            text-align: center;
            color: #fbbf24;
        }
        """

        phase: reactive[str] = reactive("checking")

        def __init__(self, device_id: str, device_name: str, **kwargs) -> None:
            super().__init__(**kwargs)
            self._device_id = device_id
            self._device_name = device_name

        def compose(self) -> ComposeResult:
            with Vertical(id="modal-container"):
                yield Static("[bold #38bdf8]Server Check[/]", classes="modal-title")
                yield Static("", id="status-message")
                yield Static("", id="prompt-message")
                with Horizontal(classes="button-row", id="action-buttons"):
                    yield Button("Install", id="btn-install", variant="primary")
                    yield Button("Skip", id="btn-skip", variant="default")
                    yield Button("Back", id="btn-back", variant="default")

        def on_mount(self) -> None:
            # Skip the base auto_focus — we manage focus based on phase
            self._update_phase_ui()
            self.run_worker(self._check_server, thread=True)

        def _update_phase_ui(self) -> None:
            """Update widget visibility and content based on current phase."""
            status = self.query_one("#status-message", Static)
            prompt = self.query_one("#prompt-message", Static)
            buttons = self.query_one("#action-buttons")

            if self.phase == "checking":
                status.update(
                    f"Checking frida-server on [bold]{self._device_name}[/]..."
                )
                prompt.update("")
                buttons.display = False
            elif self.phase == "prompt":
                status.update("")
                prompt.update(
                    "[bold #fbbf24]frida-server not detected on this device.[/]"
                )
                buttons.display = True
                try:
                    self.query_one("#btn-install", Button).focus()
                except Exception:
                    pass
            elif self.phase == "installing":
                status.update("Installing frida-server...")
                prompt.update("")
                buttons.display = False
            elif self.phase == "done":
                status.update("[bold #4ade80]frida-server is running![/]")
                prompt.update("")
                buttons.display = False

        def watch_phase(self, new_phase: str) -> None:
            """React to phase changes by updating the UI."""
            try:
                self._update_phase_ui()
            except Exception:
                pass

        def _dismiss_ok(self) -> None:
            """Dismiss with 'ok' — must be a proper method so the return
            value of dismiss() is discarded (not propagated to the timer
            handler, which would try to await it and raise ScreenError)."""
            self.dismiss("ok")

        def _check_server(self) -> None:
            """Background worker to check whether frida-server is reachable."""
            try:
                from friTap.backends import get_backend
                backend = get_backend()
                device = backend.get_device(mobile=self._device_id)
                if not backend.check_connectivity(device):
                    raise ConnectionError("Server not reachable")

                # Server is running
                def _success():
                    self.phase = "done"
                    self.set_timer(0.5, self._dismiss_ok)

                self.app.call_from_thread(_success)
            except Exception:
                self.app.call_from_thread(
                    lambda: setattr(self, "phase", "prompt")
                )

        def on_button_pressed(self, event: Button.Pressed) -> None:
            if event.button.id == "btn-install":
                self.phase = "installing"
                self.run_worker(self._do_install, thread=True)
            elif event.button.id == "btn-skip":
                self.dismiss("skipped")
            elif event.button.id == "btn-back":
                self.dismiss(None)

        def _do_install(self) -> None:
            """Background worker to install and start frida-server."""
            try:
                from friTap.backends import get_backend
                device = get_backend().get_device(mobile=self._device_id)

                from friTap.server_manager.factory import get_server_manager
                mgr = get_server_manager(device)

                def _progress(msg: str) -> None:
                    self.app.call_from_thread(
                        lambda: self.query_one("#status-message", Static).update(msg)
                    )

                _progress(
                    f"Installing frida-server for {self._device_name}..."
                )
                mgr.install(device, callback=_progress)

                _progress("Starting frida-server...")
                mgr.start(device)

                def _done():
                    self.phase = "done"
                    self.set_timer(0.5, self._dismiss_ok)

                self.app.call_from_thread(_done)
            except Exception as e:
                def _fail(err=e):
                    self.query_one("#status-message", Static).update(
                        f"[bold #ef4444]Install failed:[/] {err}"
                    )
                    self.phase = "prompt"

                self.app.call_from_thread(_fail)
