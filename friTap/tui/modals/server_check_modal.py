#!/usr/bin/env python3

"""
Server check modal for friTap TUI wizard.

Checks whether frida-server is running on the selected device
and optionally installs it via the server manager.
"""

from __future__ import annotations

from typing import Optional

try:
    from textual.app import ComposeResult
    from textual.containers import Horizontal, Vertical
    from textual.reactive import reactive
    from textual.widgets import Button, Static
    TEXTUAL_AVAILABLE = True
except ImportError:
    TEXTUAL_AVAILABLE = False

if TEXTUAL_AVAILABLE:
    from friTap.tui.themes import c

    from .base import FriTapModal

    class ServerCheckModal(FriTapModal[Optional[str]]):
        """Modal that checks frida-server status and offers installation."""

        DEFAULT_CSS = """
        ServerCheckModal > #modal-container {
            width: 65;
            height: auto;
            max-height: 70%;
            background: $fritap-bg-modal;
            border: solid $fritap-border-default;
            padding: 1 2;
        }
        ServerCheckModal #status-message {
            margin: 1 0;
            text-align: center;
            color: $fritap-text-secondary;
        }
        ServerCheckModal #prompt-message {
            margin: 1 0;
            text-align: center;
            color: $warning;
        }
        """

        phase: reactive[str] = reactive("checking")

        def __init__(self, device_id: str, device_name: str, **kwargs) -> None:
            super().__init__(**kwargs)
            self._device_id = device_id
            self._device_name = device_name
            self._error_message: Optional[str] = None

        def compose(self) -> ComposeResult:
            with Vertical(id="modal-container"):
                yield Static(f"[bold {c('primary')}]Server Check[/]", classes="modal-title")
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
                status.update(self._error_text())
                prompt.update(
                    f"[bold {c('warning')}]frida-server not detected on this device.[/]"
                )
                buttons.display = True
                try:
                    self.query_one("#btn-install", Button).focus()
                except Exception:
                    pass
            elif self.phase == "starting":
                status.update(
                    f"frida-server not running on [bold]{self._device_name}[/] "
                    "— starting it via AndroidFridaManager..."
                )
                prompt.update("")
                buttons.display = False
            elif self.phase == "installing":
                status.update("Installing frida-server...")
                prompt.update("")
                buttons.display = False
            elif self.phase == "done":
                status.update(f"[bold {c('success')}]frida-server is running![/]")
                prompt.update("")
                buttons.display = False

        def _error_text(self) -> str:
            if not self._error_message:
                return ""
            return f"[bold {c('error-strong')}]Error:[/] {self._error_message}"

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

        # ----------------------------------------------------------
        # Workers
        # ----------------------------------------------------------

        def _lookup_device(self):
            from friTap.backends import get_backend
            return get_backend().get_device(mobile=self._device_id)

        def _check_server(self) -> None:
            """Background worker: probe, and auto-start on Android if needed.

            Uses probe_frida_server, not check_connectivity: on frida 17 a
            server-less USB device still enumerates via the ADB fallback.
            """
            from friTap.server_manager.probe import (
                ServerState,
                is_attach_capable,
                probe_frida_server,
            )
            try:
                device = self._lookup_device()
                state = probe_frida_server(device)
            except Exception:
                device, state = None, ServerState.UNREACHABLE
            if is_attach_capable(state):
                self.app.call_from_thread(self._finish_ok)
                return
            mgr = self._android_manager(device) if state is ServerState.NOT_RUNNING else None
            if mgr is None:
                self.app.call_from_thread(self._show_prompt, None)
                return
            self.app.call_from_thread(setattr, self, "phase", "starting")
            self._bring_up(mgr, device)

        @staticmethod
        def _android_manager(device):
            """Return the Android server manager for *device*, else None."""
            try:
                from friTap.server_manager.factory import get_server_manager
                mgr = get_server_manager(device)
            except Exception:
                return None
            return mgr if mgr.platform_name == "android" else None

        def _bring_up(self, mgr, device) -> None:
            """Run ensure_running; dismiss "ok" on success, else show the error."""
            try:
                mgr.ensure_running(device, callback=self._progress)
            except Exception as exc:
                self.app.call_from_thread(self._show_prompt, str(exc))
                return
            self.app.call_from_thread(self._finish_ok)

        def _progress(self, msg: str) -> None:
            """Thread-safe progress line in the status area."""
            self.app.call_from_thread(
                lambda: self.query_one("#status-message", Static).update(msg)
            )

        def _finish_ok(self) -> None:
            self.phase = "done"
            self.set_timer(0.5, self._dismiss_ok)

        def _show_prompt(self, error: Optional[str]) -> None:
            """Return to the Install/Skip/Back prompt, optionally with an error."""
            self._error_message = error
            if self.phase == "prompt":
                self._update_phase_ui()
            else:
                self.phase = "prompt"

        def on_button_pressed(self, event: Button.Pressed) -> None:
            if event.button.id == "btn-install":
                self.phase = "installing"
                self.run_worker(self._do_install, thread=True)
            elif event.button.id == "btn-skip":
                self.dismiss("skipped")
            elif event.button.id == "btn-back":
                self.dismiss(None)

        def _do_install(self) -> None:
            """Background worker: install (non-Android) then ensure_running."""
            try:
                device = self._lookup_device()
                from friTap.server_manager.factory import get_server_manager
                mgr = get_server_manager(device)
                # Android's ensure_running installs the version-matched
                # server itself; other platforms need an explicit install.
                if mgr.platform_name != "android":
                    self._progress(f"Installing frida-server for {self._device_name}...")
                    mgr.install(device, callback=self._progress)
            except Exception as exc:
                self.app.call_from_thread(self._show_prompt, f"Install failed: {exc}")
                return
            self._bring_up(mgr, device)
