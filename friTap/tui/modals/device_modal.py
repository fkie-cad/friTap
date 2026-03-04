#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Device selection modal for friTap TUI.

Enumerates connected Frida devices and allows adding remote devices.
"""

from __future__ import annotations

import sys
from typing import Optional

try:
    from textual.app import ComposeResult
    from textual.widgets import Button, Input, OptionList, Static
    from textual.widgets.option_list import Option
    from textual.containers import Vertical, Horizontal
    TEXTUAL_AVAILABLE = True
except ImportError:
    TEXTUAL_AVAILABLE = False

_PLATFORM_NAMES = {"darwin": "macOS", "win32": "Windows"}

if TEXTUAL_AVAILABLE:
    from .base import FriTapModal

    class DeviceSelectModal(FriTapModal[Optional[str]]):
        """Modal for selecting a Frida device."""

        DEFAULT_CSS = """
        DeviceSelectModal > #modal-container {
            width: 70;
            max-height: 80%;
            background: #0d1117;
            border: solid #1e3a5f;
            padding: 1 2;
        }
        DeviceSelectModal #device-list {
            height: 12;
            margin: 1 0;
            background: #080c18;
        }
        DeviceSelectModal #remote-row {
            height: 3;
            margin-top: 1;
        }
        DeviceSelectModal #remote-input {
            width: 1fr;
        }
        """

        def __init__(self, current_device_id: str = "", **kwargs) -> None:
            super().__init__(**kwargs)
            self._current_device_id = current_device_id
            self._device_map: dict[int, str] = {}  # option index -> device_id

        def compose(self) -> ComposeResult:
            with Vertical(id="modal-container"):
                yield Static("[bold #38bdf8]Select Device[/]", classes="modal-title")
                yield OptionList(id="device-list")
                with Horizontal(id="remote-row"):
                    yield Input(
                        placeholder="Remote address (host:port)...",
                        id="remote-input",
                    )
                    yield Button("Add Remote", id="btn-add-remote", variant="default")
                yield Static(
                    "[#64748b]Enter: Select  |  \u2191\u2193: Browse  |  Tab: Navigate  |  Esc: Cancel[/]",
                    classes="key-hints",
                )
                with Horizontal(classes="button-row"):
                    yield Button("Select", id="btn-select", variant="primary")
                    yield Button("Cancel", id="btn-cancel", variant="default")

        def _auto_focus(self) -> None:
            """Override base to focus the device list, not the remote input."""
            try:
                self.query_one("#device-list", OptionList).focus()
            except Exception:
                pass

        def on_mount(self) -> None:
            """Enumerate devices and populate the list."""
            super().on_mount()
            self._enumerate_devices()

        def _enumerate_devices(self) -> None:
            """Populate OptionList with connected Frida devices."""
            option_list = self.query_one("#device-list", OptionList)
            option_list.clear_options()
            self._device_map.clear()

            idx = 0
            try:
                from friTap.backends import get_backend
                devices = get_backend().enumerate_devices()
                for dev in devices:
                    if dev.type == "local":
                        platform_label = _PLATFORM_NAMES.get(sys.platform, "Linux")
                        label = f"[L] {platform_label} ({dev.name})"
                    elif dev.type == "usb":
                        label = f"[U] {dev.name}"
                    elif dev.type == "remote":
                        label = f"[R] {dev.name}"
                    else:
                        continue
                    option_list.add_option(Option(label, id=str(idx)))
                    self._device_map[idx] = dev.id
                    idx += 1
            except Exception as e:
                option_list.add_option(Option(f"Error: {e}", id="error"))

            if idx == 0:
                option_list.add_option(Option("No devices found", id="none"))

            # Try to highlight current device
            try:
                option_list.highlighted = 0
            except Exception:
                pass

        def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
            """Double-click or Enter on an option selects it."""
            self._select_highlighted()

        def on_button_pressed(self, event: Button.Pressed) -> None:
            if event.button.id == "btn-select":
                self._select_highlighted()
            elif event.button.id == "btn-cancel":
                self.dismiss(None)
            elif event.button.id == "btn-add-remote":
                self._add_remote()

        def _select_highlighted(self) -> None:
            """Dismiss with the currently highlighted device ID."""
            option_list = self.query_one("#device-list", OptionList)
            try:
                highlighted = option_list.highlighted
                if highlighted is not None and highlighted in self._device_map:
                    self.dismiss(self._device_map[highlighted])
                    return
            except Exception:
                pass
            self.dismiss(None)

        def _add_remote(self) -> None:
            """Add a remote device from the input field and refresh."""
            remote_input = self.query_one("#remote-input", Input)
            address = remote_input.value.strip()
            if not address:
                return
            try:
                from friTap.backends import get_backend
                get_backend().get_device_manager().add_remote_device(address)
                remote_input.value = ""
                self._enumerate_devices()
            except Exception as e:
                self.notify(f"Failed to add remote: {e}", severity="error")
