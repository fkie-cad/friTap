#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Process selection modal for friTap TUI.

Enumerates processes (and apps for USB devices) with real-time filtering.
Returns (display_name, frida_target, is_pid) or None on cancel.
"""

from __future__ import annotations

from typing import Optional

try:
    from textual.app import ComposeResult
    from textual.reactive import reactive
    from textual.widgets import Button, Input, OptionList, Static
    from textual.widgets.option_list import Option
    from textual.containers import Vertical, Horizontal
    TEXTUAL_AVAILABLE = True
except ImportError:
    TEXTUAL_AVAILABLE = False

if TEXTUAL_AVAILABLE:
    from .base import FriTapModal

    class ProcessSelectModal(FriTapModal[Optional[tuple[str, str, bool]]]):
        """Modal for selecting a target process to attach to."""

        DEFAULT_CSS = """
        ProcessSelectModal > #modal-container {
            width: 75;
            max-height: 85%;
            background: #0d1117;
            border: solid #1e3a5f;
            padding: 1 2;
        }
        ProcessSelectModal #filter-input {
            margin: 1 0;
        }
        ProcessSelectModal #process-list {
            height: 20;
            background: #080c18;
        }
        """

        show_all: reactive[bool] = reactive(False)

        def __init__(self, device_id: str = "", device_type: str = "local", **kwargs) -> None:
            super().__init__(**kwargs)
            self._device_id = device_id
            self._device_type = device_type
            self._all_processes: list[tuple[str, str, str, str]] = []  # (pid, name, identifier, kind)
            self._process_map: dict[int, tuple[str, str, str, str]] = {}
            self._frontmost_identifier: str = ""
            self._device = None

        def compose(self) -> ComposeResult:
            with Vertical(id="modal-container"):
                yield Static("[bold #38bdf8]Select Process[/]", classes="modal-title")
                yield Input(
                    placeholder="Filter processes...",
                    id="filter-input",
                )
                yield OptionList(id="process-list")
                yield Static(
                    "[#64748b]Enter: Attach  |  Type: Filter  |  \u2191\u2193: Browse  |  Tab: Navigate  |  Esc: Cancel[/]",
                    classes="key-hints",
                )
                with Horizontal(classes="button-row"):
                    yield Button("Attach", id="btn-attach", variant="primary")
                    if self._device_type in ("usb", "remote"):
                        yield Button("Show All", id="btn-show-all", variant="default")
                    yield Button("Cancel", id="btn-cancel", variant="default")

        def on_mount(self) -> None:
            """Load processes for the configured device."""
            super().on_mount()
            self._init_device()
            self._load_processes()

        def _init_device(self) -> None:
            """Initialize the Frida device reference."""
            try:
                from friTap.backends import get_backend
                if self._device_id:
                    self._device = get_backend().get_device(mobile=self._device_id)
                else:
                    self._device = get_backend().get_local_device()
            except Exception:
                self._device = None

        def _is_mobile_device(self) -> bool:
            """Check if the device is a mobile (USB/remote) device."""
            return self._device_type in ("usb", "remote")

        def _load_processes(self) -> None:
            """Enumerate processes from the selected device."""
            self._all_processes.clear()

            if self._device is None:
                self._all_processes.append(("\u2014", "Error: No device", "", "\u2014"))
                self._display_processes(self._all_processes)
                return

            try:
                if self._is_mobile_device() and not self.show_all:
                    # Mobile: show applications by default
                    self._load_applications()
                else:
                    # Local or "Show All": show all processes
                    self._load_all_processes()

            except Exception as e:
                self._all_processes.append(("\u2014", f"Error: {e}", "", "\u2014"))

            self._display_processes(self._all_processes)

        def _load_applications(self) -> None:
            """Load applications for mobile devices (like frida-ps -Uai)."""
            try:
                # Get frontmost app for pre-selection
                frontmost = self._device.get_frontmost_application()
                if frontmost:
                    self._frontmost_identifier = frontmost.identifier
            except Exception:
                self._frontmost_identifier = ""

            try:
                for app in self._device.enumerate_applications():
                    pid_str = str(app.pid) if app.pid else "\u2014"
                    self._all_processes.append((pid_str, app.name, app.identifier, "app"))
            except Exception as e:
                self._all_processes.append(("\u2014", f"Error listing apps: {e}", "", "\u2014"))

        def _load_all_processes(self) -> None:
            """Load all processes (full list)."""
            for proc in self._device.enumerate_processes():
                self._all_processes.append((str(proc.pid), proc.name, "", "process"))

            # For USB devices, also add applications not already in the process list
            if self._device_type == "usb":
                try:
                    for app in self._device.enumerate_applications():
                        if not any(p[2] == app.identifier for p in self._all_processes):
                            self._all_processes.append(("\u2014", app.name, app.identifier, "app"))
                except Exception:
                    pass

        def watch_show_all(self, value: bool) -> None:
            """Reload the process list when toggling show_all."""
            # Only reload if already mounted (device initialized)
            if self._device is not None:
                # Update button label
                try:
                    btn = self.query_one("#btn-show-all", Button)
                    btn.label = "Show Apps" if value else "Show All"
                except Exception:
                    pass
                # Clear filter and reload
                try:
                    self.query_one("#filter-input", Input).value = ""
                except Exception:
                    pass
                self._load_processes()

        def _display_processes(self, processes: list[tuple[str, str, str, str]]) -> None:
            """Update the OptionList with given processes."""
            option_list = self.query_one("#process-list", OptionList)
            option_list.clear_options()
            self._process_map.clear()

            frontmost_idx = None
            for idx, (pid, name, identifier, kind) in enumerate(processes):
                kind_tag = "[app]" if kind == "app" else f"[{pid}]"
                if identifier and identifier != name:
                    label = f"{kind_tag:>8}  {name} ({identifier})"
                else:
                    label = f"{kind_tag:>8}  {name}"
                option_list.add_option(Option(label, id=str(idx)))
                self._process_map[idx] = (pid, name, identifier, kind)

                # Track frontmost app index for pre-selection
                if self._frontmost_identifier and identifier == self._frontmost_identifier:
                    frontmost_idx = idx

            if not processes:
                option_list.add_option(Option("No processes found", id="none"))

            # Pre-select frontmost app if found, otherwise first item
            try:
                if frontmost_idx is not None:
                    option_list.highlighted = frontmost_idx
                else:
                    option_list.highlighted = 0
            except Exception:
                pass

        def on_input_changed(self, event: Input.Changed) -> None:
            """Filter process list in real time."""
            if event.input.id != "filter-input":
                return
            search = event.value.lower().strip()
            if not search:
                self._display_processes(self._all_processes)
            else:
                filtered = [
                    (pid, name, identifier, kind)
                    for pid, name, identifier, kind in self._all_processes
                    if search in name.lower() or search in identifier.lower() or search in pid
                ]
                self._display_processes(filtered)

        def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
            """Double-click or Enter on a process selects it."""
            self._select_highlighted()

        def on_button_pressed(self, event: Button.Pressed) -> None:
            if event.button.id == "btn-attach":
                self._select_highlighted()
            elif event.button.id == "btn-show-all":
                self.show_all = not self.show_all
            elif event.button.id == "btn-cancel":
                self.dismiss(None)

        def _select_highlighted(self) -> None:
            """Dismiss with the selected process info."""
            option_list = self.query_one("#process-list", OptionList)
            try:
                highlighted = option_list.highlighted
                if highlighted is not None and highlighted in self._process_map:
                    pid, name, identifier, kind = self._process_map[highlighted]
                    if pid != "\u2014":
                        # Running process/app — use PID for Frida, display name for UI
                        self.dismiss((name, pid, True))
                    else:
                        # Not running — use display name for both
                        self.dismiss((name, name, False))
                    return
            except Exception:
                pass
            self.dismiss(None)
