#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Spawn input modal for friTap TUI.

Supports two modes:
- App list view: browse installed applications on mobile devices (USB/remote)
- Manual input view: enter a package name or binary path directly
"""

from __future__ import annotations

from typing import Optional

try:
    from textual.app import ComposeResult
    from textual.widgets import Button, Input, OptionList, Static
    from textual.widgets.option_list import Option
    from textual.containers import Vertical, Horizontal
    TEXTUAL_AVAILABLE = True
except ImportError:
    TEXTUAL_AVAILABLE = False

if TEXTUAL_AVAILABLE:
    from .base import FriTapModal

    class SpawnInputModal(FriTapModal[Optional[str]]):
        """Modal for entering a package name or binary path to spawn.

        On mobile devices, shows a browsable list of installed applications.
        On local devices (or via toggle), shows a manual text input.
        """

        DEFAULT_CSS = """
        SpawnInputModal > #modal-container {
            max-height: 85%;
            width: 70;
        }
        SpawnInputModal #filter-input {
            margin: 1 0;
        }
        SpawnInputModal #spawn-input {
            margin: 1 0;
        }
        SpawnInputModal #app-list {
            height: 20;
            background: #080c18;
        }
        SpawnInputModal #app-list-view {
            display: none;
            height: auto;
        }
        SpawnInputModal #manual-view {
            height: auto;
        }
        """

        def __init__(
            self,
            device_id: str = "",
            device_type: str = "local",
            **kwargs,
        ) -> None:
            super().__init__(**kwargs)
            self._device_id = device_id
            self._device_type = device_type
            self._all_apps: list[tuple[str, str]] = []  # (name, identifier)
            self._app_map: dict[int, tuple[str, str]] = {}
            self._device = None
            self._manual_mode: bool = False

        def compose(self) -> ComposeResult:
            with Vertical(id="modal-container"):
                yield Static("[bold #38bdf8]Spawn Application[/]", classes="modal-title")

                # App list view — shown for mobile devices
                with Vertical(id="app-list-view"):
                    yield Input(
                        placeholder="Filter applications...",
                        id="filter-input",
                    )
                    yield OptionList(id="app-list")

                # Manual input view — shown for local devices or toggle
                with Vertical(id="manual-view"):
                    yield Static(
                        "[#8f9bb3]Enter a package name (e.g. com.example.app) "
                        "or path to binary (e.g. /usr/bin/curl)[/]"
                    )
                    yield Input(
                        placeholder="Package name or /path/to/binary...",
                        id="spawn-input",
                    )

                yield Static(
                    "[#64748b]Enter: Spawn  |  Type: Filter  |  \u2191\u2193: Browse  |  Esc: Cancel[/]",
                    classes="key-hints",
                )
                with Horizontal(classes="button-row"):
                    yield Button("Spawn", id="btn-spawn", variant="primary")
                    if self._is_mobile_device():
                        yield Button("Manual Input", id="btn-toggle-mode", variant="default")
                    yield Button("Cancel", id="btn-cancel", variant="default")

        def on_mount(self) -> None:
            """Initialize device and load applications if mobile."""
            super().on_mount()
            self._init_device()

            if self._is_mobile_device():
                self._load_applications()
                self._set_view_mode(manual=self._manual_mode)
            # Local devices stay in manual view (the default)

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

        def _load_applications(self) -> None:
            """Enumerate installed applications from the device."""
            self._all_apps.clear()

            if self._device is None:
                self.notify("No device available. Switching to manual input.", severity="warning")
                self._manual_mode = True
                return

            try:
                for app in self._device.enumerate_applications():
                    self._all_apps.append((app.name, app.identifier))
                # Sort alphabetically by name
                self._all_apps.sort(key=lambda x: x[0].lower())
            except Exception as e:
                self.notify(
                    f"Failed to list applications: {e}. Switching to manual input.",
                    severity="warning",
                )
                self._manual_mode = True
                return

            self._display_apps(self._all_apps)

        def _display_apps(self, apps: list[tuple[str, str]]) -> None:
            """Populate the OptionList with the given applications."""
            option_list = self.query_one("#app-list", OptionList)
            option_list.clear_options()
            self._app_map.clear()

            for idx, (name, identifier) in enumerate(apps):
                if identifier and identifier != name:
                    label = f"{name} ({identifier})"
                else:
                    label = name
                option_list.add_option(Option(label, id=str(idx)))
                self._app_map[idx] = (name, identifier)

            if not apps:
                option_list.add_option(Option("No applications found", id="none"))

            # Select first item
            try:
                option_list.highlighted = 0
            except Exception:
                pass

        def _set_view_mode(self, manual: bool) -> None:
            """Switch between app list view and manual input view."""
            self.query_one("#app-list-view").styles.display = "none" if manual else "block"
            self.query_one("#manual-view").styles.display = "block" if manual else "none"
            focus_id = "#spawn-input" if manual else "#filter-input"
            try:
                self.query_one(focus_id, Input).focus()
            except Exception:
                pass

        def on_input_changed(self, event: Input.Changed) -> None:
            """Filter the application list in real time."""
            if event.input.id != "filter-input":
                return
            search = event.value.lower().strip()
            if not search:
                self._display_apps(self._all_apps)
            else:
                filtered = [
                    (name, identifier)
                    for name, identifier in self._all_apps
                    if search in name.lower() or search in identifier.lower()
                ]
                self._display_apps(filtered)

        def on_input_submitted(self, event: Input.Submitted) -> None:
            """Route Enter key based on which input triggered it."""
            if event.input.id == "filter-input":
                self._select_highlighted()
            elif event.input.id == "spawn-input":
                self._submit()

        def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
            """Double-click or Enter on an application selects it."""
            self._select_highlighted()

        def on_button_pressed(self, event: Button.Pressed) -> None:
            if event.button.id == "btn-spawn":
                if self._manual_mode or not self._is_mobile_device():
                    self._submit()
                else:
                    self._select_highlighted()
            elif event.button.id == "btn-toggle-mode":
                self._toggle_mode()
            elif event.button.id == "btn-cancel":
                self.dismiss(None)

        def _toggle_mode(self) -> None:
            """Toggle between app list view and manual input view."""
            self._manual_mode = not self._manual_mode
            try:
                btn = self.query_one("#btn-toggle-mode", Button)
                btn.label = "App List" if self._manual_mode else "Manual Input"
            except Exception:
                pass

            self._set_view_mode(manual=self._manual_mode)

        def _select_highlighted(self) -> None:
            """Dismiss with the identifier of the highlighted application."""
            option_list = self.query_one("#app-list", OptionList)
            try:
                highlighted = option_list.highlighted
                if highlighted is not None and highlighted in self._app_map:
                    _name, identifier = self._app_map[highlighted]
                    self.dismiss(identifier)
                    return
            except Exception:
                pass
            self.notify("No application selected.", severity="warning")

        def _submit(self) -> None:
            """Dismiss with the manually entered input value."""
            spawn_input = self.query_one("#spawn-input", Input)
            value = spawn_input.value.strip()
            if value:
                self.dismiss(value)
            else:
                self.notify("Please enter a target to spawn.", severity="warning")
