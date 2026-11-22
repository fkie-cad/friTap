#!/usr/bin/env python3
"""A host Textual app that mounts the friTap viewer as a screen (embedding mode B).

Usage:
    python tap_viewer_host_app.py capture.tap

Keys on the host home screen:
    v           push the friTap viewer (TapViewerScreen) for the .tap file
    t           switch the host theme (the host themes define no $fritap-*
                variables; the viewer adds them without overriding host values)
    escape      host binding with priority=True (see below)
    ctrl+q      quit the host

This script demonstrates how a host program can:
  - push ``TapViewerScreen`` into its own app and handle ``TapViewerScreen.Closed``
  - stay running (and back on its own home screen) after the viewer closes
  - bind ``escape`` with ``priority=True`` safely: Textual priority bindings on
    the App beat the viewer's own bindings, so the host must step aside while
    a viewer is anywhere in the screen stack (``check_action``). Otherwise it
    would swallow Escape inside the viewer's modals. The alternative is to call
    ``viewer.go_back()`` first and only act when it returns False.
"""

import argparse
import sys
from pathlib import Path

# Allow standalone execution from the example/ directory
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.screen import Screen
from textual.theme import Theme
from textual.widgets import Footer, Header, Static

from friTap.ui import TapViewerScreen

HOST_THEMES = (
    Theme(name="host-night", primary="#4f9dff", secondary="#9b59b6", dark=True),
    Theme(name="host-day", primary="#0057b8", secondary="#7d3c98", dark=False),
)


class HomeScreen(Screen):
    """The host's own screen; the viewer is pushed on top of it."""

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("Host home screen. Press v to open the friTap viewer.", id="home-text")
        yield Footer()


class HostApp(App):
    TITLE = "Host application"

    BINDINGS = [
        Binding("v", "open_viewer", "Viewer"),
        Binding("t", "switch_theme", "Theme"),
        Binding("escape", "host_escape", "Esc", priority=True),
    ]

    def __init__(self, tap_path: str, output_dir=None, **kwargs) -> None:
        super().__init__(**kwargs)
        self.tap_path = tap_path
        self.output_dir = output_dir
        self.escape_presses_on_home = 0

    def on_mount(self) -> None:
        for theme in HOST_THEMES:
            self.register_theme(theme)
        self.theme = HOST_THEMES[0].name
        self.push_screen(HomeScreen())

    def check_action(self, action: str, parameters: tuple):
        """Step aside for the viewer: a False here lets Escape reach the viewer."""
        if action == "host_escape" and self._viewer_in_stack():
            return False
        return True

    def _viewer_in_stack(self) -> bool:
        return any(isinstance(screen, TapViewerScreen) for screen in self.screen_stack)

    def action_host_escape(self) -> None:
        self.escape_presses_on_home += 1
        self.notify("Host handled escape (no viewer is open).")

    def action_open_viewer(self) -> None:
        if self._viewer_in_stack():
            return
        self.push_screen(TapViewerScreen(
            self.tap_path, title="Embedded viewer", output_dir=self.output_dir))

    def action_switch_theme(self) -> None:
        names = [theme.name for theme in HOST_THEMES]
        self.theme = names[(names.index(self.theme) + 1) % len(names)]

    def on_tap_viewer_screen_closed(self, message: TapViewerScreen.Closed) -> None:
        """The viewer dismisses itself; the host only reacts and stays running."""
        self.notify(f"Viewer closed ({message.tap_path})")
        self.call_after_refresh(self._ensure_home)

    def _ensure_home(self) -> None:
        if isinstance(self.screen, TapViewerScreen) and len(self.screen_stack) > 1:
            self.pop_screen()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Host Textual app embedding the friTap viewer as a screen.",
    )
    parser.add_argument("tap_file", help="Path to the .tap capture file")
    args = parser.parse_args(argv)
    if not Path(args.tap_file).exists():
        print(f"error: No such .tap file: {args.tap_file}", file=sys.stderr)
        return 2
    HostApp(args.tap_file).run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
