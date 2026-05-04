#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Help screen overlay for friTap TUI.

Full-screen overlay showing categorized keybindings and usage info.
"""

from __future__ import annotations

try:
    from textual.app import ComposeResult
    from textual.binding import Binding
    from textual.screen import Screen
    from textual.widgets import Static
    from textual.containers import Vertical, VerticalScroll  # noqa: F401
    TEXTUAL_AVAILABLE = True
except ImportError:
    TEXTUAL_AVAILABLE = False

from friTap.tui.themes import c


def _build_help_text() -> str:
    """Build help text with current theme colors."""
    return f"""\
[bold {c('primary')}]friTap Keyboard Reference[/]

[bold {c('text-muted')}]=== Target ===[/]
  [bold {c('accent')}]d[/]         Select device
  [bold {c('accent')}]a[/]         Attach to running process
  [bold {c('accent')}]s[/]         Spawn new application

[bold {c('text-muted')}]=== Capture Mode ===[/]
  [bold {c('accent')}]1[/]         Full capture (keys + pcap)
  [bold {c('accent')}]2[/]         Key extraction only
  [bold {c('accent')}]3[/]         Plaintext pcap
  [bold {c('accent')}]4[/]         Live Wireshark pipe

[bold {c('text-muted')}]=== Control ===[/]
  [bold {c('accent')}]Enter[/]     Start / Stop capture (toggle)
  [bold {c('accent')}]c[/]         Clear console
  [bold {c('accent')}]y[/]         Copy log to clipboard

[bold {c('text-muted')}]=== Setup ===[/]
  [bold {c('accent')}]i[/]         Install & start frida-server

[bold {c('text-muted')}]=== Options ===[/]
  [bold {c('accent')}]v[/]         Toggle verbose mode
  [bold {c('accent')}]e[/]         Toggle experimental mode
  [bold {c('accent')}]d[/]         Toggle debug log (fritap_debug_*.log)
  [bold {c('accent')}]t[/]         Toggle light/dark theme
  [bold {c('accent')}]?[/]         Show this help

[bold {c('text-muted')}]=== Views ===[/]
  [bold {c('accent')}]f[/]         Toggle console / flow view

[bold {c('text-muted')}]=== Flow Detail ===[/]
  [bold {c('accent')}]p[/]         Body processing (decode/decompress)
  [bold {c('accent')}]r[/]         Reset all processing
  [bold {c('accent')}]h[/]         Toggle raw hexdump (full message)
  [bold {c('accent')}]s[/]         Save body to file
  [bold {c('accent')}]x[/]         Explorer Mode (select + parse byte range)

[bold {c('text-muted')}]=== Explorer Mode ===[/]
  [bold {c('accent')}]v[/]         Toggle mark mode (start/stop byte selection)
  [bold {c('accent')}]arrows[/]    Extend selection (in mark mode)
  [bold {c('accent')}]p[/]         Parse selected bytes
  [bold {c('accent')}]t[/]         Toggle hex / text view
  [bold {c('accent')}]Esc[/]       Cancel mark / close explorer

[bold {c('text-muted')}]=== Navigation ===[/]
  [bold {c('accent')}]Tab[/]       Switch focus between panels
  [bold {c('accent')}]Esc[/]       Back from detail / stop capture / close modal
  [bold {c('accent')}]q[/]         Quit friTap

[dim {c('text-dim')}]Press Esc or q to close this help screen.[/]
"""

if TEXTUAL_AVAILABLE:

    class HelpScreen(Screen):
        """Full-screen help overlay with keybinding reference."""

        DEFAULT_CSS = """
        HelpScreen {
            align: center middle;
            background: $fritap-modal-overlay;
        }
        HelpScreen > #help-container {
            width: 60;
            max-height: 85%;
            background: $fritap-bg-modal;
            border: solid $fritap-border-default;
            padding: 2 3;
        }
        """

        BINDINGS = [
            Binding("escape", "dismiss_help", "Close", show=True),
            Binding("q", "dismiss_help", "Close", show=False),
        ]

        def compose(self) -> ComposeResult:
            with VerticalScroll(id="help-container"):
                yield Static(_build_help_text(), id="help-text")

        def action_dismiss_help(self) -> None:
            """Close the help screen."""
            self.app.pop_screen()
