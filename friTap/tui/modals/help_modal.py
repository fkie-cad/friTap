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

_HELP_TEXT = """\
[bold #38bdf8]friTap Keyboard Reference[/]

[bold #64748b]=== Target ===[/]
  [bold cyan]d[/]         Select device
  [bold cyan]a[/]         Attach to running process
  [bold cyan]s[/]         Spawn new application

[bold #64748b]=== Capture Mode ===[/]
  [bold cyan]1[/]         Full capture (keys + pcap)
  [bold cyan]2[/]         Key extraction only
  [bold cyan]3[/]         Plaintext pcap
  [bold cyan]4[/]         Live Wireshark pipe

[bold #64748b]=== Control ===[/]
  [bold cyan]Enter[/]     Start / Stop capture (toggle)
  [bold cyan]c[/]         Clear console
  [bold cyan]y[/]         Copy log to clipboard

[bold #64748b]=== Setup ===[/]
  [bold cyan]i[/]         Install & start frida-server

[bold #64748b]=== Options ===[/]
  [bold cyan]v[/]         Toggle verbose mode
  [bold cyan]e[/]         Toggle experimental mode
  [bold cyan]?[/]         Show this help

[bold #64748b]=== Navigation ===[/]
  [bold cyan]Tab[/]       Switch focus between panels
  [bold cyan]Esc[/]       Stop capture / close modal
  [bold cyan]q[/]         Quit friTap

[dim #8f9bb3]Press Esc or q to close this help screen.[/]
"""

if TEXTUAL_AVAILABLE:

    class HelpScreen(Screen):
        """Full-screen help overlay with keybinding reference."""

        DEFAULT_CSS = """
        HelpScreen {
            align: center middle;
            background: rgba(5, 8, 17, 0.92);
        }
        HelpScreen > #help-container {
            width: 60;
            max-height: 85%;
            background: #0d1117;
            border: solid #1e3a5f;
            padding: 2 3;
        }
        """

        BINDINGS = [
            Binding("escape", "dismiss_help", "Close", show=True),
            Binding("q", "dismiss_help", "Close", show=False),
        ]

        def compose(self) -> ComposeResult:
            with VerticalScroll(id="help-container"):
                yield Static(_HELP_TEXT, id="help-text")

        def action_dismiss_help(self) -> None:
            """Close the help screen."""
            self.app.pop_screen()
