#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ActivityLog widget for friTap TUI.

Extends RichLog with typed log methods for different event categories,
timestamped output, and ASCII welcome banner.
"""

from __future__ import annotations

from datetime import datetime
from typing import List

try:
    from textual.widgets import RichLog
    from rich.text import Text
    TEXTUAL_AVAILABLE = True
except ImportError:
    TEXTUAL_AVAILABLE = False

from friTap.tui.themes import c

# Raw logo parts: (fri_part, tap_part) — built as Text objects to avoid
# markup escaping issues (backslash + closing tag) and ReprHighlighter
# interference that corrupts colors on ASCII art characters.
_FRITAP_LOGO_PARTS = [
    ("  ___     _", " _____          "),
    (" / _|_ __(_)", "_   _|__ _ _ __ "),
    ("| |_| '__| |", " | |/ _` | '_  \\"),
    ("|  _| |  | |", " | | (_| | |_) |"),
    ("|_| |_|  |_|", " |_|\\__,_| .__/"),
    ("",            "                     |_|   "),
]


def _build_logo_line(fri_part: str, tap_part: str):
    """Build a single logo line as a rich Text object with consistent colors."""
    line = Text(no_wrap=True, overflow="ignore")
    if fri_part:
        line.append(fri_part, style=c('brand-fri'))
    if tap_part:
        line.append(tap_part, style=c('brand-tap'))
    return line


def _ts() -> str:
    """Return a short HH:MM:SS timestamp."""
    return datetime.now().strftime("%H:%M:%S")


if TEXTUAL_AVAILABLE:

    class ActivityLog(RichLog):
        """Real-time activity log with typed log methods."""

        _MAX_LINES = 10_000

        def __init__(self, **kwargs) -> None:
            super().__init__(
                highlight=True,
                markup=True,
                wrap=True,
                auto_scroll=True,
                **kwargs,
            )
            self._plain_lines: List[str] = []

        def _trim_lines(self) -> None:
            """Cap _plain_lines to _MAX_LINES, keeping the most recent."""
            if len(self._plain_lines) > self._MAX_LINES:
                self._plain_lines = self._plain_lines[-self._MAX_LINES:]

        # ----------------------------------------------------------
        # Welcome banner
        # ----------------------------------------------------------

        def show_welcome(self, version: str = "") -> None:
            """Display the friTap ASCII logo and version info."""
            for fri_part, tap_part in _FRITAP_LOGO_PARTS:
                self.write(_build_logo_line(fri_part, tap_part))
            if version:
                self.write(f"  [{c('info')}]v{version}[/]")
            self.write(f"  [{c('info')}]Real-time key extraction and traffic decryption[/]")
            self.write("")
            self.write(f"  [{c('text-dim')}]Press [bold]?[/bold] for help  |  [bold]d[/bold] to select device  |  [bold]q[/bold] to quit[/]")
            self.write("")

        # ----------------------------------------------------------
        # Typed log methods
        # ----------------------------------------------------------

        def log_info(self, message: str) -> None:
            """Log an informational message."""
            ts = _ts()
            self._plain_lines.append(f"{ts} INFO: {message}")
            self._trim_lines()
            self.write(f"[{c('text-dim')}]{ts}[/] [{c('info')}]INFO[/]  {message}")

        def log_error(self, message: str) -> None:
            """Log an error message."""
            ts = _ts()
            self._plain_lines.append(f"{ts} ERROR: {message}")
            self._trim_lines()
            self.write(f"[{c('text-dim')}]{ts}[/] [{c('error')}]ERROR[/] {message}")

        def log_warning(self, message: str) -> None:
            """Log a warning message."""
            ts = _ts()
            self._plain_lines.append(f"{ts} WARNING: {message}")
            self._trim_lines()
            self.write(f"[{c('text-dim')}]{ts}[/] [{c('warning')}]WARN[/]  {message}")

        def log_success(self, message: str) -> None:
            """Log a success message."""
            ts = _ts()
            self._plain_lines.append(f"{ts} SUCCESS: {message}")
            self._trim_lines()
            self.write(f"[{c('text-dim')}]{ts}[/] [{c('success')}]OK[/]    {message}")

        def log_key(self, preview: str) -> None:
            """Log a TLS key extraction event."""
            ts = _ts()
            self._plain_lines.append(f"{ts} KEY: {preview}")
            self._trim_lines()
            self.write(f"[{c('text-dim')}]{ts}[/] [{c('primary')}]KEY[/]   {preview}")

        def log_data(self, function: str, src: str, dst: str, size: str) -> None:
            """Log a captured data event."""
            ts = _ts()
            line = f"{function}: {src} -> {dst} ({size} bytes)"
            self._plain_lines.append(f"{ts} DATA: {line}")
            self._trim_lines()
            self.write(
                f"[{c('text-dim')}]{ts}[/] [{c('accent-data')}]DATA[/]  "
                f"[bold]{function}[/] {src} -> {dst} ({size}B)"
            )

        def log_library(self, name: str, path: str) -> None:
            """Log a library detection event."""
            ts = _ts()
            self._plain_lines.append(f"{ts} LIB: {name} ({path})")
            self._trim_lines()
            self.write(
                f"[{c('text-dim')}]{ts}[/] [{c('accent-library')}]LIB[/]   "
                f"[bold]{name}[/] ({path})"
            )

        def log_session(self, event_type: str) -> None:
            """Log a session lifecycle event."""
            ts = _ts()
            self._plain_lines.append(f"{ts} SESSION: {event_type}")
            self._trim_lines()
            self.write(
                f"[{c('text-dim')}]{ts}[/] [{c('secondary')}]SESSION[/] {event_type}"
            )

        def log_detach(self, reason: str) -> None:
            """Log a detach notification."""
            ts = _ts()
            self._plain_lines.append(f"{ts} DETACH: {reason}")
            self._trim_lines()
            self.write(
                f"[{c('text-dim')}]{ts}[/] [{c('warning')}]DETACH[/] {reason}"
            )

        def log_live(self, message: str) -> None:
            """Log a live Wireshark event."""
            ts = _ts()
            self._plain_lines.append(f"{ts} LIVE: {message}")
            self._trim_lines()
            self.write(f"[{c('text-dim')}]{ts}[/] [{c('accent')}]LIVE[/]  {message}")

        # ----------------------------------------------------------
        # Utilities
        # ----------------------------------------------------------

        def clear(self) -> None:
            """Clear the log and the plain-text buffer."""
            super().clear()
            self._plain_lines.clear()

        def get_plain_text(self) -> str:
            """Return all log lines as plain text for clipboard export."""
            return "\n".join(self._plain_lines)

        def get_line_count(self) -> int:
            """Return the number of plain-text log lines."""
            return len(self._plain_lines)
