#!/usr/bin/env python3

"""
Report modal for the friTap TUI.

Shows the ``fritap report`` digest (hosts, endpoints and findings grouped per
protocol, with OWASP MASVS tags) for the current capture or replay, rendered as
scrollable text. The ``focus`` (all / security / privacy) is cycled with ``f``;
``Esc`` closes. The digest text is displayed with ``markup=False`` (as a Rich
``Text``) so attacker-controlled hosts/paths in the capture can never inject
console markup.

The modal is data-source agnostic: it is handed a ``make_markdown(focus)``
callable by the screen (replay reads the ``.tap``; a live session digests the
in-memory flows), so this widget knows nothing about where the flows come from.
"""

from __future__ import annotations

from typing import Callable, Optional

try:
    from textual.app import ComposeResult
    from textual.binding import Binding
    from textual.containers import Vertical, VerticalScroll
    from textual.widgets import Static
    TEXTUAL_AVAILABLE = True
except ImportError:
    TEXTUAL_AVAILABLE = False


if TEXTUAL_AVAILABLE:
    from rich.text import Text

    from friTap.tui.themes import c

    from .base import FriTapModal

    class ReportModal(FriTapModal[Optional[None]]):
        """Scrollable digest/report view with a cyclable focus."""

        DEFAULT_CSS = """
        ReportModal > #modal-container {
            width: 110;
            max-width: 95%;
            height: 90%;
            max-height: 90%;
        }
        ReportModal #report-scroll {
            height: 1fr;
            margin: 1 0;
        }
        """

        BINDINGS = [
            Binding("escape", "cancel", "Close", show=True),
            Binding("f", "cycle_focus", "Focus", show=True),
        ]

        #: Focus values the ``f`` key cycles through, matching FOCUS_CHOICES.
        FOCUSES: tuple[str, ...] = ("all", "security", "privacy")

        def __init__(self, make_markdown: Callable[[str], str],
                     initial: str = "all", **kwargs) -> None:
            super().__init__(**kwargs)
            self._make_markdown = make_markdown
            try:
                self._idx = self.FOCUSES.index(initial)
            except ValueError:
                self._idx = 0

        @property
        def _focus(self) -> str:
            return self.FOCUSES[self._idx]

        def compose(self) -> ComposeResult:
            # Content is provided at compose time (non-empty), like HelpScreen,
            # and the body is a Rich Text so captured content is never parsed as
            # console markup.
            with Vertical(id="modal-container"):
                yield Static(self._title_markup(), classes="modal-title", id="report-title")
                with VerticalScroll(id="report-scroll"):
                    yield Static(Text(self._markdown()), id="report-body")
                yield Static(
                    f"[{c('text-muted')}]f: change focus  ·  Esc: close[/]",
                    classes="key-hints",
                )

        def on_mount(self) -> None:
            # Focus the scroll region so arrow/page keys scroll the report.
            try:
                self.query_one("#report-scroll").focus()
            except Exception:
                pass

        def action_cycle_focus(self) -> None:
            self._idx = (self._idx + 1) % len(self.FOCUSES)
            self._refresh()

        def _title_markup(self) -> str:
            return (f"[bold {c('primary')}]Report[/] "
                    f"[dim]· focus: {self._focus} · MASVS · f: change focus[/]")

        def _markdown(self) -> str:
            try:
                return self._make_markdown(self._focus)
            except Exception as exc:  # noqa: BLE001 — never let a render error crash the TUI
                return f"Report failed: {exc}"

        def _refresh(self) -> None:
            try:
                self.query_one("#report-title", Static).update(self._title_markup())
                self.query_one("#report-body", Static).update(Text(self._markdown()))
            except Exception:
                pass
