"""Findings filter status bar widget — compact indicator for findings view.

The actual filter editing happens in the FindingsFilterModal. This widget
displays the current filter summary and match count, and offers quick-filter
key hints. Mirrors :class:`~friTap.tui.widgets.filter_bar.FilterBar`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from friTap.analysis.filtering import FindingFilter

try:
    from textual.app import ComposeResult
    from textual.containers import Horizontal
    from textual.message import Message
    from textual.widgets import Static
    TEXTUAL_AVAILABLE = True
except ImportError:
    TEXTUAL_AVAILABLE = False


if TEXTUAL_AVAILABLE:

    _HINT = "[dim]/: filter  c: creds  p: pii  1: critical  shift+esc: clear[/]"

    class FindingsFilterBar(Horizontal):
        """Compact filter status indicator shown in findings view.

        Displays the active findings filter label and match count.
        Emits FindingsFilterChanged when the filter state is updated.
        """

        class FindingsFilterChanged(Message):
            """Emitted when the active findings filter changes."""
            def __init__(self, flt: "FindingFilter | None") -> None:
                super().__init__()
                self.flt = flt

        def __init__(self, **kwargs) -> None:
            super().__init__(**kwargs)
            self._current_filter: "FindingFilter | None" = None
            self._label: str = ""

        def compose(self) -> ComposeResult:
            yield Static(_HINT, id="findings-filter-summary")
            yield Static("", id="findings-filter-status")

        # -- Public API for MainScreen ----------------------------------------

        def apply_filter(self, flt: "FindingFilter | None", label: str = "") -> None:
            """Apply a FindingFilter and emit FindingsFilterChanged."""
            self._current_filter = flt
            self._label = label
            self._update_summary()
            self.post_message(self.FindingsFilterChanged(self._current_filter))

        def clear_filter(self) -> None:
            """Programmatically clear the active filter and emit the change."""
            if not self.has_active_filter:
                return
            self._current_filter = None
            self._label = ""
            self._update_summary()
            self.post_message(self.FindingsFilterChanged(None))

        @property
        def has_active_filter(self) -> bool:
            return self._current_filter is not None

        @property
        def label(self) -> str:
            return self._label

        def update_match_count(self, visible: int, total: int) -> None:
            """Update the match counter display."""
            try:
                status = self.query_one("#findings-filter-status", Static)
            except Exception:
                return
            if not self.has_active_filter:
                status.update(f"[dim]{total} findings[/]")
            else:
                status.update(f"[bold]{visible}[/]/{total} findings")

        # -- Internal ---------------------------------------------------------

        def _update_summary(self) -> None:
            """Update the summary label with current filter state."""
            try:
                summary = self.query_one("#findings-filter-summary", Static)
            except Exception:
                return
            if self.has_active_filter:
                shown = self._label or "active"
                summary.update(f"[bold]Filter:[/] {shown}  [dim](/: edit  shift+esc: clear)[/]")
            else:
                summary.update(_HINT)
