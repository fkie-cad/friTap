"""Filter status bar widget — compact indicator showing active filter state.

The actual filter editing happens in the FilterModal. This widget displays
the current filter summary and match count. Pressing "/" on this widget
or clicking it re-opens the FilterModal.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from friTap.filter.evaluator import FilterEngine

try:
    from textual.app import ComposeResult
    from textual.containers import Horizontal
    from textual.message import Message
    from textual.widgets import Static
    TEXTUAL_AVAILABLE = True
except ImportError:
    TEXTUAL_AVAILABLE = False


if TEXTUAL_AVAILABLE:

    # Toggle label lookup for display
    _TOGGLE_LABELS: dict[str, str] = {
        "toggle-http": "HTTP",
        "toggle-errors": "Errors",
        "toggle-ohttp": "OHTTP",
        "toggle-ipsec": "IPSec",
        "toggle-ssh": "SSH",
    }

    class FilterBar(Horizontal):
        """Compact filter status indicator shown in flow view.

        Displays the active filter text, active toggles, and match count.
        Emits FilterChanged when the filter state is updated from the modal.
        """

        class FilterChanged(Message):
            """Emitted when the active filter expression changes."""
            def __init__(
                self,
                engine: "FilterEngine | None",
                toggle_engine: "FilterEngine | None",
            ) -> None:
                super().__init__()
                self.engine = engine
                self.toggle_engine = toggle_engine

        def __init__(self, **kwargs) -> None:
            super().__init__(**kwargs)
            self._current_engine: FilterEngine | None = None
            self._toggle_engine: FilterEngine | None = None
            self._filter_text: str = ""
            self._active_toggles: set[str] = set()

        def compose(self) -> ComposeResult:
            yield Static("[dim]/: open filter[/]", id="filter-summary")
            yield Static("", id="filter-status")

        # -- Public API for MainScreen ----------------------------------------

        def apply_result(
            self,
            text: str,
            text_engine: "FilterEngine | None",
            toggle_engine: "FilterEngine | None",
            active_toggles: set[str],
        ) -> None:
            """Apply a FilterResult from the FilterModal and emit FilterChanged."""
            self._filter_text = text
            self._current_engine = text_engine
            self._toggle_engine = toggle_engine
            self._active_toggles = set(active_toggles)
            self._update_summary()
            self.post_message(self.FilterChanged(self._current_engine, self._toggle_engine))

        def clear_filter(self) -> None:
            """Programmatically clear the active filter and emit FilterChanged."""
            if not self.has_active_filter:
                return
            self._filter_text = ""
            self._current_engine = None
            self._toggle_engine = None
            self._active_toggles = set()
            self._update_summary()
            self.post_message(self.FilterChanged(None, None))

        @property
        def filter_text(self) -> str:
            return self._filter_text

        @property
        def active_toggles(self) -> set[str]:
            return set(self._active_toggles)

        @property
        def has_active_filter(self) -> bool:
            return self._current_engine is not None or self._toggle_engine is not None

        def update_match_count(self, visible: int, total: int) -> None:
            """Update the match counter display."""
            status = self.query_one("#filter-status", Static)
            if not self.has_active_filter:
                status.update(f"[dim]{total} flows[/]")
            else:
                status.update(f"[bold]{visible}[/]/{total} flows")

        # -- Internal ---------------------------------------------------------

        def _update_summary(self) -> None:
            """Update the summary label with current filter state."""
            summary = self.query_one("#filter-summary", Static)
            parts: list[str] = []

            if self._filter_text:
                parts.append(f"[bold]Filter:[/] {self._filter_text}")

            if self._active_toggles:
                toggle_names = [
                    _TOGGLE_LABELS.get(tid, tid)
                    for tid in sorted(self._active_toggles)
                ]
                parts.append("[" + "] [".join(toggle_names) + "]")

            if parts:
                summary.update("  ".join(parts) + "  [dim](/: edit)[/]")
            else:
                summary.update("[dim]/: open filter[/]")
