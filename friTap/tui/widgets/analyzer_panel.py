"""Analyzer panel widget — interactive analyzer chooser and results dashboard.

A single docked panel with two visual states held in one widget:

* **Chooser** — a multi-select list of analyzer names, an optional one-off
  plugin-path input, a progress line, and Run/Clear actions. This is the
  default state.
* **Dashboard** — shown once results exist; renders selectable chips grouped
  by severity, analyzer (source), and category, built from the dict returned
  by :func:`~friTap.analysis.filtering.summarize`. Selecting a chip emits a
  :class:`~friTap.analysis.filtering.FindingFilter` so the host can drive the
  findings view.

Mirrors the Message/posting conventions of
:class:`~friTap.tui.widgets.findings_filter_bar.FindingsFilterBar` and
:class:`~friTap.tui.widgets.findings_list.FindingsListWidget`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from friTap.analysis.filtering import FindingFilter

try:
    from textual.app import ComposeResult
    from textual.binding import Binding
    from textual.containers import Horizontal, Vertical
    from textual.message import Message
    from textual.widgets import Button, Input, SelectionList, Static
    from textual.widgets.selection_list import Selection
    TEXTUAL_AVAILABLE = True
except ImportError:
    TEXTUAL_AVAILABLE = False


if TEXTUAL_AVAILABLE:
    from friTap.analysis.filtering import FindingFilter

    class AnalyzerPanel(Vertical):
        """Interactive analyzer chooser and results dashboard.

        Toggles between a chooser container and a dashboard container by
        flipping their ``.display`` flags. Posts intent messages (run, clear,
        chip-selected, close) for the host screen to act on.
        """

        class RunRequested(Message):
            """Emitted when the user asks to run the selected analyzers."""
            def __init__(self, analyzer_names: list[str], analyzer_path: str | None) -> None:
                super().__init__()
                self.analyzer_names = analyzer_names
                self.analyzer_path = analyzer_path

        class ClearRequested(Message):
            """Emitted when the user asks to clear analyzer results."""

        class ChipSelected(Message):
            """Emitted when a dashboard chip is selected; carries a FindingFilter."""
            def __init__(self, flt: "FindingFilter", label: str) -> None:
                super().__init__()
                self.flt = flt
                self.label = label

        class CloseRequested(Message):
            """Emitted when the user asks to close the panel."""

        BINDINGS = [
            Binding("r", "run", "Run", show=False),
            Binding("x", "clear", "Clear", show=False),
            Binding("escape", "close", "Close", show=False),
        ]

        DEFAULT_CSS = """
        AnalyzerPanel {
            width: auto;
            height: auto;
        }
        AnalyzerPanel #analyzer-dashboard {
            height: auto;
        }
        AnalyzerPanel .chip-row {
            height: auto;
            margin: 0 0 1 0;
        }
        AnalyzerPanel .analyzer-chip {
            min-width: 8;
            height: 1;
            margin: 0 1 0 0;
        }
        AnalyzerPanel #analyzer-actions {
            height: auto;
        }
        AnalyzerPanel #analyzer-progress {
            height: 1;
            margin: 0;
        }
        AnalyzerPanel #analyzer-path-input {
            height: 3;
            margin: 0;
        }
        """

        def __init__(self, **kwargs) -> None:
            super().__init__(**kwargs)
            self._available: list[str] = []
            # Maps each dashboard chip's button id -> the FindingFilter it
            # applies. Ids are index-based so they stay valid widget ids even
            # when an analyzer/category name contains spaces or dots.
            self._chip_filters: dict[str, "FindingFilter"] = {}

        # -- Compose ----------------------------------------------------------

        def compose(self) -> ComposeResult:
            with Vertical(id="analyzer-chooser"):
                yield SelectionList(id="analyzer-select")
                yield Input(
                    placeholder="one-off plugin path  module:Class  (optional)",
                    id="analyzer-path-input",
                )
                yield Static("Idle", id="analyzer-progress")
                with Horizontal(id="analyzer-actions"):
                    yield Button("Run (r)", id="analyzer-run-btn", variant="primary")
                    yield Button("Clear (x)", id="analyzer-clear-btn")
            dashboard = Vertical(id="analyzer-dashboard")
            dashboard.display = False
            yield dashboard

        # -- Chooser population ----------------------------------------------

        def set_available(self, names: list[str]) -> None:
            """Populate the analyzer SelectionList, selecting all by default.

            When re-populating, names that were previously selected stay
            selected; on the first population every analyzer is selected.
            """
            previously = set(self.selected_names()) if self._available else None
            self._available = list(names)
            sel = self.query_one("#analyzer-select", SelectionList)
            sel.clear_options()
            for name in self._available:
                initial = name in previously if previously is not None else True
                sel.add_option(Selection(name, name, initial))

        def selected_names(self) -> list[str]:
            """Return the analyzer names currently selected in the list."""
            try:
                sel = self.query_one("#analyzer-select", SelectionList)
            except Exception:
                return []
            return list(sel.selected)

        # -- Progress ---------------------------------------------------------

        def set_progress(self, done: int, total: int, label: str = "") -> None:
            """Update the progress Static line."""
            try:
                progress = self.query_one("#analyzer-progress", Static)
            except Exception:
                return
            if label:
                progress.update(label)
            elif total == 0 and done == 0:
                progress.update("Idle")
            else:
                progress.update(f"Running {done}/{total} flows…")

        # -- Dashboard --------------------------------------------------------

        def show_dashboard(self, summary: dict) -> None:
            """Switch to the dashboard state and (re)build chips from *summary*.

            *summary* is the dict returned by
            :func:`~friTap.analysis.filtering.summarize`:
            ``{total, by_severity, by_source, by_category}``.
            """
            chooser = self.query_one("#analyzer-chooser", Vertical)
            dashboard = self.query_one("#analyzer-dashboard", Vertical)
            chooser.display = False
            dashboard.display = True
            dashboard.remove_children()
            self._chip_filters.clear()

            total = summary.get("total", 0)
            dashboard.mount(Static(f"[bold]Analyzers — {total} findings[/]"))

            dashboard.mount(self._build_chip_row(
                summary.get("by_severity", {}), "sev",
                label=lambda v: str(v).upper(),
                # Exact severity bucket (not a floor) so the chip's count matches
                # the filtered result, consistent with the source/category chips.
                make_filter=lambda v: FindingFilter(severities=frozenset({str(v)})),
            ))
            dashboard.mount(self._build_chip_row(
                summary.get("by_source", {}), "src",
                make_filter=lambda v: FindingFilter(sources=frozenset({v})),
            ))
            dashboard.mount(self._build_chip_row(
                summary.get("by_category", {}), "cat",
                make_filter=lambda v: FindingFilter(categories=frozenset({v})),
            ))
            dashboard.mount(self._build_actions_row(total))

        def _build_chip_row(self, items: dict, kind: str, *, make_filter,
                             label=str) -> "Horizontal":
            """Build one row of selectable chips from a ``{value: count}`` mapping.

            Records each chip's :class:`FindingFilter` under its index-based id in
            ``_chip_filters`` so press handling is a dict lookup rather than
            parsing the value back out of the id.
            """
            buttons = []
            for i, (value, count) in enumerate(items.items()):
                btn_id = f"chip-{kind}-{i}"
                self._chip_filters[btn_id] = make_filter(value)
                buttons.append(
                    Button(f"{label(value)} {count}", id=btn_id, classes="analyzer-chip")
                )
            return Horizontal(*buttons, classes="chip-row")

        def _build_actions_row(self, total: int) -> "Horizontal":
            # Distinct ids from the chooser's run/clear buttons (which remain in
            # the DOM, merely hidden) to avoid duplicate widget ids in the tree.
            self._chip_filters["chip-all"] = FindingFilter()
            buttons = [
                Button(f"View all {total}", id="chip-all", classes="analyzer-chip"),
                Button("Re-run (r)", id="analyzer-rerun-btn", variant="primary",
                       classes="analyzer-chip"),
                Button("Clear (x)", id="analyzer-clearall-btn", classes="analyzer-chip"),
            ]
            return Horizontal(*buttons, classes="chip-row")

        def reset(self) -> None:
            """Return to the chooser state and set progress to Idle."""
            try:
                chooser = self.query_one("#analyzer-chooser", Vertical)
                dashboard = self.query_one("#analyzer-dashboard", Vertical)
            except Exception:
                return
            dashboard.display = False
            chooser.display = True
            self.set_progress(0, 0)

        # -- Actions ----------------------------------------------------------

        def action_run(self) -> None:
            path = self._path_input_value()
            self.post_message(self.RunRequested(self.selected_names(), path))

        def action_clear(self) -> None:
            self.post_message(self.ClearRequested())

        def action_close(self) -> None:
            self.post_message(self.CloseRequested())

        def _path_input_value(self) -> str | None:
            try:
                value = self.query_one("#analyzer-path-input", Input).value.strip()
            except Exception:
                return None
            return value or None

        # -- Button routing ---------------------------------------------------

        def on_button_pressed(self, event: "Button.Pressed") -> None:
            btn_id = event.button.id

            if btn_id in ("analyzer-run-btn", "analyzer-rerun-btn"):
                self.action_run()
                return
            if btn_id in ("analyzer-clear-btn", "analyzer-clearall-btn"):
                self.action_clear()
                return

            flt = self._chip_filters.get(btn_id) if btn_id else None
            if flt is not None:
                label = str(event.button.label) if event.button.label else ""
                self.post_message(self.ChipSelected(flt, label))
