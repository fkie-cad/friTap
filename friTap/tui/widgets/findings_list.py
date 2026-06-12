"""Findings list widget — interactive table of analysis findings.

Mirrors :class:`~friTap.tui.widgets.flow_list.FlowListWidget`: findings are
held in a backing store (``_all_findings``) and display filtering is
non-destructive — only findings passing the active :class:`FindingFilter`
appear in the DataTable.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from friTap.analysis import Finding
    from friTap.analysis.filtering import FindingFilter

try:
    from textual.widgets import DataTable
    from textual.message import Message
    TEXTUAL_AVAILABLE = True
except ImportError:
    TEXTUAL_AVAILABLE = False

from friTap.tui.themes import c

if TEXTUAL_AVAILABLE:
    from friTap.analysis import Severity

    class FindingsListWidget(DataTable):
        """Interactive findings list displayed as a DataTable.

        Columns: Severity | Source | Category | Conf | Title | Flow

        Supports display filtering via set_filter(). Filtering is
        non-destructive: all findings are kept in _all_findings, and only
        findings passing the filter appear in the DataTable.
        """

        class FindingSelected(Message):
            """Emitted when a finding row is selected."""
            def __init__(self, index: int, flow_id: str) -> None:
                super().__init__()
                self.index = index
                self.flow_id = flow_id

        def __init__(self, **kwargs) -> None:
            super().__init__(**kwargs)
            self.cursor_type = "row"
            self.zebra_stripes = True
            self._all_findings: list["Finding"] = []
            self._filter: "FindingFilter | None" = None
            # Row key (str index) -> nothing; we track visible indices in order.
            self._visible_indices: list[int] = []
            self._filter_bar_ref = None  # cached FindingsFilterBar reference

        # Fixed column widths (Severity..Conf..Flow) + cell padding + scrollbar.
        # Severity(9)+Source(13)+Category(11)+Conf(6)+Flow(14) = 53 cols
        # + padding (5 cols × 2) + scrollbar (2) = 65
        _FIXED_COLS_WIDTH = 65

        @property
        def _title_col_width(self) -> int:
            """Width for the Title column — fills remaining space."""
            available = self.size.width - self._FIXED_COLS_WIDTH
            return max(available, 20)

        def on_mount(self) -> None:
            """Set up columns with explicit widths so Title fills remaining space."""
            self.add_column("Severity", width=9)
            self.add_column("Source", width=13)
            self.add_column("Category", width=11)
            self.add_column("Conf", width=6)
            self.add_column("Title", width=self._title_col_width)
            self.add_column("Flow", width=14)

        def on_resize(self, event) -> None:
            """Update Title column width when terminal is resized."""
            try:
                cols = list(self.columns.keys())
                if len(cols) >= 5:
                    self.columns[cols[4]].width = self._title_col_width
            except Exception:
                pass

        # -- Backing store API ------------------------------------------------

        def add_findings(self, findings: list["Finding"]) -> None:
            """Append findings to the backing store and rebuild visible rows."""
            self._all_findings.extend(findings)
            self._rebuild_visible()

        def clear_findings(self) -> None:
            """Clear all findings from the table and backing store."""
            self.clear()
            self._all_findings.clear()
            self._visible_indices.clear()

        # -- Filter API -------------------------------------------------------

        def set_filter(self, flt: "FindingFilter | None") -> None:
            """Apply a new display filter. Rebuilds visible rows to match."""
            self._filter = flt
            self._rebuild_visible()

        def _passes_filter(self, finding: "Finding") -> bool:
            """Return True if the finding passes the active filter."""
            if self._filter is None:
                return True
            return self._filter.matches(finding)

        @property
        def visible_count(self) -> int:
            return len(self._visible_indices)

        @property
        def total_count(self) -> int:
            return len(self._all_findings)

        # -- Row rendering ----------------------------------------------------

        @staticmethod
        def _format_severity(finding: "Finding") -> str:
            """Format the Severity cell with theme-aware color markup."""
            sev = finding.severity
            label = sev.value.upper()
            if sev == Severity.CRITICAL:
                return f"[bold {c('error')}]{label}[/]"
            if sev == Severity.HIGH:
                return f"[{c('error')}]{label}[/]"
            if sev == Severity.MEDIUM:
                return f"[{c('warning')}]{label}[/]"
            if sev == Severity.LOW:
                return f"[{c('info')}]{label}[/]"
            return f"[{c('text-muted')}]{label}[/]"

        @staticmethod
        def _format_conf(finding: "Finding") -> str:
            try:
                return f"{finding.confidence:.0%}"
            except Exception:
                return "-"

        def _add_row(self, index: int, finding: "Finding") -> None:
            values = [
                self._format_severity(finding),
                finding.source or "-",
                finding.category or "-",
                self._format_conf(finding),
                finding.title or "-",
                (finding.flow_id[:12] if finding.flow_id else "-"),
            ]
            self.add_row(*values, key=str(index))
            self._visible_indices.append(index)

        def _rebuild_visible(self) -> None:
            """Rebuild the DataTable showing only findings that pass the filter."""
            self.clear()
            self._visible_indices.clear()
            for index, finding in enumerate(self._all_findings):
                if self._passes_filter(finding):
                    self._add_row(index, finding)
            self._notify_match_count()

        def _notify_match_count(self) -> None:
            """Post match count to the FindingsFilterBar if available."""
            if self._filter_bar_ref is None:
                try:
                    from .findings_filter_bar import FindingsFilterBar
                    self._filter_bar_ref = self.screen.query_one(
                        "#findings-filter-bar", FindingsFilterBar
                    )
                except Exception:
                    return
            try:
                self._filter_bar_ref.update_match_count(
                    self.visible_count, self.total_count
                )
            except Exception:
                self._filter_bar_ref = None

        def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
            """When a row is selected, emit FindingSelected."""
            if event.row_key is None or event.row_key.value is None:
                return
            try:
                index = int(event.row_key.value)
            except (ValueError, TypeError):
                return
            if 0 <= index < len(self._all_findings):
                flow_id = self._all_findings[index].flow_id or ""
                self.post_message(self.FindingSelected(index, flow_id))
