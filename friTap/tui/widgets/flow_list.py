"""Flow list widget — mitmproxy-style interactive flow table."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from friTap.flow.models import Flow, FlowSummary
    from friTap.filter.evaluator import FilterEngine

try:
    from textual.widgets import DataTable
    from textual.message import Message
    TEXTUAL_AVAILABLE = True
except ImportError:
    TEXTUAL_AVAILABLE = False

from friTap.constants import PROTOCOL_HTTP1, PROTOCOL_HTTP2, PROTOCOL_HTTP3, PROTOCOL_WEBSOCKET
from friTap.tui.themes import c

if TEXTUAL_AVAILABLE:
    from datetime import datetime
    from friTap.flow.models import FlowState, FlowSummary

    class FlowListWidget(DataTable):
        """Interactive flow list displayed as a DataTable.

        Columns: # | Timestamp | Protocol | Method | Host + Path | Status | Size | Duration

        Supports display filtering via set_filter(). Filtering is non-destructive:
        all flows are kept in _all_flow_data, and only visible flows appear in
        the DataTable.
        """

        class FlowSelected(Message):
            """Emitted when a flow row is selected."""
            def __init__(self, flow_id: str) -> None:
                super().__init__()
                self.flow_id = flow_id

        def __init__(self, **kwargs) -> None:
            super().__init__(**kwargs)
            self._flow_row_keys: dict[str, object] = {}  # flow_id -> row_key (visible only)
            self._flow_counter = 0
            self._auto_scroll = True
            self.cursor_type = "row"
            self.zebra_stripes = True
            self._extra_columns: list = []  # ColumnProvider instances
            # Filter state — preserves insertion order (Python 3.7+)
            self._all_flow_data: dict[str, "FlowSummary"] = {}
            self._filter_engine: "FilterEngine | None" = None
            # Cell value cache — only update cells whose values changed
            self._row_cache: dict[str, list] = {}
            self._toggle_engine: "FilterEngine | None" = None
            self._filter_bar_ref = None  # cached FilterBar reference

        # Total space for all columns except Connection: column widths (61) + cell padding (8×2) + scrollbar (2).
        _FIXED_COLS_WIDTH = 79

        def register_column(self, provider) -> None:
            """Register a plugin ColumnProvider for an extra column."""
            self._extra_columns.append(provider)

        @property
        def _connection_col_width(self) -> int:
            """Width for the Connection column — fills remaining space."""
            available = self.size.width - self._FIXED_COLS_WIDTH
            return max(available, 30)

        def on_mount(self) -> None:
            """Set up columns with explicit widths so Connection fills remaining space."""
            self.add_column("#", width=5)
            self.add_column("Time", width=10)
            self.add_column("Proto", width=10)
            self.add_column("Method", width=8)
            self.add_column("Connection", width=self._connection_col_width)
            self.add_column("Status", width=8)
            self.add_column("Size", width=10)
            self.add_column("Duration", width=10)
            for col_provider in self._extra_columns:
                self.add_column(col_provider.name)

        def on_resize(self, event) -> None:
            """Update Connection column width when terminal is resized."""
            try:
                cols = list(self.columns.keys())
                if len(cols) >= 5:
                    self.columns[cols[4]].width = self._connection_col_width
            except Exception:
                pass

        # -- Filter API -------------------------------------------------------

        def set_filter(
            self,
            engine: "FilterEngine | None",
            toggle_engine: "FilterEngine | None" = None,
        ) -> None:
            """Apply a new display filter. Rebuilds visible rows to match."""
            self._filter_engine = engine
            self._toggle_engine = toggle_engine
            self._rebuild_visible()

        def _passes_filter(self, flow: "Flow | FlowSummary") -> bool:
            """Return True if the flow passes both the text and toggle filters."""
            if self._filter_engine and not self._filter_engine.matches(flow):
                return False
            if self._toggle_engine and not self._toggle_engine.matches(flow):
                return False
            return True

        @property
        def visible_count(self) -> int:
            return len(self._flow_row_keys)

        @property
        def total_count(self) -> int:
            return len(self._all_flow_data)

        # -- Flow operations --------------------------------------------------

        def add_or_update_flow(self, flow: "Flow") -> None:
            """Add a new flow row or update an existing one.

            Converts the Flow to a FlowSummary (~200 bytes) so the list
            widget does not pin full Flow objects with chunks and body data.
            Skips re-creation when nothing display-relevant has changed.
            """
            old = self._all_flow_data.get(flow.flow_id)
            if (old is not None
                    and old.state == flow.state
                    and old.total_bytes == flow._total_bytes
                    and (old.request is not None) == (flow.request is not None)
                    and (old.response is not None) == (flow.response is not None)):
                summary = old
            else:
                summary = FlowSummary.from_flow(flow)
                self._all_flow_data[flow.flow_id] = summary

            visible = self._passes_filter(summary)

            if flow.flow_id in self._flow_row_keys:
                if visible:
                    self._update_row(summary)
                else:
                    # Was visible, no longer passes filter → remove from table
                    try:
                        self.remove_row(self._flow_row_keys.pop(flow.flow_id))
                    except Exception:
                        self._flow_row_keys.pop(flow.flow_id, None)
                    self._row_cache.pop(flow.flow_id, None)
            elif visible:
                self._add_row(summary)

            self._notify_match_count()

        _SHORT_PROTO = {
            PROTOCOL_HTTP1: "HTTP",
            PROTOCOL_HTTP2: "H2",
            PROTOCOL_HTTP3: "H3",
            PROTOCOL_WEBSOCKET: "WS",
        }

        @staticmethod
        def _format_method(flow) -> str:
            """Format method column, appending protocol badge if trailing data exists."""
            method = flow.display_method or "-"
            if flow.has_trailing_data:
                short = FlowListWidget._SHORT_PROTO.get(flow.trailing_protocol, "")
                badge = f"+{short}" if short else "+data"
                method = f"{method} [{c('warning')}]{badge}[/]"
            return method

        def _add_row(self, flow: "Flow") -> None:
            self._flow_counter += 1
            ts = datetime.fromtimestamp(flow.started).strftime("%H:%M:%S")

            values = [
                str(self._flow_counter),
                ts,
                flow.display_protocol.upper() if flow.display_protocol != "unknown" else "???",
                self._format_method(flow),
                flow.display_connection or "-",
                self._format_status(flow),
                flow.display_size,
                self._format_duration(flow),
            ]
            # Append plugin column values
            for col_provider in self._extra_columns:
                try:
                    values.append(col_provider.value(flow))
                except Exception:
                    values.append("-")

            row_key = self.add_row(*values, key=flow.flow_id)
            self._flow_row_keys[flow.flow_id] = row_key

            if self._auto_scroll:
                self.scroll_end(animate=False)

        def _update_row(self, flow: "Flow") -> None:
            """Update an existing row — only update cells whose values changed."""
            try:
                row_key = self._flow_row_keys[flow.flow_id]

                cols = list(self.columns.keys())
                if len(cols) < 8:
                    return

                new_vals = [
                    flow.display_protocol.upper() if flow.display_protocol != "unknown" else "???",
                    self._format_method(flow),
                    flow.display_connection or "-",
                    self._format_status(flow),
                    flow.display_size,
                    self._format_duration(flow),
                ]
                # Diff against cached values — only update changed cells
                old_vals = self._row_cache.get(flow.flow_id)
                if old_vals is None:
                    old_vals = [None] * len(new_vals)
                for i, (old, new) in enumerate(zip(old_vals, new_vals)):
                    if old != new:
                        self.update_cell(row_key, cols[i + 2], new)
                self._row_cache[flow.flow_id] = new_vals

                # Update plugin columns
                for i, col_provider in enumerate(self._extra_columns):
                    col_idx = 8 + i
                    if col_idx < len(cols):
                        try:
                            self.update_cell(row_key, cols[col_idx], col_provider.value(flow))
                        except Exception:
                            pass
            except Exception:
                pass

        def _rebuild_visible(self) -> None:
            """Rebuild the DataTable showing only flows that pass the filter.

            Called when the filter changes. Maintains insertion order.
            """
            self.clear()
            self._flow_row_keys.clear()
            self._row_cache.clear()
            self._flow_counter = 0

            for flow in self._all_flow_data.values():
                if self._passes_filter(flow):
                    self._add_row(flow)

            self._notify_match_count()

        def _notify_match_count(self) -> None:
            """Post match count to FilterBar if available."""
            if self._filter_bar_ref is None:
                try:
                    from .filter_bar import FilterBar
                    self._filter_bar_ref = self.screen.query_one("#filter-bar", FilterBar)
                except Exception:
                    return
            try:
                self._filter_bar_ref.update_match_count(self.visible_count, self.total_count)
            except Exception:
                self._filter_bar_ref = None

        def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
            """When a row is selected, emit FlowSelected."""
            flow_id = str(event.row_key.value) if event.row_key else None
            if flow_id:
                self.post_message(self.FlowSelected(flow_id))

        def clear_flows(self) -> None:
            """Clear all flows from the table and backing store."""
            self.clear()
            self._flow_row_keys.clear()
            self._flow_counter = 0
            self._all_flow_data.clear()

        def _format_status(self, flow: "Flow") -> str:
            status = flow.display_status
            if not status:
                return "..."
            code = 0
            try:
                code = int(status.split()[0])
            except (ValueError, IndexError):
                pass
            if 200 <= code < 300:
                return f"[{c('success')}]{status}[/]"
            elif 300 <= code < 400:
                return f"[{c('warning')}]{status}[/]"
            elif code >= 400:
                return f"[{c('error')}]{status}[/]"
            return status

        def _format_duration(self, flow: "Flow") -> str:
            if flow.state != FlowState.COMPLETE:
                return "..."
            d = flow.duration
            if d < 0.001:
                return "<1ms"
            if d < 1:
                return f"{d*1000:.0f}ms"
            return f"{d:.2f}s"

        @staticmethod
        def _truncate(text: str, max_len: int) -> str:
            if len(text) <= max_len:
                return text
            return text[:max_len - 3] + "..."
