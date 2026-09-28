"""Flow list widget — mitmproxy-style interactive flow table."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from friTap.filter.evaluator import FilterEngine
    from friTap.flow.models import Flow, FlowSummary

try:
    from textual.message import Message
    from textual.widgets import DataTable
    TEXTUAL_AVAILABLE = True
except ImportError:
    TEXTUAL_AVAILABLE = False

from friTap.constants import (
    PROTOCOL_HTTP1,
    PROTOCOL_HTTP2,
    PROTOCOL_HTTP3,
    PROTOCOL_MTPROTO,
    PROTOCOL_SIGNAL,
    PROTOCOL_TELEGRAM_E2E,
    PROTOCOL_WEBSOCKET,
)
from friTap.filter.content_index import FlowContentIndex
from friTap.filter.layer_fields import filter_attrs_key
from friTap.tui.themes import c


def layer_signature(flow: object) -> tuple:
    """Cheap fingerprint of a flow's layer-derived, byte-independent state.

    Captures what can change without the byte count moving (a reparse, late
    TLS metadata, MTProto messages or dc_id/auth_key_id set after the fact):
    the detected protocol, the process name, the TLS session id (it adds the
    ``tls`` protocol) and, as the LAST element, :func:`filter_attrs_key` --
    per layer its name, message count and every scalar a display-filter field
    reads (TLS SNI/ALPN/version/cipher, MTProto dc_id/envelope ...), so a
    filterable attribute can never change without a summary rebuild.
    Iterates ``flow.layers`` directly and never reads ``flow.<layer name>``,
    which would auto-create an empty layer.
    """
    return (getattr(flow, "detected_protocol", "") or "",
            getattr(flow, "process_name", "") or "",
            getattr(flow, "ssl_session_id", "") or "",
            filter_attrs_key(flow))


if TEXTUAL_AVAILABLE:
    from datetime import datetime

    from friTap.flow.display import is_message_transport, message_direction_status
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
            # flow_id -> layer_signature() the stored summary was built from.
            self._layer_signatures: dict[str, tuple] = {}
            # flow_id -> filter_attrs_key() the stored summary's attrs came from.
            self._filter_attrs_keys: dict[str, tuple] = {}
            self._filter_engine: "FilterEngine | None" = None
            # Cell value cache — only update cells whose values changed
            self._row_cache: dict[str, list] = {}
            self._toggle_engine: "FilterEngine | None" = None
            self._filter_bar_ref = None  # cached FilterBar reference
            # Content-aware Proto/Method widths: start compact, grow only when a
            # row actually needs it (e.g. HTTP/2[Signal], "1:1 · 4 msgs").
            self._proto_w = self._BASE_PROTO_WIDTH
            self._method_w = self._BASE_METHOD_WIDTH
            # Searchable content for ``frame`` filters; built lazily, only for
            # engines that need it. The owning screen injects the flow lookup.
            self._content_index = FlowContentIndex()

        # Compact defaults — fit plain protos (HTTP/2, WS) and short methods.
        _BASE_PROTO_WIDTH = 10
        _BASE_METHOD_WIDTH = 8
        # Caps so a long layered label can't starve the Connection column.
        # 24 fits "WebSocket[Telegram-E2E]" (23); 16 fits "group · 12 msgs" (15).
        _MAX_PROTO_WIDTH = 24
        _MAX_METHOD_WIDTH = 16
        # Fixed width of the non-flexible columns (# + Time + Status + Size +
        # Duration = 43) and the per-table overhead (8 cols × 2 padding + 2
        # scrollbar = 18). Proto/Method are added dynamically; Connection fills
        # the rest. With base widths this reproduces the former constant 79.
        _NONFLEX_BASE = 43
        _PADDING_AND_SCROLLBAR = 18

        def register_column(self, provider) -> None:
            """Register a plugin ColumnProvider for an extra column."""
            self._extra_columns.append(provider)

        @property
        def _connection_col_width(self) -> int:
            """Width for the Connection column — fills the space left after the
            (possibly widened) Proto/Method columns."""
            fixed = (self._NONFLEX_BASE + self._proto_w + self._method_w
                     + self._PADDING_AND_SCROLLBAR)
            return max(self.size.width - fixed, 30)

        def on_mount(self) -> None:
            """Set up columns with explicit widths so Connection fills remaining space."""
            self.add_column("#", width=5)
            self.add_column("Time", width=10)
            self.add_column("Proto", width=self._proto_w)
            self.add_column("Method", width=self._method_w)
            self.add_column("Connection", width=self._connection_col_width)
            self.add_column("Status", width=8)
            self.add_column("Size", width=10)
            self.add_column("Duration", width=10)
            for col_provider in self._extra_columns:
                self.add_column(col_provider.name)

        def on_resize(self, event) -> None:
            """Reflow Proto/Method/Connection widths when the terminal resizes."""
            self._apply_column_widths()

        def _apply_column_widths(self) -> None:
            """Push the current Proto/Method widths to the table and refill the
            Connection column. Cheap and idempotent; safe to call on every change."""
            try:
                cols = list(self.columns.keys())
                if len(cols) < 5:
                    return
                self.columns[cols[2]].width = self._proto_w
                self.columns[cols[3]].width = self._method_w
                self.columns[cols[4]].width = self._connection_col_width
                self.refresh(layout=True)
            except Exception:
                pass

        def _consider_row_widths(self, flow) -> None:
            """Grow Proto/Method (capped) if THIS row needs more than the current
            width. Growth-only and O(1): plain HTTP captures never trigger it;
            only longer labels (HTTP/2[Signal], "1:1 · 4 msgs") expand a column."""
            proto_need = min(len(self._format_proto(flow)), self._MAX_PROTO_WIDTH)
            method_need = min(self._method_plain_len(flow), self._MAX_METHOD_WIDTH)
            new_proto = max(self._proto_w, proto_need)
            new_method = max(self._method_w, method_need)
            if new_proto != self._proto_w or new_method != self._method_w:
                self._proto_w = new_proto
                self._method_w = new_method
                self._apply_column_widths()

        def _recompute_proto_method_widths(self, visible_flows=None) -> None:
            """Full recompute over all visible flows (can shrink back to base when
            wide rows are filtered out). Used on rebuild/filter, not per-row.

            *visible_flows* is the already-filtered flow list; when omitted the
            filter is evaluated here (callers that just filtered should pass it
            so the — possibly content-searching — filter runs once per flow).
            """
            if visible_flows is None:
                visible_flows = [s for s in self._all_flow_data.values()
                                 if self._passes_filter(s)]
            proto_w = self._BASE_PROTO_WIDTH
            method_w = self._BASE_METHOD_WIDTH
            for summary in visible_flows:
                proto_w = max(proto_w, min(len(self._format_proto(summary)),
                                           self._MAX_PROTO_WIDTH))
                method_w = max(method_w, min(self._method_plain_len(summary),
                                             self._MAX_METHOD_WIDTH))
            self._proto_w = proto_w
            self._method_w = method_w
            self._apply_column_widths()

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
            return all(self._engine_matches(engine, flow)
                       for engine in (self._filter_engine, self._toggle_engine)
                       if engine)

        def _engine_matches(self, engine: "FilterEngine", flow) -> bool:
            """Evaluate *engine* with the content index as its context.

            An engine without ``frame`` terms never touches the context, so
            passing it unconditionally loads no flow content.
            """
            return engine.matches(flow, ctx=self._content_index)

        def set_flow_lookup(self, flow_lookup) -> None:
            """Inject ``flow_id -> Flow | None`` used to load content for ``frame``."""
            self._content_index.set_flow_lookup(flow_lookup)

        @property
        def content_index(self) -> FlowContentIndex:
            return self._content_index

        def count_matches(self, engine: "FilterEngine") -> int:
            """Number of current flows (visible or not) that *engine* matches.

            Ignores the active filters; used for live suggestion row counts.
            """
            count = 0
            for summary in list(self._all_flow_data.values()):
                try:
                    if self._engine_matches(engine, summary):
                        count += 1
                except Exception:
                    continue
            return count

        @property
        def visible_count(self) -> int:
            return len(self._flow_row_keys)

        @property
        def total_count(self) -> int:
            return len(self._all_flow_data)

        # -- Flow operations --------------------------------------------------

        def add_or_update_flow(
            self, flow: "Flow", summary: "FlowSummary | None" = None,
        ) -> None:
            """Add a new flow row or update an existing one.

            Converts the Flow to a FlowSummary (~200 bytes) so the list
            widget does not pin full Flow objects with chunks and body data.
            Skips re-creation when nothing display-relevant has changed.
            A prebuilt *summary* (replay rows) is stored as-is.
            """
            old = self._all_flow_data.get(flow.flow_id)
            signature = layer_signature(flow)
            if (summary is None and old is not None
                    and self._layer_signatures.get(flow.flow_id) == signature
                    and old.state == flow.state
                    and old.total_bytes == flow._total_bytes
                    and (old.request is not None) == (flow.request is not None)
                    and (old.response is not None) == (flow.response is not None)):
                summary = old
            else:
                if summary is None:
                    summary = self._summarize(flow, old, attrs_key=signature[-1])
                else:
                    self._filter_attrs_keys.pop(flow.flow_id, None)
                self._all_flow_data[flow.flow_id] = summary
                self._layer_signatures[flow.flow_id] = signature
                if old is not None:
                    # Content (bytes/parse results/layers) changed — drop
                    # stale text; the index key alone (flow_id, total_bytes)
                    # can't see a same-size reparse.
                    self._content_index.invalidate(flow.flow_id)

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

        def _summarize(
            self, flow: "Flow", old: "FlowSummary | None", attrs_key: "tuple | None" = None,
        ) -> "FlowSummary":
            """Build *flow*'s summary, reusing *old*'s filter attrs (the costly
            part of a live rebuild) while the layer state they derive from is
            unchanged. *attrs_key* is a precomputed :func:`filter_attrs_key`
            (``layer_signature`` already holds it)."""
            if attrs_key is None:
                attrs_key = filter_attrs_key(flow)
            reusable = (old is not None
                        and self._filter_attrs_keys.get(flow.flow_id) == attrs_key)
            self._filter_attrs_keys[flow.flow_id] = attrs_key
            return FlowSummary.from_flow(
                flow, filter_attrs=old.filter_attrs if reusable else None)

        _SHORT_PROTO = {
            PROTOCOL_HTTP1: "HTTP",
            PROTOCOL_HTTP2: "H2",
            PROTOCOL_HTTP3: "H3",
            PROTOCOL_WEBSOCKET: "WS",
            PROTOCOL_SIGNAL: "SIG",
            PROTOCOL_MTPROTO: "MTP",
            PROTOCOL_TELEGRAM_E2E: "TG-E2E",
        }

        @staticmethod
        def _format_proto(flow) -> str:
            """Format the protocol column, preserving nested layered labels.

            For a layered label like ``HTTP/2[Signal]`` the casing is preserved
            verbatim; otherwise the plain protocol is upper-cased as before.
            """
            label = flow.display_protocol_layered
            if label and "[" in label:
                return label
            return label.upper() if label and label != "unknown" else "???"

        @staticmethod
        def _method_parts(flow) -> tuple[str, str]:
            """Return ``(method, badge)`` — the plain method text plus an optional
            trailing-data badge (e.g. ``+WS``), both markup-free for measurement."""
            method = flow.display_method or "-"
            # Fall back to the E2E inner summary (e.g. "1:1 · 3 msgs") when there's no method.
            if method == "-":
                inner = getattr(flow, "inner_summary", "") or ""
                if inner:
                    method = inner
            return method, FlowListWidget._trailing_badge(flow)

        @staticmethod
        def _trailing_badge(flow) -> str:
            """``+WS``-style badge for request- or response-direction trailing data."""
            if flow.has_trailing_data:
                protocol = flow.trailing_protocol
            elif getattr(flow, "has_response_trailing_data", False):
                protocol = getattr(flow, "response_trailing_protocol", "")
            else:
                return ""
            short = FlowListWidget._SHORT_PROTO.get(protocol, "")
            return f"+{short}" if short else "+data"

        @staticmethod
        def _format_method(flow) -> str:
            """Format method column, appending protocol badge if trailing data exists."""
            method, badge = FlowListWidget._method_parts(flow)
            if badge:
                return f"{method} [{c('warning')}]{badge}[/]"
            return method

        @staticmethod
        def _method_plain_len(flow) -> int:
            """Visible width of the method cell (markup excluded) for column sizing."""
            method, badge = FlowListWidget._method_parts(flow)
            return len(method) + (len(badge) + 1 if badge else 0)

        def _add_row(self, flow: "Flow") -> None:
            self._flow_counter += 1
            self._consider_row_widths(flow)
            ts = datetime.fromtimestamp(flow.started).strftime("%H:%M:%S")

            values = [
                str(self._flow_counter),
                ts,
                self._format_proto(flow),
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

                # A flow that just became Signal (e.g. after re-parse) may now
                # need a wider Proto/Method column.
                self._consider_row_widths(flow)

                new_vals = [
                    self._format_proto(flow),
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

            visible_flows = [flow for flow in self._all_flow_data.values()
                             if self._passes_filter(flow)]
            for flow in visible_flows:
                self._add_row(flow)

            # Full recompute so columns can shrink back to base when the wide
            # (Signal/E2E) rows were filtered out. Reuses the filtered list so
            # the filter is evaluated once per flow per rebuild.
            self._recompute_proto_method_widths(visible_flows)
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

        def row_number_of(self, flow_id: str) -> int | None:
            """The ``#`` shown for *flow_id*'s visible row, else None (filtered/unknown)."""
            row_key = self._flow_row_keys.get(flow_id)
            if row_key is None:
                return None
            try:
                return int(str(self.get_row(row_key)[0]))
            except Exception:
                return None

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
            self._layer_signatures.clear()
            self._filter_attrs_keys.clear()
            self._content_index.clear()
            # Reset Proto/Method back to compact defaults.
            self._proto_w = self._BASE_PROTO_WIDTH
            self._method_w = self._BASE_METHOD_WIDTH
            self._apply_column_widths()

        @staticmethod
        def _message_transport_status(flow) -> str:
            """Status cell for a message-stream flow (no HTTP status exists).

            Every message-stream flow is one packet, so the cell shows its
            direction (``sent`` / ``recv``; ``sent+recv`` only for legacy
            paired taps) and ``-`` only when nothing was parsed.
            """
            return message_direction_status(flow) or "-"

        def _format_status(self, flow: "Flow") -> str:
            if is_message_transport(flow):
                return self._message_transport_status(flow)
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
