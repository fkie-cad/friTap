"""Flow detail widget -- tabbed view showing request, response, and connection details."""

from __future__ import annotations

import json
import os
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from friTap.flow.models import Flow

try:
    from textual.widgets import Static, RichLog, TabbedContent, TabPane
    from textual.containers import Vertical
    from textual.message import Message
    from textual.binding import Binding
    TEXTUAL_AVAILABLE = True
except ImportError:
    TEXTUAL_AVAILABLE = False

from rich.markup import escape as _markup_escape
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.box import ROUNDED
from rich.rule import Rule
from collections import Counter

from friTap.flow.models import format_byte_size
from friTap.tui.themes import c
from friTap.tui.modals.body_processing_modal import BodyProcessingModal, BodyProcessingResult

def _is_text(data: bytes) -> bool:
    """Check if data is printable UTF-8 text."""
    try:
        text = data.decode("utf-8")
        return text.isprintable() or '\n' in text or '\r' in text
    except (UnicodeDecodeError, ValueError):
        return False


def format_hexdump_lines(
    data: bytes,
    bytes_per_line: int = 16,
    start_offset: int = 0,
    markup: bool = False,
) -> list[str]:
    """Format raw bytes as hex dump lines.

    Args:
        data: Raw bytes to format.
        bytes_per_line: Bytes per output line (default 16).
        start_offset: Byte offset shown in the left column.
        markup: If ``True``, wrap offset and ASCII columns in Rich
            ``[dim]`` markup for use with :class:`RichLog`.

    Returns:
        List of formatted hex dump strings, one per line.
    """
    lines: list[str] = []
    for offset in range(0, len(data), bytes_per_line):
        chunk = data[offset : offset + bytes_per_line]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        hex_part = hex_part.ljust(bytes_per_line * 3 - 1)
        display_offset = start_offset + offset
        if markup:
            lines.append(
                f"[{c('hex-offset')}]{display_offset:08x}[/]  "
                f"[{c('hex-data')}]{hex_part}[/]  "
                f"[{c('hex-ascii')}]{ascii_part}[/]"
            )
        else:
            lines.append(f"{display_offset:08x}  {hex_part}  {ascii_part}")
    return lines


def _get_header(headers: dict, name: str) -> str:
    """Case-insensitive header lookup, returns lowercased value or ``""``."""
    for key, val in headers.items():
        if key.lower() == name:
            return val.lower()
    return ""


if TEXTUAL_AVAILABLE:
    from datetime import datetime
    from friTap.flow.models import FlowState

    # Tab pane IDs — plain strings to avoid str-enum repr issues with Textual
    _TAB_REQUEST = "tab-request"
    _TAB_RESPONSE = "tab-response"
    _TAB_DETAIL = "tab-detail"
    _TAB_MESSAGE = "tab-message"
    _TAB_LAYERS = "tab-layers"

    def _flow_signal_layer(flow):
        """Return a flow's parsed Signal layer (non-mutating), or None.

        Module-level helper so both the static ``_auto_select_tab`` and the
        instance methods can share one definition.
        """
        try:
            return flow.layer("signal")
        except Exception:
            return None

    def _flow_is_signal(flow) -> bool:
        """True if *flow* has a Signal layer carrying parsed messages."""
        layer = _flow_signal_layer(flow)
        return bool(layer is not None and getattr(layer, "messages", None))

    # Message-bearing layers, innermost (E2E) last so a Telegram Secret-Chat
    # layer is preferred over the carrier MTProto transport when both exist.
    _MESSAGE_LAYER_NAMES = ("signal", "mtproto", "telegram_e2e")

    def _flow_message_layer(flow):
        """Return the flow's preferred message-bearing layer, or None.

        Scans Signal / MTProto / Telegram-E2E layers and returns the innermost
        one that actually carries parsed ``messages`` (so a Secret-Chat layer
        wins over the MTProto transport that carries it).
        """
        chosen = None
        for name in _MESSAGE_LAYER_NAMES:
            try:
                layer = flow.layer(name)
            except Exception:
                layer = None
            if layer is not None and getattr(layer, "messages", None):
                chosen = layer
        return chosen

    def _flow_has_messages(flow) -> bool:
        """True if any Signal / MTProto / Telegram-E2E layer carries messages."""
        return _flow_message_layer(flow) is not None

    class FlowDetailWidget(Vertical):
        """Tabbed detail view for a single flow.

        Tabs: Request | Response | Detail
        Shortcuts: p=parse r=reset s=save h=hex
        """

        BINDINGS = [
            Binding("escape", "back", "Back", show=False),
            Binding("p", "open_body_processing", "Parse", show=False),
            Binding("r", "processing_reset", "Reset", show=False),
            Binding("s", "save_body", "Save Body", show=False),
            Binding("h", "toggle_raw_hex", "Hex View", show=False),
            Binding("n", "next_segment", "Next Segment", show=False),
            Binding("N", "prev_segment", "Prev Segment", show=False),
            Binding("x", "open_explorer", "Explorer", show=False),
            Binding("bracketleft", "prev_layer", "Prev Layer", show=False),
            Binding("bracketright", "next_layer", "Next Layer", show=False),
            Binding("l", "toggle_layer_view", "Raw layers", show=False),
        ]

        class BackRequested(Message):
            """Emitted when user wants to go back to flow list."""
            pass

        def __init__(self, **kwargs) -> None:
            super().__init__(**kwargs)
            self._current_flow = None
            self._extra_tabs: list = []  # TabProvider instances
            self._active_processing: BodyProcessingResult | None = None
            self._pre_modal_processing: BodyProcessingResult | None = None
            self._raw_request: bool = False
            self._raw_response: bool = False
            self._skip_tab_event: bool = False
            # Sibling flows that belong to the SAME logical conversation as the
            # current flow (e.g. Signal opens several TCP connections to its chat
            # server, splitting outbound/inbound across them). Set by the screen
            # before show_flow; the Message tab merges their messages into one
            # time-ordered transcript. Empty -> single-flow behavior.
            self._conversation_siblings: list = []
            self._last_explorer_result = None  # ExplorerResult from last explorer session
            # Widget refs assigned in compose(); None until then
            self._header_widget: Static | None = None
            self._tabs: TabbedContent | None = None
            self._request_log: RichLog | None = None
            self._response_log: RichLog | None = None
            self._detail_log: RichLog | None = None
            self._message_log: RichLog | None = None
            self._layers_log: RichLog | None = None
            self._segment_offsets: list[int] = []  # RichLog line offsets for n/N navigation
            # Layers-tab navigation state
            self._current_layer_idx: int = 0
            self._layer_view: dict[int, str] = {}  # layer index -> "hex" | "parsed"

        def register_tab(self, provider) -> None:
            """Register a plugin TabProvider for an extra tab."""
            self._extra_tabs.append(provider)

        def set_conversation_siblings(self, flows) -> None:
            """Set sibling flows that share the current flow's logical conversation.

            The screen calls this (before :meth:`show_flow`) with the other Signal
            flows of the same session so the Message tab can present one merged,
            time-ordered transcript across the separate TCP connections that carry
            each direction. Pass an empty list / None for single-flow behavior.
            """
            self._conversation_siblings = list(flows or [])

        def compose(self):
            self._header_widget = Static("", id="flow-detail-header")
            yield self._header_widget
            tab_titles = ["Request", "Response", "Detail", "Message", "Layers"]
            for tab_provider in self._extra_tabs:
                tab_titles.append(tab_provider.title)

            # Widget IDs also referenced in friTap/tui/css/fritap.tcss
            self._request_log = RichLog(id="request-log", wrap=True, highlight=True, markup=True, auto_scroll=False)
            self._response_log = RichLog(id="response-log", wrap=True, highlight=True, markup=True, auto_scroll=False)
            self._detail_log = RichLog(id="detail-log", wrap=True, highlight=True, markup=True, auto_scroll=False)
            self._message_log = RichLog(id="message-log", wrap=True, highlight=True, markup=True, auto_scroll=False)
            self._layers_log = RichLog(id="layers-log", wrap=True, highlight=True, markup=True, auto_scroll=False)

            with TabbedContent(*tab_titles, id="flow-tabs") as self._tabs:
                with TabPane("Request", id=_TAB_REQUEST):
                    yield self._request_log
                with TabPane("Response", id=_TAB_RESPONSE):
                    yield self._response_log
                with TabPane("Detail", id=_TAB_DETAIL):
                    yield self._detail_log
                with TabPane("Message", id=_TAB_MESSAGE):
                    yield self._message_log
                with TabPane("Layers", id=_TAB_LAYERS):
                    yield self._layers_log
                for tab_provider in self._extra_tabs:
                    with TabPane(tab_provider.title, id=f"tab-{tab_provider.tab_id}"):
                        yield RichLog(id=f"{tab_provider.tab_id}-log", wrap=True, highlight=True, markup=True, auto_scroll=False)

        def _reset_view_state(self) -> None:
            self._raw_request = False
            self._raw_response = False
            self._active_processing = None
            self._current_layer_idx = 0
            self._layer_view = {}

        def show_flow(self, flow: "Flow") -> None:
            """Display flow details in the tabbed view.

            Only the auto-selected tab is rendered eagerly; other tabs
            are rendered lazily when the user switches to them via
            :meth:`on_tabbed_content_tab_activated`.
            """
            if self._current_flow is not flow:
                self._reset_view_state()
            self._current_flow = flow
            self._update_header(flow)
            try:
                self._update_tab_labels(self._tabs, flow)
                self._skip_tab_event = True
                self._auto_select_tab(self._tabs, flow)
                self._skip_tab_event = False
                self._render_tab(flow, self._tabs.active)
            except Exception:
                self._skip_tab_event = False

        def scroll_to_top(self) -> None:
            """Scroll the active tab's RichLog to the top.

            Call from ``call_after_refresh`` after the widget becomes visible
            so Textual has completed layout and scroll positions stick.
            """
            try:
                active = self._tabs.active
                log_map = {
                    _TAB_REQUEST: self._request_log,
                    _TAB_RESPONSE: self._response_log,
                    _TAB_DETAIL: self._detail_log,
                    _TAB_MESSAGE: self._message_log,
                    _TAB_LAYERS: self._layers_log,
                }
                log = log_map.get(active)
                if log:
                    log.scroll_home(animate=False)
            except Exception:
                pass

        @staticmethod
        def _auto_select_tab(tabs: TabbedContent, flow: "Flow") -> None:
            """Select the first tab that has meaningful data."""
            if _flow_has_messages(flow):
                tabs.active = _TAB_MESSAGE
            elif flow.has_request_data:
                tabs.active = _TAB_REQUEST
            elif flow.has_response_data:
                tabs.active = _TAB_RESPONSE
            else:
                tabs.active = _TAB_DETAIL

        def _update_tab_labels(self, tabs: TabbedContent, flow: "Flow") -> None:
            """Dim tab labels for tabs without data; mark raw-hex tabs."""
            label_map = {
                _TAB_REQUEST: ("Request", flow.has_request_data, self._raw_request),
                _TAB_RESPONSE: ("Response", flow.has_response_data, self._raw_response),
                _TAB_DETAIL: ("Detail", True, False),
                _TAB_MESSAGE: ("Message", _flow_has_messages(flow), False),
                _TAB_LAYERS: ("Layers", bool(getattr(flow, "layers", None)), False),
            }
            for pane_id, (name, has_data, is_raw) in label_map.items():
                try:
                    tab = tabs.get_tab(pane_id)
                    label = name if has_data else f"{name} [dim]\u00b7[/]"
                    if is_raw:
                        label += f" [bold {c('warning')}][HEX][/]"
                    tab.label = label
                except Exception:
                    pass

        def _render_tab(self, flow: "Flow", tab_id: str) -> None:
            """Render a single tab by its pane ID."""
            if tab_id == _TAB_REQUEST:
                self._update_request(flow)
            elif tab_id == _TAB_RESPONSE:
                self._update_response(flow)
            elif tab_id == _TAB_DETAIL:
                self._update_detail(flow)
            elif tab_id == _TAB_MESSAGE:
                self._render_message_tab(flow)
            elif tab_id == _TAB_LAYERS:
                self._render_layers_tab(flow)
            else:
                self._update_extra_tabs(flow)

        def refresh_flow(self, flow: "Flow") -> None:
            """Re-render only the visible tab if the given flow is currently displayed."""
            if self._current_flow is None or self._current_flow.flow_id != flow.flow_id:
                return
            self._current_flow = flow
            self._update_header(flow)
            try:
                self._update_tab_labels(self._tabs, flow)
                self._render_tab(flow, self._tabs.active)
            except Exception:
                self.show_flow(flow)

        def on_tabbed_content_tab_activated(self, event: TabbedContent.TabActivated) -> None:
            """Re-render the newly visible tab to ensure fresh content."""
            if self._skip_tab_event or self._current_flow is None:
                return
            self._render_tab(self._current_flow, event.pane.id)

        # ----------------------------------------------------------
        # Actions
        # ----------------------------------------------------------

        def action_back(self) -> None:
            """Go back to the flow list."""
            self.post_message(self.BackRequested())

        def action_open_body_processing(self) -> None:
            if not self._current_flow:
                return
            body = self._get_active_body_preview()
            self._pre_modal_processing = self._active_processing
            seg_count = len(self._current_flow.segments) if self._current_flow else 1
            self.app.push_screen(
                BodyProcessingModal(
                    current=self._active_processing,
                    body_preview=body,
                    on_change=self._on_body_processing_change,
                    segment_count=max(seg_count, 1),
                ),
                callback=self._on_body_processing_result,
            )

        def _on_body_processing_change(self, result) -> None:
            """Live-update the flow detail while the body processing modal is open."""
            self._active_processing = result
            if self._current_flow:
                self.show_flow(self._current_flow)

        def _on_body_processing_result(self, result) -> None:
            if result is None:
                # User cancelled — revert to pre-modal state
                self._active_processing = self._pre_modal_processing
                if self._current_flow:
                    self.show_flow(self._current_flow)
                return
            self._active_processing = result
            if self._current_flow:
                self.show_flow(self._current_flow)

        def action_processing_reset(self) -> None:
            self._reset_view_state()
            if self._current_flow:
                self.show_flow(self._current_flow)

        def action_toggle_raw_hex(self) -> None:
            """Toggle raw hexdump mode for the current tab (request or response)."""
            if not self._current_flow:
                return
            try:
                active = self._tabs.active
            except Exception:
                return
            if active == _TAB_REQUEST:
                self._raw_request = not self._raw_request
            elif active == _TAB_RESPONSE:
                self._raw_response = not self._raw_response
            else:
                return
            self._update_header(self._current_flow)
            self._update_tab_labels(self._tabs, self._current_flow)
            self._render_tab(self._current_flow, active)

        def _on_layers_tab(self) -> bool:
            """True when a flow is loaded and the active tab is the Layers tab."""
            if not self._current_flow:
                return False
            try:
                return self._tabs.active == _TAB_LAYERS
            except Exception:
                return False

        def _rerender_layers(self) -> None:
            """Re-render the Layers tab and refresh the header hint."""
            self._update_header(self._current_flow)
            self._render_tab(self._current_flow, _TAB_LAYERS)

        def action_prev_layer(self) -> None:
            """Move the layer focus marker up one layer (clamped)."""
            if not self._on_layers_tab():
                return
            self._current_layer_idx = max(0, self._current_layer_idx - 1)
            self._rerender_layers()

        def action_next_layer(self) -> None:
            """Move the layer focus marker down one layer (clamped)."""
            if not self._on_layers_tab():
                return
            layers = getattr(self._current_flow, "layers", None) or []
            self._current_layer_idx = min(max(0, len(layers) - 1), self._current_layer_idx + 1)
            self._rerender_layers()

        def action_toggle_layer_view(self) -> None:
            """``l``: open the raw layer view, or flip parsed/hex when on it.

            From any non-Layers tab (e.g. the Message tab, which advertises
            "press l for the raw layer view"), this switches to the Layers tab
            and lands on the message-bearing layer. Once on the Layers tab it
            flips the focused layer between its parsed and hex views.
            """
            if not self._current_flow:
                return
            if not self._on_layers_tab():
                try:
                    self._tabs.active = _TAB_LAYERS
                except Exception:
                    return
                self._focus_message_layer()
                self._rerender_layers()
                return
            layers = getattr(self._current_flow, "layers", None) or []
            idx = self._current_layer_idx
            if idx >= len(layers):
                return
            current = self._layer_view.get(idx, self._default_layer_view(layers[idx]))
            self._layer_view[idx] = "hex" if current == "parsed" else "parsed"
            self._rerender_layers()

        def _focus_message_layer(self) -> None:
            """Point ``_current_layer_idx`` at the message-bearing layer, if any.

            So jumping to the raw layer view lands on the layer whose transport
            records the user came to inspect, rather than the outermost layer.
            """
            layers = getattr(self._current_flow, "layers", None) or []
            for idx, layer in enumerate(layers):
                if self._layer_has_messages(layer):
                    self._current_layer_idx = idx
                    return

        def action_next_segment(self) -> None:
            """Scroll to next segment boundary in the request tab."""
            self._scroll_to_segment(1)

        def action_prev_segment(self) -> None:
            """Scroll to previous segment boundary in the request tab."""
            self._scroll_to_segment(-1)

        def _scroll_to_segment(self, direction: int) -> None:
            """Scroll the request log to the next/previous segment boundary."""
            if not self._segment_offsets or not self._current_flow:
                return
            try:
                log = self._request_log
                current_y = log.scroll_y
                if direction > 0:
                    # Find next offset after current scroll position
                    for offset in self._segment_offsets:
                        if offset > current_y + 2:
                            log.scroll_to(y=offset, animate=True)
                            return
                else:
                    # Find previous offset before current scroll position
                    for offset in reversed(self._segment_offsets):
                        if offset < current_y - 2:
                            log.scroll_to(y=offset, animate=True)
                            return
            except Exception:
                pass

        @staticmethod
        def _explorer_body(flow: "Flow", direction: str) -> tuple[bytes, dict]:
            """Return (body, headers) for the explorer, preferring raw pre-decompression bytes."""
            is_request = direction == "request"
            msg = flow.request if is_request else flow.response
            dir_key = "write" if is_request else "read"
            body = getattr(msg, "raw", b"") or (
                flow.request_body if is_request else flow.response_body
            )
            if not body:
                body = flow.get_direction_bytes(dir_key)
            headers = msg.headers if msg else {}
            return body, headers

        def action_open_explorer(self) -> None:
            """Open Explorer Mode for the active tab's body."""
            flow = self._current_flow
            if not flow:
                return
            try:
                active = self._tabs.active
            except Exception:
                return
            if active == _TAB_REQUEST:
                body, headers = self._explorer_body(flow, "request")
                direction = "request"
            elif active == _TAB_RESPONSE:
                body, headers = self._explorer_body(flow, "response")
                direction = "response"
            else:
                return  # no explorer on Detail tab
            if not body:
                return
            from friTap.tui.modals.explorer_modal import ExplorerModal
            self.app.push_screen(
                ExplorerModal(body=body, direction=direction, headers=headers),
                callback=self._on_explorer_result,
            )

        def _on_explorer_result(self, result) -> None:
            """Handle ExplorerResult returned from Explorer Mode.

            The result is available for future use (e.g. annotating the
            flow detail view with parsed sub-regions).
            """
            if result is None:
                return
            # Store for potential future use by plugins or extensions
            self._last_explorer_result = result

        def _get_active_body_preview(self) -> bytes:
            """Get first 4096 bytes of the currently displayed body for preview."""
            flow = self._current_flow
            if not flow:
                return b""
            body = flow.response_body or flow.request_body
            return body[:4096] if body else b""

        def _describe_pipeline(self) -> str:
            """Human-readable description of the active processing chain."""
            if not self._active_processing:
                return ""
            parts = []
            if self._active_processing.decompression:
                parts.append(self._active_processing.decompression)
            if self._active_processing.decoder:
                label = self._active_processing.decoder
                if label == "protobuf" and self._active_processing.protobuf_config:
                    pc = self._active_processing.protobuf_config
                    if pc.schema_path:
                        label = "protobuf (schema)"
                    else:
                        label = "protobuf (raw)"
                parts.append(label)
            return " -> ".join(parts)

        def action_save_body(self) -> None:
            """Save the active tab's body (request or response) to a file."""
            from friTap.flow.http_utils import (
                parse_content_disposition_filename,
                filename_from_url,
                sanitize_filename,
            )

            flow = self._current_flow
            if flow is None:
                return

            active = self._tabs.active
            if active == _TAB_REQUEST:
                msg = flow.request
                direction = "request"
            else:
                msg = flow.response
                direction = "response"

            if msg is None:
                self.app.notify(f"No {direction} data to save.", severity="warning")
                return

            dir_key = "write" if direction == "request" else "read"
            raw_body = msg.body if msg.body else flow.reconstruct_body(dir_key)
            if not raw_body:
                self.app.notify(f"Empty {direction} body.", severity="warning")
                return

            # Decompress via Flow helper; _active_processing overrides auto-detected encoding
            encoding_override = self._active_processing.decompression if self._active_processing else ""
            body = flow._get_decompressed_body(msg, dir_key, encoding_override=encoding_override)

            filename = None
            if direction == "response":
                cd = flow.get_response_header("content-disposition")
                if cd:
                    filename = parse_content_disposition_filename(cd)
            if not filename and flow.request and flow.request.url:
                filename = filename_from_url(flow.request.url)
            if not filename:
                filename = f"body_{direction}.bin"
            filename = sanitize_filename(filename)

            save_path = os.path.join(os.getcwd(), filename)
            try:
                with open(save_path, "wb") as f:
                    f.write(body)
                size_str = format_byte_size(len(body))
                self.app.notify(f"Saved {size_str} to {save_path}")
            except OSError as e:
                self.app.notify(f"Save failed: {e}", severity="error")

        # ----------------------------------------------------------
        # Tab updates
        # ----------------------------------------------------------

        def _update_extra_tabs(self, flow: "Flow") -> None:
            """Update plugin-provided tabs."""
            for tab_provider in self._extra_tabs:
                try:
                    log = self.query_one(f"#{tab_provider.tab_id}-log", RichLog)
                    log.clear()
                    content = tab_provider.render(flow)
                    if content:
                        log.write(content)
                    else:
                        log.write("[dim]No data[/]")
                    log.scroll_home(animate=False)
                except Exception:
                    pass

        def _update_header(self, flow: "Flow") -> None:
            header = self._header_widget
            ts = datetime.fromtimestamp(flow.started).strftime("%H:%M:%S.%f")[:-3]
            method = flow.display_method or "-"
            host = flow.display_host or "-"
            status = flow.display_status or "pending"
            proto = flow.display_protocol.upper() if flow.display_protocol != "unknown" else "???"

            pipeline_desc = self._describe_pipeline()
            raw_hints = []
            if self._raw_request:
                raw_hints.append("REQ:HEX")
            if self._raw_response:
                raw_hints.append("RES:HEX")
            raw_indicator = f"  [bold {c('warning')}]{' '.join(raw_hints)}[/]" if raw_hints else ""

            if pipeline_desc:
                decomp_hint = f"  [dim]p:parse r:reset s:save h:hex x:explore[/]  [{c('accent')}]{pipeline_desc}[/]{raw_indicator}"
            else:
                decomp_hint = f"  [dim]p:parse r:reset s:save h:hex x:explore[/]{raw_indicator}"

            try:
                on_layers = self._tabs is not None and self._tabs.active == _TAB_LAYERS
            except Exception:
                on_layers = False
            if on_layers:
                decomp_hint += "  [dim][ ] prev/next layer · l hex/parsed[/]"

            header.update(
                f"[bold {c('primary')}]{proto}[/] [bold]{method}[/] {host}  "
                f"[dim]>[/] {status}  [dim]@{ts}[/]  "
                f"[dim italic]Escape: back[/]{decomp_hint}\n"
                f"[dim]{flow.src_addr}:{flow.src_port} \u2192 {flow.dst_addr}:{flow.dst_port}[/]"
            )

        def _render_raw_hex(self, log: RichLog, flow: "Flow", direction: str, label: str) -> None:
            """Render full raw hexdump for a direction, bypassing all parsing.

            When multiple chunks exist for the direction, annotates each
            chunk with its offset range and function name so the user can
            see where protocol boundaries fall.
            """
            dir_chunks = []
            total = 0
            for ch in flow.chunks:
                if ch.direction == direction:
                    dir_chunks.append(ch)
                    total += len(ch.data)
            if not total:
                log.write(f"[dim]No {label} data captured[/]")
                log.scroll_home(animate=False)
                return

            log.write(f"[bold {c('warning')}]--- Raw Hexdump (full message, {total:,} bytes) ---[/]")
            log.write("[dim]Parser disabled. Press h to restore parsed view, r to reset all.[/]")
            log.write("")

            if len(dir_chunks) > 1:
                # Annotated view: show each chunk with its boundary
                offset = 0
                bytes_budget = self._HEXDUMP_RENDER_LIMIT
                for i, ch in enumerate(dir_chunks):
                    if bytes_budget <= 0:
                        break
                    end = offset + len(ch.data) - 1
                    fn = ch.function or direction
                    log.write(
                        f"[bold {c('accent')}][{fn}] "
                        f"0x{offset:04x} - 0x{end:04x} "
                        f"({len(ch.data):,} bytes)[/]"
                    )
                    log.write(f"[dim]{'─' * 50}[/]")
                    render_bytes = ch.data[:bytes_budget]
                    self._write_hexdump(log, render_bytes, start_offset=offset)
                    bytes_budget -= len(render_bytes)
                    offset += len(ch.data)
                    if i < len(dir_chunks) - 1:
                        log.write("")
            else:
                self._write_hexdump(log, dir_chunks[0].data[:self._HEXDUMP_RENDER_LIMIT])

            log.scroll_home(animate=False)

        @staticmethod
        def _nonhttp_transport_label(flow: "Flow") -> str:
            """Display name of a non-HTTP, message-bearing transport, else "".

            For MTProto / Telegram-Secret-Chat flows the Request/Response tabs hit
            the HTTP ``request is None`` path; without this they would print the
            misleading "headers could not be parsed" (it is not HTTP). Returns the
            protocol label (e.g. "MTProto") so the tab can point the user at the
            Message tab instead. Signal is handled separately (its own transcript).
            """
            layer = _flow_message_layer(flow)
            name = getattr(layer, "name", "") if layer is not None else ""
            if name in ("mtproto", "telegram_e2e"):
                from friTap.constants import LAYER_DISPLAY_NAMES
                return LAYER_DISPLAY_NAMES.get(name, name)
            return ""

        def _update_request(self, flow: "Flow") -> None:
            log = self._request_log
            log.clear()
            self._segment_offsets = []

            if self._raw_request:
                self._render_raw_hex(log, flow, "write", "request")
                return

            # Signal flows: show the readable chat transcript instead of raw
            # protobuf. The `h` toggle (raw_request) above still shows raw hex.
            # Request = OUTBOUND-only (this flow's own write direction); the merged
            # both-direction timeline lives on the Message tab.
            if self._is_signal_flow(flow):
                self._render_signal_messages(log, flow, direction_filter="write")
                log.scroll_home(animate=False)
                return

            req = flow.request
            if req is None:
                raw = flow.get_direction_bytes("write", max_bytes=self._TEXT_RENDER_LIMIT)
                if raw:
                    proto = self._nonhttp_transport_label(flow)
                    if proto:
                        log.write(f"[dim]{proto} transport — decrypted messages are on the "
                                  f"Message tab. Raw transport bytes:[/]")
                    elif "HTTP/2" in (flow.detected_protocol or ""):
                        log.write("[dim]HTTP/2 connection data (partial capture)[/]")
                        self._render_incomplete_h2_note(log, raw)
                    else:
                        log.write("[dim]Request headers could not be parsed (raw data shown)[/]")
                    log.write("")
                    self._render_body(log, raw, {})
                else:
                    log.write("[dim]No request data captured[/]")
                log.scroll_home(animate=False)
                return

            # HTTP/2 control frame display
            if req.is_control_frame:
                self._render_control_frame(log, req)
                log.scroll_home(animate=False)
                return

            # Segment header when trailing data forms a second segment
            if flow.trailing_bytes is not None:
                proto_label = getattr(req, 'protocol', '') or flow.display_protocol
                log.write(f"[bold {c('accent')}]SEGMENT 1  {proto_label}[/]")
                log.write(f"[bold {c('accent')}]{'═' * 60}[/]")

            # Request line
            if hasattr(req, 'method') and req.method:
                version = getattr(req, 'protocol', 'HTTP/1.1')
                url = getattr(req, 'url', '/')
                log.write(f"[bold {c('primary')}]{req.method} {url} {version}[/]")

            # Headers
            headers = getattr(req, 'headers', {})
            if headers:
                log.write("")
                for name, value in headers.items():
                    log.write(f"[bold]{name}:[/] {value}")

            # Body
            body = req.body if req.body else flow.reconstruct_body("write")
            if body:
                log.write("")
                log.write(f"[bold {c('success')}]--- Body ---[/]")
                if req.content_encoding == "permessage-deflate":
                    log.write("[dim italic]Auto-decompressed (permessage-deflate)[/]")
                self._render_body(log, body, headers)

            # Warn when parsed view shows much less data than raw chunks
            self._render_data_mismatch_banner(log, flow, "write", len(body) if body else 0)

            # Trailing data warning (shown in request tab for write-direction trailing data)
            self._render_trailing_data(log, flow)

            log.scroll_home(animate=False)

        def _update_response(self, flow: "Flow") -> None:
            log = self._response_log
            log.clear()

            if self._raw_response:
                self._render_raw_hex(log, flow, "read", "response")
                return

            # Signal flows: show the readable chat transcript instead of raw
            # protobuf. The `h` toggle (raw_response) above still shows raw hex.
            # Response = INBOUND-only (this flow's own read direction); the merged
            # both-direction timeline lives on the Message tab.
            if self._is_signal_flow(flow):
                self._render_signal_messages(log, flow, direction_filter="read")
                log.scroll_home(animate=False)
                return

            resp = flow.response
            if resp is None:
                raw = flow.get_direction_bytes("read", max_bytes=self._TEXT_RENDER_LIMIT)
                if raw:
                    proto = self._nonhttp_transport_label(flow)
                    if proto:
                        log.write(f"[dim]{proto} transport — decrypted messages are on the "
                                  f"Message tab. Raw transport bytes:[/]")
                    elif "HTTP/2" in (flow.detected_protocol or ""):
                        log.write("[dim]HTTP/2 connection data (partial capture)[/]")
                        self._render_incomplete_h2_note(log, raw)
                    else:
                        log.write("[dim]Response headers could not be parsed (raw data shown)[/]")
                    log.write("")
                    self._render_body(log, raw, {})
                else:
                    log.write("[dim]No response data captured[/]")
                log.scroll_home(animate=False)
                return

            # HTTP/2 control frame display
            if resp.is_control_frame:
                self._render_control_frame(log, resp)
                log.scroll_home(animate=False)
                return

            # Status line
            if hasattr(resp, 'status_code') and resp.status_code:
                version = getattr(resp, 'protocol', 'HTTP/1.1')
                status_text = getattr(resp, 'status_text', '')
                code = resp.status_code
                if 200 <= code < 300:
                    color = c('success')
                elif 300 <= code < 400:
                    color = c('warning')
                else:
                    color = c('error')
                log.write(f"[bold {color}]{version} {code} {status_text}[/]")

            # Headers
            headers = getattr(resp, 'headers', {})
            if headers:
                log.write("")
                for name, value in headers.items():
                    log.write(f"[bold]{name}:[/] {value}")

            # Body
            body = resp.body if resp.body else flow.reconstruct_body("read")
            if body:
                log.write("")
                log.write(f"[bold {c('success')}]--- Body ---[/]")
                if resp.content_encoding == "permessage-deflate":
                    log.write("[dim italic]Auto-decompressed (permessage-deflate)[/]")
                self._render_body(log, body, headers)

            # Warn when parsed view shows much less data than raw chunks
            self._render_data_mismatch_banner(log, flow, "read", len(body) if body else 0)

            log.scroll_home(animate=False)

        def _update_detail(self, flow: "Flow") -> None:
            log = self._detail_log
            log.clear()

            # Byte in/out summary at top (single pass)
            bytes_sent = bytes_recv = 0
            for ch in flow.chunks:
                if ch.direction == "write":
                    bytes_sent += len(ch.data)
                else:
                    bytes_recv += len(ch.data)
            log.write(f"[bold {c('primary')}]Traffic Summary[/]")
            log.write(f"[bold]Bytes sent:[/]     {format_byte_size(bytes_sent)}")
            log.write(f"[bold]Bytes received:[/] {format_byte_size(bytes_recv)}")
            log.write("")

            log.write(f"[bold {c('primary')}]Connection Details[/]")
            log.write("")
            log.write(f"[bold]Flow ID:[/]        {flow.flow_id}")
            log.write(f"[bold]Connection:[/]     {flow.connection_id}")
            log.write(f"[bold]State:[/]          {flow.state.value}")
            log.write("")
            log.write(f"[bold]Source:[/]         {flow.src_addr}:{flow.src_port}")
            log.write(f"[bold]Destination:[/]    {flow.dst_addr}:{flow.dst_port}")
            if flow.ssl_session_id:
                log.write(f"[bold]SSL Session:[/]    {flow.ssl_session_id}")
            log.write("")

            ts_start = datetime.fromtimestamp(flow.started).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            log.write(f"[bold]Started:[/]        {ts_start}")
            if flow.state == FlowState.COMPLETE and flow.ended > 0:
                ts_end = datetime.fromtimestamp(flow.ended).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
                log.write(f"[bold]Ended:[/]          {ts_end}")
                log.write(f"[bold]Duration:[/]       {flow.duration * 1000:.1f}ms")

            log.write("")
            log.write(f"[bold]Protocol:[/]       {flow.display_protocol}")
            log.write(f"[bold]Chunks:[/]         {len(flow.chunks)}")

            total_bytes = bytes_sent + bytes_recv
            log.write(f"[bold]Total bytes:[/]    {total_bytes}")

            # Trailing data summary in detail tab
            if flow.trailing_bytes:
                tb = flow.trailing_bytes
                log.write("")
                log.write(f"[bold {c('warning')}]Trailing Data[/]")
                log.write(f"[bold]Unconsumed:[/]     {len(tb):,} bytes")
                if flow.trailing_protocol:
                    log.write(f"[bold]Protocol:[/]       {flow.trailing_protocol}")
                if flow.trailing_parse:
                    sp = flow.trailing_parse
                    log.write(f"[bold]Sub-parsed:[/]     {sp.method} {sp.url}")

            log.scroll_home(animate=False)

        # ----------------------------------------------------------
        # Layer stack rendering
        # ----------------------------------------------------------

        # Per-layer typed metadata fields rendered (in order) above the generic
        # to_dict() fallback. Keeps the most useful fields prominent.
        _LAYER_PRIMARY_FIELDS = {
            "tls": ("sni", "version", "alpn", "cipher", "library"),
            "quic": ("sni", "version", "alpn", "cipher"),
            "signal": ("chat_type", "identifier", "message_count"),
            "mtproto": ("transport", "dc_id", "auth_key_id", "message_count"),
        }

        _LAYER_BYTES_PREVIEW = 256

        def _render_layers_tab(self, flow: "Flow") -> None:
            """Render the flow's protocol layer stack as a drillable view."""
            log = self._layers_log
            log.clear()

            layers = getattr(flow, "layers", None) or []
            if not layers:
                log.write("[dim]No layer stack[/]")
                log.scroll_home(animate=False)
                return

            log.write(f"[bold {c('primary')}]Protocol Layer Stack[/]  [dim]({len(layers)} layers)[/]")
            log.write("")

            # Clamp the focused-layer index to the current layer set.
            if self._current_layer_idx >= len(layers):
                self._current_layer_idx = max(0, len(layers) - 1)

            for idx, layer in enumerate(layers):
                self._render_one_layer(log, layer, idx)
                log.write("")

            log.scroll_home(animate=False)

        @staticmethod
        def _layer_has_messages(layer) -> bool:
            """True if a layer carries parsed message entries.

            Protocol-agnostic: any layer with a populated ``messages`` list
            (Signal, MTProto cloud, or Telegram Secret-Chat E2E) renders as a
            chat transcript via :meth:`_render_layer_parsed`.
            """
            return bool(getattr(layer, "messages", None))

        def _default_layer_view(self, layer) -> str:
            """Default view for a layer: parsed for signal layers with messages, else hex."""
            is_signal = getattr(layer, "name", "") == "signal" or self._layer_has_messages(layer)
            if is_signal and self._layer_has_messages(layer):
                return "parsed"
            return "hex"

        def _signal_layer(self, flow: "Flow"):
            """Return *flow*'s parsed Signal layer (non-mutating), or None."""
            return _flow_signal_layer(flow)

        def _is_signal_flow(self, flow: "Flow") -> bool:
            """True if *flow* has a Signal layer carrying parsed messages."""
            layer = self._signal_layer(flow)
            return bool(layer is not None and self._layer_has_messages(layer))

        @classmethod
        def _format_msg_time(cls, ts) -> str:
            """Format a Signal epoch-ms timestamp as HH:MM:SS; '' when unknown."""
            dt = cls._msg_datetime(ts, secs=False)
            return dt.strftime("%H:%M:%S") if dt is not None else ""

        @staticmethod
        def _msg_datetime(ts, *, secs: bool = False):
            """Local ``datetime`` for an epoch ts, or None when unusable.

            *secs* selects the time base: epoch-seconds (MTProto/E2E) when True,
            epoch-milliseconds (Signal) otherwise — matching the per-protocol
            time formatters so dividers and bubble captions agree.
            """
            try:
                ts = int(ts)
            except (TypeError, ValueError):
                return None
            if ts <= 0:
                return None
            try:
                return datetime.fromtimestamp(ts if secs else ts / 1000)
            except (OverflowError, OSError, ValueError):
                return None

        def _render_signal_messages(self, log: RichLog, flow: "Flow",
                                    *, direction_filter: str | None = None,
                                    merge_siblings: bool = False) -> None:
            """Render a Signal flow as a conversation transcript.

            Thin wrapper over the unified :meth:`_render_conversation` renderer,
            kept because the Request/Response tabs call it for Signal flows (via
            :meth:`_is_signal_flow`). Routes through the Signal layer so the
            epoch-ms timestamp formatter is selected. The Request/Response tabs
            pass *direction_filter* to show only outbound/inbound; the Message tab
            passes *merge_siblings* for the merged conversation.
            """
            layer = self._signal_layer(flow)
            if layer is None:
                log.write("[dim]No decrypted messages in this flow[/]")
                return
            self._render_conversation(log, flow, layer,
                                      direction_filter=direction_filter,
                                      merge_siblings=merge_siblings)

        def _render_message_tab(self, flow: "Flow") -> None:
            """Render the built-in Message tab as a protocol-agnostic conversation.

            Routes ANY message-bearing layer (Signal, MTProto cloud, Telegram
            Secret-Chat E2E, or any future messenger) through the single unified
            :meth:`_render_conversation` renderer. Empty state is generic.
            """
            log = self._message_log
            log.clear()
            # Prefer the Signal layer when present so its epoch-ms timestamp
            # formatter is used; otherwise fall back to the innermost
            # message-bearing layer (Secret-Chat wins over MTProto transport).
            layer = self._signal_layer(flow) if self._is_signal_flow(flow) else None
            is_signal = layer is not None
            if layer is None:
                layer = _flow_message_layer(flow)
            if layer is None:
                log.write("[dim]No decrypted messages in this flow[/]")
                log.scroll_home(animate=False)
                return
            # Signal conversations are merged across the session's sibling flows so
            # outbound and inbound (which ride separate TCP connections) appear as
            # one time-ordered transcript. Other protocols render single-flow.
            self._render_conversation(log, flow, layer, merge_siblings=is_signal)
            log.scroll_home(animate=False)

        # CHAT kinds form the visible message flow; bodies render in quotes.
        _CHAT_KINDS = frozenset({"text", "data", "message"})
        # Participant/identity kind (MTProto/E2E) — promoted to the header and
        # the Participants detail block, never a flow row.
        _PARTICIPANT_KIND = "user"
        # Signal session-metadata kinds (plaintext WS/REST context) — surfaced as a
        # detailed "Session metadata" block, not chat bubbles. Bare transport
        # chatter (receipt/typing/ws-response) stays in the collapsed summary.
        _SESSION_META_KINDS = frozenset(
            {"rest", "profile", "device-list", "prekey", "ws-request"}
        )
        # Direction values that mean "sent by this device" (→). The decrypted
        # message-dict contract uses "write"; live/other producers may use synonyms.
        _OUTBOUND_DIRECTIONS = frozenset({"write", "outgoing", "sent"})
        # Per-kind glyph for the Session-metadata rows.
        _META_ICONS = {"profile": "👤", "device-list": "📱", "prekey": "🔑",
                       "rest": "✉", "ws-request": "·"}
        # An E164 phone number: '+' then 6+ digits. Used to prefer a human phone
        # number over a UUID/PNI when labelling the conversation peer.
        _E164_RE = re.compile(r"^\+\d{6,}$")

        @classmethod
        def _is_outbound(cls, entry) -> bool:
            """True if a message dict is outbound (sent by this device)."""
            return (entry.get("direction") or "") in cls._OUTBOUND_DIRECTIONS

        def _conversation_participants(self, layer, messages) -> list[dict]:
            """Derive conversation participants from a message-bearing layer.

            Returns a list of ``{"name", "detail", "is_self"}`` dicts, deduped:

            * MTProto/E2E — when the layer carries ``kind=="user"`` items, those
              ARE the participants. ``name`` = the body up to the first " (" or
              " ["; ``is_self`` when the relationship/body marks self (``[you]``);
              ``detail`` = the full body.
            * Signal/others — participants are the distinct non-empty ``sender``
              values among RECEIVED messages, plus a synthetic "you" iff there is
              any outgoing message. ``detail`` = the sender string.
            """
            users = [m for m in messages
                     if (m.get("kind") or "") == self._PARTICIPANT_KIND]
            if users:
                return self._participants_from_users(users)
            return self._participants_from_senders(messages)

        def _participants_from_users(self, users) -> list[dict]:
            """Build participant dicts from MTProto/E2E ``kind=="user"`` items."""
            participants: list[dict] = []
            seen: set[str] = set()
            for entry in users:
                body = (entry.get("body") or "").strip()
                name = self._participant_name(body) or (entry.get("sender") or "?")
                if name in seen:
                    continue
                seen.add(name)
                rel = (entry.get("relationship") or "")
                lowered = f"{rel} {body}".lower()
                is_self = "self" in lowered or "[you]" in lowered
                participants.append(
                    {"name": name, "detail": body or name, "is_self": is_self}
                )
            return participants

        def _participants_from_senders(self, messages) -> list[dict]:
            """Build participant dicts from distinct senders (Signal etc.)."""
            participants: list[dict] = []
            seen: set[str] = set()
            has_outgoing = False
            for entry in messages:
                if self._is_outbound(entry):
                    has_outgoing = True
                    continue
                sender = (entry.get("sender") or "").strip()
                if sender and sender not in seen:
                    seen.add(sender)
                    participants.append(
                        {"name": sender, "detail": sender, "is_self": False}
                    )
            if has_outgoing:
                participants.insert(0, {"name": "you", "detail": "you",
                                        "is_self": True})
            return participants

        def _resolve_peer_identity(self, messages) -> tuple[str, str]:
            """Best peer display id + kind from the gathered messages.

            Resolution chain (first hit wins) — we cannot recover our own number
            from the wire, so this only ever identifies the OTHER party:

              1. ``phone`` — any inbound ``sender`` matching E164 (``+\\d{6,}``).
              2. ``uuid``  — first inbound ``sender`` that is non-empty, not a
                 phone and not ``PNI:``-prefixed; else a ``kind=="profile"``
                 ``meta.uuid`` (ACI) seen on the wire.
              3. ``pni``   — first ``PNI:``-prefixed sender/identity.
              4. ``("", "unknown")`` when nothing resolves.

            Returns ``(display, kind)`` with ``kind`` in
            {"phone", "uuid", "pni", "unknown"}.
            """
            phone = sender_uuid = pni = profile_uuid = ""
            for m in messages:
                if not profile_uuid and (m.get("kind") or "") == "profile":
                    profile_uuid = ((m.get("meta") or {}).get("uuid") or "").strip()
                if self._is_outbound(m):
                    continue
                sender = (m.get("sender") or "").strip()
                if not sender:
                    continue
                if not phone and self._E164_RE.match(sender):
                    phone = sender
                elif sender.startswith("PNI:"):
                    pni = pni or sender
                elif not sender_uuid:
                    sender_uuid = sender

            # Precedence is now explicit and order-independent: a phone always
            # wins, then an ACI from a sender, then an ACI from a profile record,
            # then a PNI.
            if phone:
                return phone, "phone"
            if sender_uuid:
                return sender_uuid, "uuid"
            if profile_uuid:
                return profile_uuid, "uuid"
            if pni:
                return pni, "pni"
            return "", "unknown"

        @staticmethod
        def _participant_name(body: str) -> str:
            """Display name = body up to the first " (" or " [" marker."""
            name = body
            for marker in (" (", " ["):
                idx = name.find(marker)
                if idx >= 0:
                    name = name[:idx]
            return name.strip()

        def _sender_id_to_name(self, messages) -> dict:
            """Map ``user_id`` -> display name from the ``kind=="user"`` records.

            Lets group chat rows resolve a numeric ``sender`` id to a readable
            name. Keyed by the stringified id to match the message-dict
            ``sender`` field (also a string).
            """
            mapping: dict = {}
            for entry in messages:
                if (entry.get("kind") or "") != self._PARTICIPANT_KIND:
                    continue
                uid = entry.get("user_id") or 0
                if not uid:
                    continue
                name = self._participant_name(entry.get("body") or "")
                if name:
                    mapping[str(uid)] = name
            return mapping

        def _participants_header_parts(self, participants) -> tuple[str, str, str]:
            """Return ``(left, connector, right)`` for the participants header:
            ``self (you)`` on the left (accent), peer name(s) on the right
            (primary), and ``⇄`` between when both sides exist (else "").
            """
            if not participants:
                return "", "", ""

            self_p = next((p for p in participants if p.get("is_self")), None)
            others = [p for p in participants if not p.get("is_self")]

            left = (f"[bold {c('accent')}]{self._esc(self_p['name'])}[/] [dim](you)[/]"
                    if self_p is not None else "")
            if len(others) > 3:
                right = f"[bold {c('primary')}]{len(others)} participants[/]"
            elif others:
                names = ", ".join(self._esc(p["name"]) for p in others)
                right = f"[bold {c('primary')}]{names}[/]"
            else:
                right = ""

            return left, ("⇄" if left and right else ""), right

        def _peer_summary_parts(self, peer_display: str,
                                peer_kind: str) -> tuple[str, str, str]:
            """Return ``(left, connector, right)`` naming whom we are talking to;
            ``("", "", "")`` when unknown. A phone number is high-confidence (solid
            ``→``); a UUID/PNI is shortened and tagged with ``⇄`` so the reader
            knows it is an opaque identifier, not a number.
            """
            if not peer_display or peer_kind == "unknown":
                return "", "", ""

            left = f"[bold {c('accent')}]you[/]"
            if peer_kind == "phone":
                return left, "→", f"[bold {c('primary')}]{self._esc(peer_display)}[/]"

            tag = "pni" if peer_kind == "pni" else "uuid"
            right = (f"[bold {c('primary')}]{self._esc(peer_display[:8])}…[/]"
                     f"[dim]({tag})[/]")
            return left, "⇄", right

        def _write_header_row(self, log: RichLog, left: str, glyph: str,
                              right: str, *, use_bubbles: bool,
                              glyph_style: str = "dim") -> None:
            """Render a two-sided conversation header (participants / peer summary).

            In bubble mode it is laid out through the chat grid so the connector
            lands in the same gutter column as the message arrows and the right
            cell aligns with the received bubbles; otherwise it is a compact line.
            """
            if not (left or right):
                return
            if use_bubbles and left and right and glyph:
                grid = self._chat_grid(right_justify=True)
                grid.add_row(left, Text(glyph, style=glyph_style), right)
                log.write(grid)
            elif left and right and glyph:
                log.write(f"{left}  [{glyph_style}]{glyph}[/]  {right}")
            else:
                log.write(left or right)

        def _write_day_divider(self, log: RichLog, dt, *,
                               use_bubbles: bool) -> None:
            """Full-width dashed date divider. In bubble mode the date is anchored
            on the message-arrow axis — a 2-column ``ratio`` grid puts the date at
            the start of the right half, which is the same x as the gutter arrows —
            with dashes filling both sides. In row mode (arrows on the left) the
            date sits at the left. Dashed (``╌``) so it reads lighter than the
            solid bubble borders."""
            date = dt.strftime("%a %d %b %Y")
            if use_bubbles:
                # The right half is a left-aligned Rule, which puts one space
                # after the date before its dashes. Prefix the label with one
                # space so the left dashes are separated by the same single space
                # — symmetric gaps — while the gap itself lands on the arrow axis.
                grid = Table(box=None, show_header=False, expand=True,
                             padding=0, pad_edge=False)
                grid.add_column(ratio=self._BUBBLE_RATIO)
                grid.add_column(ratio=self._BUBBLE_RATIO)
                grid.add_row(Rule(characters="╌", style="dim"),
                             Rule(Text(" " + date, style="dim"),
                                  characters="╌", style="dim", align="left"))
                log.write(grid)
            else:
                log.write(Rule(Text(date, style="dim"),
                               characters="╌", style="dim", align="left"))

        @staticmethod
        def _sorted_by_time(messages: list) -> list:
            """Stable time-sort with carry-forward for zero-timestamp records.

            Chat messages carry a real timestamp; transport records (receipts,
            typing) often carry ``0``. A naive sort would sink all zero-timestamp
            records to the top. Instead each zero/missing-timestamp record inherits
            the previous record's timestamp (carry-forward), and the original index
            breaks ties — so receipts stay next to the message they relate to and
            the two directions interleave by real send time.
            """
            annotated = []
            last_ts = 0
            for idx, m in enumerate(messages):
                ts = m.get("timestamp") or 0
                try:
                    ts = int(ts)
                except (TypeError, ValueError):
                    ts = 0
                if ts > 0:
                    last_ts = ts
                    anchor = ts
                else:
                    anchor = last_ts
                annotated.append((anchor, idx, m))
            annotated.sort(key=lambda t: (t[0], t[1]))
            return [m for _, _, m in annotated]

        def _gather_conversation_messages(self, flow, layer,
                                          merge_siblings: bool) -> list:
            """Collect this flow's messages, optionally merged with sibling flows.

            When *merge_siblings* is set (the Message tab), union the message lists
            of every sibling Signal flow of the same conversation so one transcript
            spans the separate per-direction connections. De-dup is by FLOW (each
            flow contributes its messages exactly once) — NOT by content — so two
            genuinely identical messages on the wire both survive. Keying by
            flow_id is required because the sibling list arrives as ``copy.copy``
            snapshots, so the selected flow's own snapshot is not ``is flow``.
            """
            messages = list(getattr(layer, "messages", None) or [])
            siblings = getattr(self, "_conversation_siblings", None) or []
            if not merge_siblings or not siblings:
                return messages
            layer_name = getattr(layer, "name", "")
            seen_ids = {getattr(flow, "flow_id", id(flow))}
            for sib in siblings:
                sib_id = getattr(sib, "flow_id", id(sib))
                if sib_id in seen_ids:
                    continue
                seen_ids.add(sib_id)
                sib_layer = sib.layer(layer_name) if hasattr(sib, "layer") else None
                messages.extend(getattr(sib_layer, "messages", None) or [])
            return messages

        def _render_conversation(self, log: RichLog, flow: "Flow", layer,
                                 *, direction_filter: str | None = None,
                                 merge_siblings: bool = False) -> None:
            """Unified protocol-agnostic conversation renderer for any layer.

            Structure (per the conversation-view spec):
              1. Header — ``<Protocol> · <chat>    <N chat messages>``.
              2. Participants header line (``self (you)  ↔  others``).
              3. Separator.
              4. Message flow — CHAT-kind entries only, in time order.
              5. ``Participants`` detail block (full body / sender per bullet).
              6. Collapsed transport summary for non-chat/non-participant kinds.

            *direction_filter* ("write"/"read") restricts the view to one
            direction (Request = outbound, Response = inbound); *merge_siblings*
            unions the conversation's other per-connection flows (Message tab).
            """
            messages = self._gather_conversation_messages(flow, layer, merge_siblings)
            messages = self._sorted_by_time(messages)
            if direction_filter in ("write", "read"):
                want_outbound = direction_filter == "write"
                messages = [m for m in messages
                            if self._is_outbound(m) == want_outbound]
            protocol, chat = self._message_chat_descriptor(layer)
            # Signal uses epoch-ms timestamps; MTProto / E2E use epoch-seconds.
            # `time_fn` (the bubble/row caption) and `secs` (the day-divider's
            # datetime base) are chosen together here so the two never drift.
            is_signal = getattr(layer, "name", "") == "signal"
            time_fn = self._format_msg_time if is_signal else self._format_msg_time_secs
            secs = not is_signal

            chat_msgs = [m for m in messages
                         if (m.get("kind") or "") in self._CHAT_KINDS]
            participants = self._conversation_participants(layer, messages)
            # Map numeric user ids -> display names from the identity records so
            # group chat rows attribute "from <name>" instead of a raw id. 1:1
            # flows are unaffected (their incoming sender is empty/peer-only).
            id_to_name = self._sender_id_to_name(messages)
            transport = [m for m in messages
                         if (m.get("kind") or "") not in self._CHAT_KINDS
                         and (m.get("kind") or "") != self._PARTICIPANT_KIND]

            # 1. Header — count is CHAT messages only.
            count = len(chat_msgs)
            count_label = f"{count} message" + ("" if count == 1 else "s")
            head = f"[bold {c('accent')}]{protocol}"
            if chat:
                head += f" · {chat}"
            head += f"[/]    [dim]{count_label}[/]"
            log.write(head)

            # Decide the layout ONCE per render (width is invariant across it):
            # the two-column bubble grid on a wide-enough terminal, single-column
            # rows otherwise. The headers, arrows and dividers all key off this.
            use_bubbles = self._bubble_width_ok(log)

            # 2. Participants header — self (you) | ⇄ | peer(s). In bubble mode it
            # is laid out through the chat grid so its connector lines up with the
            # message arrows and the peer cell with the received bubbles.
            p_left, p_glyph, p_right = self._participants_header_parts(participants)
            self._write_header_row(log, p_left, p_glyph, p_right,
                                   use_bubbles=use_bubbles)

            # 2b. Peer-identity summary — names WHOM we are talking to, preferring
            # a phone number. Signal-only: MTProto/E2E already surface named
            # participants (with phones) in the header above, and their numeric
            # senders are internal ids, not peer identifiers.
            if is_signal:
                peer_display, peer_kind = self._resolve_peer_identity(messages)
                s_left, s_glyph, s_right = self._peer_summary_parts(
                    peer_display, peer_kind)
                self._write_header_row(log, s_left, s_glyph, s_right,
                                       use_bubbles=use_bubbles)

            # 3. Separator — full width so it ends at the received bubble's right edge.
            log.write(Rule(characters="─", style="dim"))

            # 4. Message flow — CHAT entries only, with a dashed date divider
            # whenever the calendar day changes between consecutive (time-sorted)
            # messages; its date sits on the message-arrow axis (see below).
            if chat_msgs:
                last_day = None
                for entry in chat_msgs:
                    dt = self._msg_datetime(entry.get("timestamp", 0), secs=secs)
                    if dt is not None and (day := dt.strftime("%Y-%m-%d")) != last_day:
                        self._write_day_divider(log, dt, use_bubbles=use_bubbles)
                        last_day = day
                    self._render_chat_row(log, entry, time_fn, id_to_name,
                                          use_bubbles=use_bubbles)
            else:
                log.write("[dim](no messages)[/]")

            # 5. Participants detail block.
            if participants:
                log.write("")
                log.write(f"[bold {c('primary')}]Participants[/]")
                for p in participants:
                    detail = str(p.get("detail") or p.get("name") or "").replace("[", r"\[")
                    log.write(f"  [dim]•[/] {detail}")

            # 6a. Aggregated session/identity panel (distinct profiles seen).
            self._render_session_identity_panel(log, transport)

            # 6b. Detailed Session-metadata block (REST calls, profiles, devices,
            # prekeys). High-signal records get one readable row each.
            session_meta = [m for m in transport
                            if (m.get("kind") or "") in self._SESSION_META_KINDS]
            if session_meta:
                log.write("")
                log.write(f"[bold {c('primary')}]Session metadata[/]")
                for entry in session_meta:
                    self._render_session_meta_row(log, entry, time_fn)

            # 6c. Collapsed summary for the remaining low-signal transport chatter.
            other = [m for m in transport
                     if (m.get("kind") or "") not in self._SESSION_META_KINDS]
            if other:
                breakdown = Counter((m.get("kind") or "other") for m in other)
                summary = " · ".join(f"{n} {k}" for k, n in breakdown.most_common())
                plural = "" if len(other) == 1 else "s"
                log.write(
                    f"[dim]+ {len(other)} transport record{plural} "
                    f"({summary}) — press l for the raw layer view[/]"
                )

        @staticmethod
        def _esc(value) -> str:
            """Escape Rich markup in arbitrary text (shared escaper)."""
            return _markup_escape(str(value or ""))

        def _render_session_identity_panel(self, log: RichLog, transport) -> None:
            """Summarize distinct Signal identities (profiles) seen this session."""
            profiles = {}
            for m in transport:
                if (m.get("kind") or "") != "profile":
                    continue
                meta = m.get("meta") or {}
                uuid = meta.get("uuid") or ""
                if uuid and uuid not in profiles:
                    profiles[uuid] = meta
            if not profiles:
                return
            log.write("")
            log.write(f"[bold {c('primary')}]Session identities[/]")
            for uuid, meta in profiles.items():
                name = meta.get("name")
                caps = meta.get("capabilities") or {}
                on = ", ".join(k for k, v in caps.items() if v)
                devices = meta.get("devices") or []
                bits = [f"[bold]{self._esc(name)}[/]"] if name else []
                bits.append(f"[dim]{self._esc(uuid)}[/]")
                if devices:
                    bits.append(f"[dim]{len(devices)} device(s)[/]")
                if on:
                    bits.append(f"[dim]caps: {self._esc(on)}[/]")
                log.write(f"  [dim]•[/] " + "  ".join(bits))

        @staticmethod
        def _rest_label(entry) -> str:
            """``VERB path [status]`` summary of a REST/WS record (unescaped)."""
            verb = entry.get("verb") or ""
            path = entry.get("path") or ""
            status = entry.get("status") or 0
            label = " ".join(x for x in (verb, path) if x)
            if status:
                label += f" [{status}]"
            return label

        def _render_session_meta_row(self, log: RichLog, entry, time_fn) -> None:
            """Render one session-metadata record (REST/profile/device/prekey)."""
            kind = entry.get("kind") or ""
            arrow = "→" if self._is_outbound(entry) else "←"
            ts = time_fn(entry.get("timestamp", 0))
            meta = entry.get("meta") or {}

            head = [arrow]
            if ts:
                head.append(f"[dim]{ts}[/]")
            head.append(self._META_ICONS.get(kind, "·"))
            if kind == "profile":
                head.append("profile " + self._esc(meta.get("uuid") or ""))
            elif kind in ("device-list", "prekey"):
                n = meta.get("device_count", len(meta.get("devices", [])))
                noun = "device list" if kind == "device-list" else "prekey bundle"
                head.append(f"{noun} ({n} device(s))")
            else:  # rest / ws-request
                head.append(self._esc(self._rest_label(entry) or kind))
            log.write(f"[{c('primary')}]{'  '.join(head)}[/]")

            detail = self._session_meta_detail(kind, meta)
            if detail:
                log.write(f"      [dim]{detail}[/]")

        def _session_meta_detail(self, kind: str, meta: dict) -> str:
            """Secondary detail line for a session-metadata record (escaped)."""
            if kind == "profile":
                parts = []
                if meta.get("uuid"):
                    parts.append(f"uuid {self._esc(meta['uuid'])}")
                caps = meta.get("capabilities") or {}
                on = ", ".join(k for k, v in caps.items() if v)
                if on:
                    parts.append(f"caps: {self._esc(on)}")
                ik = meta.get("identityKey")
                if isinstance(ik, str) and ik:
                    parts.append(f"identityKey {self._esc(ik[:22])}…")
                return " · ".join(parts)
            if kind in ("device-list", "prekey"):
                devs = meta.get("devices") or []
                return self._esc(", ".join(
                    f"dev{d.get('id', d.get('deviceId', '?'))}"
                    + (f" reg{d['registrationId']}" if d.get("registrationId") else "")
                    for d in devs
                ))
            if kind == "rest":
                if meta.get("type") == "rest-message" and meta.get("destination"):
                    return f"to {self._esc(meta['destination'])}"
                if meta.get("keys"):
                    return "keys: " + self._esc(", ".join(meta["keys"]))
            return ""

        def _render_chat_row(self, log: RichLog, entry, time_fn,
                             id_to_name=None, *, use_bubbles: bool = True) -> None:
            """Render one CHAT-kind message dict as a flow row (arrow + body).

            ``id_to_name`` resolves a numeric group ``sender`` id to a readable
            name; unknown / non-numeric senders fall back to the raw value.
            ``use_bubbles`` is decided once per render by the caller (the
            two-column bubble layout vs the narrow-terminal single-column rows).

            ``entry`` is always a message dict here — the caller's ``chat_msgs``
            filter already reads ``entry.get("kind")`` on every record, so a
            non-dict would have raised before reaching this row renderer.
            """
            sender = entry.get("sender", "") or ""
            timestamp = entry.get("timestamp", 0)
            body = entry.get("body", "") or ""

            if sender and id_to_name and str(sender).isdigit():
                sender = id_to_name.get(str(sender), sender)

            outgoing = self._is_outbound(entry)
            arrow = "→" if outgoing else "←"
            ts = time_fn(timestamp)

            # Chat-bubble layout (sent left / received right, arrow between) on a
            # wide-enough terminal; the single-column rows below are the readable
            # narrow-terminal fallback.
            if use_bubbles:
                self._render_chat_bubble(log, entry, sender, body, ts, outgoing)
                return

            head_parts = [arrow]
            if ts:
                head_parts.append(f"[dim]{ts}[/]")
            head_parts.append("💬")
            if not outgoing and sender:
                head_parts.append(f"[dim]from {self._esc(sender)}[/]")
            log.write(f"[bold {c('primary')}]{'  '.join(head_parts)}[/]")

            shown, overflow, flag_bits = self._chat_body_parts(entry, body)
            quote = c("success")
            if not shown:
                log.write(f"      [dim italic]{self._EMPTY_CHAT_BODY}[/]")
            else:
                lines = shown.replace("[", r"\[").split("\n")
                if len(lines) == 1:
                    log.write(f'      [bold {quote}]“{lines[0]}”[/]')
                else:
                    log.write(f'      [bold {quote}]“[/]')
                    for ln in lines:
                        log.write(f'        [bold {quote}]{ln}[/]')
                    log.write(f'      [bold {quote}]”[/]')
                if overflow:
                    log.write(f"      [dim]… {overflow:,} more chars[/]")
            if flag_bits:
                log.write(f"      [dim]• {', '.join(flag_bits)}[/]")

        def _chat_body_parts(self, entry, body) -> tuple[str, int, list[str]]:
            """Shared content model for both chat layouts.

            Returns ``(shown, overflow, flags)``: the stripped body capped at the
            shared render limit, the count of characters hidden by that cap, and
            the present attachment/quote/reaction markers in order. Each layout
            handles presentation (markup row vs bubble ``Text``); sharing the
            content decisions keeps truncation and flags identical regardless of
            which layout (terminal width) renders the message.
            """
            text = (body or "").strip()
            limit = self._CHAT_BODY_LIMIT
            flags = [k for k in ("attachments", "quote", "reaction")
                     if entry.get(k)]
            return text[:limit], max(0, len(text) - limit), flags

        # Chat-bubble tuning. Below _BUBBLE_MIN_WIDTH columns the single-column
        # arrow rows are used instead. Each bubble half is _BUBBLE_RATIO of
        # (ratio + arrow-gutter + ratio), capping a bubble near ~62% of width.
        _BUBBLE_MIN_WIDTH = 48
        _BUBBLE_RATIO = 5
        # Per-message body cap for the conversation view (both layouts). Kept far
        # below _TEXT_RENDER_LIMIT: a chat message is human-readable text, and
        # word-wrapping a multi-KB body inside a justified Panel is costly. The
        # raw layer / Detail view still shows the full body up to _TEXT_RENDER_LIMIT.
        _CHAT_BODY_LIMIT = 16 * 1024
        # Placeholder for a chat message with no text body — shared by both
        # layouts so their empty-message rendering can't drift.
        _EMPTY_CHAT_BODY = "(empty message)"

        @classmethod
        def _bubble_width_ok(cls, log) -> bool:
            """True when the log is wide enough for the two-column bubble layout.

            Defensive: a hidden / not-yet-laid-out RichLog reports width 0 (and an
            un-mounted one or a size-less test fake raises), so we treat any
            unknown/zero width as wide — the bubble layout is the default and the
            first eager render happens before the panel is shown (width 0). The
            narrow fallback then triggers only on a genuinely small terminal that
            reports a real positive width below the threshold.
            """
            try:
                width = log.content_size.width
            except (RuntimeError, AttributeError):
                # RuntimeError: widget not yet mounted; AttributeError: a size-less
                # test fake. Both mean "width unknown" -> assume wide.
                return True
            if not width:
                return True
            return width >= cls._BUBBLE_MIN_WIDTH

        def _chat_grid(self, *, right_justify: bool = False) -> Table:
            """A 3-column expand grid (left | width-3 centred gutter | right) shared
            by the chat bubbles and the aligned conversation headers, so their
            middle column — the message arrow / header connector — lands on the
            same x. ``right_justify`` pins the right cell to the far right edge:
            used for the headers so the peer aligns with the received bubbles'
            right edge, while the bubbles leave it default (their Panel expands to
            fill the column either way, and right-justifying would misalign the
            Panel's own contents)."""
            grid = Table(box=None, show_header=False, expand=True,
                         padding=0, pad_edge=False)
            grid.add_column(ratio=self._BUBBLE_RATIO)
            grid.add_column(width=3, justify="center")
            grid.add_column(ratio=self._BUBBLE_RATIO,
                            justify="right" if right_justify else "left")
            return grid

        def _bubble_body_text(self, entry, body) -> Text:
            """Build a bubble's body ``Text``: message (or empty marker), plus a
            dimmed overflow note and flag line. Uses the shared ``_chat_body_parts``
            content model, so truncation/flags match the single-column layout."""
            shown, overflow, flag_bits = self._chat_body_parts(entry, body)
            text = Text(shown or self._EMPTY_CHAT_BODY,
                        style="" if shown else "dim italic")
            if overflow:
                text.append(f"\n… {overflow:,} more chars", style="dim")
            if flag_bits:
                text.append("\n• " + ", ".join(flag_bits), style="dim")
            return text

        def _render_chat_bubble(self, log: RichLog, entry, sender, body, ts,
                                outgoing) -> None:
            """Render one CHAT message as a left (sent) / right (received) bubble.

            The arrow sits in a fixed centre gutter between the two columns so the
            direction reads at a glance regardless of which side is filled. The
            timestamp (and ``from <sender>`` for inbound) becomes the bubble's
            dimmed title, aligned to the bubble's own side.
            """
            if outgoing:
                caption, border, title_align, glyph = ts or "", c("accent"), "left", "→"
            else:
                caption = "  ".join(
                    p for p in (f"from {sender}" if sender else "", ts) if p)
                border, title_align, glyph = c("success"), "right", "←"

            bubble = Panel(
                self._bubble_body_text(entry, body), box=ROUNDED,
                border_style=border,
                title=(f"[dim]{self._esc(caption)}[/]" if caption else None),
                title_align=title_align, expand=True, padding=(0, 1),
            )
            arrow = Text(glyph, style=border)

            table = self._chat_grid()
            cells = (bubble, arrow, "") if outgoing else ("", arrow, bubble)
            table.add_row(*cells)
            log.write(table)

        # Kind -> (icon/label, is_chat) for the Message-tab row heading. Chat
        # kinds render the body prominently in quotes; others stay muted.
        _KIND_LABELS = {
            "text": ("💬 message", True),
            "data": ("💬 message", True),
            "message": ("💬 message", True),
            "user": ("👤 user", False),
            "service": ("[dim]service[/]", False),
            "ack": ("[dim]ack[/]", False),
            "rpc": ("[dim]rpc[/]", False),
            "update": ("[dim]update[/]", False),
            "receipt": ("[dim]receipt[/]", False),
            "unparsed": ("[dim]unparsed[/]", False),
        }

        def _message_chat_descriptor(self, layer) -> tuple[str, str]:
            """Return ``(protocol_label, chat_descriptor)`` for the transcript header.

            * Signal   -> ("Signal", "1:1 conversation" / "group conversation")
            * MTProto  -> ("MTProto", "cloud")
            * Tg E2E   -> ("Telegram", "Secret Chat")

            Only Telegram-E2E (genuine secret-chat layering) says "Secret Chat".
            """
            name = getattr(layer, "name", "") or ""
            if name == "signal":
                chat_type = getattr(layer, "chat_type", "") or ""
                convo = "group" if chat_type == "group" else "1:1"
                return "Signal", f"{convo} conversation"
            if name == "telegram_e2e":
                return "Telegram", "Secret Chat"
            if name == "mtproto":
                return "MTProto", "cloud"
            from friTap.constants import LAYER_DISPLAY_NAMES
            return LAYER_DISPLAY_NAMES.get(name, name or "Messages"), ""

        def _render_layer_transcript(self, log: RichLog, flow: "Flow", layer) -> None:
            """Render a message-bearing layer's entries as a chat transcript.

            Mirrors :meth:`_render_signal_messages` so MTProto / Telegram-E2E
            flows present identically. Reads the shared message-dict contract
            (``direction``, ``timestamp``, ``kind``, ``body``, ``method``,
            ``sender``) defensively so partly-enriched dicts still render.
            """
            messages = list(getattr(layer, "messages", None) or [])
            protocol, chat = self._message_chat_descriptor(layer)

            # Split meaningful content (chat text, identities, updates) from the
            # high-volume transport chatter (acks, rpc acks, pings, …). The
            # transcript surfaces the former in full and collapses the latter into
            # one summary line, so a busy flow's dozens of msgs_acks never bury the
            # actual messages (Signal's transcript stays clean because it has only a
            # handful of receipts; MTProto carries far more service records).
            meaningful = [m for m in messages
                          if (m.get("kind") or "") in self._MEANINGFUL_KINDS]
            noise = [m for m in messages
                     if (m.get("kind") or "") not in self._MEANINGFUL_KINDS]

            count = len(meaningful)
            count_label = (f"{count} message" + ("" if count == 1 else "s")
                           if count else "no messages")
            head = f"[bold {c('accent')}]{protocol}"
            if chat:
                head += f" · {chat}"
            head += f"[/]    [dim]{count_label}[/]"
            log.write(head)
            log.write(f"[dim]{'─' * 54}[/]")

            for entry in meaningful:
                self._render_transcript_entry(log, entry)

            if noise:
                breakdown = Counter((m.get("kind") or "other") for m in noise)
                summary = " · ".join(f"{n} {k}" for k, n in breakdown.most_common())
                if meaningful:
                    log.write("")
                plural = "" if len(noise) == 1 else "s"
                log.write(
                    f"[dim]+ {len(noise)} transport record{plural} "
                    f"({summary}) — press l for the raw layer view[/]"
                )
            elif not meaningful:
                log.write("[dim]no messages[/]")

        # Kinds shown in full in the Message transcript; everything else
        # (ack/rpc/service/receipt/unparsed) is transport chatter, collapsed.
        _MEANINGFUL_KINDS = frozenset({"text", "data", "message", "user", "update"})

        def _render_transcript_entry(self, log: RichLog, entry) -> None:
            """Render one message-dict as a transcript row (heading + optional body)."""
            try:
                direction = entry.get("direction", "") or ""
                sender = entry.get("sender", "") or ""
                timestamp = entry.get("timestamp", 0)
                kind = entry.get("kind", "") or ""
                body = entry.get("body", "") or ""
                method = entry.get("method", "") or ""
            except AttributeError:
                return

            outgoing = direction in ("write", "outgoing", "sent")
            arrow = "→" if outgoing else "←"
            ts = self._format_msg_time_secs(timestamp)
            label, is_chat = self._KIND_LABELS.get(kind, (kind or "message", False))

            head_parts = [arrow]
            if ts:
                head_parts.append(f"[dim]{ts}[/]")
            head_parts.append(label)
            # Show the TL method only when it adds information (not for chat rows,
            # and not when it merely repeats the kind label, e.g. a "user" item).
            if method and not is_chat and method.lower() != kind.lower():
                head_parts.append(f"[dim]{method}[/]")
            # "from <sender>" only on received chat rows — for a user/identity row
            # the sender id is the user's own id and just repeats the body.
            if not outgoing and sender and kind != "user":
                head_parts.append(f"[dim]from {sender}[/]")
            log.write(f"[bold {c('primary')}]{'  '.join(head_parts)}[/]")

            # Render any body (chat text, or a user/identity summary) in quotes when
            # it's a chat kind; otherwise show it indented and muted.
            text = (body or "").strip()
            if text:
                limit = self._TEXT_RENDER_LIMIT
                shown = text[:limit].replace("[", r"\[")
                if is_chat:
                    quote = c("success")
                    lines = shown.split("\n")
                    if len(lines) == 1:
                        log.write(f'      [bold {quote}]“{lines[0]}”[/]')
                    else:
                        log.write(f'      [bold {quote}]“[/]')
                        for ln in lines:
                            log.write(f'        [bold {quote}]{ln}[/]')
                        log.write(f'      [bold {quote}]”[/]')
                else:
                    for ln in shown.split("\n"):
                        log.write(f"      [dim]{ln}[/]")
                if len(text) > limit:
                    log.write(f"      [dim]… {len(text) - limit:,} more chars[/]")

        @classmethod
        def _format_msg_time_secs(cls, ts) -> str:
            """Format an epoch-SECONDS timestamp as HH:MM:SS; '' when unknown.

            MTProto / Telegram message dicts use epoch seconds (per the data
            contract), unlike Signal's epoch-ms (:meth:`_format_msg_time`). Both
            formatters delegate to :meth:`_msg_datetime` so the day dividers
            (which also use it) can never disagree with the captions.
            """
            dt = cls._msg_datetime(ts, secs=True)
            return dt.strftime("%H:%M:%S") if dt is not None else ""

        def _render_one_layer(self, log: RichLog, layer, idx: int = 0) -> None:
            """Render a single protocol layer: header, metadata, then parsed/hex body."""
            name = getattr(layer, "name", "?")
            depth = getattr(layer, "depth", 0)
            data = getattr(layer, "data", None)
            source = getattr(data, "data_source", "none") if data is not None else "none"
            metadata_only = getattr(layer, "metadata_only", False)

            tags = [source]
            if metadata_only:
                tags.append("metadata-only")
            marker = "▸ " if idx == self._current_layer_idx else "  "
            log.write(
                f"[bold {c('accent')}]{marker}[{depth}] {name}[/] "
                f"[dim]({', '.join(tags)})[/]"
            )

            self._render_layer_metadata(log, layer, name)

            view = self._layer_view.get(idx, self._default_layer_view(layer))
            if view == "parsed":
                self._render_layer_parsed(log, layer, idx)
            elif source != "none" and data is not None:
                self._render_layer_bytes(log, data)

        def _render_layer_parsed(self, log: RichLog, layer, idx: int) -> None:
            """Render the parsed (human-readable) view for a layer.

            Understands any message-bearing layer (Signal, MTProto cloud, or
            Telegram Secret-Chat E2E) via :meth:`_layer_has_messages`; other
            layers fall through with a short hint so the user can switch to hex.
            """
            is_signal = getattr(layer, "name", "") == "signal" or self._layer_has_messages(layer)
            if not is_signal:
                log.write("    [dim]no parsed view — press l for hex[/]")
                return

            messages = getattr(layer, "messages", None) or []
            if not messages:
                log.write("    [dim]no parsed messages[/]")
                return

            # Legend for the MTProto transport categories, shown once when any
            # are present so "ack"/"rpc"/"service" rows below are self-explaining.
            if {(m.get("kind") or "") for m in messages} & {"ack", "rpc", "service"}:
                log.write("    [dim]ack = msgs_ack · rpc = rpc_result · "
                          "service = pong/salt/session/error[/]")

            for entry in messages:
                try:
                    direction = entry.get("direction", "") or ""
                    sender = entry.get("sender", "") or ""
                    timestamp = entry.get("timestamp", "") or ""
                    kind = entry.get("kind", "") or ""
                    body = entry.get("body", "") or ""
                    method = entry.get("method", "") or ""
                except AttributeError:
                    continue

                # "write" = client->server = sent by this device (outgoing);
                # "read" = received. Accept the synonyms defensively.
                arrow = "→" if direction in ("write", "outgoing", "sent") else "←"
                head_bits = [b for b in (arrow, sender, kind) if b]
                # Escape wire-derived fields (sender/kind) — a literal "[" would be
                # parsed as Rich markup and can raise MarkupError on the RichLog.
                head = "  ".join(self._esc(b) for b in head_bits)
                # Surface the TL type name so "rpc"/"service"/"ack" records say
                # WHICH call/service they are (e.g. "rpc  users"); skip it when
                # it merely repeats the kind label.
                method_suffix = (f"  [dim]{self._esc(method)}[/]"
                                 if method and method.lower() != kind.lower()
                                 else "")
                ts_suffix = f"  [dim]@{self._esc(timestamp)}[/]" if timestamp else ""
                log.write(f"    [bold {c('accent')}]{head}[/]{method_suffix}{ts_suffix}")

                # Plaintext metadata records (REST/profile/device/prekey) carry no
                # chat body; show their verb/path/status and the parsed JSON dict.
                rest_line = self._rest_label(entry)
                if rest_line:
                    log.write(f"      [dim]{self._esc(rest_line)}[/]")
                entry_meta = entry.get("meta")
                if isinstance(entry_meta, dict) and entry_meta:
                    for k, v in entry_meta.items():
                        if k == "type":
                            continue
                        log.write(f"      [dim]{self._esc(k)}: {self._esc(v)}[/]")

                if body:
                    self._write_text_body(
                        log, body.encode("utf-8", "replace"), errors="replace"
                    )

                flag_bits = []
                if entry.get("attachments"):
                    flag_bits.append("attachments")
                if entry.get("quote"):
                    flag_bits.append("quote")
                if entry.get("reaction"):
                    flag_bits.append("reaction")
                if flag_bits:
                    log.write(f"    [dim]• {', '.join(flag_bits)}[/]")

        def _render_layer_metadata(self, log: RichLog, layer, name: str) -> None:
            """Render typed metadata fields for a layer (indented)."""
            try:
                meta = layer.to_dict()
            except Exception:
                meta = {}
            # Drop identity fields already shown in the header, and the parsed
            # message list (rendered separately by _render_layer_parsed, not as a
            # raw repr in the metadata block).
            meta = {k: v for k, v in meta.items()
                    if k not in ("name", "depth", "messages")}

            primary = self._LAYER_PRIMARY_FIELDS.get(name, ())
            ordered_keys = [k for k in primary if k in meta]
            ordered_keys += [k for k in meta if k not in ordered_keys]

            wrote_any = False
            for key in ordered_keys:
                value = meta.get(key)
                if value in (None, "", 0, False):
                    continue
                log.write(f"    [bold]{key}:[/] {value}")
                wrote_any = True
            if not wrote_any:
                log.write("    [dim]no metadata[/]")

        def _render_layer_bytes(self, log: RichLog, data) -> None:
            """Render a short read/write byte summary for a layer with data."""
            limit = self._LAYER_BYTES_PREVIEW
            for label, direction in (("write (c2s)", "write"), ("read (s2c)", "read")):
                try:
                    raw = data.direction(direction)
                except Exception:
                    raw = b""
                if not raw:
                    continue
                log.write(f"    [bold {c('success')}]{label}:[/] {len(raw):,} bytes")
                self._write_hexdump(log, raw[:limit])
                if len(raw) > limit:
                    log.write(f"    [dim]... {len(raw) - limit:,} more bytes[/]")

        # ----------------------------------------------------------
        # Trailing data rendering
        # ----------------------------------------------------------

        _TRAILING_HEX_LIMIT = 512

        def _render_trailing_data(self, log: RichLog, flow: "Flow") -> None:
            """Render trailing data as a second segment with parsed content if available."""
            tb = flow.trailing_bytes
            if tb is None:
                return

            # Segment divider — record approximate scroll offset for n/N navigation
            # RichLog has no public line_count; use virtual_size height as proxy
            try:
                self._segment_offsets.append(int(log.virtual_size.height))
            except Exception:
                pass
            log.write("")
            log.write(f"[bold {c('warning')}]{'═' * 60}[/]")
            proto_label = flow.trailing_protocol or "unknown"
            log.write(
                f"[bold {c('warning')}]SEGMENT 2  "
                f"[{c('accent')}]{proto_label}[/]  "
                f"[dim]({len(tb):,} bytes trailing)[/]"
            )
            log.write(f"[bold {c('warning')}]{'═' * 60}[/]")

            sp = flow.trailing_parse
            if sp is not None:
                # Request/status line
                if sp.method:
                    url = getattr(sp, 'url', '') or ''
                    version = getattr(sp, 'protocol', '')
                    log.write(f"[bold {c('primary')}]{sp.method} {url} {version}[/]")
                elif sp.status_code:
                    version = getattr(sp, 'protocol', 'HTTP/1.1')
                    log.write(f"[bold]{version} {sp.status_code} {sp.status_text}[/]")
                # Headers
                headers = getattr(sp, 'headers', {})
                if headers:
                    log.write("")
                    for name, value in headers.items():
                        log.write(f"[bold]{name}:[/] {value}")
                # Body
                body = sp.body
                if body:
                    log.write("")
                    log.write(f"[bold {c('success')}]--- Body ---[/]")
                    if _is_text(body):
                        text = body.decode("utf-8", errors="replace")
                        if len(text) > 2048:
                            text = text[:2048] + "\n... (truncated)"
                        log.write(text)
                    else:
                        self._write_hexdump(log, body[:self._TRAILING_HEX_LIMIT])
            else:
                # No sub-parse — show raw hexdump preview
                log.write("")
                log.write("[dim]Raw trailing bytes (press h for full hex view):[/]")
                self._write_hexdump(log, tb[:self._TRAILING_HEX_LIMIT])
                if len(tb) > self._TRAILING_HEX_LIMIT:
                    log.write(f"[dim]... {len(tb) - self._TRAILING_HEX_LIMIT:,} more bytes[/]")

        # ----------------------------------------------------------
        # Data mismatch detection
        # ----------------------------------------------------------

        def _render_data_mismatch_banner(
            self, log: RichLog, flow: "Flow", direction: str, parsed_body_size: int,
        ) -> None:
            """Show a warning when raw captured data significantly exceeds what the parsed view represents.

            Estimates "accounted-for" bytes: body + decoded headers + protocol
            framing overhead.  Only warns when raw data exceeds that estimate
            by more than 256 bytes — this avoids false positives on HTTP/2
            responses where HPACK-compressed headers + control frames can be
            large without any hidden data.
            """
            # Message-bearing flows (Signal/MTProto/E2E) render a decrypted
            # transcript, not an HTTP body, so the HTTP-shaped byte accounting below
            # is meaningless and would always fire (e.g. "62 B of 456 B"). Skip it.
            if _flow_has_messages(flow):
                return
            raw_total = sum(len(c.data) for c in flow.chunks if c.direction == direction)
            if raw_total <= 0:
                return
            # Estimate bytes the parsed view already represents
            accounted = parsed_body_size
            msg = flow.request if direction == "write" else flow.response
            if msg is not None:
                headers = getattr(msg, 'headers', {})
                for k, v in headers.items():
                    accounted += len(k) + len(str(v)) + 4  # ": " + "\r\n"
                accounted += 32  # status/request line + protocol framing
            if raw_total - accounted <= 256:
                return
            parsed_str = format_byte_size(parsed_body_size)
            raw_str = format_byte_size(raw_total)
            log.write("")
            log.write(
                f"[bold {c('warning')}]\u26a0 Parsed view shows {parsed_str} "
                f"of {raw_str} captured. Press h for full hex view.[/]"
            )

        # ----------------------------------------------------------
        # Body rendering
        # ----------------------------------------------------------

        # ----------------------------------------------------------
        # Decoder functions for body rendering
        # ----------------------------------------------------------

        def _decode_protobuf(self, log: RichLog, body: bytes, headers: dict) -> None:
            try:
                from friTap.parsers.protobuf import decode_raw, format_message, extract_grpc_messages
                content_type = _get_header(headers, "content-type")
                grpc_msgs = extract_grpc_messages(body, content_type)
                if grpc_msgs:
                    for i, msg_bytes in enumerate(grpc_msgs):
                        if i > 0:
                            log.write("")
                        log.write(f"[bold]gRPC message {i + 1}[/]")
                        decoded = decode_raw(msg_bytes)
                        log.write(format_message(decoded))
                else:
                    decoded = decode_raw(body)
                    log.write(format_message(decoded))
            except ImportError:
                log.write("[dim yellow]Protobuf parser not available[/]")
            except Exception as e:
                log.write(f"[dim yellow]Protobuf decode error: {e}[/]")
                self._write_hexdump(log, body)

        @staticmethod
        def _decode_json(log: RichLog, body: bytes, _headers: dict) -> None:
            try:
                parsed = json.loads(body)
                formatted = json.dumps(parsed, indent=2)
                log.write(formatted)
            except (json.JSONDecodeError, UnicodeDecodeError):
                log.write("[dim yellow]Not valid JSON[/]")
                log.write(body.decode("utf-8", errors="replace"))

        def _decode_base64(self, log: RichLog, body: bytes, _headers: dict) -> None:
            import base64 as b64mod
            try:
                decoded_bytes = b64mod.b64decode(body)
                if _is_text(decoded_bytes):
                    log.write(decoded_bytes.decode("utf-8"))
                else:
                    self._write_hexdump(log, decoded_bytes)
            except Exception:
                log.write("[dim yellow]Base64 decode failed[/]")
                self._write_hexdump(log, body)

        def _decode_hex(self, log: RichLog, body: bytes, _headers: dict) -> None:
            self._write_hexdump(log, body)

        @staticmethod
        def _decode_raw_utf8(log: RichLog, body: bytes, _headers: dict) -> None:
            log.write(body.decode("utf-8", errors="replace"))

        # Dispatch table: decoder name → method
        _DECODERS = {
            "protobuf": _decode_protobuf,
            "json": _decode_json,
            "base64": _decode_base64,
            "hex": _decode_hex,
            "raw_utf8": _decode_raw_utf8,
        }

        def _render_control_frame(self, log: RichLog, req) -> None:
            """Render HTTP/2 connection-level control frame details."""
            from friTap.parsers.http2 import H2_URL_CONNECTION_SETUP

            if req.url == H2_URL_CONNECTION_SETUP:
                log.write(f"[bold {c('primary')}]HTTP/2 Connection Setup[/]")
            else:
                log.write(f"[bold {c('primary')}]HTTP/2 Connection Control[/]")

            log.write(f"[bold {c('accent')}]{'═' * 40}[/]")
            log.write(f"[bold]Frame:[/] {req.method}")
            log.write("")

            headers = req.headers if req.headers else {}
            if headers:
                for name, value in headers.items():
                    log.write(f"  [bold]{name}:[/]  {value}")

        def _render_incomplete_h2_note(self, log: RichLog, raw: bytes) -> None:
            """Show informational note for incomplete HTTP/2 frames."""
            if len(raw) < 9:
                return
            try:
                from friTap.parsers.http2 import _FRAME_TYPE_NAMES, _FRAME_HEADER_SIZE
                length = int.from_bytes(raw[:3], "big")
                frame_type = raw[3]
                stream_id = int.from_bytes(raw[5:9], "big") & 0x7FFFFFFF
                name = _FRAME_TYPE_NAMES.get(frame_type, f"type={frame_type}")
                have = len(raw) - _FRAME_HEADER_SIZE
                if length > have:
                    log.write(
                        f"[dim]  Frame: {name} (stream {stream_id}, "
                        f"expected {length} bytes, got {have})[/]"
                    )
                else:
                    log.write(f"[dim]  Frame: {name} (stream {stream_id}, {length} bytes)[/]")
            except Exception:
                pass

        def _render_body(self, log: RichLog, body: bytes, headers: dict) -> None:
            """Render body content with appropriate formatting.

            Two modes:
            1. **Active processing** — user-selected decompression + decoder
               from the Body Processing modal (press ``p``).
            2. **Standard rendering** — auto-detect from Content-Type / Content-Encoding.
            """
            if self._active_processing:
                body = self._apply_active_processing(log, body, headers)
                if body is None:
                    return  # decoder already rendered output

            self._render_body_standard(log, body, headers)

        def _apply_active_processing(
            self, log: RichLog, body: bytes, headers: dict,
        ) -> bytes | None:
            """Apply user-selected decompression + decoder.

            Returns the (possibly decompressed) body for standard rendering,
            or ``None`` if a decoder already wrote output to *log*.
            """
            processed = body
            if self._active_processing.decompression:
                try:
                    from friTap.parsers.decompress import decompress_body
                    processed, err = decompress_body(processed, self._active_processing.decompression)
                    if err:
                        log.write(f"[dim yellow]Decompression note: {err}[/]")
                except ImportError:
                    log.write("[dim yellow]Decompression module not available[/]")

            decoder_name = self._active_processing.decoder or ""
            decoder_fn = self._DECODERS.get(decoder_name)
            if decoder_fn is not None:
                decoder_fn(self, log, processed, headers)
                return None  # decoder handled output

            # Decompression only, no decoder — fall through to standard rendering
            return processed

        def _render_body_standard(self, log: RichLog, body: bytes, headers: dict) -> None:
            """Auto-render body based on Content-Encoding and Content-Type."""
            # Decompress if Content-Encoding is set
            content_encoding = _get_header(headers, "content-encoding")
            if content_encoding:
                try:
                    from friTap.parsers.decompress import decompress_body
                    body, err = decompress_body(body, content_encoding)
                    if err:
                        log.write(f"[dim yellow]Decompression note: {err}[/]")
                except ImportError:
                    pass

            content_type = _get_header(headers, "content-type")

            # OHTTP detection banner
            self._render_ohttp_banner(log, content_type)

            if "application/json" in content_type or "text/json" in content_type:
                try:
                    parsed = json.loads(body)
                    log.write(json.dumps(parsed, indent=2))
                    return
                except (json.JSONDecodeError, UnicodeDecodeError):
                    pass

            if ("text/" in content_type
                    or "application/xml" in content_type
                    or "application/javascript" in content_type):
                try:
                    self._write_text_body(log, body, errors="replace")
                    return
                except Exception:
                    pass

            if _is_text(body):
                self._write_text_body(log, body)
                return

            self._write_hexdump(log, body)

        def _render_ohttp_banner(self, log: RichLog, content_type: str) -> None:
            """Show OHTTP encryption/decryption status banner if applicable."""
            if "message/ohttp-req" in content_type:
                ohttp_type = "request"
            elif "message/ohttp-res" in content_type:
                ohttp_type = "response"
            else:
                return

            label = "Request" if ohttp_type == "request" else "Response"
            flow = self._current_flow
            has_decrypted = False
            if flow is not None:
                if ohttp_type == "request" and flow.ohttp_inner_request is not None:
                    has_decrypted = True
                elif ohttp_type == "response" and flow.ohttp_inner_response is not None:
                    has_decrypted = True

            log.write(f"[dim]Content-Type: message/ohttp-{ohttp_type[:3]} (Oblivious HTTP, RFC 9458)[/]")
            if has_decrypted:
                log.write(f"[bold green]OHTTP Decrypted {label}[/]")
                log.write("[dim]Decrypted inner content available in the [bold]OHTTP Inner[/bold] tab.[/]")
            else:
                log.write(f"[bold yellow]OHTTP Encrypted {label}[/]")
                log.write("[dim]Body is HPKE-encrypted (X25519 + AES-128-GCM).[/]")
                ohttp_tab_active = any(
                    getattr(t, 'tab_id', '') == 'ohttp' for t in self._extra_tabs
                )
                if ohttp_tab_active:
                    log.write("[dim]OHTTP decryption active — no inner payload captured for this flow.[/]")
                    log.write("[dim]The target app may not use NSS for HPKE, or the hook did not fire.[/]")
                else:
                    log.write("[dim]Enable OHTTP decryption in capture settings to see inner content.[/]")
            log.write("")

        # Render caps to prevent the TUI from freezing on large bodies.
        # Full data is still in Flow.chunks and PCAP.
        _HEXDUMP_RENDER_LIMIT = 64 * 1024   # 64 KB
        _TEXT_RENDER_LIMIT = 256 * 1024      # 256 KB

        def _write_text_body(self, log: RichLog, body: bytes, errors: str = "strict") -> None:
            """Write text body with render-limit truncation.

            The RichLog has ``markup=True``, so a literal ``[`` in the decoded body
            (e.g. JSON, a chat message, a path) would be parsed as Rich markup and
            can raise ``MarkupError`` on an unbalanced tag. Escape it.
            """
            limit = self._TEXT_RENDER_LIMIT
            log.write(body[:limit].decode("utf-8", errors=errors).replace("[", r"\["))
            if len(body) > limit:
                log.write(
                    f"[dim italic]... {len(body) - limit:,} more bytes truncated "
                    f"({len(body):,} total)[/]"
                )

        def _write_hexdump(
            self, log: RichLog, data: bytes,
            bytes_per_line: int = 16, start_offset: int = 0,
        ) -> None:
            """Write a hexdump of binary data (first 64 KB; full data in PCAP)."""
            render_data = data[:self._HEXDUMP_RENDER_LIMIT]
            lines = format_hexdump_lines(
                render_data,
                bytes_per_line=bytes_per_line,
                start_offset=start_offset,
                markup=True,
            )
            if lines:
                log.write("\n".join(lines))
            if len(data) > self._HEXDUMP_RENDER_LIMIT:
                remaining = len(data) - self._HEXDUMP_RENDER_LIMIT
                log.write(
                    f"[dim italic]... {remaining:,} more bytes "
                    f"({len(data):,} total) — full data available in PCAP export[/]"
                )

        def _has_binary_data(self, flow: "Flow") -> bool:
            """Check if any body data would render as hexdump (samples first 512 bytes)."""
            for attr in ('request', 'response'):
                msg = getattr(flow, attr, None)
                if msg is None:
                    continue
                body = getattr(msg, 'body', b'')
                if body and not _is_text(body[:512]):
                    return True
            return False
