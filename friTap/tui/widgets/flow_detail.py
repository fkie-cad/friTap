"""Flow detail widget -- tabbed view showing request, response, and connection details."""

from __future__ import annotations

import json
import os
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
            self._last_explorer_result = None  # ExplorerResult from last explorer session
            # Widget refs assigned in compose(); None until then
            self._header_widget: Static | None = None
            self._tabs: TabbedContent | None = None
            self._request_log: RichLog | None = None
            self._response_log: RichLog | None = None
            self._detail_log: RichLog | None = None
            self._segment_offsets: list[int] = []  # RichLog line offsets for n/N navigation

        def register_tab(self, provider) -> None:
            """Register a plugin TabProvider for an extra tab."""
            self._extra_tabs.append(provider)

        def compose(self):
            self._header_widget = Static("", id="flow-detail-header")
            yield self._header_widget
            tab_titles = ["Request", "Response", "Detail"]
            for tab_provider in self._extra_tabs:
                tab_titles.append(tab_provider.title)

            # Widget IDs also referenced in friTap/tui/css/fritap.tcss
            self._request_log = RichLog(id="request-log", wrap=True, highlight=True, markup=True, auto_scroll=False)
            self._response_log = RichLog(id="response-log", wrap=True, highlight=True, markup=True, auto_scroll=False)
            self._detail_log = RichLog(id="detail-log", wrap=True, highlight=True, markup=True, auto_scroll=False)

            with TabbedContent(*tab_titles, id="flow-tabs") as self._tabs:
                with TabPane("Request", id=_TAB_REQUEST):
                    yield self._request_log
                with TabPane("Response", id=_TAB_RESPONSE):
                    yield self._response_log
                with TabPane("Detail", id=_TAB_DETAIL):
                    yield self._detail_log
                for tab_provider in self._extra_tabs:
                    with TabPane(tab_provider.title, id=f"tab-{tab_provider.tab_id}"):
                        yield RichLog(id=f"{tab_provider.tab_id}-log", wrap=True, highlight=True, markup=True, auto_scroll=False)

        def _reset_view_state(self) -> None:
            self._raw_request = False
            self._raw_response = False
            self._active_processing = None

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
                }
                log = log_map.get(active)
                if log:
                    log.scroll_home(animate=False)
            except Exception:
                pass

        @staticmethod
        def _auto_select_tab(tabs: TabbedContent, flow: "Flow") -> None:
            """Select the first tab that has meaningful data."""
            if flow.has_request_data:
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
            from friTap.flow.models import Flow
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

        def _update_request(self, flow: "Flow") -> None:
            log = self._request_log
            log.clear()
            self._segment_offsets = []

            if self._raw_request:
                self._render_raw_hex(log, flow, "write", "request")
                return

            req = flow.request
            if req is None:
                raw = flow.get_direction_bytes("write", max_bytes=self._TEXT_RENDER_LIMIT)
                if raw:
                    if "HTTP/2" in (flow.detected_protocol or ""):
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
                    log.write(f"[dim italic]Auto-decompressed (permessage-deflate)[/]")
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

            resp = flow.response
            if resp is None:
                raw = flow.get_direction_bytes("read", max_bytes=self._TEXT_RENDER_LIMIT)
                if raw:
                    if "HTTP/2" in (flow.detected_protocol or ""):
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
                    log.write(f"[dim italic]Auto-decompressed (permessage-deflate)[/]")
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
                log.write(f"[dim]Decrypted inner content available in the [bold]OHTTP Inner[/bold] tab.[/]")
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
            """Write text body with render-limit truncation."""
            limit = self._TEXT_RENDER_LIMIT
            log.write(body[:limit].decode("utf-8", errors=errors))
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
