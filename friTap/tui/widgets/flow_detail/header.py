"""Flow-detail header line, raw hex views, trailing data and the data-mismatch banner."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from rich.markup import escape as _markup_escape
from textual.widgets import RichLog

from friTap.flow.display import TELEGRAM_LAYER_NAMES
from friTap.flow.models import format_byte_size
from friTap.tui.themes import c
from friTap.tui.widgets import flow_detail as _fd
from friTap.tui.widgets.hexdump import _is_text
from friTap.tui.widgets.wire_text import safe_static_text

from .helpers import (
    _TAB_LAYERS,
    _escape_bracket_label,
    _flow_message_layer,
    _safe_layer,
    _safe_wire_text,
)

if TYPE_CHECKING:
    from friTap.flow.models import Flow


class HeaderMixin:
    """Header line, plugin tabs, raw hexdumps, trailing data and the data-mismatch banner."""

    def _update_extra_tabs(self, flow: "Flow") -> None:
        """Update plugin-provided tabs."""
        for tab_provider in self._plugin_tab_providers():
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
        method = safe_static_text(flow.display_method or "-")
        host = safe_static_text(flow.display_host or "-")
        status_part = self._header_status_part(flow)
        proto = self._layered_detail_protocol(flow)
        if not proto:
            proto = flow.display_protocol.upper() if flow.display_protocol != "unknown" else "???"

        pipeline_desc = self._describe_pipeline()
        raw_hints = []
        if self._raw_request:
            raw_hints.append("REQ:HEX")
        if self._raw_response:
            raw_hints.append("RES:HEX")
        raw_indicator = f"  [bold {c('warning')}]{' '.join(raw_hints)}[/]" if raw_hints else ""

        if pipeline_desc:
            decomp_hint = f"  [dim]p:parse r:reset s:save h:hex x:explore[/]  [{c('accent')}]{safe_static_text(pipeline_desc)}[/]{raw_indicator}"
        else:
            decomp_hint = f"  [dim]p:parse r:reset s:save h:hex x:explore[/]{raw_indicator}"

        try:
            on_layers = self._tabs is not None and self._tabs.active == _TAB_LAYERS
        except Exception:
            on_layers = False
        if on_layers:
            decomp_hint += "  [dim][ ] prev/next layer · l hex/parsed[/]"

        header.update(
            f"[bold {c('primary')}]{_escape_bracket_label(proto)}[/] [bold]{method}[/] {host}  "
            f"{status_part}[dim]@{ts}[/]  "
            f"[dim italic]Escape: back[/]{decomp_hint}\n"
            f"[dim]{flow.src_addr}:{flow.src_port} \u2192 {flow.dst_addr}:{flow.dst_port}[/]"
        )

    @staticmethod
    def _has_inner_e2e_layer(flow: "Flow") -> bool:
        """True when *flow* carries an inner E2E layer (Signal, MTProto, RC4...)."""
        from friTap.flow.display import INNER_E2E_LAYER_NAMES

        return any(_safe_layer(flow, name) is not None
                   for name in INNER_E2E_LAYER_NAMES)

    @staticmethod
    def _layered_detail_protocol(flow: "Flow") -> str:
        """Layered protocol label (as in the flow list) for message flows, else "".

        Applies when the flow rides a message transport (MTProto / Secret
        Chat) or carries an inner E2E layer, so the header / Detail tab agree
        with the list instead of echoing the carrier (e.g. "WebSocket").
        """
        from friTap.flow.display import (
            display_protocol_layered,
            is_message_transport,
        )

        has_inner = HeaderMixin._has_inner_e2e_layer(flow)
        if not (has_inner or is_message_transport(flow)):
            return ""
        label = display_protocol_layered(flow)
        return "" if label in ("", "unknown") else label

    @classmethod
    def _detail_protocol(cls, flow: "Flow") -> str:
        """Protocol string for the detail view: layered label, else the parsed one."""
        return cls._layered_detail_protocol(flow) or flow.display_protocol

    @staticmethod
    def _header_status_part(flow: "Flow") -> str:
        """Header ``> status`` fragment; omitted for message transports."""
        from friTap.flow.display import display_status_for, is_message_transport

        if is_message_transport(flow):
            return ""
        status = display_status_for(flow)
        if not status and HeaderMixin._has_inner_e2e_layer(flow):
            return ""  # opaque inner-cipher payload: no HTTP-style status
        status = status or "pending"
        return f"[dim]>[/] {safe_static_text(status)}  "

    def _render_raw_hex(self, log: RichLog, flow: "Flow", direction: str, label: str) -> None:
        """Render the raw hexdump of *direction*, bypassing parsing.

        With several chunks, each is annotated with its offset range and
        function name to show where protocol boundaries fall.
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
                    f"({len(ch.data):,} bytes)"
                    f"{self._chunk_stream_suffix(ch)}[/]"
                )
                log.write(f"[dim]{'─' * 50}[/]")
                render_bytes = ch.data[:bytes_budget]
                self._write_hexdump(log, render_bytes, start_offset=offset)
                bytes_budget -= len(render_bytes)
                offset += len(ch.data)
                if i < len(dir_chunks) - 1:
                    log.write("")
        else:
            stream_suffix = self._chunk_stream_suffix(dir_chunks[0])
            if stream_suffix:
                log.write(f"[dim]{stream_suffix.strip()}[/]")
            self._write_hexdump(log, dir_chunks[0].data[:self._HEXDUMP_RENDER_LIMIT])

        log.scroll_home(animate=False)

    @staticmethod
    def _chunk_stream_suffix(chunk) -> str:
        """`` stream N`` for a chunk with a known transport stream id, else ""."""
        stream_id = getattr(chunk, "stream_id", None)
        return f" stream {stream_id}" if stream_id is not None else ""

    @staticmethod
    def _nonhttp_transport_label(flow: "Flow") -> str:
        """Display name of a non-HTTP, message-bearing transport (e.g. "MTProto"), else "".

        Lets the Request/Response tabs point at the Message tab instead of
        claiming that HTTP headers could not be parsed.
        """
        layer = _flow_message_layer(flow)
        name = getattr(layer, "name", "") if layer is not None else ""
        if name in TELEGRAM_LAYER_NAMES:
            from friTap.constants import LAYER_DISPLAY_NAMES
            return LAYER_DISPLAY_NAMES.get(name, name)
        return ""

    _TRAILING_HEX_LIMIT = 512

    def _render_trailing_data(self, log: RichLog, flow: "Flow",
                              which: str = "request") -> None:
        """Render trailing data as a second segment with parsed content if available.

        *which* selects the request (write) or response (read) trailing slot.
        """
        tb, trailing_protocol, sp = self._trailing_slot(flow, which)
        if tb is None:
            return

        # Record the divider's scroll offset for n/N navigation. RichLog has
        # no public line_count, so virtual_size height is the proxy.
        try:
            self._segment_offsets.append(int(log.virtual_size.height))
        except Exception:
            pass
        log.write("")
        log.write(f"[bold {c('warning')}]{'═' * 60}[/]")
        proto_label = trailing_protocol or "unknown"
        log.write(
            f"[bold {c('warning')}]SEGMENT 2  "
            f"[{c('accent')}]{_safe_wire_text(proto_label)}[/]  "
            f"[dim]({len(tb):,} bytes trailing)[/]"
        )
        log.write(f"[bold {c('warning')}]{'═' * 60}[/]")

        if sp is not None:
            if sp.method:
                url = getattr(sp, 'url', '') or ''
                version = getattr(sp, 'protocol', '')
                log.write(f"[bold {c('primary')}]{self._wire_line(sp.method, url, version)}[/]")
            elif sp.status_code:
                version = getattr(sp, 'protocol', 'HTTP/1.1')
                log.write(f"[bold]{self._wire_line(version, sp.status_code, sp.status_text)}[/]")
            headers = getattr(sp, 'headers', {})
            if headers:
                log.write("")
                self._write_wire_headers(log, headers)
            body = sp.body
            if body:
                log.write("")
                log.write(f"[bold {c('success')}]--- Body ---[/]")
                if self._processing_applies_to(1):
                    self._render_body(log, body, headers, segment=1)
                elif _is_text(body):
                    text = body.decode("utf-8", errors="replace")
                    if len(text) > 2048:
                        text = text[:2048] + "\n... (truncated)"
                    log.write(_markup_escape(text))
                else:
                    self._write_hexdump(log, body[:self._TRAILING_HEX_LIMIT])
        elif self._processing_applies_to(1):
            # No sub-parse, but processing targets this segment.
            log.write("")
            self._render_body(log, tb, {}, segment=1)
        else:
            # No sub-parse: raw hexdump preview.
            log.write("")
            log.write("[dim]Raw trailing bytes (press h for full hex view):[/]")
            self._write_hexdump(log, tb[:self._TRAILING_HEX_LIMIT])
            if len(tb) > self._TRAILING_HEX_LIMIT:
                log.write(f"[dim]... {len(tb) - self._TRAILING_HEX_LIMIT:,} more bytes[/]")

    def _render_data_mismatch_banner(
        self, log: RichLog, flow: "Flow", direction: str, parsed_body_size: int,
    ) -> None:
        """Warn when raw captured data significantly exceeds what the parsed view shows.

        Accounted bytes are body + decoded headers + framing overhead; the
        256-byte slack avoids false positives from HPACK headers and HTTP/2
        control frames.
        """
        # Message-bearing flows render a transcript, not an HTTP body, so the
        # byte accounting below would always fire.
        if _fd._flow_has_messages(flow):
            return
        raw_total = sum(len(c.data) for c in flow.chunks if c.direction == direction)
        if raw_total <= 0:
            return
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
