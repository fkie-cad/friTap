"""Flow-detail Request, Response and Detail tabs."""

from __future__ import annotations

from typing import TYPE_CHECKING

from rich.markup import escape as _markup_escape
from textual.widgets import RichLog

from friTap.flow.models import FlowState, format_byte_size
from friTap.tui.themes import c
from friTap.tui.widgets import telegram_panes
from friTap.tui.widgets.tl_tree_render import local_time
from friTap.tui.widgets.wire_text import safe_wire_text, write_capped_text

from .helpers import _get_header, _safe_layer, _safe_wire_text

if TYPE_CHECKING:
    from friTap.flow.models import Flow


class DetailTabsMixin:
    """Request, Response and Detail tab content."""

    def _update_request(self, flow: "Flow") -> None:
        log = self._request_log
        log.clear()
        self._segment_offsets = []

        if self._raw_request:
            self._render_raw_hex(log, flow, "write", "request")
            return

        # Signal: outbound chat transcript instead of raw protobuf (`h` still
        # shows hex); the merged timeline lives on the Message tab.
        if self._is_signal_flow(flow):
            self._render_signal_messages(log, flow, direction_filter="write")
            log.scroll_home(animate=False)
            return

        req = flow.request
        if req is None or self._is_message_transport_flow(flow):
            self._render_unparsed_side(log, flow, "write", "Request")
            log.scroll_home(animate=False)
            return

        if req.is_control_frame:
            self._render_control_frame(log, req)
            log.scroll_home(animate=False)
            return

        # Trailing data forms a second segment.
        if flow.trailing_bytes is not None:
            proto_label = getattr(req, 'protocol', '') or flow.display_protocol
            log.write(f"[bold {c('accent')}]SEGMENT 1  {_safe_wire_text(proto_label)}[/]")
            log.write(f"[bold {c('accent')}]{'═' * 60}[/]")

        if hasattr(req, 'method') and req.method:
            version = getattr(req, 'protocol', 'HTTP/1.1')
            url = getattr(req, 'url', '/')
            log.write(f"[bold {c('primary')}]{self._wire_line(req.method, url, version)}[/]")

        headers = getattr(req, 'headers', {})
        if headers:
            log.write("")
            self._write_wire_headers(log, headers)

        body = req.body if req.body else flow.reconstruct_body("write")
        if body:
            log.write("")
            log.write(f"[bold {c('success')}]--- Body ---[/]")
            if req.content_encoding == "permessage-deflate":
                log.write("[dim italic]Auto-decompressed (permessage-deflate)[/]")
            self._render_body(log, body, headers)
        self._render_app_cipher_views(log, req, headers, body or b"")

        self._render_data_mismatch_banner(log, flow, "write", len(body) if body else 0)
        # Write-direction trailing data; the response tab shows the read side.
        self._render_trailing_data(log, flow)

        log.scroll_home(animate=False)

    @staticmethod
    def _app_cipher_views(req, headers: dict, body: bytes) -> list:
        """Decoded app-layer cipher views for this request (cheap host/path gate)."""
        from friTap.parsers.app_ciphers.registry import default_registry
        host = (getattr(req, "host", "") or _get_header(headers, "host")
                or _get_header(headers, ":authority"))
        return default_registry().decode_request(
            host, getattr(req, "url", "") or "", body,
            _get_header(headers, "content-encoding"))

    def _render_app_cipher_views(self, log: RichLog, req, headers: dict, body: bytes) -> None:
        """Append one section per matching app-cipher decoder (e.g. AppLovin)."""
        for view in self._app_cipher_views(req, headers, body):
            log.write("")
            log.write(f"[bold {c('success')}]--- {_markup_escape(view.title)} ---[/]")
            for note in view.notes:
                log.write(f"[dim]{safe_wire_text(note)}[/]")
            if view.ok:
                write_capped_text(log, view.text.encode("utf-8"), errors="replace")
            else:
                log.write(f"[{c('warning')}]Not decrypted: {safe_wire_text(view.reason)}[/]")

    def _update_response(self, flow: "Flow") -> None:
        log = self._response_log
        log.clear()

        if self._raw_response:
            self._render_raw_hex(log, flow, "read", "response")
            return

        # Signal: inbound chat transcript instead of raw protobuf (`h` still
        # shows hex); the merged timeline lives on the Message tab.
        if self._is_signal_flow(flow):
            self._render_signal_messages(log, flow, direction_filter="read")
            log.scroll_home(animate=False)
            return

        resp = flow.response
        if resp is None or self._is_message_transport_flow(flow):
            self._render_unparsed_side(log, flow, "read", "Response")
            log.scroll_home(animate=False)
            return

        if resp.is_control_frame:
            self._render_control_frame(log, resp)
            log.scroll_home(animate=False)
            return

        # Read-direction trailing data forms a second segment.
        if getattr(flow, "response_trailing_bytes", None) is not None:
            proto_label = getattr(resp, 'protocol', '') or flow.display_protocol
            log.write(f"[bold {c('accent')}]SEGMENT 1  {_safe_wire_text(proto_label)}[/]")
            log.write(f"[bold {c('accent')}]{'═' * 60}[/]")

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
            log.write(f"[bold {color}]{self._wire_line(version, code, status_text)}[/]")

        headers = getattr(resp, 'headers', {})
        if headers:
            log.write("")
            self._write_wire_headers(log, headers)

        body = resp.body if resp.body else flow.reconstruct_body("read")
        if body:
            log.write("")
            log.write(f"[bold {c('success')}]--- Body ---[/]")
            if resp.content_encoding == "permessage-deflate":
                log.write("[dim italic]Auto-decompressed (permessage-deflate)[/]")
            self._render_body(log, body, headers)

        self._render_data_mismatch_banner(log, flow, "read", len(body) if body else 0)
        self._render_trailing_data(log, flow, which="response")

        log.scroll_home(animate=False)

    def _update_detail(self, flow: "Flow") -> None:
        log = self._detail_log
        log.clear()

        # Byte in/out summary (single pass).
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
        stream_id = flow.stream_id
        if stream_id is not None:
            log.write(f"[bold]Stream:[/]         {stream_id}")
        log.write(f"[bold]State:[/]          {flow.state.value}")
        log.write("")
        log.write(f"[bold]Source:[/]         {flow.src_addr}:{flow.src_port}")
        log.write(f"[bold]Destination:[/]    {flow.dst_addr}:{flow.dst_port}")
        if getattr(flow, "transport", "") == "telegram_e2e":
            fingerprint = self._secret_chat_fingerprint(flow)
            if fingerprint:
                log.write(f"[bold]Secret chat:[/]    {_markup_escape(fingerprint)}")
        elif flow.ssl_session_id:
            log.write(f"[bold]SSL Session:[/]    {flow.ssl_session_id}")
        log.write("")

        ts_start = local_time(flow.started, millis=True)
        log.write(f"[bold]Started:[/]        {ts_start}")
        if flow.state == FlowState.COMPLETE and flow.ended > 0:
            ts_end = local_time(flow.ended, millis=True)
            log.write(f"[bold]Ended:[/]          {ts_end}")
            log.write(f"[bold]Duration:[/]       {flow.duration * 1000:.1f}ms")

        log.write("")
        log.write(f"[bold]Protocol:[/]       {_markup_escape(self._detail_protocol(flow))}")
        log.write(f"[bold]Chunks:[/]         {len(flow.chunks)}")

        total_bytes = bytes_sent + bytes_recv
        log.write(f"[bold]Total bytes:[/]    {total_bytes}")

        if getattr(flow, "transport", "") == "telegram_e2e":
            self._render_secret_chat_section(log, flow)
        elif getattr(flow, "transport", "") == "mtproto":
            self._render_telegram_packet_section(log, flow)

        # Trailing data summary in detail tab (never for TL message packets)
        if not self._is_message_transport_flow(flow):
            self._render_trailing_summary(log, flow, "request", "Trailing Data")
            self._render_trailing_summary(
                log, flow, "response", "Trailing Data (response)")

        log.scroll_home(animate=False)

    def _render_trailing_summary(self, log: RichLog, flow: "Flow",
                                 which: str, title: str) -> None:
        """Detail-tab summary of one trailing slot (no-op when empty)."""
        tb, protocol, sp = self._trailing_slot(flow, which)
        if not tb:
            return
        log.write("")
        log.write(f"[bold {c('warning')}]{title}[/]")
        log.write(f"[bold]Unconsumed:[/]     {len(tb):,} bytes")
        if protocol:
            log.write(f"[bold]Protocol:[/]       {protocol}")
        if sp:
            log.write(f"[bold]Sub-parsed:[/]     {sp.method} {sp.url}")

    @staticmethod
    def _secret_chat_fingerprint(flow: "Flow") -> str:
        """Chat key fingerprint from the E2E layer, else the session id suffix."""
        layer = _safe_layer(flow, "telegram_e2e")
        fp = getattr(layer, "key_fingerprint", "") if layer is not None else ""
        if fp:
            return fp
        sid = getattr(flow, "ssl_session_id", "") or ""
        prefix = "telegram_e2e:"
        return sid[len(prefix):] if sid.startswith(prefix) else ""

    def _secret_chat_header_values(self, flow: "Flow", name: str) -> str:
        """``sent X · recv Y`` for TL header *name*; sides lacking it are omitted."""
        parts = []
        for side, direction in (("sent", "write"), ("recv", "read")):
            msg = self._parsed_tl_message(flow, direction)
            value = (msg.headers or {}).get(name) if msg is not None else None
            if value not in (None, ""):
                parts.append(f"{side} {value}")
        return " · ".join(parts)

    def _render_telegram_section(self, log: RichLog, layer, title: str,
                                 extra_rows=(), *, with_peer: bool = False) -> None:
        """Detail-tab Telegram block: title, non-empty ``label: value`` rows,
        then the (peer,) envelope, cross-reference and users sections."""
        log.write("")
        log.write(f"[bold {c('primary')}]{title}[/]")
        for label, value in extra_rows:
            if value:
                log.write(f"[bold]{label + ':':<17}[/] {_markup_escape(value)}")
        self._write_packet_forensics(log, layer, with_users=True, with_peer=with_peer)

    def _secret_chat_rows(self, flow: "Flow", layer) -> list[tuple[str, str]]:
        """``(label, value)`` summary rows of a Secret-Chat flow (values may be empty)."""
        rows = [("Key fingerprint", self._secret_chat_fingerprint(flow))]
        if layer is not None and getattr(layer, "chat_id", 0):
            rows.append(("Chat ID", str(layer.chat_id)))
        for label, direction in (("Sent", "write"), ("Received", "read")):
            rows.append((label, self._format_pane_time(
                self._first_chunk_time(flow, direction))))
        rows.append(("Random IDs", self._secret_chat_header_values(flow, "random_id")))
        rows.append(("In seq no", self._secret_chat_header_values(flow, "in_seq_no")))
        rows.append(("Out seq no", self._secret_chat_header_values(flow, "out_seq_no")))
        return rows

    def _render_secret_chat_section(self, log: RichLog, flow: "Flow") -> None:
        """Detail-tab block summarising a Telegram Secret Chat flow."""
        layer = _safe_layer(flow, "telegram_e2e")
        self._render_telegram_section(log, layer, "Telegram Secret Chat",
                                      self._secret_chat_rows(flow, layer), with_peer=True)

    def _render_secret_chat_forensics(self, log: RichLog, layer) -> None:
        """Secret-Chat peer, envelope, carrier reference and users (Detail tab)."""
        self._write_packet_forensics(log, layer, with_users=True, with_peer=True)

    def _write_packet_forensics(self, log: RichLog, layer, *, with_users: bool,
                                with_peer: bool = False) -> None:
        """(Peer +) Envelope + Cross-references (+ Users) sections of a Telegram layer."""
        if with_peer:
            self._write_tl_section(log, "Peer", telegram_panes.peer_lines(
                getattr(layer, "peer", None)))
        self._write_tl_section(log, "Envelope", telegram_panes.envelope_lines(layer))
        self._write_tl_section(log, "Cross-references",
                               telegram_panes.refs_lines(layer, self._row_of))
        if with_users:
            self._write_tl_section(log, "Users", telegram_panes.users_lines(
                getattr(layer, "users", None)))

    def _render_telegram_packet_section(self, log: RichLog, flow: "Flow") -> None:
        """Detail-tab block of one MTProto packet: envelope, refs, users."""
        layer = _safe_layer(flow, "mtproto")
        if layer is not None:
            self._render_telegram_section(log, layer, "Telegram Packet (MTProto)")
