"""Flow-detail body rendering: decoders, the processing pipeline and text/hexdump output."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from rich.markup import escape as _markup_escape
from rich.text import Text
from textual.widgets import RichLog

from friTap.analysis._json_walk import exceeds_depth
from friTap.tui.modals.body_processing_modal import ProtobufConfig
from friTap.tui.themes import c
from friTap.tui.widgets import telegram_panes
from friTap.tui.widgets.hexdump import _is_text, format_hexdump_lines
from friTap.tui.widgets.wire_text import TEXT_RENDER_LIMIT, write_capped_text

from .helpers import _get_header, _log, _safe_wire_text, _write_capped_decoder_lines

if TYPE_CHECKING:
    from friTap.flow.models import Flow


class BodyMixin:
    """Body rendering: the ``_DECODERS`` dispatch, processing pipeline, text/hexdump."""

    #: Protobuf decode output is capped at this many lines (plus an overflow line).
    _PROTOBUF_RENDER_MAX_LINES = 4000

    def _decode_protobuf(self, log: RichLog, body: bytes, headers: dict) -> None:
        """Shared protobuf/gRPC decode honouring the configured schema, gRPC mode
        and backend; falls back to a hexdump when nothing decodes."""
        from friTap.parsers.protobuf import decode_protobuf_view
        from friTap.tui.widgets.protobuf_render import protobuf_view_lines

        view = decode_protobuf_view(
            body,
            content_type=_get_header(headers, "content-type"),
            grpc_encoding=_get_header(headers, "grpc-encoding"),
            **self._protobuf_config().view_options(),
        )
        self._last_protobuf_mode = view.mode
        # One joined write: a RichLog.write per line is ~4x slower on big bodies.
        log.write("\n".join(protobuf_view_lines(view, self._PROTOBUF_RENDER_MAX_LINES)))
        if not view.ok:
            self._write_hexdump(log, body)

    def _protobuf_config(self) -> ProtobufConfig:
        """The active protobuf settings, or defaults when none were chosen."""
        processing = self._active_processing
        return getattr(processing, "protobuf_config", None) or ProtobufConfig()

    # Instance methods: the _DECODERS dispatch calls ``fn(self, log, body, headers)``.
    def _decode_json(self, log: RichLog, body: bytes, _headers: dict) -> None:
        formatted = self._pretty_json(body)
        if formatted is not None:
            self._write_pretty_json(log, formatted)
            return
        if len(body) > self._TEXT_RENDER_LIMIT:
            log.write("[dim yellow]JSON too large to pretty-print (raw text shown)[/]")
        else:
            log.write("[dim yellow]Not valid JSON[/]")
        self._write_text_body(log, body, errors="replace")

    def _pretty_json(self, body: bytes) -> str | None:
        """Indented JSON for *body*, or None when invalid, too deep or too large.

        Bodies above :attr:`_TEXT_RENDER_LIMIT` are not parsed (unbounded work
        on the UI thread). Depth beyond ``MAX_JSON_DEPTH`` is rejected because
        indented output grows quadratically with depth and CPython 3.14
        ``json.loads`` does not raise ``RecursionError`` on deep input.
        """
        if len(body) > self._TEXT_RENDER_LIMIT:
            return None
        try:
            parsed = json.loads(body)
            if exceeds_depth(parsed):
                return None
            return json.dumps(parsed, indent=2)
        except (ValueError, UnicodeDecodeError, RecursionError):
            return None

    def _write_pretty_json(self, log: RichLog, formatted: str) -> None:
        """Write pretty-printed JSON escaped and capped at the text render limit."""
        write_capped_text(log, formatted.encode("utf-8"), self._TEXT_RENDER_LIMIT)

    def _decode_base64(self, log: RichLog, body: bytes, _headers: dict) -> None:
        import base64 as b64mod
        try:
            decoded_bytes = b64mod.b64decode(body)
            if _is_text(decoded_bytes):
                self._write_text_body(log, decoded_bytes, errors="replace")
            else:
                self._write_hexdump(log, decoded_bytes)
        except Exception:
            log.write("[dim yellow]Base64 decode failed[/]")
            self._write_hexdump(log, body)

    def _decode_hex(self, log: RichLog, body: bytes, _headers: dict) -> None:
        self._write_hexdump(log, body)

    def _decode_raw_utf8(self, log: RichLog, body: bytes, _headers: dict) -> None:
        self._write_text_body(log, body, errors="replace")

    def _tl_domain(self) -> str:
        """TL schema domain of the current flow: Secret-Chat or MTProto."""
        return telegram_panes.tl_domain_for(self._current_flow)

    def _decode_tl(self, log: RichLog, body: bytes, _headers: dict) -> None:
        """Schema-driven TL decode rendered as a tree (MTProto / Secret Chat)."""
        from friTap.offline.mtproto.tl import decode_tl_cached
        from friTap.tui.widgets.tl_tree_render import render_tl_tree
        node = decode_tl_cached(bytes(body), self._tl_domain())
        for line in render_tl_tree(node):
            log.write(line)

    _DECODERS = {
        "protobuf": _decode_protobuf,
        "json": _decode_json,
        "base64": _decode_base64,
        "hex": _decode_hex,
        "raw_utf8": _decode_raw_utf8,
        "tl": _decode_tl,
    }

    def _render_control_frame(self, log: RichLog, req) -> None:
        """Render HTTP/2 connection-level control frame details."""
        from friTap.parsers.http2 import H2_URL_CONNECTION_SETUP

        if req.url == H2_URL_CONNECTION_SETUP:
            log.write(f"[bold {c('primary')}]HTTP/2 Connection Setup[/]")
        else:
            log.write(f"[bold {c('primary')}]HTTP/2 Connection Control[/]")

        log.write(f"[bold {c('accent')}]{'═' * 40}[/]")
        log.write(f"[bold]Frame:[/] {_safe_wire_text(req.method)}")
        log.write("")

        headers = req.headers if req.headers else {}
        if headers:
            for name, value in headers.items():
                log.write(f"  [bold]{_safe_wire_text(name)}:[/]  {_safe_wire_text(value)}")

    def _render_incomplete_h2_note(self, log: RichLog, raw: bytes) -> None:
        """Show informational note for incomplete HTTP/2 frames."""
        from friTap.parsers.http2_dataframe import describe_frame_header

        header = describe_frame_header(raw)
        if header is None:
            return
        name, stream_id = header.type_name, header.stream_id
        if header.truncated:
            log.write(
                f"[dim]  Frame: {name} (stream {stream_id}, "
                f"expected {header.length} bytes, got {header.available})[/]"
            )
        else:
            log.write(f"[dim]  Frame: {name} (stream {stream_id}, {header.length} bytes)[/]")

    def _render_body(
        self, log: RichLog, body: bytes, headers: dict, segment: int = 0,
    ) -> None:
        """Render a body: the ``p`` modal's processing when it targets *segment*
        (0 = primary, 1 = trailing), then auto-detected standard rendering."""
        if self._processing_applies_to(segment):
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
        processed, notes, error = self._decompress_active(body)
        self._write_processing_banner(log, notes, error)
        return self._run_active_decoder(log, processed, headers)

    def _decompress_active(self, body: bytes) -> tuple[bytes, list[str], str | None]:
        """Apply the user-selected decompression leniently.

        Returns ``(data, notes, error)``; a gzip member behind a framing
        header (e.g. an MTProto ``rpc_result``) is found and noted.
        """
        encoding = self._active_processing.decompression if self._active_processing else None
        if not encoding:
            return body, [], None
        from friTap.parsers.decompress import decompress_lenient
        return decompress_lenient(body, encoding)

    def _run_active_decoder(self, log: RichLog, body: bytes, headers: dict) -> bytes | None:
        """Run the selected decoder; ``None`` when it wrote output, else *body*."""
        decoder_name = self._active_processing.decoder or ""
        decoder_fn = self._DECODERS.get(decoder_name)
        if decoder_fn is not None:
            decoder_fn(self, log, body, headers)
            return None  # decoder handled output
        if self._run_extension_decoder(log, decoder_name, body, headers):
            return None  # extension decoder handled output
        # Decompression only: fall through to standard rendering.
        return body

    @staticmethod
    def _run_extension_decoder(
        log: RichLog, name: str, body: bytes, headers: dict,
    ) -> bool:
        """Show the registered extension decoder *name*; ``False`` if none.

        *headers* is the same ``dict`` the built-in decoders receive. Lines
        are written as literal ``Text``; a raising (third-party) decoder
        shows a literal error line instead of crashing.
        """
        from friTap.extensions import get_body_decoders

        spec = next((s for s in get_body_decoders() if s.name == name), None)
        if spec is None:
            return False
        try:
            lines = spec.decode(body, headers)
            _write_capped_decoder_lines(log, lines)
        except Exception as exc:
            _log.exception("flow detail: extension decoder %r failed", name)
            log.write(Text(f"Decoder {spec.label} failed: {type(exc).__name__}: {exc}",
                           style=f"bold {c('error')}"))
        return True

    def _render_processed_body(self, log: RichLog, body: bytes, headers: dict) -> None:
        """Render an already-decompressed body through the selected decoder."""
        remaining = self._run_active_decoder(log, body, headers)
        if remaining is not None:
            self._render_body_standard(log, remaining, headers)

    @staticmethod
    def _write_processing_banner(log: RichLog, notes: list[str], error: str | None) -> None:
        """Bold ⚠ lines describing what body processing did (or why it failed)."""
        for note in notes:
            log.write(f"[bold {c('warning')}]⚠ Processing: {_markup_escape(note)}[/]")
        if error:
            log.write(f"[bold {c('error')}]⚠ Processing failed: {_markup_escape(error)}[/]")
        if notes or error:
            log.write("")

    def _render_body_standard(self, log: RichLog, body: bytes, headers: dict) -> None:
        """Auto-render body based on Content-Encoding and Content-Type."""
        content_encoding = _get_header(headers, "content-encoding")
        if content_encoding:
            try:
                from friTap.parsers.decompress import (
                    MAX_AUTO_DECOMPRESS,
                    decompress_body,
                )
                body, err = decompress_body(
                    body, content_encoding, max_out=MAX_AUTO_DECOMPRESS)
                if err:
                    log.write(f"[dim yellow]Decompression note: {_markup_escape(err)}[/]")
            except ImportError:
                pass

        content_type = _get_header(headers, "content-type")

        self._render_ohttp_banner(log, content_type)

        if "application/json" in content_type or "text/json" in content_type:
            formatted = self._pretty_json(body)
            if formatted is not None:
                self._write_pretty_json(log, formatted)
                return

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
    _TEXT_RENDER_LIMIT = TEXT_RENDER_LIMIT  # 256 KB

    def _write_text_body(self, log: RichLog, body: bytes, errors: str = "strict") -> None:
        """Write text body with render-limit truncation, markup-escaped.

        The RichLog has ``markup=True``, so a literal ``[`` in the body could
        raise ``MarkupError``.
        """

        write_capped_text(log, body, self._TEXT_RENDER_LIMIT, errors)

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
