"""Flow-detail Request/Response pane for parsed MTProto / Telegram TL messages."""

from __future__ import annotations

from typing import TYPE_CHECKING

from rich.markup import escape as _markup_escape
from textual.widgets import RichLog

from friTap.constants import PROTOCOL_MTPROTO, PROTOCOL_TELEGRAM_E2E
from friTap.tui.themes import c
from friTap.tui.widgets import telegram_panes
from friTap.tui.widgets.tl_tree_render import local_time

from .helpers import _safe_layer, _safe_wire_text

if TYPE_CHECKING:
    from friTap.flow.models import Flow


class TlMessagePaneMixin:
    """Request/Response pane for parsed MTProto / Telegram TL messages."""

    # ParseResult protocols produced by the transport-pinned TL parsers.
    _TL_MESSAGE_PROTOCOLS = frozenset({PROTOCOL_TELEGRAM_E2E, PROTOCOL_MTPROTO})
    # Per-direction (title, time label) of the TL message pane.
    _TL_PANE_LABELS = {"write": ("SENT message", "Sent"),
                       "read": ("RECEIVED message", "Received")}
    # TL display headers not worth a row in the message pane.
    _TL_PANE_SKIP_HEADERS = frozenset({"content-type"})

    @staticmethod
    def _is_message_transport_flow(flow: "Flow") -> bool:
        """True for MTProto / Secret-Chat flows (message streams, not HTTP)."""
        from friTap.flow.display import is_message_transport
        return is_message_transport(flow)

    @classmethod
    def _parsed_tl_message(cls, flow: "Flow", direction: str):
        """The pinned-TL ParseResult for *direction* ("write"/"read"), else None."""
        msg = flow.request if direction == "write" else flow.response
        if msg is None or getattr(msg, "protocol", "") not in cls._TL_MESSAGE_PROTOCOLS:
            return None
        return msg

    @classmethod
    def _first_chunk_time(cls, flow: "Flow", direction: str) -> float:
        """Timestamp of the first chunk in *direction*, or 0.0 when none."""
        return cls._nth_chunk_time(flow, direction, 0)

    @staticmethod
    def _format_pane_time(ts: float) -> str:
        """``YYYY-MM-DD HH:MM:SS.mmm`` for an epoch-seconds ts; "" when unknown."""
        return local_time(ts, millis=True) if ts and ts > 0 else ""

    def _render_tl_message_pane(self, log: RichLog, flow: "Flow", direction: str) -> bool:
        """Render one decrypted TL packet forensically.

        Order: processing banner, title/time, Envelope, Cross-references,
        TL fields, TL tree, then processed body or E2E text. Returns False
        (nothing written) when *direction* has no pinned-TL parse.
        """
        msg = self._parsed_tl_message(flow, direction)
        if msg is None:
            return False
        body, processed = msg.body, self._processing_applies_to(0) and bool(msg.body)
        if processed:
            body, notes, error = self._decompress_active(body)
            self._write_processing_banner(log, notes, error)
        self._write_tl_pane_title(log, flow, msg, direction)
        layer = self._telegram_layer(flow)
        self._write_packet_forensics(log, layer, with_users=False)
        self._write_tl_fields(log, msg.headers or {})
        if msg.error:
            log.write(f"[{c('warning')}]{_markup_escape(msg.error)}[/]")
        records = self._tl_pane_records(flow, direction, msg)
        self._write_decoded_tl(log, flow, layer, records)
        self._write_tl_message_body(log, msg, body, processed, records)
        return True

    def _write_tl_pane_title(self, log: RichLog, flow: "Flow", msg, direction: str) -> None:
        """``SENT message  MTProto · method`` plus the packet time."""
        title, time_label = self._TL_PANE_LABELS[direction]
        method = _markup_escape(msg.method or "")
        log.write(f"[bold {c('accent')}]{title}[/]  "
                  f"[dim]{_markup_escape(msg.protocol)} · {method}[/]")
        when = self._format_pane_time(self._first_chunk_time(flow, direction))
        if when:
            log.write(f"[bold]{time_label}:[/] {when}")

    @staticmethod
    def _telegram_layer(flow: "Flow"):
        """The flow's own ``mtproto`` / ``telegram_e2e`` layer, else None."""
        return _safe_layer(flow, getattr(flow, "transport", "") or "")

    def set_row_resolver(self, resolver) -> None:
        """Set ``flow_id -> row number | None`` used for ``#N`` cross-references."""
        self._row_resolver = resolver

    def _row_of(self, flow_id) -> int | None:
        """Row number of *flow_id* in the flow list, else None (never raises)."""
        resolver = getattr(self, "_row_resolver", None)
        if resolver is None or flow_id is None:
            return None
        try:
            return resolver(flow_id)
        except Exception:
            return None

    @staticmethod
    def _write_tl_section(log: RichLog, title: str, lines: list[str]) -> None:
        """A bold section heading followed by *lines* (nothing when empty)."""
        if not lines:
            return
        log.write("")
        log.write(f"[bold {c('primary')}]{title}[/]")
        for line in lines:
            log.write(line)

    @staticmethod
    def _tl_pane_records(flow: "Flow", direction: str, msg) -> list[bytes]:
        """TL record bytes of *direction*; an MTProto parse body when no chunks."""
        records = telegram_panes.tl_records_for(flow, direction)
        if records or telegram_panes.tl_domain_for(flow) != "mtproto" or not msg.body:
            return records
        return [bytes(msg.body)]

    def _write_decoded_tl(self, log: RichLog, flow: "Flow", layer,
                          records: list[bytes]) -> None:
        """The schema-decoded TL tree of every record (msg_ids resolved to rows)."""
        if not records:
            return
        refs = getattr(layer, "refs", None) or {}
        lines = telegram_panes.decoded_tree_lines(
            records, telegram_panes.tl_domain_for(flow),
            request_method=refs.get("request_method"),
            ref_label=telegram_panes.make_ref_label(refs, self._row_of))
        self._write_tl_section(log, "Decoded TL", lines)

    def _write_tl_message_body(self, log: RichLog, msg, body: bytes, processed: bool,
                               records: list[bytes]) -> None:
        """Processed body / E2E message text; a raw MTProto record stays behind ``h``."""
        if not msg.body:
            return
        if not processed and bytes(msg.body) in records:
            log.write("")
            log.write(f"[dim]{len(msg.body):,} raw bytes — press h for the hexdump, "
                      f"p to process[/]")
            return
        log.write("")
        log.write(f"[bold {c('success')}]--- Message ---[/]")
        if processed:
            self._render_processed_body(log, body, msg.headers or {})
        else:
            self._render_body(log, body, msg.headers or {})

    def _write_tl_fields(self, log: RichLog, headers: dict) -> None:
        """Write the decoded TL fields (display headers) as ``name: value`` rows."""
        rows = [(k, v) for k, v in headers.items()
                if k.lower() not in self._TL_PANE_SKIP_HEADERS]
        if not rows:
            return
        log.write("")
        for name, value in rows:
            log.write(f"[bold]{_markup_escape(str(name))}:[/] {_markup_escape(str(value))}")

    @staticmethod
    def _wire_line(*parts) -> str:
        """Space-joined request/status line with every wire-derived part escaped."""
        return " ".join(_safe_wire_text(p) for p in parts if p not in (None, ""))

    @staticmethod
    def _write_wire_headers(log: RichLog, headers: dict) -> None:
        """Write parsed HTTP headers as ``name: value`` rows, escaped for markup."""
        for name, value in headers.items():
            log.write(f"[bold]{_safe_wire_text(name)}:[/] {_safe_wire_text(value)}")

    def _render_unparsed_side(self, log: RichLog, flow: "Flow", direction: str,
                              label: str) -> None:
        """A side without an HTTP parse: the pinned-TL message pane, else raw bytes.

        *label* ("Request"/"Response") names the side in the fallback notes.
        A message-transport flow without a pinned TL parse for *direction*
        falls back to the raw transport bytes like any unparsed side.
        """
        if (self._is_message_transport_flow(flow)
                and self._render_tl_message_pane(log, flow, direction)):
            return
        raw = flow.get_direction_bytes(direction, max_bytes=self._TEXT_RENDER_LIMIT)
        if not raw:
            log.write(f"[dim]No {label.lower()} data captured[/]")
            return
        self._write_raw_fallback_note(log, flow, raw, label)
        log.write("")
        self._render_body(log, raw, {})

    def _write_raw_fallback_note(self, log: RichLog, flow: "Flow", raw: bytes,
                                 label: str) -> None:
        """Why raw bytes are shown: non-HTTP transport, partial HTTP/2, or no parse."""
        proto = self._nonhttp_transport_label(flow)
        if proto:
            log.write(f"[dim]{proto} transport — decrypted messages are on the "
                      f"Message tab. Raw transport bytes:[/]")
        elif "HTTP/2" in (flow.detected_protocol or ""):
            log.write("[dim]HTTP/2 connection data (partial capture)[/]")
            self._render_incomplete_h2_note(log, raw)
        else:
            log.write(f"[dim]{label} headers could not be parsed (raw data shown)[/]")
