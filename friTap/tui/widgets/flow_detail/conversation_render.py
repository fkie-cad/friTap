"""Flow-detail Message tab: conversation transcript rendering."""

from __future__ import annotations

from collections import Counter
from typing import TYPE_CHECKING

from rich.box import ROUNDED
from rich.markup import escape as _markup_escape
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text
from textual.widgets import RichLog

from friTap.tui.themes import c
from friTap.tui.widgets.tl_tree_render import local_datetime

from .helpers import _flow_message_layer, _flow_signal_layer

if TYPE_CHECKING:
    from friTap.flow.models import Flow


class ConversationRenderMixin:
    """Message tab: conversation transcript, chat rows and bubbles."""

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

        *secs*: epoch-seconds (MTProto/E2E); otherwise epoch-ms (Signal).
        """
        try:
            ts = int(ts)
        except (TypeError, ValueError):
            return None
        if ts <= 0:
            return None
        return local_datetime(ts if secs else ts / 1000)

    def _render_signal_messages(self, log: RichLog, flow: "Flow",
                                *, direction_filter: str | None = None,
                                merge_siblings: bool = False) -> None:
        """Render a Signal flow as a conversation transcript.

        Uses the Signal layer so the epoch-ms formatter is selected.
        *direction_filter* limits to one side; *merge_siblings* merges the
        conversation's other flows.
        """
        layer = self._signal_layer(flow)
        if layer is None:
            log.write("[dim]No decrypted messages in this flow[/]")
            return
        self._render_conversation(log, flow, layer,
                                  direction_filter=direction_filter,
                                  merge_siblings=merge_siblings)

    def _render_message_tab(self, flow: "Flow") -> None:
        """Render the Message tab: any message-bearing layer via :meth:`_render_conversation`."""

        log = self._message_log
        log.clear()
        # Prefer the Signal layer (epoch-ms formatter), else the innermost
        # message-bearing layer.
        layer = self._signal_layer(flow) if self._is_signal_flow(flow) else None
        is_signal = layer is not None
        if layer is None:
            layer = _flow_message_layer(flow)
        if layer is None:
            log.write("[dim]No decrypted messages in this flow[/]")
            log.scroll_home(animate=False)
            return
        # Signal directions ride separate TCP connections, so merge siblings.
        merge = is_signal or self._is_mergeable_telegram_layer(flow, layer)
        self._render_conversation(log, flow, layer, merge_siblings=merge)
        log.scroll_home(animate=False)

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
        """Full-width dashed date divider.

        In bubble mode a 2-column ``ratio`` grid anchors the date at the start
        of the right half, on the message-arrow axis; in row mode it sits left.
        """
        date = dt.strftime("%a %d %b %Y")
        if use_bubbles:
            # The left-aligned Rule puts one space after the date; the
            # leading space makes the gap before it symmetric.
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

    def _render_conversation(self, log: RichLog, flow: "Flow", layer,
                             *, direction_filter: str | None = None,
                             merge_siblings: bool = False) -> None:
        """Protocol-agnostic conversation renderer for any message-bearing layer.

        *direction_filter* ("write"/"read") keeps one direction;
        *merge_siblings* unions the conversation's other flows (Message tab).
        """
        # Sibling sources and structured users are computed once per render.
        sources = self._secret_chat_sources(flow, merge_siblings)
        structured_users = self._structured_users_for(flow, layer, merge_siblings, sources)
        messages = self._gather_conversation_messages(
            flow, layer, merge_siblings, sources, structured_users)
        messages = self._sorted_by_time(messages)
        if direction_filter in ("write", "read"):
            want_outbound = direction_filter == "write"
            messages = [m for m in messages
                        if self._is_outbound(m) == want_outbound]
        protocol, chat = self._message_chat_descriptor(layer)
        # Signal uses epoch-ms, MTProto / E2E epoch-seconds. `time_fn` and
        # `secs` are chosen together so captions and dividers never drift.
        is_signal = getattr(layer, "name", "") == "signal"
        time_fn = self._format_msg_time if is_signal else self._format_msg_time_secs
        secs = not is_signal

        chat_msgs = [m for m in messages
                     if (m.get("kind") or "") in self._CHAT_KINDS]
        participants = (
            self._structured_participants(flow, layer, messages, merge_siblings,
                                          sources, structured_users)
            or self._conversation_participants(layer, messages)
        )
        # Group chat rows show "from <name>" instead of a numeric id.
        id_to_name = self._sender_id_to_name(messages, structured_users)
        transport = [m for m in messages
                     if (m.get("kind") or "") not in self._CHAT_KINDS
                     and (m.get("kind") or "") != self._PARTICIPANT_KIND]

        # 1. Header; the count is CHAT messages only.
        count = len(chat_msgs)
        count_label = f"{count} message" + ("" if count == 1 else "s")
        head = f"[bold {c('accent')}]{protocol}"
        if chat:
            head += f" · {chat}"
        head += f"[/]    [dim]{count_label}[/]"
        log.write(head)

        # Layout decided once per render: bubble grid when wide enough, else rows.
        use_bubbles = self._bubble_width_ok(log)

        # 2. Participants header: self (you) | connector | peer(s).
        p_left, p_glyph, p_right = self._participants_header_parts(participants)
        self._write_header_row(log, p_left, p_glyph, p_right,
                               use_bubbles=use_bubbles)

        # 2b. Signal-only peer summary (prefers a phone number); MTProto/E2E
        # already name participants above and their senders are internal ids.
        if is_signal:
            peer_display, peer_kind = self._resolve_peer_identity(messages)
            s_left, s_glyph, s_right = self._peer_summary_parts(
                peer_display, peer_kind)
            self._write_header_row(log, s_left, s_glyph, s_right,
                                   use_bubbles=use_bubbles)

        # 3. Full-width separator.
        log.write(Rule(characters="─", style="dim"))

        # 4. CHAT entries, with a date divider whenever the day changes.
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

        # 6b. Session-metadata block: one row per high-signal record.

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
            log.write("  [dim]•[/] " + "  ".join(bits))

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
        """Render one CHAT-kind message dict as a bubble or a single-column row.

        ``id_to_name`` resolves a numeric group ``sender`` id; other senders
        are shown as-is.
        """
        sender = entry.get("sender", "") or ""
        timestamp = entry.get("timestamp", 0)
        body = entry.get("body", "") or ""

        if sender and id_to_name and str(sender).isdigit():
            sender = id_to_name.get(str(sender), sender)

        outgoing = self._is_outbound(entry)
        arrow = "→" if outgoing else "←"
        ts = time_fn(timestamp)

        # Single-column rows below are the narrow-terminal fallback.
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
        """Shared content model for both chat layouts, so truncation and flags match.

        Returns ``(shown, overflow, flags)``: the capped stripped body, the
        number of hidden characters, and the attachment/quote/reaction markers.
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
    # Per-message body cap for the conversation view. Far below
    # _TEXT_RENDER_LIMIT because word-wrapping a multi-KB body inside a
    # justified Panel is costly; the raw layer view still shows the full body.
    _CHAT_BODY_LIMIT = 16 * 1024
    # Placeholder for an empty chat message, shared by both layouts.
    _EMPTY_CHAT_BODY = "(empty message)"

    @classmethod
    def _bubble_width_ok(cls, log) -> bool:
        """True when the log is wide enough for the two-column bubble layout.

        Unknown or zero width counts as wide: the first eager render happens
        before the pane is shown, so only a real small width picks rows.
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
        """3-column grid (left | width-3 centred gutter | right) shared by bubbles
        and headers so arrows and connectors share one x.

        ``right_justify`` is for headers only; it would misalign a bubble
        Panel's contents.
        """
        grid = Table(box=None, show_header=False, expand=True,
                     padding=0, pad_edge=False)
        grid.add_column(ratio=self._BUBBLE_RATIO)
        grid.add_column(width=3, justify="center")
        grid.add_column(ratio=self._BUBBLE_RATIO,
                        justify="right" if right_justify else "left")
        return grid

    def _bubble_body_text(self, entry, body) -> Text:
        """A bubble's body ``Text``: message (or empty marker), overflow note
        and flag line, from :meth:`_chat_body_parts`."""
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
        """Render one CHAT message as a left (sent) / right (received) bubble,
        with the arrow in the centre gutter and the time as the bubble title."""
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

    def _message_chat_descriptor(self, layer) -> tuple[str, str]:
        """Return ``(protocol_label, chat_descriptor)`` for the transcript header."""
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

    @classmethod
    def _format_msg_time_secs(cls, ts) -> str:
        """Format an epoch-seconds (MTProto / Telegram) timestamp as HH:MM:SS;
        '' when unknown."""

        dt = cls._msg_datetime(ts, secs=True)
        return dt.strftime("%H:%M:%S") if dt is not None else ""
