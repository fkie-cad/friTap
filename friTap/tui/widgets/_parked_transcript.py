"""Parked, not wired in: message-tab "layer transcript" renderers superseded by the
conversation renderers in :mod:`friTap.tui.widgets.flow_detail`.

No active widget imports this module. It is kept (logic preserved) so it can be
re-activated: add :class:`ParkedTranscriptRenderMixin` to the host widget's bases
(``class FlowDetail(ParkedTranscriptRenderMixin, Static)``) and call
``self._render_layer_transcript(log, flow, layer)`` from the message-tab build path.
The host must provide ``_message_chat_descriptor``, ``_format_msg_time_secs`` and
``_TEXT_RENDER_LIMIT``. ``_KIND_LABELS`` / ``_MEANINGFUL_KINDS`` live here with them.
"""

from __future__ import annotations

from collections import Counter
from typing import TYPE_CHECKING

from friTap.tui.themes import c

if TYPE_CHECKING:
    from textual.widgets import RichLog

    from friTap.flow.models import Flow


class ParkedTranscriptRenderMixin:
    """Parked message-tab transcript renderers (see module docstring)."""

    # Kind -> (icon/label, is_chat) for the row heading; chat kinds show the body prominently in quotes.
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

    # Kinds shown in full; the rest (ack/rpc/service/receipt/unparsed) is collapsed transport chatter.
    _MEANINGFUL_KINDS = frozenset({"text", "data", "message", "user", "update"})

    def _render_layer_transcript(self, log: "RichLog", flow: "Flow", layer) -> None:
        """Render a message-bearing layer's entries as a chat transcript.

        Mirrors :meth:`_render_signal_messages`; reads the shared message-dict contract
        (``direction``, ``timestamp``, ``kind``, ``body``, ``method``, ``sender``) defensively.
        """
        messages = list(getattr(layer, "messages", None) or [])
        protocol, chat = self._message_chat_descriptor(layer)

        # Show meaningful content in full and collapse high-volume chatter (acks, pings)
        # into one summary line so dozens of msgs_acks never bury the messages.
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

    def _render_transcript_entry(self, log: "RichLog", entry) -> None:
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
        # Show the TL method only when it adds information.
        if method and not is_chat and method.lower() != kind.lower():
            head_parts.append(f"[dim]{method}[/]")
        # "from <sender>" only on received chat rows; on user/identity rows the id repeats the body.
        if not outgoing and sender and kind != "user":
            head_parts.append(f"[dim]from {sender}[/]")
        log.write(f"[bold {c('primary')}]{'  '.join(head_parts)}[/]")

        # Chat kinds render the body in quotes, others indented and muted.
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
