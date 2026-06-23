"""PARKED / NOT-YET-WIRED TUI code — retained for possible future use.

This module holds the message-tab "layer transcript" renderers that were
**superseded** by the conversation renderers (``_render_conversation`` /
``_render_chat_row``) in :mod:`friTap.tui.widgets.flow_detail`. The code below
is intentionally NOT imported by any active widget, so it cannot affect the
running UI. It is kept verbatim (logic + comments preserved) so a future
maintainer can re-activate it instead of rewriting it.

The two renderers were relocated out of ``FlowDetail`` as a *mixin* so that
``self`` semantics are preserved: they still reference live sibling members on
the host widget (``self._message_chat_descriptor``, ``self._format_msg_time_secs``,
``self._TEXT_RENDER_LIMIT``), all of which remain defined on ``FlowDetail``.
The kind-classification constants used only by these two methods
(``_KIND_LABELS`` / ``_MEANINGFUL_KINDS``) are kept here with them.

HOW TO RE-ACTIVATE
------------------
1. Add this mixin to the host widget's bases, e.g.::

       from friTap.tui.widgets._parked_transcript import ParkedTranscriptRenderMixin

       class FlowDetail(ParkedTranscriptRenderMixin, Static):
           ...

2. Call ``self._render_layer_transcript(log, flow, layer)`` from the relevant
   message-tab build path. The mixin resolves ``self._message_chat_descriptor``,
   ``self._format_msg_time_secs`` and ``self._TEXT_RENDER_LIMIT`` from the host
   widget at runtime.
"""

from __future__ import annotations

from collections import Counter
from typing import TYPE_CHECKING

from friTap.tui.themes import c

if TYPE_CHECKING:
    from textual.widgets import RichLog
    from friTap.flow.models import Flow


class ParkedTranscriptRenderMixin:
    """Parked message-tab transcript renderers (see module docstring).

    Mix into a ``FlowDetail``-like widget to re-activate. Relies on the host
    providing ``_message_chat_descriptor``, ``_format_msg_time_secs`` and the
    ``_TEXT_RENDER_LIMIT`` class attribute.
    """

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

    # Kinds shown in full in the Message transcript; everything else
    # (ack/rpc/service/receipt/unparsed) is transport chatter, collapsed.
    _MEANINGFUL_KINDS = frozenset({"text", "data", "message", "user", "update"})

    def _render_layer_transcript(self, log: "RichLog", flow: "Flow", layer) -> None:
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
