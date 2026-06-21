"""Analyzer finding-detail widget — a finding-centric view of a flow.

Reached by pressing Enter on a row in the Findings Viewer. Unlike the regular
:class:`~friTap.tui.widgets.flow_detail.FlowDetailWidget` (which is flow-centric
and tabbed), this view leads with the *finding*: what was matched, where, and a
one-key base64 decode for values like HTTP Basic auth. The matched value is
highlighted in the surrounding request/response context.

Navigation (handled by the host screen):
* ``Esc`` → back to the findings list (category filter preserved).
* ``d``   → switch to the regular flow-detail view for the same flow.
* ``b``   → toggle base64 decoding of candidate values.

The body is rendered as a single scrollable :class:`Static` (markup built
in-memory) rather than a ``RichLog`` — the content is small and a Static avoids
the log's incremental-render machinery.
"""

from __future__ import annotations

import base64
import binascii
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from friTap.analysis import Finding
    from friTap.flow.models import Flow

try:
    from textual.binding import Binding
    from textual.containers import VerticalScroll
    from textual.message import Message
    from textual.widgets import Static
    TEXTUAL_AVAILABLE = True
except ImportError:
    TEXTUAL_AVAILABLE = False

from friTap.tui.themes import c


from friTap.analysis import EVIDENCE_VALUE_KEYS, primary_evidence_value

# Evidence keys worth surfacing as context (not the raw value).
_CONTEXT_KEYS = ("location", "header", "field", "type", "host", "url", "content_type", "cwe")


def _looks_text(data: bytes) -> bool:
    try:
        text = data.decode("utf-8")
    except (UnicodeDecodeError, ValueError):
        return False
    return all(ch in "\n\t\r" or ch.isprintable() for ch in text)


def _try_base64(value: str) -> str | None:
    """Return the decoded text if *value* is valid printable base64, else None."""
    s = value.strip()
    # Strip a leading auth scheme (e.g. "Basic dXNlcjpwYXNz").
    if " " in s:
        s = s.split(" ", 1)[1].strip()
    if len(s) < 4 or len(s) % 4 != 0:
        return None
    try:
        decoded = base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError):
        return None
    if not decoded or not _looks_text(decoded):
        return None
    text = decoded.decode("utf-8")
    # Avoid echoing trivially-unchanged input.
    return text if text != s else None


def _esc(value) -> str:
    """Escape Rich markup brackets in dynamic text so it renders literally."""
    return str(value).replace("[", "\\[")


if TEXTUAL_AVAILABLE:
    from friTap.analysis import Severity

    _SEV_COLORS = {
        Severity.CRITICAL: "error",
        Severity.HIGH: "error",
        Severity.MEDIUM: "warning",
        Severity.LOW: "info",
        Severity.INFO: "text-muted",
    }

    class AnalyzerFindingDetailWidget(VerticalScroll):
        """Finding-centric detail view with a base64-decode helper."""

        BINDINGS = [
            Binding("escape", "back", "Back", show=False),
            Binding("b", "toggle_decode", "Base64", show=False),
            Binding("d", "open_full_detail", "Full detail", show=False),
        ]

        class BackRequested(Message):
            """Emitted to return to the findings list."""

        class FullDetailRequested(Message):
            """Emitted to switch to the regular flow-detail view."""
            def __init__(self, flow_id: str) -> None:
                super().__init__()
                self.flow_id = flow_id

        def __init__(self, **kwargs) -> None:
            super().__init__(**kwargs)
            self._finding: "Finding | None" = None
            self._flow: "Flow | None" = None
            self._decode = False
            self._header: "Static | None" = None
            self._body: "Static | None" = None

        def compose(self):
            self._header = Static("", id="finding-detail-header")
            yield self._header
            self._body = Static("", id="finding-detail-body")
            yield self._body

        # -- public API -------------------------------------------------------

        def show_finding(self, finding: "Finding", flow: "Flow | None") -> None:
            """Display *finding* in the context of *flow* (which may be None)."""
            if self._finding is not finding:
                self._decode = False
            self._finding = finding
            self._flow = flow
            self._rebuild()

        def scroll_to_top(self) -> None:
            try:
                self.scroll_home(animate=False)
            except Exception:
                pass

        # -- actions ----------------------------------------------------------

        def action_back(self) -> None:
            self.post_message(self.BackRequested())

        def action_toggle_decode(self) -> None:
            self._decode = not self._decode
            self._rebuild()

        def action_open_full_detail(self) -> None:
            if self._flow is not None:
                self.post_message(self.FullDetailRequested(self._flow.flow_id))

        # -- rendering --------------------------------------------------------

        def _primary_value(self) -> str | None:
            return primary_evidence_value(self._finding) if self._finding else None

        def _rebuild(self) -> None:
            if self._finding is None or self._header is None or self._body is None:
                return
            self._header.update(self._header_markup())
            self._body.update("\n".join(self._body_lines()))

        def _header_markup(self) -> str:
            f = self._finding
            color = c(_SEV_COLORS.get(f.severity, "text-muted"))
            cat = f.category or "-"
            try:
                conf = f"{f.confidence:.0%}"
            except Exception:
                conf = "-"
            decode_hint = "b: hide base64" if self._decode else "b: base64 decode"
            return (
                f"[bold {color}]{f.severity.value.upper()}[/] [bold]{_esc(f.title or '-')}[/]  "
                f"[dim]· {_esc(f.source or '-')}/{_esc(cat)}  {conf}[/]\n"
                f"[dim italic]Esc: back  ·  d: full detail  ·  {decode_hint}[/]"
            )

        def _body_lines(self) -> list[str]:
            f = self._finding
            lines: list[str] = []
            if f.description:
                lines.append(_esc(f.description))
                lines.append("")

            primary = self._primary_value()
            if primary is not None:
                lines.append(f"[bold {c('warning')}]Matched value[/]")
                lines.append(f"[{c('accent')}]{_esc(primary)}[/]")
                lines.append("")

            ev = f.evidence or {}
            context = {k: ev[k] for k in _CONTEXT_KEYS if k in ev}
            extras = {k: v for k, v in ev.items()
                      if k not in _CONTEXT_KEYS and k not in EVIDENCE_VALUE_KEYS}
            if context or extras:
                lines.append(f"[bold {c('primary')}]Evidence[/]")
                for k, v in {**context, **extras}.items():
                    lines.append(f"[bold]{_esc(k)}:[/] {_esc(v)}")
                lines.append("")

            if self._decode:
                lines.extend(self._decode_lines(primary))

            lines.extend(self._flow_lines(primary))
            return lines

        def _decode_lines(self, primary: "str | None") -> list[str]:
            candidates: list[tuple[str, str]] = []
            if primary:
                candidates.append(("matched value", primary))
            auth = self._flow_header("authorization")
            if auth:
                candidates.append(("Authorization", auth))
            for ev_val in (self._finding.evidence or {}).values():
                if isinstance(ev_val, str) and ev_val not in (primary, auth):
                    candidates.append(("evidence", ev_val))

            out = [f"[bold {c('success')}]Base64 decode[/]"]
            shown = False
            for label, value in candidates:
                decoded = _try_base64(value)
                if decoded is not None:
                    out.append(f"[dim]{label} →[/] [{c('accent')}]{_esc(decoded)}[/]")
                    shown = True
            if not shown:
                out.append("[dim]No decodable base64 value found.[/]")
            out.append("")
            return out

        def _flow_header(self, name: str) -> str:
            """Case-insensitive lookup across request then response headers."""
            flow = self._flow
            if flow is None:
                return ""
            for msg in (getattr(flow, "request", None), getattr(flow, "response", None)):
                headers = getattr(msg, "headers", None) or {}
                for k, v in headers.items():
                    if k.lower() == name.lower():
                        return str(v)
            return ""

        def _flow_lines(self, primary: "str | None") -> list[str]:
            flow = self._flow
            if flow is None:
                return ["[dim]No flow context available for this finding.[/]"]
            lines = [f"[bold {c('primary')}]Flow[/]"]
            method = getattr(flow, "display_method", "") or "-"
            host = getattr(flow, "display_host", "") or "-"
            status = getattr(flow, "display_status", "") or "-"
            lines.append(f"[bold]{_esc(method)}[/] {_esc(host)}  [dim]>[/] {_esc(status)}")
            lines.append(f"[dim]{flow.src_addr}:{flow.src_port} → "
                         f"{flow.dst_addr}:{flow.dst_port}[/]")
            lines.append("")

            req = getattr(flow, "request", None)
            headers = getattr(req, "headers", None) or {}
            if headers:
                lines.append("[bold]Request headers[/]")
                for name, value in headers.items():
                    if primary and primary in str(value):
                        lines.append(
                            f"[reverse]{_esc(name)}: {_esc(value)}[/]  "
                            f"[bold {c('warning')}]← finding[/]"
                        )
                    else:
                        lines.append(f"[bold]{_esc(name)}:[/] {_esc(value)}")
                lines.append("")

            body = getattr(req, "body", None) if req else None
            if body:
                try:
                    text = body[:512].decode("utf-8", errors="replace")
                    lines.append("[bold]Request body (preview)[/]")
                    lines.append(_esc(text))
                except Exception:
                    pass
            return lines
