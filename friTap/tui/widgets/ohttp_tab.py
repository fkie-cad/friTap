"""OHTTP Inner tab provider for FlowDetailWidget.

Implements the TabProvider duck-type interface (title, tab_id, render(flow))
to display decrypted OHTTP bhttp inner request/response payloads.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from friTap.tui.widgets.wire_text import (
    TEXT_RENDER_LIMIT,
    capped_text_lines,
    safe_wire_text,
)

if TYPE_CHECKING:
    from friTap.flow.models import Flow


class OhttpTabProvider:
    """Tab provider that renders decrypted OHTTP inner request/response."""

    title = "OHTTP Inner"
    tab_id = "ohttp"

    def render(self, flow: "Flow") -> Optional[str]:
        """Render the decrypted OHTTP bhttp payload, or return None if no OHTTP data."""
        if not flow.ohttp_inner_request and not flow.ohttp_inner_response:
            return None

        lines = []

        if flow.ohttp_inner_request:
            r = flow.ohttp_inner_request
            lines.append("[bold yellow]Inner Request (decrypted bhttp)[/]")
            lines.append(f"[bold]{safe_wire_text(r.method)}[/] {safe_wire_text(r.url)}")
            if r.host:
                lines.append(f"Host: {safe_wire_text(r.host)}")
            lines.extend(_header_lines(r.headers))
            if r.body:
                lines.append("")
                lines.append(_body_markup(r.body))

        if flow.ohttp_inner_response:
            resp = flow.ohttp_inner_response
            if lines:
                lines.append("")
            lines.append("[bold yellow]Inner Response (decrypted bhttp)[/]")
            lines.append(f"[bold]{resp.status_code} {safe_wire_text(resp.status_text)}[/]")
            lines.extend(_header_lines(resp.headers))
            if resp.body:
                lines.append("")
                lines.append(_body_markup(resp.body))

        return "\n".join(lines)


def _header_lines(headers) -> list[str]:
    """Indented ``name: value`` rows, escaped: bhttp headers are wire-derived."""
    return [f"  {safe_wire_text(k)}: {safe_wire_text(v)}" for k, v in (headers or {}).items()]


def _capped_body_markup(body: bytes) -> str:
    """*body* as escaped markup, capped exactly like the flow-detail text tabs.

    Uses :func:`capped_text_lines` (the shared ``TEXT_RENDER_LIMIT`` cap plus
    the "... more bytes truncated" notice) instead of duplicating it.
    """
    return "\n".join(capped_text_lines(body, TEXT_RENDER_LIMIT, errors="replace"))


def _body_markup(body: bytes) -> str:
    """Escaped, size-capped inner body text; a size placeholder if rendering fails."""
    try:
        return _capped_body_markup(body)
    except Exception:
        return f"[{len(body)} bytes binary]"
