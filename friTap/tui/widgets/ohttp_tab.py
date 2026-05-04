"""OHTTP Inner tab provider for FlowDetailWidget.

Implements the TabProvider duck-type interface (title, tab_id, render(flow))
to display decrypted OHTTP bhttp inner request/response payloads.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

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
            lines.append(f"[bold]{r.method}[/] {r.url}")
            if r.host:
                lines.append(f"Host: {r.host}")
            for k, v in (r.headers or {}).items():
                lines.append(f"  {k}: {v}")
            if r.body:
                lines.append("")
                try:
                    lines.append(r.body.decode("utf-8", errors="replace"))
                except Exception:
                    lines.append(f"[{len(r.body)} bytes binary]")

        if flow.ohttp_inner_response:
            resp = flow.ohttp_inner_response
            if lines:
                lines.append("")
            lines.append("[bold yellow]Inner Response (decrypted bhttp)[/]")
            lines.append(f"[bold]{resp.status_code} {resp.status_text}[/]")
            for k, v in (resp.headers or {}).items():
                lines.append(f"  {k}: {v}")
            if resp.body:
                lines.append("")
                try:
                    lines.append(resp.body.decode("utf-8", errors="replace"))
                except Exception:
                    lines.append(f"[{len(resp.body)} bytes binary]")

        return "\n".join(lines)
