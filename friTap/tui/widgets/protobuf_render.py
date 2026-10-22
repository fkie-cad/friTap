"""Render a :class:`~friTap.parsers.protobuf.view.ProtobufView` as Rich markup.

Pure function (no Textual widgets): returns a ``list[str]`` of Rich markup
lines ready for ``RichLog.write``. Every line derived from captured data is
escaped with :func:`rich.markup.escape`, so a decoded string such as
``"[/x]"`` or the wire decoder's ``[packed]`` marker renders literally instead
of vanishing or raising ``MarkupError``.

Colours come from a *color* callable mapping a semantic role (``"warning"``,
``"error"``, ``"accent"``, ``"text-muted"``) to a Rich colour; it defaults to
the running TUI theme (:func:`friTap.tui.themes.c`).
"""

from __future__ import annotations

from typing import Callable, List, Optional

from rich.markup import escape

from friTap.parsers.protobuf.view import (
    LINE_ERROR,
    LINE_HEADER,
    LINE_NOTE,
    ProtobufView,
    ViewLine,
)

ColorFn = Callable[[str], str]


def _default_color(role: str) -> str:
    from friTap.tui.themes import c

    return c(role)


def _markup_line(line: ViewLine, color: ColorFn) -> str:
    """One view line as escaped, styled markup."""
    text = escape(line.text)
    if line.kind == LINE_NOTE:
        return f"[{color('warning')}]⚠ {text}[/]"
    if line.kind == LINE_ERROR:
        return f"[{color('error')}]{text}[/]"
    if line.kind == LINE_HEADER:
        return f"[bold {color('accent')}]{text}[/]"
    return text


def protobuf_view_lines(
    view: ProtobufView,
    max_lines: Optional[int] = None,
    *,
    color: Optional[ColorFn] = None,
) -> List[str]:
    """Rich markup lines for *view*, at most *max_lines* plus an overflow line."""
    color = color or _default_color
    lines = view.lines()
    shown = lines if max_lines is None else lines[:max_lines]
    out = [_markup_line(line, color) for line in shown]
    hidden = len(lines) - len(shown)
    if hidden > 0:
        out.append(f"[{color('text-muted')}]… {hidden} more line(s)[/]")
    return out
