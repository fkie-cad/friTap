"""Safe rendering of wire-derived text in markup-enabled TUI widgets.

Everything parsed from captured traffic (method, URL, host, status text,
header names/values, bodies) is attacker-controlled. Interpolated raw into a
markup string it can inject styles, fake ``[link=...]`` / ``[@click=...]``
spans, or raise ``MarkupError`` (an unbalanced ``[/]``) and blank a tab or
crash the TUI. Control characters (``\\r``, ``\\n``, ``\\x1b``...) can also
forge extra header lines or drive the terminal.

Two markup dialects are in use:

* Rich markup -- ``RichLog(markup=True)`` and ``DataTable`` string cells go
  through :meth:`rich.text.Text.from_markup`; use :func:`safe_wire_text`.
* Textual markup -- ``Static.update(str)``; it also consumes upper-case tags
  such as ``[RC4]`` and cannot escape a backslash, so use
  :func:`safe_static_text`.
"""

from __future__ import annotations

import re

from rich.markup import escape as _rich_escape

# C0 controls except TAB, DEL, C1 controls, Unicode line/paragraph separators
# and the bidi embedding/override/isolate controls (display spoofing).
_CONTROL_CHARS = re.compile(
    "[\x00-\x08\x0a-\x1f\x7f-\x9f  ‪-‮⁦-⁩]"
)

_NAMED_ESCAPES = {
    "\r": "\\r",
    "\n": "\\n",
    "\x1b": "\\x1b",
    "\x00": "\\x00",
}


def _escape_control(match: re.Match) -> str:
    char = match.group(0)
    named = _NAMED_ESCAPES.get(char)
    if named:
        return named
    code = ord(char)
    return f"\\x{code:02x}" if code <= 0xFF else f"\\u{code:04x}"


def visible_controls(value) -> str:
    """Return *value* as text with control characters shown as ``\\r``-style escapes.

    TAB is kept; every other C0/C1 control (plus Unicode line separators and
    bidi overrides) becomes a visible escape so it cannot break the layout.
    """
    return _CONTROL_CHARS.sub(_escape_control, str(value))


def safe_wire_text(value) -> str:
    """Wire-derived *value* made safe for Rich markup (RichLog / DataTable cells)."""
    return _rich_escape(visible_controls(value))


def safe_static_text(value) -> str:
    """Wire-derived *value* made safe for Textual markup (``Static.update``).

    Every ``[`` is escaped (Textual parses upper-case tags too). Textual has
    no backslash escape, so a trailing backslash -- which would swallow the
    ``[`` of the caller's closing tag -- is followed by a space.
    """
    text = visible_controls(value).replace("[", "\\[")
    return text + " " if text.endswith("\\") else text


# Default cap for rendering a decoded text body (full data stays in the flow/PCAP).
TEXT_RENDER_LIMIT = 256 * 1024


def capped_text_lines(
    data: bytes, limit: int = TEXT_RENDER_LIMIT, errors: str = "strict",
) -> list[str]:
    """*data* decoded as UTF-8 Rich markup lines, capped at *limit* bytes.

    The first line is the escaped text (a literal ``[`` would otherwise be
    parsed as markup). Over the cap, a dim "... N more bytes truncated"
    notice follows. Cutting at *limit* can split a multi-byte character, so
    decoding is never strict then.
    """
    slice_errors = "replace" if len(data) > limit else errors
    lines = [_rich_escape(data[:limit].decode("utf-8", errors=slice_errors))]
    if len(data) > limit:
        lines.append(
            f"[dim italic]... {len(data) - limit:,} more bytes truncated "
            f"({len(data):,} total)[/]"
        )
    return lines


def write_capped_text(
    log, data: bytes, limit: int = TEXT_RENDER_LIMIT, errors: str = "strict",
) -> None:
    """Write :func:`capped_text_lines` to *log* (anything with ``write(str)``)."""
    for line in capped_text_lines(data, limit, errors):
        log.write(line)
