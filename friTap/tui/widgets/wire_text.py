"""Safe rendering of wire-derived text in markup-enabled TUI widgets.

Text parsed from captured traffic (method, URL, host, headers, bodies) is
attacker-controlled. Interpolated raw into markup it can inject styles, fake
``[link=...]``/``[@click=...]`` spans, raise ``MarkupError`` (unbalanced ``[/]``) and
blank a tab or crash the TUI; control characters (``\\r``, ``\\n``, ``\\x1b``) can forge
header lines or drive the terminal.

Two markup dialects:

* Rich markup (``RichLog(markup=True)``, ``DataTable`` string cells): :func:`safe_wire_text`.
* Textual markup (``Static.update(str)``): it also consumes upper-case tags such as
  ``[RC4]`` and cannot escape a backslash, so use :func:`safe_static_text`.
"""

from __future__ import annotations

from rich.markup import escape as _rich_escape

from friTap.text_safety import visible_controls  # noqa: F401 - re-exported


def safe_wire_text(value) -> str:
    """Wire-derived *value* made safe for Rich markup (RichLog / DataTable cells)."""
    return _rich_escape(visible_controls(value))


def safe_static_text(value) -> str:
    """Wire-derived *value* made safe for Textual markup (``Static.update``).

    Every ``[`` is escaped (upper-case tags are parsed too). There is no backslash escape,
    so a trailing backslash (which would swallow the caller's closing ``[``) gets a space.
    """
    text = visible_controls(value).replace("[", "\\[")
    return text + " " if text.endswith("\\") else text


# Default cap for rendering a decoded text body (full data stays in the flow/PCAP).
TEXT_RENDER_LIMIT = 256 * 1024


def capped_text_lines(
    data: bytes, limit: int = TEXT_RENDER_LIMIT, errors: str = "strict",
) -> list[str]:
    """*data* decoded as UTF-8 Rich markup lines, capped at *limit* bytes.

    The first line is the escaped text; over the cap a dim "... N more bytes truncated"
    notice follows. The cut can split a multi-byte character, so decoding is then never strict.
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
