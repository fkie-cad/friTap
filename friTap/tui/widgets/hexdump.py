"""Hex dump and text-sniffing helpers for the TUI (no Textual dependency)."""

from __future__ import annotations

from friTap.tui.themes import c


def _is_text(data: bytes) -> bool:
    """Check if data is printable UTF-8 text."""
    try:
        text = data.decode("utf-8")
        return text.isprintable() or '\n' in text or '\r' in text
    except (UnicodeDecodeError, ValueError):
        return False


def format_hexdump_lines(
    data: bytes,
    bytes_per_line: int = 16,
    start_offset: int = 0,
    markup: bool = False,
) -> list[str]:
    """Format raw bytes as hex dump lines (offset, hex, ASCII).

    *start_offset* is added to the offset column; *markup* wraps the columns
    in theme-colored Rich markup for a :class:`RichLog`.
    """
    lines: list[str] = []
    for offset in range(0, len(data), bytes_per_line):
        chunk = data[offset : offset + bytes_per_line]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        hex_part = hex_part.ljust(bytes_per_line * 3 - 1)
        display_offset = start_offset + offset
        if markup:
            ascii_part = ascii_part.replace("[", "\\[")
            lines.append(
                f"[{c('hex-offset')}]{display_offset:08x}[/]  "
                f"[{c('hex-data')}]{hex_part}[/]  "
                f"[{c('hex-ascii')}]{ascii_part}[/]"
            )
        else:
            lines.append(f"{display_offset:08x}  {hex_part}  {ascii_part}")
    return lines
