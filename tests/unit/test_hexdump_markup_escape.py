from rich.text import Text

from friTap.tui.themes import c
from friTap.tui.widgets.hexdump import format_hexdump_lines


def test_bracket_bytes_render_literally():
    data = b"AAAA[/]BBBB[bold]"
    for line in format_hexdump_lines(data, markup=True):
        Text.from_markup(line)
    plain = "".join(Text.from_markup(line).plain for line in format_hexdump_lines(data, markup=True))
    assert "AAAA[/]BBBB" in plain and "[bold]" not in plain.replace("AAAA[/]BBBB[bold]", "")
    assert "AAAA[/]BBBB" in plain


def test_body_without_bracket_is_unchanged():
    data = bytes(range(40))
    expected = []
    for off in range(0, len(data), 16):
        chunk = data[off:off + 16]
        hx = " ".join(f"{b:02x}" for b in chunk).ljust(47)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        expected.append(
            f"[{c('hex-offset')}]{off:08x}[/]  [{c('hex-data')}]{hx}[/]  [{c('hex-ascii')}]{asc}[/]"
        )
    assert format_hexdump_lines(data, markup=True) == expected
    assert format_hexdump_lines(b"a[b", markup=False)[0].endswith("a[b")
