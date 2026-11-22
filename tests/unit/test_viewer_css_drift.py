"""Drift + leak tests for friTap.tui.screens.viewer_css."""
import asyncio
import re
from pathlib import Path

from textual.app import App, ComposeResult
from textual.widgets import DataTable

from friTap.tui.screens.viewer_css import VIEWER_CSS, ViewerBody

TCSS = Path(__file__).resolve().parents[2] / "friTap" / "tui" / "css" / "fritap.tcss"

# viewer selector -> selector in fritap.tcss (identity: no global rule was translated)
SELECTOR_MAP: dict[str, str] = {}

_BLOCK = re.compile(r"([^{}]+)\{([^{}]*)\}")


def _blocks(css: str) -> dict[str, list[str]]:
    css = re.sub(r"/\*.*?\*/", "", css, flags=re.S)
    out: dict[str, list[str]] = {}
    for sel, body in _BLOCK.findall(css):
        sel = " ".join(sel.split())
        decls = [" ".join(d.split()) for d in body.split(";") if d.strip()]
        out[sel] = decls
    return out


def test_viewer_rules_match_fritap_tcss():
    viewer = _blocks(VIEWER_CSS)
    source = _blocks(TCSS.read_text(encoding="utf-8"))
    assert viewer, "VIEWER_CSS is empty"
    for sel, decls in viewer.items():
        src_sel = SELECTOR_MAP.get(sel, sel)
        assert src_sel in source, f"{src_sel!r} missing from fritap.tcss"
        assert decls == source[src_sel], f"drift in {sel!r}: {decls} != {source[src_sel]}"


def test_viewer_css_has_no_global_selectors():
    for sel in _blocks(VIEWER_CSS):
        for part in re.split(r"[,>\s]+", sel):
            assert not re.match(r"^(Screen|Header|Footer|Input|Button|OptionList|DataTable)\b", part), sel


class _Host(App):
    CSS = "DataTable { background: red; }"

    def get_theme_variable_defaults(self):
        # Viewer CSS uses $fritap-* variables; a foreign host does not define them.
        v = super().get_theme_variable_defaults()
        for name in ("border-default", "bg-selected", "bg-header", "text-muted", "button-hover"):
            v[f"fritap-{name}"] = "#444444"
        return v

    def compose(self) -> ComposeResult:
        yield DataTable(id="outside")
        with ViewerBody():
            yield DataTable(id="flow-list")


def test_viewer_css_does_not_leak_into_host():
    async def run():
        app = _Host()
        async with app.run_test():
            outside = app.query_one("#outside", DataTable)
            inside = app.query_one("#flow-list", DataTable)
            assert outside.styles.background.hex.lower() == "#ff0000"
            # viewer rule applies inside (scrollbar-size 1 1), not outside
            assert inside.styles.scrollbar_size_vertical == 1
            assert outside.styles.scrollbar_size_vertical != 1

    asyncio.run(run())
