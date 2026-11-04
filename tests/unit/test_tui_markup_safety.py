"""TUI output safety: wire-derived text never injects markup or crashes the TUI.

Everything rendered from captured traffic (method, URL, host, status text,
header names/values, bodies) is attacker-controlled. A header value such as
``[bold]X:[/] [/]`` used to raise ``MarkupError`` (blank tab, or a TUI crash on
tab switch / ``h``), ``[link=...]`` / ``[@click=...]`` could fake UI, control
characters could forge header lines, deep JSON raised ``RecursionError``, huge
JSON was pretty-printed unbounded, and "save body" overwrote existing files.
"""

from __future__ import annotations

import asyncio
import json

import pytest
from rich.text import Text

from friTap.flow.models import Flow
from friTap.parsers.base import ParseResult
from friTap.tui.widgets.wire_text import (
    safe_static_text,
    safe_wire_text,
    visible_controls,
)
from tests.unit._tui_flow_helpers import make_flow_detail_widget

pytest.importorskip("textual")

from textual.markup import to_content  # noqa: E402

from friTap.tui.widgets.flow_detail import (  # noqa: E402
    FlowDetailWidget,
    save_without_overwrite,
)
from friTap.tui.widgets.flow_list import FlowListWidget  # noqa: E402
from friTap.tui.widgets.ohttp_tab import OhttpTabProvider  # noqa: E402

HOSTILE_VALUES = [
    "[/]",
    "[bold]x[/]",
    "[bold]X:[/] [/]",
    "[link=http://evil]x[/link]",
    "[@click=app.quit]x[/]",
    "trailing\\",
    "\\[/]",
]
ESC_URL = "/a\x1b[31mred\r\nX-Injected: 1"


def _blob(log) -> str:
    return "\n".join(log.lines)


def _http_flow(header_value: str = "ok", url: str = "/") -> Flow:
    flow = Flow(flow_id="m1", src_addr="10.0.0.1", src_port=1,
                dst_addr="10.0.0.2", dst_port=443)
    flow.request = ParseResult(
        protocol="HTTP/1.1", method="GET", url=url, host="evil[/]",
        headers={"X-Evil": header_value, "[/]": "name-side"})
    flow.response = ParseResult(
        protocol="HTTP/1.1", status_code=200, status_text="OK [/] [bold]",
        headers={"X-Evil": header_value}, is_request=False)
    return flow


# ── pure helpers ─────────────────────────────────────────────────


def test_visible_controls_escapes_c0_c1_but_keeps_tab():
    assert visible_controls("a\r\nb") == "a\\r\\nb"
    assert visible_controls("\x1b[31m") == "\\x1b[31m"
    assert visible_controls("\x00\x07\x7f\x85") == "\\x00\\x07\\x7f\\x85"
    assert visible_controls("a\tb") == "a\tb"
    assert visible_controls("\u202eevil") == "\\u202eevil"


@pytest.mark.parametrize("value", HOSTILE_VALUES + [ESC_URL])
def test_safe_wire_text_renders_literally_in_rich(value):
    rendered = Text.from_markup(f"[bold]{safe_wire_text(value)}[/] tail").plain
    assert rendered.startswith(visible_controls(value).rstrip("\\"))
    assert rendered.endswith(" tail")


@pytest.mark.parametrize("value", HOSTILE_VALUES + ["[RC4]", ESC_URL])
def test_safe_static_text_renders_literally_in_textual(value):
    content = to_content(f"[bold]{safe_static_text(value)}[/] tail")
    assert visible_controls(value) in content.plain
    assert content.plain.endswith(" tail")


def test_safe_wire_text_neutralises_link_and_click():
    text = Text.from_markup(safe_wire_text("[link=http://evil]x[/link][@click=app.quit]y[/]"))
    assert not text.spans
    assert "[link=http://evil]" in text.plain


# ── request / response panes ─────────────────────────────────────


@pytest.mark.parametrize("value", HOSTILE_VALUES)
def test_request_and_response_headers_render_escaped(value):
    widget = make_flow_detail_widget()
    flow = _http_flow(header_value=value)
    widget._update_request(flow)
    widget._update_response(flow)
    assert f"X-Evil: {value.rstrip(chr(92))}" in _blob(widget._request_log)
    assert "[/]: name-side" in _blob(widget._request_log)
    assert "200 OK [/] [bold]" in _blob(widget._response_log)


def test_url_control_characters_are_visible_escapes():
    widget = make_flow_detail_widget()
    widget._update_request(_http_flow(url=ESC_URL))
    text = _blob(widget._request_log)
    assert "GET /a\\x1b[31mred\\r\\nX-Injected: 1 HTTP/1.1" in text
    assert "\x1b" not in text and "\r" not in text


def test_header_line_escapes_method_host_and_status():
    widget = make_flow_detail_widget()

    class _Header:
        markup = ""

        def update(self, markup):
            self.markup = markup

    widget._header_widget = _Header()
    widget._tabs = None
    flow = _http_flow()
    flow.request.method = "GE[/]T"
    widget._update_header(flow)
    plain = to_content(widget._header_widget.markup).plain
    assert "GE[/]T" in plain and "evil[/]" in plain and "OK [/] [bold]" in plain


def test_flow_list_cells_escape_wire_fields():
    flow = _http_flow()
    flow.request.method = "[bold]X:[/] [/]"
    cell = FlowListWidget._format_method(flow)
    assert Text.from_markup(cell).plain.startswith("[bold]X:[/] [/]")


def test_ohttp_tab_escapes_inner_fields():
    flow = Flow(flow_id="o1")
    flow.ohttp_inner_request = ParseResult(
        method="[/]", url="/x[bold]", host="h[/]", headers={"k[/]": "v[/]"}, body=b"[/]")
    flow.ohttp_inner_response = ParseResult(
        status_code=200, status_text="[/]", headers={"a": "[/x]"}, is_request=False)
    plain = Text.from_markup(OhttpTabProvider().render(flow)).plain
    for fragment in ("[/] /x[bold]", "Host: h[/]", "k[/]: v[/]", "200 [/]", "a: [/x]"):
        assert fragment in plain


# ── crash containment ────────────────────────────────────────────


def test_render_failure_shows_error_line_instead_of_raising():
    widget = make_flow_detail_widget()

    def _boom(flow):
        raise ValueError("bad [/] markup")

    widget._update_request = _boom
    widget._render_tab_safely(_http_flow(), "tab-request")
    assert "Could not render this view: ValueError: bad [/] markup" in _blob(widget._request_log)


# ── body rendering ───────────────────────────────────────────────


def test_deeply_nested_json_body_does_not_raise():
    widget = make_flow_detail_widget()
    body = b"[" * 100_000 + b"]" * 100_000
    widget._render_body_standard(widget._request_log, body, {"Content-Type": "application/json"})
    widget._decode_json(widget._request_log, body, {})
    assert widget._request_log.lines


def test_json_above_render_limit_is_not_pretty_printed():
    widget = make_flow_detail_widget()
    limit = FlowDetailWidget._TEXT_RENDER_LIMIT
    body = json.dumps({"k": "v" * limit}).encode()
    assert widget._pretty_json(body) is None
    assert widget._pretty_json(b'{"k": 1}') == '{\n  "k": 1\n}'
    widget._decode_json(widget._request_log, body, {})
    text = _blob(widget._request_log)
    assert "too large to pretty-print" in text
    assert "more bytes truncated" in text


def _nested_json(depth: int) -> bytes:
    return b"[" * depth + b"]" * depth


def test_pretty_json_rejects_deep_nesting_explicitly():
    # Depth 200 parses on every Python (below the 3.13 recursion limit), so a
    # None here proves the depth guard is explicit, not RecursionError-based.
    widget = make_flow_detail_widget()
    assert json.loads(_nested_json(200))
    assert widget._pretty_json(_nested_json(200)) is None


def test_pretty_json_accepts_nesting_at_the_depth_limit():
    from friTap.analysis._json_walk import MAX_JSON_DEPTH

    formatted = make_flow_detail_widget()._pretty_json(_nested_json(MAX_JSON_DEPTH))
    assert formatted is not None and formatted.count("\n") == 2 * (MAX_JSON_DEPTH - 1)


def test_deeply_nested_json_body_falls_back_to_raw_text():
    widget = make_flow_detail_widget()
    widget._decode_json(widget._request_log, _nested_json(200), {})
    text = _blob(widget._request_log)
    assert "Not valid JSON" in text and "[[[" in text


def test_pretty_json_output_is_capped_at_render_limit():
    widget = make_flow_detail_widget()
    limit = FlowDetailWidget._TEXT_RENDER_LIMIT
    body = json.dumps([1] * 120_000, separators=(",", ":")).encode()
    assert len(body) <= limit  # parsed, but its indented form is > limit
    widget._decode_json(widget._request_log, body, {})
    text = _blob(widget._request_log)
    assert text.startswith("[\n  1,") and "more bytes truncated" in text


def test_pretty_json_below_cap_is_written_unchanged():
    widget = make_flow_detail_widget()
    widget._render_body_standard(
        widget._request_log, b'{"a": "[/x]"}', {"Content-Type": "application/json"})
    assert widget._request_log.lines == ['{\n  "a": "[/x]"\n}']


def test_explorer_json_decoder_rejects_deep_nesting():
    from friTap.tui.modals.explorer_modal import ExplorerModal

    assert ExplorerModal._decode_plain(_nested_json(200), "json").startswith("JSON decode failed")
    assert ExplorerModal._decode_plain(_nested_json(100_000), "json").startswith("JSON decode failed")
    assert ExplorerModal._decode_plain(b'{"k": [1]}', "json") == '{\n  "k": [\n    1\n  ]\n}'


@pytest.mark.parametrize("decoder", ["_decode_raw_utf8", "_decode_base64"])
def test_text_decoders_are_capped(decoder):
    import base64

    widget = make_flow_detail_widget()
    raw = b"a" * (FlowDetailWidget._TEXT_RENDER_LIMIT + 10)
    body = base64.b64encode(raw) if decoder == "_decode_base64" else raw
    getattr(widget, decoder)(widget._request_log, body, {})
    assert "more bytes truncated" in _blob(widget._request_log)


def test_decoder_dispatch_accepts_self_for_json_and_raw():
    """``_DECODERS`` calls ``fn(self, log, body, headers)`` for every decoder."""
    widget = make_flow_detail_widget()
    for name in ("json", "raw_utf8"):
        FlowDetailWidget._DECODERS[name](widget, widget._request_log, b'{"a": "[/]"}', {})
    assert '"a": "[/]"' in _blob(widget._request_log)


def test_automatic_decompression_uses_auto_cap(monkeypatch):
    import friTap.parsers.decompress as decompress

    seen = {}

    def _fake(body, encoding, max_out=decompress.MAX_DECOMPRESSED_BODY):
        seen["max_out"] = max_out
        return body, ""

    monkeypatch.setattr(decompress, "decompress_body", _fake)
    widget = make_flow_detail_widget()
    widget._render_body_standard(widget._request_log, b"x", {"Content-Encoding": "gzip"})
    assert seen["max_out"] == decompress.MAX_AUTO_DECOMPRESS


def test_text_body_with_backslash_before_closing_tag_does_not_raise():
    widget = make_flow_detail_widget()
    widget._write_text_body(widget._request_log, b"a\\[/] b\\", errors="replace")
    assert "a\\[/] b" in _blob(widget._request_log)


# ── save body ────────────────────────────────────────────────────


def test_save_without_overwrite_adds_numbered_suffix(tmp_path):
    existing = tmp_path / "report.pdf"
    existing.write_bytes(b"keep me")
    first = save_without_overwrite(str(tmp_path), "report.pdf", b"one")
    second = save_without_overwrite(str(tmp_path), "report.pdf", b"two")
    assert existing.read_bytes() == b"keep me"
    assert first.endswith("report (1).pdf") and second.endswith("report (2).pdf")
    assert (tmp_path / "report (2).pdf").read_bytes() == b"two"


def test_save_without_overwrite_never_follows_existing_symlink(tmp_path):
    target = tmp_path / "victim.txt"
    target.write_bytes(b"original")
    (tmp_path / "body.bin").symlink_to(target)
    path = save_without_overwrite(str(tmp_path), "body.bin", b"payload")
    assert target.read_bytes() == b"original"
    assert path.endswith("body (1).bin")


def test_save_without_overwrite_fresh_name_and_no_extension(tmp_path):
    assert save_without_overwrite(str(tmp_path), "new.bin", b"x").endswith("new.bin")
    save_without_overwrite(str(tmp_path), "README", b"x")
    assert save_without_overwrite(str(tmp_path), "README", b"y").endswith("README (1)")


# ── headless smoke: hostile flow through the real widget ────────


def test_hostile_flow_tab_switch_and_hex_toggle_headless():
    from textual.app import App

    class _DetailApp(App):
        def compose(self):
            yield FlowDetailWidget(id="detail")

    flow = _http_flow(header_value="[bold]X:[/] [/]", url=ESC_URL)
    flow.request.method = "[bold]X:[/] [/]"

    async def _run() -> None:
        app = _DetailApp()
        async with app.run_test() as pilot:
            widget = app.query_one("#detail", FlowDetailWidget)
            widget.show_flow(flow)
            await pilot.pause()
            for tab in ("tab-response", "tab-detail", "tab-request"):
                widget._tabs.active = tab
                await pilot.pause()
            widget.action_toggle_raw_hex()
            widget.action_toggle_raw_hex()
            await pilot.pause()
            assert app.is_running

    asyncio.run(_run())
