"""OHTTP inner bodies are size-capped like the flow-detail text tabs.

A decrypted bhttp body is attacker-sized: rendering it unbounded can freeze the
TUI. The OHTTP tab uses the shared ``wire_text.capped_text_lines`` writer
(also behind ``FlowDetailWidget._write_text_body``), so it
shows at most ``_TEXT_RENDER_LIMIT`` bytes plus a "truncated" notice.
"""

from __future__ import annotations

import pytest
from rich.text import Text

from friTap.flow.models import Flow
from friTap.parsers.base import ParseResult

pytest.importorskip("textual")

from friTap.tui.widgets.flow_detail import FlowDetailWidget  # noqa: E402
from friTap.tui.widgets.ohttp_tab import OhttpTabProvider  # noqa: E402

LIMIT = FlowDetailWidget._TEXT_RENDER_LIMIT


def _ohttp_flow(request_body: bytes = b"", response_body: bytes = b"") -> Flow:
    flow = Flow(flow_id="o1", src_addr="10.0.0.1", src_port=1,
                dst_addr="10.0.0.2", dst_port=443)
    flow.ohttp_inner_request = ParseResult(
        protocol="HTTP/1.1", method="POST", url="/inner", host="inner.example",
        headers={"Content-Type": "text/plain"}, body=request_body)
    flow.ohttp_inner_response = ParseResult(
        protocol="HTTP/1.1", status_code=200, status_text="OK",
        headers={}, body=response_body, is_request=False)
    return flow


def _plain(flow: Flow) -> str:
    return Text.from_markup(OhttpTabProvider().render(flow)).plain


@pytest.mark.parametrize("side", ["request", "response"])
def test_large_inner_body_is_capped_with_truncation_notice(side):
    total = LIMIT + 10_000
    body = b"A" * total
    flow = _ohttp_flow(**{f"{side}_body": body})

    plain = _plain(flow)

    assert plain.count("A") == LIMIT
    assert f"{total - LIMIT:,} more bytes truncated ({total:,} total)" in plain


def test_body_within_limit_is_rendered_in_full_without_notice():
    flow = _ohttp_flow(request_body=b"hello [bold]world[/]", response_body=b"ok\n[/]")
    plain = _plain(flow)
    assert "hello [bold]world[/]" in plain   # still escaped, rendered literally
    assert "ok\n[/]" in plain
    assert "truncated" not in plain


def test_cut_inside_multibyte_character_does_not_raise():
    body = b"a" * (LIMIT - 1) + "é".encode() * 4  # 2-byte char split by the cap
    plain = _plain(_ohttp_flow(response_body=body))
    assert "more bytes truncated" in plain


# ── shared capped text writer (wire_text) ─────────────────────────


def _legacy_capped_lines(body: bytes, limit: int, errors: str) -> list[str]:
    """The pre-refactor ``FlowDetailWidget._write_text_body`` logic, verbatim."""
    from rich.markup import escape

    out = []
    slice_errors = "replace" if len(body) > limit else errors
    out.append(escape(body[:limit].decode("utf-8", errors=slice_errors)))
    if len(body) > limit:
        out.append(f"[dim italic]... {len(body) - limit:,} more bytes truncated "
                   f"({len(body):,} total)[/]")
    return out


class _Sink:
    def __init__(self) -> None:
        self.lines: list[str] = []

    def write(self, markup: str) -> None:
        self.lines.append(markup)


@pytest.mark.parametrize("size", [0, 10, LIMIT - 1, LIMIT, LIMIT + 1, LIMIT + 4096])
@pytest.mark.parametrize("errors", ["strict", "replace"])
def test_capped_text_lines_match_legacy_writer(size, errors):
    from friTap.tui.widgets.wire_text import TEXT_RENDER_LIMIT, capped_text_lines

    assert TEXT_RENDER_LIMIT == LIMIT
    body = (b"a[b]\\" * (size // 5 + 1))[:size]
    assert capped_text_lines(body, LIMIT, errors) == _legacy_capped_lines(body, LIMIT, errors)


@pytest.mark.parametrize("size", [5, LIMIT, LIMIT + 7])
def test_flow_detail_write_text_body_delegates_identically(size):
    body = "é".encode() * (size // 2) + b"x" * (size % 2)
    sink = _Sink()
    FlowDetailWidget._write_text_body(FlowDetailWidget, sink, body, errors="replace")
    assert sink.lines == _legacy_capped_lines(body, LIMIT, "replace")


def test_capped_text_splits_multibyte_char_without_raising():
    from friTap.tui.widgets.wire_text import capped_text_lines

    lines = capped_text_lines("é".encode() * 3, limit=3, errors="strict")
    assert lines[0] == "é�"
    assert "3 more bytes truncated (6 total)" in lines[1]
