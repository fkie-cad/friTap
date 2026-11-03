#!/usr/bin/env python3

"""Finding-detail markup safety: dynamic text renders literally.

The finding-detail widget builds Textual markup for ``Static.update``. Its
``_esc`` used to escape only ``[``, so a value ending in a backslash turned
the caller's closing ``[/]`` into the escape ``\\[/]``: the tag leaked into
the text and the style never closed. It now uses the shared
:func:`~friTap.tui.widgets.wire_text.safe_static_text`.
"""

from __future__ import annotations

import pytest

pytest.importorskip("textual")

from textual.markup import to_content  # noqa: E402

from friTap.analysis import Finding, Severity  # noqa: E402
from friTap.flow.models import Flow, FlowState  # noqa: E402
from friTap.parsers.base import ParseResult  # noqa: E402
from friTap.tui.widgets.analyzer_finding_detail import (  # noqa: E402
    AnalyzerFindingDetailWidget,
    _esc,
)

TRAILING_BACKSLASH = "C:\\Users\\victim\\"


def _plain(markup: str) -> str:
    return to_content(markup).plain


@pytest.mark.parametrize("value", [TRAILING_BACKSLASH, "\\", "x\\\\", "[/]\\"])
def test_trailing_backslash_renders_and_closing_tag_still_closes(value):
    plain = _plain(f"[bold]{_esc(value)}[/] tail")
    assert plain.startswith(value)
    assert plain.endswith(" tail")
    assert plain.count("[/]") == value.count("[/]")  # caller's tag not leaked


def _widget_with_hostile_finding() -> AnalyzerFindingDetailWidget:
    flow = Flow(flow_id="f1", connection_id="f1", src_addr="10.0.0.1", src_port=1,
                dst_addr="10.0.0.2", dst_port=443, state=FlowState.COMPLETE)
    flow.request = ParseResult(
        protocol="HTTP/1.1", method="POST", url="/", host="example.com",
        headers={"X-Path": TRAILING_BACKSLASH},
        body=b"first line\nsecond line\\", is_request=True)
    widget = AnalyzerFindingDetailWidget()
    widget._finding = Finding(
        severity=Severity.HIGH, title=TRAILING_BACKSLASH,
        description=f"line one\nends with {TRAILING_BACKSLASH}",
        source="credentials", flow_id="f1", metadata={"category": "secret"},
        evidence={"matched_data": TRAILING_BACKSLASH, "location": TRAILING_BACKSLASH},
    )
    widget._flow = flow
    widget._decode = False
    return widget


def test_header_with_trailing_backslash_title_renders():
    plain = _plain(_widget_with_hostile_finding()._header_markup())
    assert TRAILING_BACKSLASH in plain
    assert "[/]" not in plain


def test_body_lines_with_trailing_backslashes_render():
    lines = _widget_with_hostile_finding()._body_lines()
    plain = _plain("\n".join(lines))
    assert "[/]" not in plain
    assert plain.count(TRAILING_BACKSLASH) >= 4  # description, value, evidence, header


def test_multi_line_description_and_body_keep_line_breaks():
    plain_lines = _plain("\n".join(_widget_with_hostile_finding()._body_lines())).split("\n")
    assert "line one" in plain_lines
    assert "first line" in plain_lines
    assert "second line\\ " in plain_lines  # trailing backslash padded, not eaten
