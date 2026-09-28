#!/usr/bin/env python3

"""Tests for the Body Processing modal (``p`` in the flow detail view).

Covers the multi-segment key-hint markup crash (a literal ``[/]`` closed the
muted tag early -> ``MarkupError``), escaping of interpolated values in the
Protobuf preview, and the segment-targeting of the active processing in
``FlowDetailWidget``.
"""

from __future__ import annotations

import asyncio

import pytest
from rich.text import Text

from friTap.flow.models import Flow
from friTap.parsers.base import ParseResult
from friTap.tui.modals.body_processing_modal import (
    BodyProcessingResult,
    _escape_markup,
    _segment_hint,
)
from tests.unit._render_helpers import RenderingFakeLog as _FakeLog

# ---------------------------------------------------------------------------
# 1. Pure helpers
# ---------------------------------------------------------------------------

def test_segment_hint_empty_for_single_segment():
    assert _segment_hint(0) == ""
    assert _segment_hint(1) == ""


def test_segment_hint_renders_literal_bracket_label():
    hint = _segment_hint(2)
    markup = f"[dim]x{hint}  |  Esc: Cancel[/]"
    assert Text.from_markup(markup).plain == "x  |  [/]: Segment  |  Esc: Cancel"


def test_escape_markup_keeps_error_text_literal():
    exc = ValueError("bad tag [/] and [bold]x")
    markup = f"[red]Decode error: {_escape_markup(exc)}[/]"
    assert Text.from_markup(markup).plain == "Decode error: bad tag [/] and [bold]x"


# ---------------------------------------------------------------------------
# 2. FlowDetailWidget segment targeting (no Textual app)
# ---------------------------------------------------------------------------

def _make_widget(processing=None, flow=None):
    from friTap.tui.widgets.flow_detail import FlowDetailWidget
    w = FlowDetailWidget.__new__(FlowDetailWidget)
    w._active_processing = processing
    w._current_flow = flow
    w._segment_offsets = []
    return w


def _two_segment_flow(trailing=b'{"trailing": 1}', trailing_parse=None) -> Flow:
    flow = Flow(flow_id="seg")
    flow.request = ParseResult(protocol="HTTP/1.1", method="POST", url="/a",
                               body=b"primary-body")
    flow.trailing_bytes = trailing
    flow.trailing_protocol = "json"
    flow.trailing_parse = trailing_parse
    return flow


@pytest.mark.parametrize("processing, segment, expected", [
    (None, 0, False),
    (None, 1, False),
    (BodyProcessingResult(decoder="json"), 0, True),
    (BodyProcessingResult(decoder="json"), 1, False),
    (BodyProcessingResult(decoder="json", segment_index=1), 0, False),
    (BodyProcessingResult(decoder="json", segment_index=1), 1, True),
])
def test_processing_applies_to_truth_table(processing, segment, expected):
    assert _make_widget(processing)._processing_applies_to(segment) is expected


def test_processing_applies_to_defaults_missing_segment_index_to_zero():
    class _Legacy:
        decoder = "json"
        decompression = None

    w = _make_widget(_Legacy())
    assert w._processing_applies_to(0) is True
    assert w._processing_applies_to(1) is False


def test_trailing_segment_rendered_through_processing_when_targeted():
    flow = _two_segment_flow(trailing=b"68656c6c6f")
    w = _make_widget(BodyProcessingResult(decoder="hex", segment_index=1), flow)
    log = _FakeLog()
    w._render_trailing_data(log, flow)
    text = "\n".join(log.lines)
    assert "SEGMENT 2" in text
    assert "Raw trailing bytes" not in text


def test_trailing_segment_raw_when_processing_targets_primary():
    flow = _two_segment_flow(trailing=b"68656c6c6f")
    w = _make_widget(BodyProcessingResult(decoder="hex", segment_index=0), flow)
    log = _FakeLog()
    w._render_trailing_data(log, flow)
    assert "Raw trailing bytes" in "\n".join(log.lines)


def test_primary_body_skips_processing_targeting_trailing(monkeypatch):
    w = _make_widget(BodyProcessingResult(decoder="hex", segment_index=1))
    calls = []
    monkeypatch.setattr(type(w), "_apply_active_processing",
                        lambda self, *a: calls.append(a) or None)
    w._render_body(_FakeLog(), b"plain text body", {})
    assert calls == []
    w._render_body(_FakeLog(), b"plain text body", {}, segment=1)
    assert len(calls) == 1


def test_body_preview_uses_trailing_bytes_when_segment_one_targeted():
    flow = _two_segment_flow(trailing=b"TRAILING")
    assert _make_widget(BodyProcessingResult(), flow)._get_active_body_preview() \
        == b"primary-body"
    targeted = _make_widget(BodyProcessingResult(segment_index=1), flow)
    assert targeted._get_active_body_preview() == b"TRAILING"


def test_body_preview_prefers_trailing_parse_body():
    flow = _two_segment_flow(trailing=b"RAW",
                             trailing_parse=ParseResult(body=b"PARSED"))
    w = _make_widget(BodyProcessingResult(segment_index=1), flow)
    assert w._get_active_body_preview() == b"PARSED"


# ---------------------------------------------------------------------------
# 2b. T8: lenient processing, banner, TL decoder, pane-following preview
# ---------------------------------------------------------------------------

import gzip  # noqa: E402

from tests.unit._tl_helpers import msgs_ack, rpc_result  # noqa: E402

_GZIP_PAYLOAD = b"inflated payload text " * 10


def _tl_flow(read_body: bytes = b"", write_body: bytes = b"",
             transport: str = "mtproto") -> Flow:
    flow = Flow(flow_id="tl")
    flow.transport = transport
    if write_body:
        flow.request = ParseResult(protocol="MTProto", method="msgs_ack", body=write_body)
    if read_body:
        flow.response = ParseResult(protocol="MTProto", method="rpc_result", body=read_body)
    return flow


def _plain(log) -> str:
    return "\n".join(log.lines)


def test_banner_written_on_decompression_failure():
    w = _make_widget(BodyProcessingResult(decompression="gzip"))
    log = _FakeLog()
    w._render_body(log, b"not compressed at all", {})
    assert "⚠ Processing failed" in log.lines[0]
    assert "no gzip member" in log.lines[0]


def test_banner_notes_embedded_gzip_member_and_renders_inflated():
    w = _make_widget(BodyProcessingResult(decompression="gzip"))
    log = _FakeLog()
    w._render_body(log, b"\x00" * 0x1C + gzip.compress(_GZIP_PAYLOAD), {})
    assert "⚠ Processing: gzip member at offset 0x1C" in log.lines[0]
    assert "inflated payload text" in _plain(log)


def test_banner_on_unknown_encoding():
    w = _make_widget(BodyProcessingResult(decompression="lzma"))
    log = _FakeLog()
    w._render_body(log, b"abc", {})
    assert "unknown encoding" in log.lines[0]


def test_write_processing_banner_escapes_markup():
    log = _FakeLog()
    FlowDetailWidget._write_processing_banner(log, ["note [bold]x"], None)
    assert "note [bold]x" in log.lines[0]


def test_tl_decoder_renders_tree_for_msgs_ack():
    w = _make_widget(BodyProcessingResult(decoder="tl"), _tl_flow())
    log = _FakeLog()
    w._render_body(log, msgs_ack(1, 2), {})
    text = _plain(log)
    assert "msgs_ack" in text
    assert "msg_ids" in text


def test_tl_domain_follows_transport():
    assert _make_widget(None, _tl_flow())._tl_domain() == "mtproto"
    assert _make_widget(None, _tl_flow(transport="telegram_e2e"))._tl_domain() == "secret"


def test_tl_pane_banner_first_then_tl_decoded_inflated_body():
    inner = msgs_ack(7)
    body = rpc_result(5, b"") + b"\x00" * 4 + gzip.compress(inner)
    flow = _tl_flow(read_body=body)
    w = _make_widget(BodyProcessingResult(decompression="gzip", decoder="tl"), flow)
    log = _FakeLog()
    assert w._render_tl_message_pane(log, flow, "read") is True
    assert "⚠ Processing: gzip member at offset" in log.lines[0]
    assert "RECEIVED message" in _plain(log)
    assert "msgs_ack" in _plain(log).split("--- Message ---")[1]


def test_tl_pane_without_processing_has_no_banner():
    flow = _tl_flow(read_body=msgs_ack(1))
    w = _make_widget(None, flow)
    log = _FakeLog()
    w._render_tl_message_pane(log, flow, "read")
    assert "⚠" not in _plain(log)


def test_body_preview_follows_active_pane(monkeypatch):
    flow = _tl_flow(read_body=b"READ-TL", write_body=b"WRITE-TL")
    w = _make_widget(BodyProcessingResult(), flow)
    monkeypatch.setattr(type(w), "_active_pane", lambda self: "response")
    assert w._get_active_body_preview() == b"READ-TL"
    monkeypatch.setattr(type(w), "_active_pane", lambda self: "request")
    assert w._get_active_body_preview() == b"WRITE-TL"


def test_body_preview_http_response_pane(monkeypatch):
    flow = _two_segment_flow()
    flow.response = ParseResult(protocol="HTTP/1.1", body=b"resp-body")
    w = _make_widget(BodyProcessingResult(), flow)
    monkeypatch.setattr(type(w), "_active_pane", lambda self: "response")
    assert w._get_active_body_preview() == b"resp-body"


# ---------------------------------------------------------------------------
# 3. Textual pilot tests
# ---------------------------------------------------------------------------

pytest.importorskip("textual")

from textual.app import App  # noqa: E402
from textual.widgets import Static  # noqa: E402

from friTap.tui.app import FriTapApp  # noqa: E402
from friTap.tui.modals.body_processing_modal import BodyProcessingModal  # noqa: E402
from friTap.tui.widgets.flow_detail import FlowDetailWidget  # noqa: E402


def _run(body, app_factory=FriTapApp, size=(120, 40)):
    async def _main() -> None:
        app = app_factory()
        async with app.run_test(size=size) as pilot:
            await body(app, pilot)

    asyncio.run(_main())


def _key_hints_text(modal) -> str:
    return str(modal.query_one(".key-hints", Static).render())


def test_modal_with_two_segments_mounts_and_shows_segment_hint():
    seen = {}

    async def body(app, pilot):
        modal = BodyProcessingModal(segment_count=2)
        await app.push_screen(modal)
        await pilot.pause()
        seen["hints"] = _key_hints_text(modal)

    _run(body)
    assert "[/]: Segment" in seen["hints"]
    assert "Esc: Cancel" in seen["hints"]


def test_modal_with_single_segment_has_no_segment_hint():
    seen = {}

    async def body(app, pilot):
        modal = BodyProcessingModal(segment_count=1)
        await app.push_screen(modal)
        await pilot.pause()
        seen["hints"] = _key_hints_text(modal)

    _run(body)
    assert "Segment" not in seen["hints"]


def test_next_segment_key_is_returned_in_result():
    result = {}

    async def body(app, pilot):
        modal = BodyProcessingModal(segment_count=2)
        await app.push_screen(modal, callback=lambda v: result.setdefault("v", v))
        await pilot.pause()
        await pilot.press("bracketright")
        await pilot.pause()
        modal._apply()
        await pilot.pause()

    _run(body)
    assert result["v"].segment_index == 1


class _DetailApp(App):
    """Minimal host app so FlowDetailWidget can compose its RichLogs.

    Registers the friTap theme so the modal's ``$fritap-*`` CSS resolves.
    """

    def __init__(self) -> None:
        super().__init__()
        from friTap.tui.themes import FRITAP_DARK
        self.register_theme(FRITAP_DARK)
        self.theme = "fritap-dark"

    def compose(self):
        yield FlowDetailWidget(id="detail")


def test_pressing_p_on_two_segment_flow_opens_modal():
    flow = _two_segment_flow()
    seen = {}

    async def body(app, pilot):
        widget = app.query_one("#detail", FlowDetailWidget)
        widget.show_flow(flow)
        widget.focus()
        await pilot.pause()
        await pilot.press("p")
        await pilot.pause()
        seen["screen"] = app.screen
        seen["hints"] = _key_hints_text(app.screen)

    _run(body, app_factory=_DetailApp)
    assert isinstance(seen["screen"], BodyProcessingModal)
    assert "[/]: Segment" in seen["hints"]


# ---------------------------------------------------------------------------
# 4. T8 modal keyboard flow
# ---------------------------------------------------------------------------

def _modal_result(keys, current=None, focus_id=None):
    result = {}

    async def body(app, pilot):
        modal = BodyProcessingModal(current=current)
        await app.push_screen(modal, callback=lambda v: result.setdefault("v", v))
        await pilot.pause()
        if focus_id:
            modal.query_one(focus_id).focus()
            await pilot.pause()
        for key in keys:
            await pilot.press(key)
            await pilot.pause()

    _run(body, app_factory=_DetailApp)
    return result.get("v")


def test_gzip_key_then_enter_applies_gzip():
    result = _modal_result(["1", "enter"])
    assert result is not None and result.decompression == "gzip"


def test_t_key_toggles_tl_decoder_and_enter_applies():
    result = _modal_result(["t", "enter"])
    assert result is not None and result.decoder == "tl"


def test_t_twice_toggles_tl_off():
    result = _modal_result(["t", "t", "enter"])
    assert result is not None and result.decoder is None


def test_enter_on_focused_active_option_applies_instead_of_toggling_off():
    result = _modal_result(["enter"], current=BodyProcessingResult(decompression="gzip"),
                           focus_id="#opt-gzip")
    assert result is not None and result.decompression == "gzip"


def test_enter_on_focused_inactive_option_toggles_it_on():
    seen = {}

    async def body(app, pilot):
        modal = BodyProcessingModal()
        await app.push_screen(modal)
        await pilot.pause()
        modal.query_one("#opt-deflate").focus()
        await pilot.press("enter")
        await pilot.pause()
        seen["decompression"] = modal._decompression
        seen["screen"] = app.screen

    _run(body, app_factory=_DetailApp)
    assert seen["decompression"] == "deflate"
    assert isinstance(seen["screen"], BodyProcessingModal)


def test_key_hints_mention_tl_toggle():
    seen = {}

    async def body(app, pilot):
        modal = BodyProcessingModal()
        await app.push_screen(modal)
        await pilot.pause()
        seen["hints"] = _key_hints_text(modal)
        seen["label"] = str(modal.query_one("#opt-tl").label)

    _run(body, app_factory=_DetailApp)
    assert "1-9/t: Toggle" in seen["hints"]
    assert "[t] TL decode (MTProto/Telegram)" in seen["label"]


def test_processing_result_keeps_response_tab_and_rerenders_it(monkeypatch):
    """Applying processing must not auto-jump to the Message tab (hid the pane)."""
    from friTap.flow.models import FlowChunk
    from friTap.tui.widgets import flow_detail
    # Real MTProto flows carry messages, so show_flow auto-selects Message.
    monkeypatch.setattr(flow_detail, "_flow_has_messages", lambda _flow: True)
    body = rpc_result(5, b"") + gzip.compress(msgs_ack(9))
    flow = _tl_flow(read_body=body)
    flow.chunks = [FlowChunk(direction="read", data=body, timestamp=1.0)]
    seen = {}

    async def run(app, pilot):
        widget = app.query_one("#detail", FlowDetailWidget)
        widget.show_flow(flow)
        widget._tabs.active = "tab-response"
        await pilot.pause()
        widget._on_body_processing_result(BodyProcessingResult(decompression="gzip"))
        await pilot.pause()
        seen["tab"] = widget._tabs.active
        seen["text"] = "\n".join(s.text for s in widget._response_log.lines)

    _run(run, app_factory=_DetailApp)
    assert seen["tab"] == "tab-response"
    assert seen["text"].startswith("⚠ Processing: gzip member at offset")
