"""TUI protobuf views are thin wrappers around the shared ``decode_protobuf_view``.

Covers: schema / gRPC / backend settings reach the decoder (flow detail and
explorer used to ignore them), decoded text is escaped (``[packed]`` vanished
and ``[/x]`` raised ``MarkupError``), the pipeline label, and the incomplete
HTTP/2 note (the preface was read as frame type 32).
"""

from __future__ import annotations

import asyncio
import struct

import pytest
from rich.text import Text

import friTap.parsers.protobuf as protobuf_pkg
from friTap.parsers.http2_constants import HTTP2_PREFACE
from friTap.parsers.protobuf import ProtobufView, decode_protobuf_view
from friTap.tui.modals.body_processing_modal import BodyProcessingResult, ProtobufConfig
from friTap.tui.widgets.protobuf_render import protobuf_view_lines
from tests.unit._render_helpers import RenderingFakeLog

PACKED = b"\x0a\x03\x81\x01\x02"            # 1: [packed] [129, 2]
CLOSING_TAG = b"\x12\x04[/x]"               # 2: "[/x]"
BODY = PACKED + CLOSING_TAG
EXPECTED = ["1: [packed] [129, 2]", '2: "[/x]"']


def frame(payload: bytes) -> bytes:
    return b"\x00" + struct.pack(">I", len(payload)) + payload


def plain(markup_lines: list[str]) -> list[str]:
    return [Text.from_markup(line).plain for line in markup_lines]


def rendered(log) -> list[str]:
    """Visible lines of a fake log, splitting multi-line writes."""
    return "\n".join(log.lines).splitlines()


def _color(role: str) -> str:
    return "red"


# ── protobuf_view_lines ──────────────────────────────────────────


def test_view_lines_render_brackets_literally():
    lines = protobuf_view_lines(decode_protobuf_view(BODY), color=_color)
    assert plain(lines) == EXPECTED


def test_view_lines_style_notes_headers_and_errors():
    view = decode_protobuf_view(frame(BODY) + b"\x07" * 5, grpc_mode=True)
    rendered = plain(protobuf_view_lines(view, color=_color))
    assert rendered[0] == "⚠ invalid gRPC compressed flag 7 at offset 16"
    assert rendered[1] == "gRPC message 1 (11 bytes)"
    assert rendered[2:] == EXPECTED


def test_view_lines_escape_trailing_backslash_and_notes():
    view = ProtobufView(notes=["path C:\\[bold]\\"], error="bad [/] tag\\")
    assert plain(protobuf_view_lines(view, color=_color)) == [
        "⚠ path C:\\[bold]\\", "bad [/] tag\\",
    ]


def test_view_lines_max_lines_adds_overflow_line():
    view = decode_protobuf_view(BODY)
    assert plain(protobuf_view_lines(view, 1, color=_color)) == [EXPECTED[0], "… 1 more line(s)"]


# ── ProtobufConfig.view_options ──────────────────────────────────


def test_view_options_schema_only_in_schema_mode():
    cfg = ProtobufConfig(schema_less=True, schema_path="/a.proto", message_type="a.B")
    assert cfg.view_options() == {
        "grpc_mode": None, "schema_path": "", "message_type": "", "backend": "wire",
    }
    cfg.schema_less = False
    cfg.grpc_mode = True
    cfg.backend = "blackbox"
    assert cfg.view_options() == {
        "grpc_mode": True, "schema_path": "/a.proto", "message_type": "a.B",
        "backend": "blackbox",
    }


# ── FlowDetailWidget ─────────────────────────────────────────────

pytest.importorskip("textual")

from friTap.tui.widgets.flow_detail import FlowDetailWidget  # noqa: E402


def _widget(protobuf_config=None) -> FlowDetailWidget:
    widget = FlowDetailWidget.__new__(FlowDetailWidget)
    widget._active_processing = BodyProcessingResult(
        decoder="protobuf", protobuf_config=protobuf_config,
    )
    return widget


@pytest.fixture
def spy_decoder(monkeypatch):
    calls = []

    def spy(data, **kwargs):
        calls.append(kwargs)
        return decode_protobuf_view(data, **kwargs)

    monkeypatch.setattr(protobuf_pkg, "decode_protobuf_view", spy)
    return calls


def test_flow_detail_passes_schema_grpc_and_encoding(spy_decoder):
    cfg = ProtobufConfig(schema_less=False, schema_path="/s.proto", message_type="p.M",
                         grpc_mode=True)
    headers = {"Content-Type": "application/grpc", "grpc-encoding": "gzip"}
    _widget(cfg)._decode_protobuf(RenderingFakeLog(), frame(BODY), headers)
    assert spy_decoder == [{
        "content_type": "application/grpc", "grpc_encoding": "gzip",
        "grpc_mode": True, "schema_path": "/s.proto", "message_type": "p.M",
        "backend": "wire",
    }]


def test_flow_detail_without_config_uses_defaults(spy_decoder):
    _widget(None)._decode_protobuf(RenderingFakeLog(), BODY, {})
    assert spy_decoder[0]["grpc_mode"] is None and spy_decoder[0]["schema_path"] == ""


def test_flow_detail_renders_brackets_literally():
    log = RenderingFakeLog()
    _widget(ProtobufConfig())._decode_protobuf(log, BODY, {})
    assert rendered(log) == EXPECTED


def test_flow_detail_splits_grpc_from_content_type():
    log = RenderingFakeLog()
    _widget(ProtobufConfig())._decode_protobuf(
        log, frame(BODY), {"content-type": "application/grpc"})
    assert rendered(log)[0] == "gRPC message 1 (11 bytes)"
    assert rendered(log)[1:] == EXPECTED


def test_flow_detail_hexdump_when_nothing_decodes():
    log = RenderingFakeLog()
    _widget(ProtobufConfig())._decode_protobuf(log, b"\x00\xff\xff", {})
    assert "invalid field number 0" in rendered(log)[0]
    assert any("00 ff ff" in line for line in rendered(log)[1:])


@pytest.mark.parametrize("cfg, label", [
    (ProtobufConfig(schema_less=True, schema_path="/left/over.proto"), "protobuf (raw)"),
    (ProtobufConfig(schema_less=False, schema_path="/s.proto"), "protobuf (schema)"),
    (ProtobufConfig(schema_less=False, schema_path=""), "protobuf (raw)"),
])
def test_describe_pipeline_label(cfg, label):
    assert _widget(cfg)._describe_pipeline() == label


def test_incomplete_h2_note_skips_preface():
    log = RenderingFakeLog()
    settings = (6).to_bytes(3, "big") + b"\x04\x00" + b"\x00" * 4 + b"\x00" * 6
    _widget()._render_incomplete_h2_note(log, HTTP2_PREFACE + settings)
    assert log.lines == ["  Frame: SETTINGS (stream 0, 6 bytes)"]


def test_incomplete_h2_note_truncated_frame():
    log = RenderingFakeLog()
    data = (100).to_bytes(3, "big") + b"\x00\x00" + (3).to_bytes(4, "big") + b"abc"
    _widget()._render_incomplete_h2_note(log, data)
    assert log.lines == ["  Frame: DATA (stream 3, expected 100 bytes, got 3)"]


def test_incomplete_h2_note_silent_for_non_frames():
    log = RenderingFakeLog()
    _widget()._render_incomplete_h2_note(log, HTTP2_PREFACE[:20])
    _widget()._render_incomplete_h2_note(log, b"\x00\x00\x00\x20\x00\x00\x00\x00\x00")
    assert log.lines == []


# ── ExplorerModal ────────────────────────────────────────────────

from friTap.tui.modals.explorer_modal import ExplorerModal  # noqa: E402


def _explorer_decode(data: bytes, cfg) -> str:
    modal = ExplorerModal.__new__(ExplorerModal)
    return modal._decode_protobuf(data, BodyProcessingResult(decoder="protobuf",
                                                             protobuf_config=cfg))


def test_explorer_output_is_escaped_markup():
    assert Text.from_markup(_explorer_decode(BODY, None)).plain.splitlines() == EXPECTED


def test_explorer_honours_schema_unless_schema_less(spy_decoder):
    cfg = ProtobufConfig(schema_less=False, schema_path="/s.proto", message_type="p.M")
    _explorer_decode(BODY, cfg)
    cfg.schema_less = True
    _explorer_decode(BODY, cfg)
    assert [c["schema_path"] for c in spy_decoder] == ["/s.proto", ""]


def test_explorer_validates_grpc_framing_instead_of_stripping():
    out = Text.from_markup(_explorer_decode(BODY, ProtobufConfig(grpc_mode=True))).plain
    assert "not valid gRPC framing" in out and '2: "[/x]"' in out


# ── ProtobufModal (Textual pilot) ────────────────────────────────

from friTap.tui.app import FriTapApp  # noqa: E402
from friTap.tui.modals.body_processing_modal import ProtobufModal  # noqa: E402


def _preview_text(modal) -> list[str]:
    from textual.widgets import RichLog
    log = modal.query_one("#proto-preview", RichLog)
    return ["".join(seg.text for seg in strip).rstrip() for strip in log.lines]


def _run_modal(cfg: ProtobufConfig, body: bytes, interact=None) -> dict:
    seen: dict = {}

    async def _main() -> None:
        app = FriTapApp()
        async with app.run_test(size=(120, 50)) as pilot:
            modal = ProtobufModal(current=cfg, body_preview=body)
            await app.push_screen(modal, callback=lambda v: seen.setdefault("result", v))
            await pilot.pause()
            seen["preview"] = _preview_text(modal)
            from textual.widgets import Switch
            seen["backend_disabled"] = modal.query_one("#proto-backend-switch", Switch).disabled
            if interact is not None:
                await interact(modal, pilot)

    asyncio.run(_main())
    return seen


def test_modal_preview_renders_brackets_and_does_not_strip_blindly():
    seen = _run_modal(ProtobufConfig(grpc_mode=True), BODY)
    assert any("not valid gRPC framing" in line for line in seen["preview"])
    assert EXPECTED[0] in seen["preview"] and EXPECTED[1] in seen["preview"]


def test_modal_preview_caps_input():
    seen = _run_modal(ProtobufConfig(), BODY * 1000)
    assert any("preview limited to the first 4096" in line for line in seen["preview"])


def test_modal_backend_switch_disabled_without_blackbox(monkeypatch):
    import sys
    monkeypatch.setitem(sys.modules, "blackboxprotobuf", None)
    seen = _run_modal(ProtobufConfig(), BODY)
    assert seen["backend_disabled"] is True


def test_modal_returns_backend_in_result():
    async def apply(modal, pilot):
        modal._config.backend = "blackbox"
        modal.query_one("#btn-apply").press()
        await pilot.pause()

    seen = _run_modal(ProtobufConfig(), BODY, apply)
    assert seen["result"].backend == "blackbox"


def test_read_varint_wraps_wire_decoder():
    assert ProtobufModal._read_varint(b"\x96\x01", 0) == (150, 2)
    assert ProtobufModal._read_varint(b"\x96", 0) == (None, 0)


# ── Review follow-ups: perf cap, preview scroll, label, Content-Type, escaping ──


class _CountingLog(RenderingFakeLog):
    def __init__(self) -> None:
        super().__init__()
        self.writes = 0

    def write(self, item) -> None:
        self.writes += 1
        super().write(item)


def test_flow_detail_protobuf_is_one_capped_write():
    log = _CountingLog()
    many_fields = b"\x08\x01" * 5000                  # 5000 x "1: 1"
    _widget(ProtobufConfig())._decode_protobuf(log, many_fields, {})
    lines = rendered(log)
    assert log.writes == 1
    assert len(lines) == FlowDetailWidget._PROTOBUF_RENDER_MAX_LINES + 1
    assert lines[-1] == "… 1000 more line(s)"


def test_pipeline_label_reports_wire_fallback_when_schema_fails():
    cfg = ProtobufConfig(schema_less=False, schema_path="/does/not/exist.proto",
                         message_type="p.M")
    widget = _widget(cfg)
    assert widget._describe_pipeline() == "protobuf (schema)"   # before any decode
    widget._decode_protobuf(RenderingFakeLog(), BODY, {})
    assert widget._describe_pipeline() == "protobuf (raw)"


def test_rerender_active_tab_refreshes_header(monkeypatch):
    widget = _widget(ProtobufConfig())
    widget._current_flow = object()
    widget._last_protobuf_mode = "schema"
    calls = []

    class _Tabs:
        active = "request"

    widget._tabs = _Tabs()
    monkeypatch.setattr(widget, "_render_tab",
                        lambda flow, tab: calls.append(("render", widget._last_protobuf_mode)),
                        raising=False)
    monkeypatch.setattr(widget, "_update_header", lambda flow: calls.append(("header",)),
                        raising=False)
    widget._rerender_active_tab()
    assert calls == [("render", None), ("header",)]


def test_active_pane_content_type(monkeypatch):
    class _Msg:
        def __init__(self, ct):
            self.headers = {"Content-Type": ct}

    class _Flow:
        request = _Msg("application/grpc+proto")
        response = _Msg("application/json")

    widget = _widget()
    widget._current_flow = _Flow()
    monkeypatch.setattr(widget, "_active_pane", lambda: "request", raising=False)
    assert widget._active_pane_content_type() == "application/grpc+proto"
    monkeypatch.setattr(widget, "_active_pane", lambda: "response", raising=False)
    assert widget._active_pane_content_type() == "application/json"
    widget._current_flow = None
    assert widget._active_pane_content_type() == ""


def test_explorer_detects_grpc_from_content_type():
    modal = ExplorerModal.__new__(ExplorerModal)
    modal._headers = {"Content-Type": "application/grpc"}
    out = modal._decode_protobuf(frame(BODY), BodyProcessingResult(decoder="protobuf"))
    assert Text.from_markup(out).plain.splitlines() == ["gRPC message 1 (11 bytes)", *EXPECTED]


@pytest.mark.parametrize("decoder, data", [
    ("json", b'{"a": "[/x]"}'),
    ("json", b"not json [/x]"),
    ("raw_utf8", b"[/x] [bold]"),
    ("base64", b"Wy94XQ=="),                    # "[/x]"
    ("", b"[/x]"),
    ("", b"\xff[/x]"),
])
def test_explorer_plain_decoders_escape_markup(decoder, data):
    modal = ExplorerModal.__new__(ExplorerModal)
    out = modal._apply_decoder(data, decoder, BodyProcessingResult(decoder=decoder or None))
    assert "[/x]" in Text.from_markup(out).plain


@pytest.mark.parametrize("method, body", [
    ("_decode_json", b'{"a": "[/x]"}'),
    ("_decode_json", b"bad [/x]"),
    ("_decode_raw_utf8", b"[/x]"),
    ("_decode_base64", b"Wy94XQ=="),
])
def test_flow_detail_decoders_escape_markup(method, body):
    log = RenderingFakeLog()
    getattr(_widget(), method)(log, body, {})
    assert "[/x]" in "\n".join(log.lines)


def test_render_body_standard_json_escapes_markup():
    log = RenderingFakeLog()
    _widget()._render_body_standard(log, b'{"a": "[/x]"}', {"content-type": "application/json"})
    assert '"a": "[/x]"' in "\n".join(log.lines)


def test_render_control_frame_escapes_markup():
    class _Req:
        url = "h2://control"
        method = "SETTINGS [/x]"
        headers = {"[/k]": "[/v]"}

    log = RenderingFakeLog()
    _widget()._render_control_frame(log, _Req())
    text = "\n".join(log.lines)
    assert "Frame: SETTINGS [/x]" in text and "[/k]:  [/v]" in text


def test_modal_preview_detects_grpc_from_content_type_and_stays_at_top():
    async def check(modal, pilot):
        from textual.widgets import RichLog
        log = modal.query_one("#proto-preview", RichLog)
        assert log.auto_scroll is False
        assert log.scroll_y == 0

    seen: dict = {}

    async def _main() -> None:
        app = FriTapApp()
        async with app.run_test(size=(120, 50)) as pilot:
            modal = ProtobufModal(current=ProtobufConfig(), body_preview=frame(BODY * 300),
                                  content_type="application/grpc")
            await app.push_screen(modal)
            await pilot.pause()
            seen["preview"] = _preview_text(modal)
            await check(modal, pilot)

    asyncio.run(_main())
    assert seen["preview"][0].startswith("gRPC message 1")


def test_body_processing_modal_forwards_content_type_to_protobuf_modal():
    from friTap.tui.modals.body_processing_modal import BodyProcessingModal
    seen: dict = {}

    async def _main() -> None:
        app = FriTapApp()
        async with app.run_test(size=(120, 50)) as pilot:
            await app.push_screen(BodyProcessingModal(
                body_preview=frame(BODY), content_type="application/grpc"))
            await pilot.pause()
            app.screen._open_protobuf_modal()
            await pilot.pause()
            seen["screen"] = app.screen
            seen["preview"] = _preview_text(app.screen)

    asyncio.run(_main())
    assert isinstance(seen["screen"], ProtobufModal)
    assert seen["screen"]._content_type == "application/grpc"
    assert seen["preview"][0] == "gRPC message 1 (11 bytes)"


def test_grpc_switch_label_explains_auto_detection():
    seen: dict = {}

    async def _main() -> None:
        from textual.widgets import Static
        app = FriTapApp()
        async with app.run_test(size=(120, 50)) as pilot:
            modal = ProtobufModal(current=ProtobufConfig(), body_preview=BODY)
            await app.push_screen(modal)
            await pilot.pause()
            label = modal.query_one("#proto-grpc-label", Static)
            seen["label"] = str(label.render())

    asyncio.run(_main())
    assert "auto-detected from Content-Type when off" in seen["label"]
