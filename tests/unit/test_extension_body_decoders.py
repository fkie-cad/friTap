#!/usr/bin/env python3

"""Extension body decoders (BodyDecoderSpec) in the Body Processing modal and
the FlowDetail dispatch, plus literal rendering of str extension tab output."""

from __future__ import annotations

import asyncio

import pytest

pytest.importorskip("textual")

from textual.app import App  # noqa: E402
from textual.widgets import Button  # noqa: E402

from friTap.extensions import (  # noqa: E402
    BodyDecoderSpec,
    DetailTabSpec,
    register_body_decoder,
    register_detail_tab,
)
from friTap.tui.modals import body_processing_modal as bpm  # noqa: E402
from friTap.tui.modals.body_processing_modal import (  # noqa: E402
    BodyProcessingModal,
    BodyProcessingResult,
)
from friTap.tui.theme_install import install_theme  # noqa: E402
from tests.unit._ext_helpers import decoder_widget as _widget  # noqa: E402
from tests.unit._render_helpers import RenderingFakeLog as _FakeLog  # noqa: E402
from tests.unit.test_flow_detail_optional_tabs import (  # noqa: E402
    _log_text,
    _plain_flow,
    _run_with_widget,
    _show,
)


def _register(name="demo", label="Demo [x]", decode=None):
    register_body_decoder(BodyDecoderSpec(
        name=name, label=label, decode=decode or (lambda body, headers: ["ok"])))


def _builtin_keys() -> set:
    return {o[0] for o in bpm._DECOMPRESS_OPTIONS + bpm._DECODER_OPTIONS}


# ------------------------------------------------------------------ options


def test_no_decoders_registered_gives_no_extension_options():
    assert bpm._extension_decoder_options() == []


def test_extension_option_gets_free_shortcut_after_builtins():
    _register("a"), _register("b")
    options = bpm._extension_decoder_options()
    assert [o[1] for o in options] == ["a", "b"]
    keys = [o[0] for o in options]
    assert all(k and k not in _builtin_keys() | {"0"} for k in keys)
    assert len(set(keys)) == 2


def test_no_shortcut_when_no_key_is_free(monkeypatch):
    monkeypatch.setattr(bpm.string, "ascii_lowercase", "t")
    _register("a")
    assert bpm._extension_decoder_options()[0][0] is None


def test_builtin_name_collision_is_skipped():
    _register("json")
    assert bpm._extension_decoder_options() == []


def test_decompression_and_reset_name_collisions_are_skipped():
    for name in ("gzip", "zstd", "reset"):
        _register(name)
    assert bpm._extension_decoder_options() == []


def test_duplicate_extension_name_is_skipped():
    _register("dup"), _register("dup")
    assert [o[1] for o in bpm._extension_decoder_options()] == ["dup"]


def test_sanitised_clashing_names_get_distinct_ids_and_right_action():
    _register("a.b"), _register("a_b")
    result: list = []

    async def _run() -> None:
        class _App(App):
            def __init__(self):
                super().__init__()
                install_theme(self)

        app = _App()
        async with app.run_test() as pilot:
            app.push_screen(BodyProcessingModal(), callback=result.append)
            await pilot.pause()
            ids = [b.id for b in app.screen.query(Button)]
            assert "opt-ext-0" in ids and "opt-ext-1" in ids
            app.screen.query_one("#opt-ext-1", Button).press()
            await pilot.pause()
            app.screen.query_one("#btn-apply", Button).press()
            await pilot.pause()

    asyncio.run(_run())
    assert result and result[0].decoder == "a_b"


def _modal_buttons(registered: bool) -> list:
    if registered:
        _register("demo")
    out: list = []

    async def _run() -> None:
        class _App(App):
            def __init__(self):
                super().__init__()
                install_theme(self)

        app = _App()
        async with app.run_test() as pilot:
            app.push_screen(BodyProcessingModal())
            await pilot.pause()
            out.extend((str(b.label), b.id) for b in app.screen.query(Button))

    asyncio.run(_run())
    return out


def test_modal_lists_registered_decoder_after_builtins_escaped():
    buttons = _modal_buttons(registered=True)
    ids = [i for _, i in buttons]
    assert ids.index("opt-ext-0") > ids.index("opt-tl")
    label = {button_id: text for text, button_id in buttons}["opt-ext-0"]
    assert "Demo [x]" in label


def test_modal_unchanged_when_nothing_registered():
    ids = [i for _, i in _modal_buttons(registered=False)]
    assert ids == [
        "opt-gzip", "opt-deflate", "opt-brotli", "opt-zstd", "opt-json",
        "opt-protobuf", "opt-base64", "opt-hex", "opt-raw_utf8", "opt-tl",
        "opt-reset", "btn-apply", "btn-cancel",
    ]


def test_modal_shortcut_key_selects_extension_decoder():
    _register("demo")
    key = bpm._extension_decoder_options()[0][0]
    result: list = []

    async def _run() -> None:
        class _App(App):
            def __init__(self):
                super().__init__()
                install_theme(self)

        app = _App()
        async with app.run_test() as pilot:
            app.push_screen(BodyProcessingModal(), callback=result.append)
            await pilot.pause()
            await pilot.press(key)
            await pilot.press("enter")
            await pilot.pause()

    asyncio.run(_run())
    assert result and result[0].decoder == "demo"


# ----------------------------------------------------------------- dispatch


def test_dispatch_displays_decoder_lines_as_plain_text():
    seen = {}

    def decode(body, headers):
        seen["args"] = (body, headers)
        return ["line [bold]x[/bold]", "[", "two"]

    _register("demo", decode=decode)
    log = _FakeLog()
    _widget("demo")._render_body(log, b"abc", {"h": "v"})
    assert seen["args"] == (b"abc", {"h": "v"})
    assert log.lines[:3] == ["line [bold]x[/bold]", "[", "two"]


def test_raising_decoder_shows_error_line_without_crash():
    def decode(body, headers):
        raise ValueError("bad [/] tag")

    _register("demo", decode=decode)
    log = _FakeLog()
    _widget("demo")._render_body(log, b"abc", {})
    text = "\n".join(log.lines)
    assert "failed" in text and "ValueError: bad [/] tag" in text


def test_unknown_decoder_falls_through_to_standard_rendering():
    log = _FakeLog()
    _widget("nope")._render_body(log, b"plain text body", {})
    assert "plain text body" in "\n".join(log.lines)


# ------------------------------------------------------ str tab is literal


def test_str_extension_tab_renders_literally():
    register_detail_tab(DetailTabSpec(
        id="lit", label="Lit", render=lambda flow: "[bold]x[/bold] and ["))

    async def body(widget, pilot):
        flow = _plain_flow()
        _show(widget, flow, "tab-ext-lit")
        await pilot.pause()
        assert "[bold]x[/bold] and [" in _log_text(widget._ext_logs["tab-ext-lit"])

    _run_with_widget(body)


def test_bracketed_extension_label_and_active_line_render_literally():
    """``X[RC4]y`` must survive Textual markup in the button and the active line."""
    _register("x[RC4]y", label="X[RC4]y")
    seen: dict = {}

    async def _run() -> None:
        class _App(App):
            def __init__(self):
                super().__init__()
                install_theme(self)

        app = _App()
        async with app.run_test() as pilot:
            current = BodyProcessingResult(decoder="x[RC4]y")
            app.push_screen(BodyProcessingModal(current=current))
            await pilot.pause()
            seen["button"] = app.screen.query_one("#opt-ext-0", Button).label.plain
            seen["active"] = str(app.screen.query_one("#active-line").render())

    asyncio.run(_run())
    assert seen["button"].endswith("X[RC4]y")
    assert "Active: x[RC4]y" in seen["active"]
