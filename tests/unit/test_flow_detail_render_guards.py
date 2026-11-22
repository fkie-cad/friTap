#!/usr/bin/env python3

"""FlowDetail render guards for third-party / tap-derived content.

RichLog defers writes to a pane whose size is not yet known (a hidden pane's
first activation) and renders them later in ``on_resize`` -- outside
``_render_tab_safely``. These tests drive that deferred path through real
pilots and check it cannot crash the app, plus the extension decoder line cap.
"""

from __future__ import annotations

import asyncio
import itertools

import pytest

pytest.importorskip("textual")

from rich.measure import Measurement  # noqa: E402

from friTap.extensions import (  # noqa: E402
    BodyDecoderSpec,
    DetailTabSpec,
    register_body_decoder,
    register_detail_tab,
)
from friTap.flow.models import FlowChunk  # noqa: E402
from friTap.parsers.base import ParseResult  # noqa: E402
from friTap.tui.widgets import flow_detail as fd  # noqa: E402
from friTap.tui.widgets.flow_detail import FlowDetailWidget  # noqa: E402
from friTap.tui.widgets.ohttp_tab import OhttpTabProvider  # noqa: E402
from tests.unit._ext_helpers import decoder_widget as _decoder_widget  # noqa: E402
from tests.unit._render_helpers import RenderingFakeLog  # noqa: E402
from tests.unit.test_flow_detail_optional_tabs import (  # noqa: E402
    OHTTP_PANE,
    _DetailApp,
    _is_visible,
    _log_text,
    _plain_flow,
)


class _RaisingConsole:
    def __rich_console__(self, console, options):
        raise RuntimeError("boom [/oops]")
        yield  # pragma: no cover


class _RaisingMeasure:
    def __rich_console__(self, console, options):
        yield "measure-guarded content"

    def __rich_measure__(self, console, options):
        raise RuntimeError("boom from measure")


class _NotRenderable:
    def __repr__(self) -> str:
        return "NotRenderable<42>"


async def _pause(pilot, times: int = 4) -> None:
    for _ in range(times):
        await pilot.pause()


def _activate_first_time(content) -> tuple[str, bool]:
    """Show *content* in a never-activated extension pane; return (log text, app ok)."""
    register_detail_tab(DetailTabSpec(id="bad", label="Bad", render=lambda flow: content))
    result: dict = {}

    async def _run() -> None:
        app = _DetailApp()
        async with app.run_test() as pilot:
            widget = app.query_one("#detail", FlowDetailWidget)
            await pilot.pause()
            widget.show_flow(_plain_flow())
            await pilot.pause()
            log = widget._ext_logs["tab-ext-bad"]
            assert not log._size_known  # the deferred-write path is exercised
            widget._tabs.active = "tab-ext-bad"  # like a user click
            await _pause(pilot)
            assert not log._deferred_renders  # the deferred write was rendered
            result["text"] = _log_text(log)
            result["ok"] = app._exception is None and app.is_running

    asyncio.run(_run())
    return result["text"], result["ok"]


def test_raising_render_on_first_activation_shows_error_without_crash():
    text, app_ok = _activate_first_time(_RaisingConsole())
    assert app_ok
    assert "Could not render extension tab" in text
    assert "boom [/oops]" in text  # literal, not parsed as markup


def test_raising_measure_on_first_activation_still_renders_without_crash(fritap_log_records):
    records = fritap_log_records(fd.__name__)
    text, app_ok = _activate_first_time(_RaisingMeasure())
    assert app_ok
    assert "measure-guarded content" in text  # only the width probe failed; content renders
    assert any("failed to render" in r.getMessage() for r in records)


def test_non_renderable_extension_content_is_pretty_printed():
    text, app_ok = _activate_first_time(_NotRenderable())
    assert app_ok
    assert "NotRenderable<42>" in text


def test_guarded_renderable_passes_through_working_content():
    log = RenderingFakeLog()
    log.write(fd._GuardedRenderable("[bold]hi[/bold]", "x"))
    assert log.lines == ["hi"]  # str inner keeps Rich's normal handling


def test_guarded_renderable_measure_falls_back_on_error():
    from rich.console import Console

    console = Console(width=80)
    guarded = fd._GuardedRenderable(_RaisingMeasure(), "x")
    measurement = Measurement.get(console, console.options, guarded)
    assert measurement.maximum > 0


# ------------------------------------------------------------------ OHTTP


_MARKUP_HEADERS = {"X-Evil": "[bold red]boom[/]", "[/x]": "[/]"}


def _crafted_ohttp_response() -> ParseResult:
    return ParseResult(protocol="HTTP/1.1", status_code="[/oops]", status_text="[link=x]t",
                       headers=dict(_MARKUP_HEADERS), body=b"[/body]", is_request=False)


def test_ohttp_markup_escapes_every_tap_derived_value():
    flow = _plain_flow()
    flow.ohttp_inner_response = _crafted_ohttp_response()
    log = RenderingFakeLog()
    log.write(OhttpTabProvider().render(flow))
    text = "\n".join(log.lines)
    for literal in ("[/oops] [link=x]t", "X-Evil: [bold red]boom[/]", "[/x]: [/]", "[/body]"):
        assert literal in text


def test_replay_crafted_ohttp_tap_renders_literally(tmp_path):
    """``fritap -r`` on a .tap whose OHTTP response holds markup must not crash."""
    from friTap.tui.app import FriTapApp

    from tests.unit._tui_flow_helpers import make_flow, write_tap

    flow = make_flow("flow-ohttp")
    flow.chunks.append(FlowChunk(data=b"POST / HTTP/1.1\r\n\r\n", direction="write", timestamp=1.0))
    flow.ohttp_inner_response = _crafted_ohttp_response()
    tap_path = tmp_path / "crafted.tap"
    write_tap(tap_path, [flow])

    async def _go() -> None:
        app = FriTapApp(replay_file=str(tap_path))
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("enter")
            await pilot.pause()
            detail = app.screen.query_one("#flow-detail", FlowDetailWidget)
            assert detail._current_flow.ohttp_inner_response.status_code == "[/oops]"
            assert _is_visible(detail, OHTTP_PANE)
            detail._tabs.active = OHTTP_PANE
            await _pause(pilot)
            text = _log_text(detail._ohttp_log)
            assert app._exception is None and app.is_running
            assert "[/oops]" in text and "[bold red]boom[/]" in text
            assert "Could not render" not in text

    asyncio.run(_go())


def test_ohttp_markup_error_is_contained_by_render_tab_safely(monkeypatch):
    """Even unescaped markup from the provider becomes an error line, not a crash."""
    monkeypatch.setattr(OhttpTabProvider, "render", lambda self, flow: "[/oops]")

    async def _run() -> None:
        app = _DetailApp()
        async with app.run_test() as pilot:
            widget = app.query_one("#detail", FlowDetailWidget)
            await pilot.pause()
            flow = _plain_flow()
            flow.ohttp_inner_response = _crafted_ohttp_response()
            widget.show_flow(flow)
            await pilot.pause()
            widget._tabs.active = OHTTP_PANE
            await _pause(pilot)
            assert app._exception is None and app.is_running
            assert "Could not render this view" in _log_text(widget._ohttp_log)

    asyncio.run(_run())


# ------------------------------------------------------- decoder line cap


def _register_decoder(decode) -> None:
    register_body_decoder(BodyDecoderSpec(name="big", label="Big", decode=decode))


def test_decoder_output_is_capped_with_truncation_note(monkeypatch):
    monkeypatch.setattr(fd, "_EXTENSION_DECODER_MAX_LINES", 3)
    _register_decoder(lambda body, headers: [f"l{i} [x]" for i in range(10)])
    log = RenderingFakeLog()
    _decoder_widget("big")._render_body(log, b"abc", {})
    assert log.lines[:3] == ["l0 [x]", "l1 [x]", "l2 [x]"]
    assert log.lines[3] == "… truncated after 3 lines"
    assert "l3 [x]" not in log.lines


def test_decoder_output_at_cap_has_no_truncation_note(monkeypatch):
    monkeypatch.setattr(fd, "_EXTENSION_DECODER_MAX_LINES", 3)
    _register_decoder(lambda body, headers: ["a", "b", "c"])
    log = RenderingFakeLog()
    _decoder_widget("big")._render_body(log, b"abc", {})
    assert not any("truncated" in line for line in log.lines)


def test_endless_decoder_iterable_does_not_hang():
    _register_decoder(lambda body, headers: (str(i) for i in itertools.count()))
    log = RenderingFakeLog()
    _decoder_widget("big")._render_body(log, b"abc", {})
    limit = fd._EXTENSION_DECODER_MAX_LINES
    assert len(log.lines) >= limit + 1
    assert log.lines[limit] == f"… truncated after {limit:,} lines"
