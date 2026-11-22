#!/usr/bin/env python3

"""FlowDetail optional panes: extension detail tabs (DetailTabSpec) and the
built-in OHTTP inner pane. Both are composed up front and shown/hidden per
flow (no add_pane/remove_pane)."""

import asyncio

import pytest

pytest.importorskip("textual")

from textual.app import App  # noqa: E402

from friTap.extensions import (  # noqa: E402
    DetailTabSpec,
    register_detail_tab,
)
from friTap.flow.models import Flow, FlowChunk, FlowState  # noqa: E402
from friTap.parsers.base import ParseResult  # noqa: E402
from friTap.tui.widgets import flow_detail as fd  # noqa: E402
from friTap.tui.widgets.flow_detail import FlowDetailWidget  # noqa: E402

OHTTP_PANE = "tab-ohttp"


def _plain_flow(flow_id: str = "plain") -> Flow:
    flow = Flow(flow_id=flow_id, state=FlowState.COMPLETE)
    flow.chunks.append(FlowChunk(data=b"GET / HTTP/1.1\r\n\r\n", direction="write", timestamp=1.0))
    return flow


def _ohttp_flow() -> Flow:
    flow = _plain_flow("ohttp")
    flow.ohttp_inner_request = ParseResult(
        protocol="HTTP/1.1", method="POST", url="/inner", host="inner.example",
        headers={"X-Inner": "yes"}, body=b"inner-body")
    return flow


class _DetailApp(App):
    def compose(self):
        yield FlowDetailWidget(id="detail")


def _run_with_widget(body) -> None:
    async def _run() -> None:
        app = _DetailApp()
        async with app.run_test() as pilot:
            widget = app.query_one("#detail", FlowDetailWidget)
            await pilot.pause()
            await body(widget, pilot)

    asyncio.run(_run())


def _is_visible(widget: FlowDetailWidget, pane_id: str) -> bool:
    return not widget._tabs.get_tab(pane_id).has_class("-hidden")


def _log_text(log) -> str:
    deferred = getattr(log, "_deferred_renders", None)
    if deferred:
        return "\n".join(str(getattr(d, "content", d)) for d in deferred)
    return "".join("".join(seg.text for seg in line._segments) + "\n" for line in log.lines)


def _show(widget, flow, pane_id=None):
    widget.show_flow(flow)
    if pane_id is not None:
        widget._tabs.active = pane_id
        widget._render_tab_safely(flow, pane_id)


# ---------------------------------------------------------------- unit helpers


def test_extension_pane_id_is_sanitized_prefixed_and_unique():
    used: set = set()
    assert fd._extension_pane_id("my.tab id", used) == "tab-ext-my_tab_id"
    assert fd._extension_pane_id("my tab.id", used) == "tab-ext-my_tab_id-2"
    assert fd._extension_pane_id("", used) == "tab-ext-tab"


def test_flow_has_ohttp():
    assert fd._flow_has_ohttp(_ohttp_flow())
    assert not fd._flow_has_ohttp(_plain_flow())


# ---------------------------------------------------------------- extension tabs


def _register_demo_tab(render):
    register_detail_tab(DetailTabSpec(id="demo.tab", label="Demo [x]", render=render))
    return "tab-ext-demo_tab"


def test_extension_tab_shown_when_render_returns_content():
    pane_id = _register_demo_tab(
        lambda flow: f"extension says {flow.flow_id}" if flow.flow_id == "plain" else None)

    async def body(widget, pilot):
        assert not _is_visible(widget, pane_id)  # hidden before any flow
        _show(widget, _plain_flow(), pane_id)
        await pilot.pause()
        assert _is_visible(widget, pane_id)
        assert "Demo [x]" in str(widget._tabs.get_tab(pane_id).label)  # label escaped
        assert "extension says plain" in _log_text(widget._ext_logs[pane_id])

    _run_with_widget(body)


def test_extension_tab_hidden_when_render_returns_none_and_falls_back():
    pane_id = _register_demo_tab(
        lambda flow: "content" if flow.flow_id == "plain" else None)

    async def body(widget, pilot):
        flow = _plain_flow()
        _show(widget, flow, pane_id)
        await pilot.pause()
        assert widget._tabs.active == pane_id
        # Same flow refreshed, now without content -> hidden, active falls back.
        flow.flow_id = "other"
        widget._current_flow = flow
        widget.refresh_flow(flow)
        await pilot.pause()
        assert not _is_visible(widget, pane_id)
        assert widget._tabs.active == "tab-request"

    _run_with_widget(body)


def test_raising_extension_render_hides_tab_without_crashing(fritap_log_records):
    records = fritap_log_records(fd.__name__)

    def boom(flow):
        raise RuntimeError("extension bug")

    pane_id = _register_demo_tab(boom)

    async def body(widget, pilot):
        _show(widget, _plain_flow())
        await pilot.pause()
        assert not _is_visible(widget, pane_id)
        assert widget._tabs.active == "tab-request"
        assert "GET / HTTP/1.1" in _log_text(widget._request_log)
        assert any("render failed" in r.getMessage() for r in records)

    _run_with_widget(body)


def test_no_extensions_composes_no_extension_panes():
    async def body(widget, pilot):
        assert widget._ext_tabs == []
        assert not any(p.id.startswith("tab-ext-") for p in widget.query("TabPane"))

    _run_with_widget(body)


# ---------------------------------------------------------------- OHTTP pane


def test_ohttp_pane_shown_for_ohttp_flow_and_renders_inner_request():
    async def body(widget, pilot):
        _show(widget, _ohttp_flow(), OHTTP_PANE)
        await pilot.pause()
        assert _is_visible(widget, OHTTP_PANE)
        text = _log_text(widget._ohttp_log)
        assert "Inner Request (decrypted bhttp)" in text
        assert "inner-body" in text

    _run_with_widget(body)


def test_ohttp_pane_hidden_for_plain_flow_and_after_switching_away():
    async def body(widget, pilot):
        assert not _is_visible(widget, OHTTP_PANE)
        _show(widget, _ohttp_flow(), OHTTP_PANE)
        await pilot.pause()
        _show(widget, _plain_flow())
        await pilot.pause()
        assert not _is_visible(widget, OHTTP_PANE)
        assert widget._tabs.active == "tab-request"

    _run_with_widget(body)


def test_legacy_ohttp_provider_registration_does_not_duplicate_pane():
    """Live capture still registers OhttpTabProvider after compose; the
    built-in pane supersedes it instead of rendering a second copy."""
    from friTap.tui.widgets.ohttp_tab import OhttpTabProvider

    async def body(widget, pilot):
        widget.register_tab(OhttpTabProvider())
        assert widget._plugin_tab_providers() == []
        _show(widget, _ohttp_flow(), OHTTP_PANE)
        await pilot.pause()
        assert _is_visible(widget, OHTTP_PANE)
        assert len(widget.query("#ohttp-log")) == 1

    _run_with_widget(body)


# ---------------------------------------------------------------- fritap -r (replay)


def test_replay_shows_ohttp_pane_for_ohttp_flow_from_tap(tmp_path):
    """End to end: OHTTP data survives the .tap round trip and the replay
    viewer (FriTapApp(replay_file=...)) shows the OHTTP pane for that flow."""
    from friTap.tui.app import FriTapApp
    from tests.unit._tui_flow_helpers import make_flow, write_tap

    flow = make_flow("flow-ohttp")
    flow.chunks.append(FlowChunk(data=b"POST / HTTP/1.1\r\n\r\n", direction="write", timestamp=1.0))
    flow.ohttp_inner_request = _ohttp_flow().ohttp_inner_request
    tap_path = tmp_path / "ohttp.tap"
    write_tap(tap_path, [flow])

    async def _go() -> None:
        app = FriTapApp(replay_file=str(tap_path))
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("enter")
            await pilot.pause()
            detail = app.screen.query_one("#flow-detail", FlowDetailWidget)
            assert detail._current_flow is not None
            assert _is_visible(detail, OHTTP_PANE)
            detail._tabs.active = OHTTP_PANE
            await pilot.pause()
            assert "inner-body" in _log_text(detail._ohttp_log)

    asyncio.run(_go())


# ---------------------------------------------------------------- render throttle (live refresh)


# Short throttle for tests. Throttle decisions read a fake clock that only
# moves when a test advances it, so they never depend on real elapsed time;
# only the deferred re-check timer itself runs on the event loop.
_INTERVAL = 0.1
_SETTLE = _INTERVAL + 0.5


class _FakeTime:
    """Stand-in for flow_detail's ``time`` module with a hand-driven monotonic clock."""

    def __init__(self) -> None:
        self.now = 1000.0

    def monotonic(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds

    def __getattr__(self, name):
        import time
        return getattr(time, name)


@pytest.fixture
def fake_clock(monkeypatch):
    """Throttle clock frozen until advanced; patches only flow_detail's view of ``time``."""
    clock = _FakeTime()
    monkeypatch.setattr(fd, "time", clock)
    monkeypatch.setattr(fd, "_EXT_RERENDER_INTERVAL", _INTERVAL)
    return clock


async def _let_deferred_check_fire(clock: _FakeTime, pilot) -> None:
    """Advance the throttle clock past the interval, then let the re-check timer run."""
    clock.advance(_INTERVAL)
    await asyncio.sleep(_SETTLE)
    await pilot.pause()


def _add_chunk(flow: Flow) -> None:
    flow.chunks.append(FlowChunk(data=b"more", direction="read", timestamp=2.0))


def _counting_tab(calls: list, min_chunks: int = 1):
    """Register a demo tab whose render logs each call and shows from *min_chunks*."""
    def render(flow):
        calls.append(flow.flow_id)
        return f"chunks={len(flow.chunks)}" if len(flow.chunks) >= min_chunks else None
    return _register_demo_tab(render)


def test_refresh_with_unchanged_data_does_not_rerender_extension():
    calls: list = []
    _counting_tab(calls)

    async def body(widget, pilot):
        flow = _plain_flow()
        _show(widget, flow)
        for _ in range(20):
            widget.refresh_flow(flow)
        await pilot.pause()
        assert calls == ["plain"]
        assert widget._ext_recheck_timer is None

    _run_with_widget(body)


def test_changed_data_rerenders_throttled_and_deferred_check_shows_tab(fake_clock):
    calls: list = []
    pane_id = _counting_tab(calls, min_chunks=3)

    async def body(widget, pilot):
        flow = _plain_flow()
        _show(widget, flow)
        assert len(calls) == 1 and not _is_visible(widget, pane_id)
        _add_chunk(flow)
        widget.refresh_flow(flow)  # first change after selection: immediate
        assert len(calls) == 2
        _add_chunk(flow)  # now 3 chunks -> render would return content
        widget.refresh_flow(flow)
        widget.refresh_flow(flow)
        assert len(calls) == 2  # throttled
        timer = widget._ext_recheck_timer
        assert timer is not None
        widget.refresh_flow(flow)
        assert widget._ext_recheck_timer is timer  # a single deferred check
        assert not _is_visible(widget, pane_id)
        await _let_deferred_check_fire(fake_clock, pilot)
        assert len(calls) == 3
        assert widget._ext_recheck_timer is None
        assert _is_visible(widget, pane_id)

    _run_with_widget(body)


def test_deferred_check_updates_active_extension_tab_content(fake_clock):
    calls: list = []
    pane_id = _counting_tab(calls)

    async def body(widget, pilot):
        flow = _plain_flow()
        _show(widget, flow, pane_id)
        _add_chunk(flow)
        widget.refresh_flow(flow)  # immediate -> chunks=2
        _add_chunk(flow)
        widget.refresh_flow(flow)  # throttled
        assert "chunks=2" in _log_text(widget._ext_logs[pane_id])
        await _let_deferred_check_fire(fake_clock, pilot)
        assert widget._tabs.active == pane_id
        assert "chunks=3" in _log_text(widget._ext_logs[pane_id])

    _run_with_widget(body)


def test_selection_change_cancels_deferred_check(fake_clock):
    calls: list = []
    _counting_tab(calls)

    async def body(widget, pilot):
        flow_a = _plain_flow("a")
        _show(widget, flow_a)
        _add_chunk(flow_a)
        widget.refresh_flow(flow_a)
        _add_chunk(flow_a)
        widget.refresh_flow(flow_a)
        timer = widget._ext_recheck_timer
        assert timer is not None
        _show(widget, _plain_flow("b"))  # selection changes
        assert widget._ext_recheck_timer is None
        await _let_deferred_check_fire(fake_clock, pilot)
        assert calls == ["a", "a", "b"]

    _run_with_widget(body)


def test_show_flow_always_rerenders_extensions():
    calls: list = []
    _counting_tab(calls)

    async def body(widget, pilot):
        flow = _plain_flow()
        _show(widget, flow)
        _show(widget, flow)
        assert calls == ["plain", "plain"]

    _run_with_widget(body)


def test_no_extensions_refresh_creates_no_timer():
    async def body(widget, pilot):
        timers: list = []
        original = widget.set_timer

        def spy(*args, **kwargs):
            timers.append(args)
            return original(*args, **kwargs)

        widget.set_timer = spy
        flow = _plain_flow()
        _show(widget, flow)
        for _ in range(5):
            _add_chunk(flow)
            widget.refresh_flow(flow)
        await pilot.pause()
        assert timers == []
        assert widget._ext_recheck_timer is None
        assert "GET / HTTP/1.1" in _log_text(widget._request_log)

    _run_with_widget(body)


def test_refresh_with_unchanged_visibility_does_not_toggle_optional_panes():
    """A live refresh only touches the tab bar when a pane's visibility changes."""
    pane_id = _register_demo_tab(lambda flow: "content")

    async def body(widget, pilot):
        flow = _ohttp_flow()
        _show(widget, flow)
        await pilot.pause()
        toggles: list = []
        for name in ("show_tab", "hide_tab"):
            original = getattr(widget._tabs, name)
            setattr(widget._tabs, name,
                    lambda pid, _n=name, _o=original: (toggles.append((_n, pid)), _o(pid))[1])
        optional = {OHTTP_PANE, pane_id}
        for _ in range(5):
            _add_chunk(flow)
            widget.refresh_flow(flow)
        assert [t for t in toggles if t[1] in optional] == []
        _show(widget, _plain_flow())
        assert [t for t in toggles if t[1] in optional] == [("hide_tab", OHTTP_PANE)]
        assert _is_visible(widget, pane_id) and not _is_visible(widget, OHTTP_PANE)

    _run_with_widget(body)


def test_same_size_reparse_rerenders_extension(fake_clock):
    """A layer-only change (no new bytes) is still picked up via layer_signature."""
    calls: list = []
    _counting_tab(calls)

    async def body(widget, pilot):
        flow = _plain_flow()
        _show(widget, flow)
        widget.refresh_flow(flow)
        assert len(calls) == 1
        flow.detected_protocol = "reparsed"
        widget.refresh_flow(flow)
        assert len(calls) == 2

    _run_with_widget(body)


def test_byte_change_skips_the_layer_walk(fake_clock, monkeypatch):
    """The layer signature is computed only when the cheap key is unchanged (or on render)."""
    walks: list = []
    original = fd._extension_layer_signature
    monkeypatch.setattr(fd, "_extension_layer_signature",
                        lambda flow: (walks.append(1), original(flow))[1])
    calls: list = []
    _counting_tab(calls)

    async def body(widget, pilot):
        flow = _plain_flow()
        _show(widget, flow)
        _add_chunk(flow)
        widget.refresh_flow(flow)  # immediate render
        walks.clear()
        for _ in range(3):
            _add_chunk(flow)
            widget.refresh_flow(flow)  # throttled, cheap key changed
        assert walks == [] and len(calls) == 2

    _run_with_widget(body)


def test_reset_extension_render_state_drops_rendered_content():
    _register_demo_tab(lambda flow: "big content")

    async def body(widget, pilot):
        _show(widget, _plain_flow())
        assert widget._ext_content
        widget._reset_extension_render_state()
        assert widget._ext_content == {}

    _run_with_widget(body)
