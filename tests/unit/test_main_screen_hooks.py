#!/usr/bin/env python3

"""Unit tests for MainScreen's host hooks (override points for the viewer).

Each hook isolates one capture/replay branch that viewer logic used to inline.
Replay-mode results are checked on a real ``FriTapApp(replay_file=...)``;
live-mode results on a bare ``MainScreen`` with a stub capture controller.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

pytest.importorskip("textual")

from friTap.tui.app import FriTapApp
from friTap.tui.screens.main_screen import MainScreen
from tests.unit._tui_flow_helpers import make_flow, write_tap

REPLAY_BANNER_HINTS = (
    " | Enter: details | /: filter | a: analyzers | w: export"
    " | r: restart wizard | q: quit"
)


def _run_replay(tmp_path, body) -> None:
    tap_path = str(tmp_path / "replay.tap")
    write_tap(tap_path, [make_flow("flow-aaaa", 443), make_flow("flow-bbbb", 8443)])

    async def _go() -> None:
        app = FriTapApp(replay_file=tap_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            await body(app, pilot, app.screen)

    asyncio.run(_go())


class _FakeCollector:
    def __init__(self, flows):
        self._flows = list(flows)

    def get_flows(self):
        return list(self._flows)

    def get_flow(self, flow_id):
        return next((f for f in self._flows if f.flow_id == flow_id), None)


def _live_screen(flows=(), running=False, collector=True):
    """A bare MainScreen in live mode (no replay) with a stub capture controller."""
    screen = MainScreen.__new__(MainScreen)
    screen._replay_ctrl = None
    calls: list = []
    screen._capture = SimpleNamespace(
        flow_collector=_FakeCollector(flows) if collector else None,
        ssl_logger=SimpleNamespace(running=running),
        action_escape_action=lambda: calls.append("escape"),
        start_tap_recording=lambda path: calls.append(("record", path)),
    )
    return screen, calls


# ----------------------------------------------------------------------
# Replay mode (real app)
# ----------------------------------------------------------------------


def test_replay_hook_values(tmp_path):
    async def body(app, pilot, screen):
        assert screen._live_flow_collector() is None
        assert screen._has_flows() is True
        assert screen._is_capturing() is False
        assert screen._divert_analyzer_key() is False
        assert screen._flow_title_hints() == ["[dim]r: restart wizard[/]"]
        assert screen._replay_banner_hints() == REPLAY_BANNER_HINTS

        flow_ids, get_flow = screen._analyzer_flow_ids_and_getter()
        assert flow_ids == ["flow-aaaa", "flow-bbbb"]
        assert get_flow("flow-bbbb").dst_port == 8443

    _run_replay(tmp_path, body)


def test_replay_hide_host_panels(tmp_path):
    async def body(app, pilot, screen):
        screen.query_one("#activity-log").display = True
        screen.query_one("#left-panel").display = True
        screen.query_one("#right-panel").remove_class("flow-mode")

        screen._hide_host_panels()

        assert screen.query_one("#activity-log").display is False
        assert screen.query_one("#left-panel").display is False
        assert screen.query_one("#right-panel").has_class("flow-mode")

    _run_replay(tmp_path, body)


def test_replay_request_close_opens_quit_confirmation(tmp_path):
    async def body(app, pilot, screen):
        screen._request_close()
        await pilot.pause()
        assert type(app.screen).__name__ == "QuitConfirmModal"

    _run_replay(tmp_path, body)


def test_replay_escape_at_top_level_requests_close(tmp_path):
    async def body(app, pilot, screen):
        requested: list = []
        screen._request_close = lambda: requested.append(True)
        await pilot.press("escape")
        await pilot.pause()
        assert requested == [True]

    _run_replay(tmp_path, body)


# ----------------------------------------------------------------------
# Live mode (stub capture controller)
# ----------------------------------------------------------------------


def test_live_has_flows_counts_collector():
    assert _live_screen([make_flow("f1", 443)])[0]._has_flows() is True
    assert _live_screen([])[0]._has_flows() is False
    assert _live_screen(collector=False)[0]._has_flows() is False


def test_live_analyzer_flow_ids_and_getter():
    flows = [make_flow("f1", 443), make_flow("f2", 80)]
    flow_ids, get_flow = _live_screen(flows)[0]._analyzer_flow_ids_and_getter()
    assert flow_ids == ["f1", "f2"]
    assert get_flow("f2") is flows[1]

    empty_ids, empty_get = _live_screen(collector=False)[0]._analyzer_flow_ids_and_getter()
    assert empty_ids == [] and empty_get("f1") is None


def test_live_is_capturing_follows_ssl_logger():
    assert _live_screen(running=True)[0]._is_capturing() is True
    assert _live_screen(running=False)[0]._is_capturing() is False
    screen, _ = _live_screen()
    screen._capture.ssl_logger = None
    assert screen._is_capturing() is False


def test_live_flow_title_hints_add_console_and_stop_capture():
    hints = _live_screen(running=True)[0]._flow_title_hints()
    assert hints[:2] == ["[dim]r: restart wizard[/]", "[dim]f: console view[/]"]
    assert len(hints) == 3 and "Esc: stop capture" in hints[2]

    idle = _live_screen(running=False)[0]._flow_title_hints()
    assert idle == ["[dim]r: restart wizard[/]", "[dim]f: console view[/]"]


def test_live_divert_analyzer_key_attaches_without_flows():
    screen, _ = _live_screen([])
    attached: list = []
    screen.action_attach = lambda: attached.append(True)
    assert screen._divert_analyzer_key() is True
    assert attached == [True]

    with_flows, _ = _live_screen([make_flow("f1", 443)])
    with_flows.action_attach = lambda: attached.append("unexpected")
    assert with_flows._divert_analyzer_key() is False
    assert attached == [True]


def test_live_capture_delegating_hooks():
    screen, calls = _live_screen()
    assert screen._live_flow_collector() is screen._capture.flow_collector
    screen._escape_running_capture()
    screen._start_live_tap_recording("/tmp/out.tap")
    assert calls == ["escape", ("record", "/tmp/out.tap")]


def test_live_signal_siblings_via_shared_matcher():
    def sig(flow_id, sport, dport, dst="2.2.2.2", transport="signal"):
        return SimpleNamespace(flow_id=flow_id, src_addr="1.1.1.1", src_port=sport,
                               dst_addr=dst, dst_port=dport, transport=transport)

    a, b = sig("a", 45072, 443), sig("b", 45088, 443)
    other, tls = sig("o", 45100, 443, dst="9.9.9.9"), sig("t", 45072, 443, transport="tls")
    screen, _ = _live_screen([a, b, other, tls])
    assert [f.flow_id for f in screen._signal_conversation_siblings(a)] == ["a", "b"]
    assert screen._signal_conversation_siblings(tls) == []


# ----------------------------------------------------------------------
# Export (ExportMixin) — resolved on MainScreen, routed via host hooks
# ----------------------------------------------------------------------


def test_export_methods_come_from_export_mixin():
    from friTap.tui.screens.viewer_mixins import ExportMixin

    for name in ("action_save_tap", "_on_save_tap_result", "_export_replay_to_tap",
                 "_collect_export_findings", "_has_capture_flows", "action_report_digest"):
        assert getattr(MainScreen, name) is getattr(ExportMixin, name), name


def test_live_save_tap_result_records_via_hook():
    screen, calls = _live_screen([make_flow("f1", 443)])
    screen._on_save_tap_result(None)
    screen._on_save_tap_result("/tmp/live.tap")
    assert calls == [("record", "/tmp/live.tap")]


def test_live_has_capture_flows_uses_collector_hook():
    assert _live_screen([make_flow("f1", 443)])[0]._has_capture_flows() is True
    assert _live_screen([])[0]._has_capture_flows() is False
    assert _live_screen(collector=False)[0]._has_capture_flows() is False


# ----------------------------------------------------------------------
# Esc: nested-view step first, then capture stop, then close
# ----------------------------------------------------------------------


def _escape_screen(stepped: bool, running: bool):
    screen, calls = _live_screen(running=running)
    screen._escape_step = lambda: calls.append("step") or stepped
    screen._request_close = lambda: calls.append("close")
    return screen, calls


def test_escape_nested_step_wins_over_capture_stop():
    screen, calls = _escape_screen(stepped=True, running=True)
    screen.action_escape_action()
    assert calls == ["step"]


def test_escape_at_top_level_stops_running_capture():
    screen, calls = _escape_screen(stepped=False, running=True)
    screen.action_escape_action()
    assert calls == ["step", "escape"]


def test_escape_at_top_level_without_capture_requests_close():
    screen, calls = _escape_screen(stepped=False, running=False)
    screen.action_escape_action()
    assert calls == ["step", "close"]


def test_alert_comes_from_viewer_host_defaults():
    from friTap.tui.screens.viewer_mixins import ViewerHostDefaults

    assert MainScreen._alert is ViewerHostDefaults._alert
