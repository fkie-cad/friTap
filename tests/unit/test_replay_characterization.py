#!/usr/bin/env python3

"""
Characterization (safety-net) test for ``fritap -r x.tap`` in the TUI.

Pins what the REAL ``FriTapApp(replay_file=...)`` + ``MainScreen`` replay path
does TODAY, so later refactors that move code out of MainScreen can be checked
against it. Assertions describe current behaviour, not desired behaviour.

Each async body is driven with ``asyncio.run`` (no async pytest plugin).
"""

from __future__ import annotations

import asyncio
import re

import pytest

pytest.importorskip("textual")

from friTap.flow.models import Flow, FlowState
from friTap.flow.tap_writer import TapWriter
from friTap.tui.app import FriTapApp


def _make_flow(flow_id: str, dst_port: int) -> Flow:
    return Flow(
        flow_id=flow_id,
        connection_id=flow_id,
        src_addr="10.0.0.1",
        src_port=12345,
        dst_addr="93.184.216.34",
        dst_port=dst_port,
        state=FlowState.COMPLETE,
    )


def _write_tap(path: str) -> None:
    writer = TapWriter()
    writer.open(path, target="test")
    writer.write_flow(_make_flow("flow-aaaa", 443))
    writer.write_flow(_make_flow("flow-bbbb", 8443))
    writer.close()


def _row_cells(flow_list, flow_id: str) -> list:
    for key in flow_list.rows:
        if key.value == flow_id:
            return [str(cell) for cell in flow_list.get_row(key)]
    raise AssertionError(f"row {flow_id} not found")


def _run(tmp_path, body) -> None:
    tap_path = str(tmp_path / "replay.tap")
    _write_tap(tap_path)

    async def _go() -> None:
        app = FriTapApp(replay_file=tap_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            await body(app, pilot)

    asyncio.run(_go())


def test_replay_title_and_flow_rows(tmp_path):
    async def body(app, pilot):
        from textual.widgets import Static

        from friTap.tui.screens.main_screen import MainScreen
        from friTap.tui.widgets.flow_list import FlowListWidget

        screen = app.screen
        assert isinstance(screen, MainScreen)

        # App-level title/sub_title are unchanged by replay mode.
        assert app.title == "friTap"
        assert app.sub_title == "Real-time key extraction and traffic decryption"
        assert screen.title is None and screen.sub_title is None

        # The replay banner is the "title" shown by MainScreen.
        banner = str(screen.query_one("#activity-title", Static).render())
        assert banner == (
            "friTap Replay  replay.tap (2 flows) | Enter: details | /: filter"
            " | a: analyzers | w: export | r: restart wizard | q: quit"
        )

        flow_list = screen.query_one("#flow-list", FlowListWidget)
        assert [c.label.plain for c in flow_list.columns.values()] == [
            "#", "Time", "Proto", "Method", "Connection", "Status", "Size", "Duration",
        ]
        assert [k.value for k in flow_list.rows] == ["flow-aaaa", "flow-bbbb"]

        for flow_id, num, port in (("flow-aaaa", "1", 443), ("flow-bbbb", "2", 8443)):
            cells = _row_cells(flow_list, flow_id)
            assert cells[0] == num
            assert re.fullmatch(r"\d\d:\d\d:\d\d", cells[1])  # wall-clock, tz dependent
            assert cells[2:4] == ["???", "-"]
            assert cells[4] == f"10.0.0.1:12345 \u2192 93.184.216.34:{port}"
            assert cells[5:7] == ["...", "-"]
            assert re.fullmatch(r"\d+ms", cells[7])

    _run(tmp_path, body)


def test_replay_enter_and_escape_open_and_close_flow_detail(tmp_path):
    async def body(app, pilot):
        from friTap.tui.widgets.flow_list import FlowListWidget

        screen = app.screen
        detail = screen.query_one("#flow-detail")
        assert detail.display is False
        assert isinstance(app.focused, FlowListWidget)

        await pilot.press("enter")
        await pilot.pause()
        assert detail.display is True
        assert not isinstance(app.focused, FlowListWidget)

        await pilot.press("escape")
        await pilot.pause()
        assert detail.display is False
        assert isinstance(app.focused, FlowListWidget)
        assert [type(s).__name__ for s in app.screen_stack] == ["Screen", "MainScreen"]

    _run(tmp_path, body)


def test_replay_slash_opens_filter_modal_and_escape_closes(tmp_path):
    async def body(app, pilot):
        await pilot.press("slash")
        await pilot.pause()
        assert type(app.screen).__name__ == "FilterModal"
        assert app.focused.id == "filter-input"

        await pilot.press("escape")
        await pilot.pause()
        assert type(app.screen).__name__ == "MainScreen"

    _run(tmp_path, body)


def test_replay_shift_f_toggles_findings_view(tmp_path):
    async def body(app, pilot):
        screen = app.screen
        findings = screen.query_one("#findings-list")
        assert findings.display is False

        await pilot.press("shift+f")
        await pilot.pause()
        assert findings.display is True
        assert app.focused.id == "findings-list"

        await pilot.press("shift+f")
        await pilot.pause()
        assert findings.display is False
        assert app.focused.id == "flow-list"

    _run(tmp_path, body)


def test_replay_a_toggles_analyzer_panel(tmp_path):
    async def body(app, pilot):
        screen = app.screen
        panel = screen._analyzer_panel()
        assert panel.display is False

        await pilot.press("a")
        await pilot.pause()
        assert panel.display is True
        assert type(app.screen).__name__ == "MainScreen"  # no attach flow in replay

        await pilot.press("a")
        await pilot.pause()
        assert panel.display is False
        assert app.focused.id == "flow-list"

    _run(tmp_path, body)


def test_replay_w_opens_save_tap_modal(tmp_path):
    async def body(app, pilot):
        await pilot.press("w")
        await pilot.pause()
        assert type(app.screen).__name__ == "SaveTapModal"
        assert app.focused.id == "tap-path-input"
        assert [type(s).__name__ for s in app.screen_stack] == [
            "Screen", "MainScreen", "SaveTapModal",
        ]

    _run(tmp_path, body)
