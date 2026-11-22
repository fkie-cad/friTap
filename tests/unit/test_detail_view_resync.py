#!/usr/bin/env python3

"""Live flow updates that arrive while the flow list is hidden reach it later.

``MainScreen._update_flow_ui`` only touches the flow list while it is shown.
Updates skipped while the detail view (or the console view) was open must be
applied when the list is shown again. The host is a real ``FriTapApp`` loaded
from a .tap, switched to live mode (no replay controller) before the updates.
"""

from __future__ import annotations

import asyncio

import pytest

pytest.importorskip("textual")

from friTap.flow.models import FlowState
from friTap.tui.app import FriTapApp
from friTap.tui.widgets.flow_list import FlowListWidget
from tests.unit._tui_flow_helpers import make_flow, write_tap


def _run_live(tmp_path, body) -> None:
    tap_path = str(tmp_path / "seed.tap")
    write_tap(tap_path, [make_flow("flow-seed", 443)])

    async def _go() -> None:
        app = FriTapApp(replay_file=tap_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            screen = app.screen
            screen._replay_ctrl = None
            await body(screen, pilot, screen.query_one("#flow-list", FlowListWidget))

    asyncio.run(_go())


def _open_detail(screen, flow) -> None:
    screen._detail_origin = "flow"
    screen._present_flow_detail(flow)
    assert screen.query_one("#flow-detail").display
    assert not screen.query_one("#flow-list").display


def test_flow_added_while_detail_open_is_listed_after_back(tmp_path):
    async def body(screen, pilot, flow_list):
        _open_detail(screen, make_flow("flow-seed", 443))
        screen._update_flow_ui(make_flow("flow-new", 8443), "created")
        await pilot.pause()
        assert "flow-new" not in flow_list._all_flow_data

        screen._back_to_flow_list()
        await pilot.pause()
        assert "flow-new" in flow_list._all_flow_data
        assert "flow-new" in flow_list._flow_row_keys

    _run_live(tmp_path, body)


def test_flow_updated_while_detail_open_is_current_after_back(tmp_path):
    async def body(screen, pilot, flow_list):
        live = make_flow("flow-live", 8443)
        live.state = FlowState.ACTIVE
        screen._update_flow_ui(live, "created")
        assert flow_list._all_flow_data["flow-live"].state == FlowState.ACTIVE

        _open_detail(screen, live)
        live.state = FlowState.COMPLETE
        screen._update_flow_ui(live, "completed")
        await pilot.pause()
        assert flow_list._all_flow_data["flow-live"].state == FlowState.ACTIVE

        screen._back_to_flow_list()
        await pilot.pause()
        assert flow_list._all_flow_data["flow-live"].state == FlowState.COMPLETE

    _run_live(tmp_path, body)


def test_flow_added_in_console_view_is_listed_on_flow_view(tmp_path):
    async def body(screen, pilot, flow_list):
        screen._activate_legacy_view()
        screen._update_flow_ui(make_flow("flow-console", 8443), "created")
        assert "flow-console" not in flow_list._all_flow_data

        screen._activate_flow_view()
        await pilot.pause()
        assert "flow-console" in flow_list._flow_row_keys

    _run_live(tmp_path, body)


def test_back_without_skipped_updates_does_no_list_work(tmp_path, monkeypatch):
    async def body(screen, pilot, flow_list):
        calls: list = []
        monkeypatch.setattr(
            flow_list, "add_or_update_flow", lambda *a, **k: calls.append(a),
        )
        _open_detail(screen, make_flow("flow-seed", 443))
        screen._back_to_flow_list()
        await pilot.pause()
        assert calls == []

    _run_live(tmp_path, body)


def test_skipped_updates_are_applied_once(tmp_path, monkeypatch):
    async def body(screen, pilot, flow_list):
        flow = make_flow("flow-new", 8443)
        _open_detail(screen, flow)
        for _ in range(3):
            screen._update_flow_ui(flow, "updated")
        calls: list = []
        real = flow_list.add_or_update_flow
        monkeypatch.setattr(
            flow_list, "add_or_update_flow",
            lambda f, *a, **k: (calls.append(f.flow_id), real(f, *a, **k)),
        )
        screen._back_to_flow_list()
        _open_detail(screen, flow)
        screen._back_to_flow_list()
        await pilot.pause()
        assert calls == ["flow-new"]

    _run_live(tmp_path, body)


def test_clearing_the_list_drops_skipped_updates(tmp_path):
    async def body(screen, pilot, flow_list):
        _open_detail(screen, make_flow("flow-seed", 443))
        screen._update_flow_ui(make_flow("flow-stale", 8443), "created")
        screen._clear_shown_rows()
        screen._back_to_flow_list()
        await pilot.pause()
        assert "flow-stale" not in flow_list._all_flow_data

    _run_live(tmp_path, body)
