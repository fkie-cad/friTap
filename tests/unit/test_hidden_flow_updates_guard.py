"""One failing pending flow must not abort the view switch or drop the rest."""

from __future__ import annotations

import asyncio

import pytest

pytest.importorskip("textual")

from friTap.tui.app import FriTapApp
from friTap.tui.widgets.flow_list import FlowListWidget
from tests.unit._tui_flow_helpers import make_flow, write_tap


def test_bad_pending_flow_does_not_block_back_to_list(tmp_path):
    tap_path = str(tmp_path / "seed.tap")
    write_tap(tap_path, [make_flow("flow-seed", 443)])

    async def _go() -> None:
        app = FriTapApp(replay_file=tap_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            screen = app.screen
            screen._replay_ctrl = None
            flow_list = screen.query_one("#flow-list", FlowListWidget)
            screen._detail_origin = "flow"
            screen._present_flow_detail(make_flow("flow-seed", 443))

            real_add = flow_list.add_or_update_flow

            def flaky(flow):
                if flow.flow_id == "flow-bad":
                    raise RuntimeError("boom")
                return real_add(flow)

            flow_list.add_or_update_flow = flaky
            for fid, port in (("flow-a", 8001), ("flow-bad", 8002), ("flow-b", 8003)):
                screen._update_flow_ui(make_flow(fid, port), "created")

            screen._back_to_flow_list()
            await pilot.pause()
            assert flow_list.display
            assert "flow-a" in flow_list._all_flow_data
            assert "flow-b" in flow_list._all_flow_data
            assert not screen._hidden_flow_updates

    asyncio.run(_go())
