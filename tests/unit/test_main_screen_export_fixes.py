"""Markup escaping, export-over-source guard and the no-flows hook."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

pytest.importorskip("textual")

from friTap.tui.app import FriTapApp
from friTap.tui.screens.main_screen import MainScreen
from friTap.tui.screens.viewer_mixins import ExportMixin, ViewerHostDefaults
from tests.unit._tui_flow_helpers import make_flow, write_tap


def test_main_screen_escapes_tap_filename_in_markup(tmp_path):
    tap_path = str(tmp_path / "x[bold].tap")
    write_tap(tap_path, [make_flow("f1", 443)])

    async def _go():
        app = FriTapApp(replay_file=tap_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            screen = app.screen
            assert screen._replay_filename == "x\\[bold].tap"
            for wid in ("#activity-title", "#capture-indicator"):
                rendered = str(screen.query_one(wid).render())
                assert "x[bold].tap" in rendered, (wid, rendered)

    asyncio.run(_go())


def _export_host(replay_file):
    host = SimpleNamespace(
        _replay_file=replay_file, _replay_ctrl=MagicMock(), app=MagicMock(),
    )
    host._alert = MagicMock()
    return host


def test_export_refuses_to_overwrite_open_capture(tmp_path):
    src = tmp_path / "cap.tap"
    src.write_bytes(b"orig")
    host = _export_host(str(src))
    ExportMixin._export_replay_to_tap(host, str(tmp_path / "." / "cap.tap"))
    host._alert.assert_called_once()
    assert src.read_bytes() == b"orig"


def test_export_success_alert_escapes_path(tmp_path):
    host = _export_host(str(tmp_path / "src.tap"))
    host._replay_ctrl.header = None
    host._replay_ctrl.get_flows.return_value = []
    host._replay_ctrl.read_request_contexts.return_value = []
    host._collect_export_findings = lambda: {}
    target = str(tmp_path / "o[bold]x.tap")
    ExportMixin._export_replay_to_tap(host, target)
    modal = host.app.push_screen.call_args[0][0]
    assert modal._message.endswith("o\\[bold]x.tap[/]")


def test_no_flows_message_hook():
    assert ViewerHostDefaults._no_flows_to_save_message(None) == "No flows to save."
    assert MainScreen._no_flows_to_save_message(None) == (
        "No flows to save.\nStart a capture with flow view first."
    )
    host = SimpleNamespace(
        _has_flows=lambda: False, app=MagicMock(),
        _no_flows_to_save_message=lambda: "HOOK",
    )
    ExportMixin.action_save_tap(host)
    assert host.app.push_screen.call_args[0][0]._message == "HOOK"
