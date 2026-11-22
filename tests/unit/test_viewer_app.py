#!/usr/bin/env python3

"""Tests for mode A: ``TapViewerApp`` / ``open_tap`` (task 5.1)."""

from __future__ import annotations

import asyncio
import logging
import sys

import pytest

pytest.importorskip("textual")

from friTap.tui import viewer_app  # noqa: E402
from friTap.tui.screens.tap_viewer import TapViewerScreen  # noqa: E402
from friTap.tui.viewer_app import (  # noqa: E402
    TapViewerApp,
    friTap_logger_names,
    muted_fritap_console,
    open_tap,
)
from tests.unit._tui_flow_helpers import make_flow, write_tap  # noqa: E402


@pytest.fixture
def tap(tmp_path) -> str:
    path = str(tmp_path / "mode_a.tap")
    write_tap(path, [make_flow("flow-aaaa", 443), make_flow("flow-bbbb", 8443)])
    return path


class Capture(logging.Handler):
    def __init__(self, stream=None):
        super().__init__()
        self.records: list = []

    def emit(self, record):
        self.records.append(record.getMessage())


def test_app_shows_viewer_detail_back_and_quit(tap):
    app = TapViewerApp(tap, title="Host CLI")
    seen: dict = {}

    async def go():
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.pause()
            viewer = app.screen
            seen["is_viewer"] = isinstance(viewer, TapViewerScreen)
            table = viewer.query_one("#flow-list")
            seen["rows"] = [k.value for k in table.rows]
            await pilot.press("enter")
            await pilot.pause()
            await pilot.press("escape")
            await pilot.pause()
            seen["back_in_viewer"] = app.screen is viewer
            await pilot.press("q")
            await pilot.pause()
            await pilot.pause()

    asyncio.run(go())
    assert seen["is_viewer"]
    assert seen["rows"] == ["flow-aaaa", "flow-bbbb"]
    assert seen["back_in_viewer"]
    assert app.title == "Host CLI"
    assert app.sub_title == "mode_a.tap"
    assert app._exit is True


def test_app_defaults_and_theme(tap):
    app = TapViewerApp(tap)
    assert app.title == "friTap"
    assert app.theme == "fritap-dark"
    assert TapViewerApp(tap, theme="fritap-light").theme == "fritap-light"


def test_open_tap_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        open_tap(str(tmp_path / "nope.tap"))


def test_open_tap_without_textual_raises_import_error(tap, monkeypatch):
    monkeypatch.setattr(viewer_app, "TEXTUAL_AVAILABLE", False)
    with pytest.raises(ImportError, match="fritap\\[tui\\]"):
        open_tap(tap)


def test_logger_names_exclude_root():
    names = friTap_logger_names()
    assert "" not in names and "friTap" in names


def test_mute_restore_leaves_root_alone_and_restores_fritap():
    root_handler = Capture()
    console = logging.StreamHandler(sys.stderr)
    fritap_log = logging.getLogger("friTap")
    root = logging.getLogger()
    root.addHandler(root_handler)
    fritap_log.addHandler(console)
    before = console.level
    try:
        with muted_fritap_console():
            assert console.level > logging.CRITICAL
            assert root_handler.level == logging.NOTSET
            root.warning("during")
        assert console.level == before
        root.warning("after")
        assert root_handler.level == logging.NOTSET
        assert "during" in root_handler.records and "after" in root_handler.records
    finally:
        root.removeHandler(root_handler)
        fritap_log.removeHandler(console)


def test_open_tap_runs_app_with_muting_and_restores(tap, monkeypatch):
    console = logging.StreamHandler(sys.stderr)
    fritap_log = logging.getLogger("friTap")
    fritap_log.addHandler(console)
    levels: list = []
    monkeypatch.setattr(
        TapViewerApp, "run", lambda self, *a, **k: levels.append(console.level)
    )
    try:
        open_tap(tap)
        assert levels and levels[0] > logging.CRITICAL
        assert console.level == logging.NOTSET
    finally:
        fritap_log.removeHandler(console)
