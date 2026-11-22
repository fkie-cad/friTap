"""Optional save directory for .tap saves; default (cwd-relative) unchanged."""

from __future__ import annotations

import asyncio
import os
import re
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

from friTap.tui.app import FriTapApp
from friTap.tui.modals.save_tap_modal import SaveTapModal
from friTap.tui.screens.viewer_mixins.export import ExportMixin
from friTap.tui.widgets.flow_detail import FlowDetailWidget
from tests.unit._tui_flow_helpers import make_flow, write_tap

_DEFAULT_NAME = re.compile(r"^capture_\d{8}_\d{6}\.tap$")


def _submit(modal: SaveTapModal, typed: str):
    modal.query_one = MagicMock(return_value=SimpleNamespace(value=typed))
    modal.dismiss = MagicMock()
    modal._submit()
    return modal.dismiss.call_args[0][0]


def test_modal_default_suggestion_is_bare_name():
    assert _DEFAULT_NAME.match(SaveTapModal()._suggested_name)


def test_modal_default_dismisses_relative_value_unchanged():
    assert _submit(SaveTapModal(), "foo") == "foo.tap"
    assert _submit(SaveTapModal(), "sub/x.tap") == "sub/x.tap"


def test_modal_directory_suggestion_and_join(tmp_path):
    modal = SaveTapModal(directory=tmp_path)
    suggested = Path(modal._suggested_name)
    assert suggested.parent == tmp_path
    assert _DEFAULT_NAME.match(suggested.name)
    assert _submit(modal, "foo") == str(tmp_path / "foo.tap")


def test_modal_directory_keeps_absolute_path(tmp_path):
    other = tmp_path / "elsewhere" / "a.tap"
    modal = SaveTapModal(directory=tmp_path / "out")
    assert _submit(modal, str(other)) == str(other)


def test_export_mixin_passes_directory(tmp_path):
    for attrs, expected in (({"_output_dir": tmp_path}, tmp_path), ({"_output_dir": None}, None)):
        host = SimpleNamespace(
            _has_flows=lambda: True,
            app=MagicMock(),
            _on_save_tap_result=lambda p: None,
            **attrs,
        )
        ExportMixin.action_save_tap(host)
        modal = host.app.push_screen.call_args[0][0]
        assert isinstance(modal, SaveTapModal)
        assert modal._directory == (Path(expected) if expected else None)


def test_flow_detail_save_directory(tmp_path):
    fn = FlowDetailWidget._save_directory
    with_dir = SimpleNamespace(screen=SimpleNamespace(_output_dir=tmp_path))
    without = SimpleNamespace(screen=SimpleNamespace())
    assert fn(with_dir) == str(tmp_path)
    assert fn(without) == os.getcwd()


def test_main_screen_default_path_unchanged(tmp_path):
    tap_path = str(tmp_path / "replay.tap")
    write_tap(tap_path, [make_flow("f1", 443, src_port=1, dst_addr="1.2.3.4")])

    async def _go():
        app = FriTapApp(replay_file=tap_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            assert getattr(app.screen, "_output_dir", None) is None
            await pilot.press("w")
            await pilot.pause()
            assert type(app.screen).__name__ == "SaveTapModal"
            assert app.screen._directory is None
            assert _DEFAULT_NAME.match(app.screen._suggested_name)

    asyncio.run(_go())


def test_modal_relative_directory_joined_once():
    modal = SaveTapModal(directory="out")
    suggested = modal._suggested_name
    assert Path(suggested).parent == Path("out")
    assert _submit(modal, suggested) == suggested
    assert _submit(modal, "foo") == str(Path("out") / "foo.tap")
    assert _submit(modal, "sub/x.tap") == "sub/x.tap"


def test_modal_absolute_directory_default_suggestion_roundtrip(tmp_path):
    modal = SaveTapModal(directory=tmp_path)
    assert _submit(modal, modal._suggested_name) == modal._suggested_name
