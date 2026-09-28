#!/usr/bin/env python3

"""Regression tests for resync-search-depth validation (T4).

The TUI's advanced field and the CLI's ``--resync-search-depth`` used a bare
``int()``: a huge value made the MTProto resync search allocate gigabytes of
keystream, a negative one silently disabled mid-stream recovery.
"""

from __future__ import annotations

import argparse
import asyncio
import types

import pytest

from friTap.offline.cli import (
    RESYNC_SEARCH_DEPTH_MAX,
    _build_parser,
    parse_resync_search_depth,
)
from friTap.offline.mtproto.transport import (
    DEFAULT_OBF_ENDPOINT_MATCH_BLOCKS,
    DEFAULT_OBF_MAX_BLOCKS,
)


class TestParseResyncSearchDepth:

    def test_bound_is_four_times_endpoint_ceiling(self):
        assert RESYNC_SEARCH_DEPTH_MAX == 4 * DEFAULT_OBF_ENDPOINT_MATCH_BLOCKS

    @pytest.mark.parametrize("raw, expected", [
        ("0", 0), ("4096", 4096), (" 20000 ", 20000),
        (str(RESYNC_SEARCH_DEPTH_MAX), RESYNC_SEARCH_DEPTH_MAX),
    ])
    def test_accepts_in_range(self, raw, expected):
        assert parse_resync_search_depth(raw) == expected

    @pytest.mark.parametrize("raw", [
        "-1", str(RESYNC_SEARCH_DEPTH_MAX + 1), "999999999999", "abc", "1.5", "",
    ])
    def test_rejects_invalid(self, raw):
        with pytest.raises(argparse.ArgumentTypeError):
            parse_resync_search_depth(raw)

    def test_cli_accepts_valid_and_defaults(self):
        parser = _build_parser()
        args = parser.parse_args(["--from-pcap", "x.pcap"])
        assert args.resync_search_depth == DEFAULT_OBF_MAX_BLOCKS
        args = parser.parse_args(
            ["--from-pcap", "x.pcap", "--resync-search-depth", "5000"]
        )
        assert args.resync_search_depth == 5000

    @pytest.mark.parametrize("raw", ["-1", "100000000", "lots"])
    def test_cli_rejects_invalid_with_usage_error(self, raw, capsys):
        parser = _build_parser()
        with pytest.raises(SystemExit) as exc:
            parser.parse_args(
                ["--from-pcap", "x.pcap", "--resync-search-depth", raw]
            )
        assert exc.value.code == 2
        assert "resync search depth" in capsys.readouterr().err


textual = pytest.importorskip("textual")


def _convert_with_depth(value: str):
    """Push the confirm modal, type *value*, press Convert.

    Returns ``(dismissed_result, modal_still_on_top, error_text, error_visible)``.
    """
    from textual.widgets import Input, Static

    from friTap.tui.app import FriTapApp
    from friTap.tui.modals.pcap_to_tap_modals import PcapToTapConfirmModal

    out: dict = {"value": "NOT-DISMISSED"}

    async def _run() -> None:
        app = FriTapApp()
        async with app.run_test() as pilot:
            modal = PcapToTapConfirmModal(summary={
                "pcap": "c.pcap", "tap": "c.tap",
                "protocol_keylogs": {"tls": "t.log"},
            })
            await app.push_screen(modal, callback=lambda v: out.update(value=v))
            await pilot.pause()
            modal.query_one("#resync-depth-input", Input).value = value
            await pilot.pause()
            modal.on_button_pressed(types.SimpleNamespace(
                button=types.SimpleNamespace(id="btn-convert")
            ))
            await pilot.pause()
            out["on_top"] = app.screen is modal
            out["error"], out["visible"] = "", False
            if out["on_top"]:
                label = modal.query_one("#resync-depth-error", Static)
                out["error"] = str(label.render())
                out["visible"] = label.has_class("visible")

    asyncio.run(_run())
    return out["value"], out["on_top"], out["error"], out["visible"]


class TestConfirmModalDepthValidation:

    @pytest.mark.parametrize("value", ["-5", "999999999", "nope"])
    def test_invalid_depth_refuses_convert_and_shows_error(self, value):
        result, on_top, error, visible = _convert_with_depth(value)
        assert result == "NOT-DISMISSED"
        assert on_top
        assert visible
        assert "resync search depth" in error

    def test_valid_depth_converts(self):
        result, on_top, _error, _visible = _convert_with_depth("0")
        assert result["resync_search_depth"] == 0
        assert not on_top

    def test_empty_depth_uses_default(self):
        result, *_ = _convert_with_depth("")
        assert result["resync_search_depth"] == DEFAULT_OBF_MAX_BLOCKS
