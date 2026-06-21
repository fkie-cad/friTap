#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Tests for the TUI Analyzer Panel (key ``a``).

Exercises the panel through the Textual app harness, focusing on the
correctness fixes:

* opening the panel from the findings view returns to the flow view first
  (the panel must not stack on top of the findings list);
* the empty-selection guard does not start a run;
* saving after an analyzer run preserves the .tap's *original* stored findings
  (the replace-per-run display cache must not cause save-time data loss).

The repo has no async pytest plugin, so async bodies run via ``asyncio.run``.
"""

from __future__ import annotations

import asyncio

import pytest

pytest.importorskip("textual")

from friTap.analysis import Finding, Severity
from friTap.flow.models import Flow, FlowState
from friTap.flow.replay import ReplayController
from friTap.flow.tap_writer import TapWriter
from friTap.tui.app import FriTapApp


def _make_flow(flow_id: str, dst_port: int = 443) -> Flow:
    return Flow(
        flow_id=flow_id,
        connection_id=flow_id,
        src_addr="10.0.0.1",
        src_port=12345,
        dst_addr="93.184.216.34",
        dst_port=dst_port,
        state=FlowState.COMPLETE,
    )


def _write_tap_with_stored_finding(path: str) -> Finding:
    """Write a .tap with one flow and one pre-existing stored finding."""
    flow = _make_flow("flow-aaaa")
    stored = Finding(
        severity=Severity.HIGH,
        title="STORED-MARKER",
        description="pre-existing finding from a prior scan",
        source="credentials",
        flow_id="flow-aaaa",
        metadata={"category": "secret"},
    )
    writer = TapWriter()
    writer.open(path, target="test")
    writer.write_flow(flow)
    writer.write_findings("flow-aaaa", [stored])
    writer.close()
    return stored


def test_a_from_findings_view_does_not_stack(tmp_path):
    """Pressing ``a`` while in the findings view returns to the flow view."""
    tap_path = str(tmp_path / "stored.tap")
    _write_tap_with_stored_finding(tap_path)

    async def _run() -> None:
        app = FriTapApp(replay_file=tap_path)
        async with app.run_test() as pilot:
            screen = app.screen
            await pilot.press("shift+f")
            await pilot.pause()
            assert screen.query_one("#findings-list").display is True

            await pilot.press("a")
            await pilot.pause()
            # Panel shown; findings list hidden (not stacked underneath).
            assert screen.query_one("#analyzer-panel").display is True
            assert screen.query_one("#findings-list").display is False

    asyncio.run(_run())


def test_empty_selection_does_not_start_run(tmp_path):
    """Running with no analyzers selected is a no-op (no worker, no token bump)."""
    tap_path = str(tmp_path / "stored.tap")
    _write_tap_with_stored_finding(tap_path)

    async def _run() -> None:
        app = FriTapApp(replay_file=tap_path)
        async with app.run_test() as pilot:
            from friTap.tui.widgets.analyzer_panel import AnalyzerPanel
            from textual.widgets import SelectionList

            screen = app.screen
            await pilot.press("a")
            await pilot.pause()

            panel = screen.query_one("#analyzer-panel", AnalyzerPanel)
            panel.query_one("#analyzer-select", SelectionList).deselect_all()
            await pilot.pause()
            assert panel.selected_names() == []

            before = screen._analyzer_run_id
            panel.action_run()
            await pilot.pause()
            # Guard fires before the run token is bumped / cache touched.
            assert screen._analyzer_run_id == before
            assert screen._findings_cache is None

    asyncio.run(_run())


def test_dashboard_chips_map_to_exact_filters(tmp_path):
    """Severity chips are exact-bucket (not a floor); source/category exact-set."""
    tap_path = str(tmp_path / "stored.tap")
    _write_tap_with_stored_finding(tap_path)

    async def _run() -> None:
        from friTap.tui.widgets.analyzer_panel import AnalyzerPanel
        from textual.widgets import Button

        app = FriTapApp(replay_file=tap_path)
        async with app.run_test() as pilot:
            await pilot.press("a")
            await pilot.pause()
            panel = app.screen.query_one("#analyzer-panel", AnalyzerPanel)
            # A category name with a dot would have crashed an id-encoded scheme.
            summary = {
                "total": 3,
                "by_severity": {"high": 2, "critical": 1},
                "by_source": {"my scanner": 3},
                "by_category": {"a.b": 3},
            }
            panel.show_dashboard(summary)
            await pilot.pause()

            chips = [b for b in panel.query(Button) if b.id and b.id.startswith("chip-")]
            assert chips, "expected dashboard chips"

            # Severity chip → exact bucket, NOT a floor.
            sev_id = next(b.id for b in chips if str(b.label).startswith("HIGH"))
            flt = panel._chip_filters[sev_id]
            assert flt.severities == frozenset({"high"})
            assert flt.min_severity is None

            # Source chip with a space recovers the full name.
            src_id = next(b.id for b in chips if str(b.label).startswith("my scanner"))
            assert panel._chip_filters[src_id].sources == frozenset({"my scanner"})

            # Distinct action-button ids (no duplicate-id collision with chooser).
            ids = {b.id for b in panel.query(Button)}
            assert "analyzer-rerun-btn" in ids and "analyzer-clearall-btn" in ids

    asyncio.run(_run())


def test_save_preserves_stored_findings_after_run(tmp_path):
    """Re-saving after a session run keeps the .tap's original stored findings."""
    tap_path = str(tmp_path / "stored.tap")
    _write_tap_with_stored_finding(tap_path)
    out_path = str(tmp_path / "exported.tap")

    async def _run() -> None:
        app = FriTapApp(replay_file=tap_path)
        async with app.run_test() as pilot:
            screen = app.screen
            await pilot.pause()

            # Simulate a session analyzer run (replace-per-run cache) that found
            # a NEW finding — distinct from the stored one.
            session = Finding(
                severity=Severity.MEDIUM,
                title="SESSION-MARKER",
                description="found during this session",
                source="ioc",
                flow_id="flow-aaaa",
                metadata={"category": "network"},
            )
            screen._findings_cache = [session]

            screen._export_replay_to_tap(out_path)
            await pilot.pause()

        rt = ReplayController(out_path)
        rt.load()
        titles = {getattr(f, "title", "") for f in rt.read_all_findings()}
        # Both the original stored finding AND the session finding survive.
        assert "STORED-MARKER" in titles
        assert "SESSION-MARKER" in titles

    asyncio.run(_run())
