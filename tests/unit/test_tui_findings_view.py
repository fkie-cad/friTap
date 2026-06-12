#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Tests for the TUI Findings Viewer.

Exercises the findings view end-to-end through the Textual app harness:
toggling into the view, the quick-filter key bindings (c/p/1), and clearing
the filter (shift+escape). Also verifies the empty-findings title hint.

Textual provides ``App.run_test()`` which returns an async context manager.
The repository has no async pytest plugin configured, so each async body is
driven from a synchronous test via ``asyncio.run``.
"""

from __future__ import annotations

import asyncio

import pytest

pytest.importorskip("textual")

from friTap.analysis import Finding, Severity
from friTap.flow.models import Flow, FlowState
from friTap.flow.tap_writer import TapWriter
from friTap.tui.app import FriTapApp


# ----------------------------------------------------------------------
# Fixtures
# ----------------------------------------------------------------------

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


def _write_tap_with_findings(path: str) -> None:
    """Write a .tap file containing two flows and three findings.

    Findings: one credentials/secret (critical), one privacy/pii (high),
    and one network finding (medium) — spanning two flows.
    """
    flow_a = _make_flow("flow-aaaa", 443)
    flow_b = _make_flow("flow-bbbb", 8443)

    creds = Finding(
        severity=Severity.CRITICAL,
        title="Hardcoded password in request body",
        description="Plaintext password observed in POST body.",
        source="credentials",
        flow_id="flow-aaaa",
        confidence=0.95,
        metadata={"category": "secret"},
    )
    pii = Finding(
        severity=Severity.HIGH,
        title="Email address leaked",
        description="A personal email address appears in the response.",
        source="privacy",
        flow_id="flow-bbbb",
        confidence=0.8,
        metadata={"category": "pii"},
    )
    net = Finding(
        severity=Severity.MEDIUM,
        title="Suspicious domain contacted",
        description="Connection to a flagged domain.",
        source="ioc",
        flow_id="flow-aaaa",
        confidence=0.6,
        metadata={"category": "network"},
    )

    writer = TapWriter()
    writer.open(path, target="test")
    writer.write_flow(flow_a)
    writer.write_flow(flow_b)
    writer.write_findings("flow-aaaa", [creds, net])
    writer.write_findings("flow-bbbb", [pii])
    writer.close()


def _write_tap_without_findings(path: str) -> None:
    writer = TapWriter()
    writer.open(path, target="test")
    writer.write_flow(_make_flow("flow-cccc", 443))
    writer.close()


# ----------------------------------------------------------------------
# Tests
# ----------------------------------------------------------------------

def test_findings_view_toggle_and_quick_filters(tmp_path):
    """shift+f opens the view; c/p/1 quick-filter; shift+escape clears."""
    tap_path = str(tmp_path / "findings.tap")
    _write_tap_with_findings(tap_path)

    async def _run() -> None:
        app = FriTapApp(replay_file=tap_path)
        async with app.run_test() as pilot:
            from friTap.tui.widgets.findings_list import FindingsListWidget

            screen = app.screen
            findings_list = screen.query_one("#findings-list", FindingsListWidget)

            # Open findings view.
            await pilot.press("shift+f")
            await pilot.pause()
            assert findings_list.display is True
            assert findings_list.total_count > 0
            total = findings_list.total_count

            # c → credentials only.
            await pilot.press("c")
            await pilot.pause()
            visible = [
                findings_list._all_findings[i] for i in findings_list._visible_indices
            ]
            assert visible, "expected at least one credentials finding"
            assert all(f.source == "credentials" for f in visible)

            # shift+escape → clear, back to total.
            await pilot.press("shift+escape")
            await pilot.pause()
            assert findings_list.visible_count == total

            # 1 → critical only.
            await pilot.press("1")
            await pilot.pause()
            visible = [
                findings_list._all_findings[i] for i in findings_list._visible_indices
            ]
            assert visible, "expected at least one critical finding"
            assert all(f.severity == Severity.CRITICAL for f in visible)

            # p → pii only (reset filter first via clear).
            await pilot.press("shift+escape")
            await pilot.pause()
            await pilot.press("p")
            await pilot.pause()
            visible = [
                findings_list._all_findings[i] for i in findings_list._visible_indices
            ]
            assert visible, "expected at least one pii finding"
            assert all((f.category == "pii") for f in visible)

    asyncio.run(_run())


def test_findings_view_empty_shows_scan_hint(tmp_path):
    """A tap with no findings has total_count==0 and a --scan title hint."""
    tap_path = str(tmp_path / "no_findings.tap")
    _write_tap_without_findings(tap_path)

    async def _run() -> None:
        app = FriTapApp(replay_file=tap_path)
        async with app.run_test() as pilot:
            from friTap.tui.widgets.findings_list import FindingsListWidget
            from textual.widgets import Static

            screen = app.screen
            findings_list = screen.query_one("#findings-list", FindingsListWidget)

            await pilot.press("shift+f")
            await pilot.pause()
            assert findings_list.total_count == 0

            title = screen.query_one("#activity-title", Static)
            rendered = str(title.render())
            assert "--scan" in rendered

    asyncio.run(_run())
