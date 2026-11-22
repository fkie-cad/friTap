#!/usr/bin/env python3

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
from friTap.tui.app import FriTapApp
from tests.unit._tui_flow_helpers import make_flow as _make_flow, write_tap

# ----------------------------------------------------------------------
# Fixtures
# ----------------------------------------------------------------------

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

    write_tap(path, [flow_a, flow_b],
              findings={"flow-aaaa": [creds, net], "flow-bbbb": [pii]})


def _write_tap_without_findings(path: str) -> None:
    write_tap(path, [_make_flow("flow-cccc", 443)])


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
            from textual.widgets import Static

            from friTap.tui.widgets.findings_list import FindingsListWidget

            screen = app.screen
            findings_list = screen.query_one("#findings-list", FindingsListWidget)

            await pilot.press("shift+f")
            await pilot.pause()
            assert findings_list.total_count == 0

            title = screen.query_one("#activity-title", Static)
            rendered = str(title.render())
            assert "--scan" in rendered

    asyncio.run(_run())


def test_findings_list_renders_markup_metachars_without_crash():
    """A finding whose data contains Rich markup (e.g. a stray ``[/]``) must not
    crash the markup-rendered DataTable — every user-derived cell is escaped."""
    from textual.app import App, ComposeResult

    from friTap.tui.widgets.findings_list import FindingsListWidget

    class _Harness(App):
        def compose(self) -> ComposeResult:
            yield FindingsListWidget(id="fl")

    findings = [
        Finding(
            severity=Severity.CRITICAL,
            title="token leak [/] here",
            description="d",
            source="cred[x]",
            flow_id="flow-aaaa",
            evidence={"matched_data": "Basic [/] dXNlcjpwYXNz"},
            metadata={"category": "sec[t]"},
        ),
        Finding(
            severity=Severity.LOW, title="ok", description="ok",
            source="ioc", flow_id="flow-bbbb", evidence={"value": "1.2.3.4"},
        ),
    ]

    async def _run() -> None:
        app = _Harness()
        async with app.run_test(size=(170, 55)) as pilot:
            fl = app.query_one("#fl", FindingsListWidget)
            fl.add_findings(findings)
            await pilot.pause()
            await pilot.pause()  # forces a full row render; pre-fix raised MarkupError
            assert fl.total_count == 2
            assert fl.row_count == 2

    asyncio.run(_run())
