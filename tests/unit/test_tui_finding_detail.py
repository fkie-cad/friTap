#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Tests for the analyzer finding-detail view and its navigation.

Covers:
* ``_try_base64`` decoding (incl. an HTTP Basic-auth scheme prefix);
* the finding-detail body includes a decoded value when base64 mode is on;
* a regression guard that the widget does NOT override Textual's internal
  ``Widget._render`` (doing so returns a ``None`` visual and crashes rendering);
* the navigation hierarchy through the Textual app harness:
  findings → finding-detail → (d) flow-detail → (Esc) finding-detail →
  (Esc) findings; and filtered → (Esc) all → (Esc) flows.
"""

from __future__ import annotations

import asyncio
import base64

import pytest

pytest.importorskip("textual")

from friTap.analysis import Finding, Severity
from friTap.flow.models import Flow, FlowState
from friTap.flow.tap_writer import TapWriter
from friTap.tui.app import FriTapApp
from friTap.tui.widgets.analyzer_finding_detail import (
    AnalyzerFindingDetailWidget,
    _try_base64,
)


def _mkflow(fid: str) -> Flow:
    return Flow(flow_id=fid, connection_id=fid, src_addr="10.0.0.1", src_port=1234,
                dst_addr="93.184.216.34", dst_port=443, state=FlowState.COMPLETE)


def _write_tap(path: str) -> None:
    b64 = base64.b64encode(b"admin:s3cret").decode()
    cred = Finding(
        severity=Severity.CRITICAL, title="Basic auth credential",
        description="HTTP Basic auth observed", source="credentials",
        flow_id="flow-aaaa", metadata={"category": "secret"},
        evidence={"matched_data": "Basic " + b64, "location": "Authorization"},
    )
    ioc = Finding(
        severity=Severity.MEDIUM, title="Flagged domain", description="bad.example",
        source="ioc", flow_id="flow-bbbb", metadata={"category": "network"},
        evidence={"value": "bad.example"},
    )
    writer = TapWriter()
    writer.open(path, target="test")
    writer.write_flow(_mkflow("flow-aaaa"))
    writer.write_flow(_mkflow("flow-bbbb"))
    writer.write_findings("flow-aaaa", [cred])
    writer.write_findings("flow-bbbb", [ioc])
    writer.close()


# ----------------------------------------------------------------------
# Pure-function / widget-unit tests (no app needed)
# ----------------------------------------------------------------------

def test_try_base64_handles_scheme_prefix():
    b64 = base64.b64encode(b"admin:s3cret").decode()
    assert _try_base64("Basic " + b64) == "admin:s3cret"
    assert _try_base64(b64) == "admin:s3cret"
    assert _try_base64("not base64!") is None
    assert _try_base64("") is None


def test_does_not_override_textual_render():
    # Regression: a method named ``_render`` shadows Textual's internal
    # Widget._render and returns a None visual → render crash.
    assert "_render" not in AnalyzerFindingDetailWidget.__dict__


def test_body_lines_include_decoded_value_when_enabled():
    b64 = base64.b64encode(b"admin:s3cret").decode()
    finding = Finding(
        severity=Severity.CRITICAL, title="Basic auth", description="d",
        source="credentials", flow_id="x", metadata={"category": "secret"},
        evidence={"matched_data": "Basic " + b64},
    )
    w = AnalyzerFindingDetailWidget()
    w._finding = finding
    w._flow = None

    w._decode = False
    assert not any("admin:s3cret" in line for line in w._body_lines())

    w._decode = True
    decoded_lines = w._body_lines()
    assert any("admin:s3cret" in line for line in decoded_lines)


# ----------------------------------------------------------------------
# Navigation through the app harness
# ----------------------------------------------------------------------

def test_finding_opens_detail_and_navigation_hierarchy(tmp_path):
    tap = str(tmp_path / "findings.tap")
    _write_tap(tap)

    async def _run() -> None:
        app = FriTapApp(replay_file=tap)
        async with app.run_test(size=(170, 50)) as pilot:
            scr = app.screen
            await pilot.pause()
            scr.action_toggle_findings_view()
            await pilot.pause()
            fl = scr.query_one("#findings-list")

            # Enter on a finding → finding-detail (NOT the regular flow-detail).
            scr.on_findings_list_widget_finding_selected(fl.FindingSelected(0, "flow-aaaa"))
            await pilot.pause()
            assert scr.query_one("#finding-detail").display is True
            assert scr.query_one("#flow-detail").display is False

            # 'd' → switch to the regular flow-detail view (origin recorded).
            scr.query_one("#finding-detail").action_open_full_detail()
            await pilot.pause()
            assert scr.query_one("#flow-detail").display is True
            assert scr._detail_origin == "finding"

            # Esc → back to the finding-detail (not the flow list).
            scr.action_escape_action()
            await pilot.pause()
            assert scr.query_one("#finding-detail").display is True

            # Esc → back to the findings list.
            scr.action_escape_action()
            await pilot.pause()
            assert scr.query_one("#findings-list").display is True

            # Filter (category), then Esc steps: filtered → all → flow list.
            from friTap.analysis.filtering import FindingFilter
            scr._apply_findings_filter(FindingFilter(categories=frozenset({"secret"})), "secret")
            await pilot.pause()
            assert fl.has_filter is True

            scr.action_escape_action()
            await pilot.pause()
            assert fl.has_filter is False
            assert scr.query_one("#findings-list").display is True

            scr.action_escape_action()
            await pilot.pause()
            assert scr.query_one("#flow-list").display is True

    asyncio.run(_run())
