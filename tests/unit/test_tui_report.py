#!/usr/bin/env python3

"""
Tests for the in-TUI MASVS surfacing and the Report modal:

* the finding-detail body shows a MASVS line for a mapped finding (and nothing
  for an unmapped one);
* pressing ``R`` opens the Report modal on a replay, its body carries the
  rendered digest (with MASVS tags), and ``f`` cycles the focus.
"""

from __future__ import annotations

import asyncio

import pytest

pytest.importorskip("textual")

from friTap.analysis import Finding, Severity
from friTap.flow.layers import TlsLayer
from friTap.tui.app import FriTapApp
from friTap.tui.widgets.analyzer_finding_detail import AnalyzerFindingDetailWidget
from tests.unit._digest_helpers import http_flow, write_tap


def _write_tap(path: str) -> None:
    # The digest RE-ANALYZES flows (it does not read stored findings), so the
    # tap must carry real content: a weak-TLS flow (-> tls_hygiene MASVS-NETWORK-1)
    # and a Bearer token (-> credentials MASVS-AUTH-1/CRYPTO-1).
    weak = http_flow("f1", host="legacy.example.com", url="/ping")
    weak.add_layer(TlsLayer(version="TLS 1.0", cipher="TLS_RSA_WITH_RC4_128_SHA"))
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig"
    secret = http_flow("f2", host="api.example.com", url="/v2/me",
                       headers={"authorization": f"Bearer {jwt}"})
    secret.add_layer(TlsLayer(version="TLS 1.3", cipher="TLS_AES_128_GCM_SHA256"))
    write_tap(str(path), [weak, secret])


# ----------------------------------------------------------------------
# MASVS in the finding-detail body (direct widget, no app)
# ----------------------------------------------------------------------

def test_finding_detail_shows_masvs_for_mapped_finding():
    f = Finding(severity=Severity.HIGH, title="Bearer token in Authorization header",
                description="d", source="credentials", flow_id="x",
                metadata={"category": "secret"})
    w = AnalyzerFindingDetailWidget()
    w._finding = f
    w._flow = None
    body = "\n".join(w._body_lines())
    assert "MASVS" in body and "MASVS-AUTH-1" in body


def test_finding_detail_no_masvs_for_unmapped_finding():
    f = Finding(severity=Severity.INFO, title="Domain: x.example", description="d",
                source="ioc", flow_id="x", metadata={"category": "network"})
    w = AnalyzerFindingDetailWidget()
    w._finding = f
    w._flow = None
    assert "MASVS" not in "\n".join(w._body_lines())


# ----------------------------------------------------------------------
# Report modal through the app harness
# ----------------------------------------------------------------------

def test_report_modal_opens_and_cycles_focus(tmp_path):
    tap = str(tmp_path / "r.tap")
    _write_tap(tap)

    async def _run() -> None:
        from textual.widgets import Static

        from friTap.tui.modals.report_modal import ReportModal

        app = FriTapApp(replay_file=tap)
        async with app.run_test(size=(170, 50)) as pilot:
            scr = app.screen
            await pilot.pause()

            scr.action_report_digest()
            await pilot.pause()
            assert isinstance(app.screen, ReportModal)

            # the body widget exists and the rendered digest carries MASVS tags
            app.screen.query_one("#report-body", Static)
            assert "MASVS" in app.screen._markdown()
            assert app.screen._focus == "all"

            app.screen.action_cycle_focus()
            await pilot.pause()
            assert isinstance(app.screen, ReportModal)
            assert app.screen._focus == "security"

            app.screen.action_cancel()
            await pilot.pause()
            assert not isinstance(app.screen, ReportModal)

    asyncio.run(_run())
