#!/usr/bin/env python3

"""Replay of per-packet message-stream rows keeps the packet's real direction.

A .tap summary of a *received* MTProto / Secret-Chat packet records only a
response side. ``MainScreen.reload_replay`` rebuilds a synthetic flow from each
summary for the flow list; it used to always attach a request stub, so every
received packet showed ``sent`` in the Status column. Synthetic bytes only.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from friTap.flow.tap_format import FlowSummary

pytest.importorskip("textual")

from friTap.tui.screens import main_screen as ms  # noqa: E402
from friTap.tui.widgets.flow_list import FlowListWidget  # noqa: E402


def _summary(flow_id, transport, has_request, has_response, method="decryptedMessage",
             protocol="Telegram-E2E", flow_method=""):
    return FlowSummary(
        flow_id=flow_id, connection_id="c", src_addr="10.0.0.1", src_port=1,
        dst_addr="10.0.0.2", dst_port=2, ssl_session_id="s", started=1.0, ended=1.0,
        transport=transport, protocol=protocol, method=method, total_size=0,
        has_request=has_request, has_response=has_response, flow_method=flow_method,
    )


class _FakeReplay:
    def __init__(self, summaries):
        self._summaries = summaries
        self.flow_count = len(summaries)

    def load(self):
        pass

    def get_summaries(self):
        return list(self._summaries)

    def get_flow(self, flow_id):
        return None


class _FakeList:
    def __init__(self):
        self.flows = []

    def clear_flows(self):
        pass

    def add_or_update_flow(self, flow, summary=None):
        self.flows.append(flow)

    def update(self, *_a, **_k):
        pass


def _replay(monkeypatch, summaries):
    from friTap.tui import replay_controller

    monkeypatch.setattr(replay_controller, "ReplayController", lambda path: _FakeReplay(summaries))
    screen = ms.MainScreen.__new__(ms.MainScreen)
    fake_list = _FakeList()
    monkeypatch.setattr(screen, "query_one", lambda *a, **k: fake_list, raising=False)
    monkeypatch.setattr(screen, "_update_capture_indicator", lambda: None, raising=False)
    monkeypatch.setattr(screen, "notify", lambda *a, **k: None, raising=False)
    monkeypatch.setattr(screen, "_activate_flow_view", lambda: None, raising=False)
    screen.reload_replay("x.tap")
    return {f.flow_id: f for f in fake_list.flows}


def test_is_received_message_summary():
    recv = _summary("r", "telegram_e2e", False, True)
    sent = _summary("s", "telegram_e2e", True, False)
    paired = _summary("p", "mtproto", True, True)
    tls = _summary("t", "tls", False, True)
    flow = SimpleNamespace
    assert ms._is_received_message_summary(flow(transport="telegram_e2e"), recv)
    assert not ms._is_received_message_summary(flow(transport="telegram_e2e"), sent)
    assert not ms._is_received_message_summary(flow(transport="mtproto"), paired)
    assert not ms._is_received_message_summary(flow(transport="tls"), tls)


def test_replay_status_column_shows_real_direction(monkeypatch):
    flows = _replay(monkeypatch, [
        _summary("sent", "telegram_e2e", True, False),
        _summary("recv", "telegram_e2e", False, True),
        _summary("mt_recv", "mtproto", False, True, method="rpc_result", protocol="MTProto"),
        _summary("legacy", "telegram_e2e", True, True),
    ])
    fmt = FlowListWidget.__new__(FlowListWidget)._format_status
    assert fmt(flows["sent"]) == "sent"
    assert fmt(flows["recv"]) == "recv"
    assert fmt(flows["mt_recv"]) == "recv"
    assert fmt(flows["legacy"]) == "sent"  # legacy paired: request-first, unchanged


def test_replay_received_row_keeps_protocol_and_method(monkeypatch):
    flows = _replay(monkeypatch, [
        _summary("mt_recv", "mtproto", False, True, method="rpc_result", protocol="MTProto"),
    ])
    f = flows["mt_recv"]
    assert f.request is None
    assert f.response is not None and not f.response.is_request
    assert f.display_protocol == "MTProto"
    assert f.flow_method == "rpc_result"
