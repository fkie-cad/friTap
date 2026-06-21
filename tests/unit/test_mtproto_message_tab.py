#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Unit tests for MTProto/Telegram TUI refinement (Message tab + Method column).

Covers the consumer side of the shared message-dict contract
(``direction``/``timestamp``/``kind``/``body``/``method``/``sender``):

* The generalised Message tab (``FlowDetailWidget._render_message_tab``) renders
  ANY message-bearing layer (Signal / MTProto / Telegram-E2E) with the Signal
  presentation, and shows a generic empty state for a flow with no messages.
* The flow-level Method scalar derivation
  (``friTap.flow.display.method_from_messages`` and ``display_method_layered``)
  with the documented chat > RPC > updates > service priority.
* ``display_protocol_layered`` layered-only-when-nested behaviour: a plain cloud
  MTProto flow stays "MTProto"; a Telegram-E2E layer inside MTProto nests.

The Message-tab assertions instantiate ``FlowDetailWidget`` via ``__new__`` and
drive the render method with a fake RichLog (no Textual app needed), mirroring
the lightweight-stub style used elsewhere in tests/unit.
"""

from __future__ import annotations

import pytest

from friTap.flow.models import Flow, FlowSummary
from friTap.flow.layers import MtprotoLayer, TelegramE2ELayer
from friTap.flow import display


# ---------------------------------------------------------------------------
# Fake RichLog — renders each write() (markup string OR Rich renderable, e.g. a
# chat-bubble Table/Panel) to visible text so substring assertions work.
# ---------------------------------------------------------------------------

from tests.unit._render_helpers import RenderingFakeLog as _FakeLog


def _mtproto_flow(messages, **layer_kwargs) -> Flow:
    flow = Flow(flow_id="mt")
    layer = MtprotoLayer(transport=layer_kwargs.pop("transport", "abridged"), **layer_kwargs)
    layer.messages = messages
    flow.add_layer(layer)
    return flow


def _make_widget():
    """A FlowDetailWidget instance with a fake message log, no Textual app."""
    from friTap.tui.widgets.flow_detail import FlowDetailWidget
    w = FlowDetailWidget.__new__(FlowDetailWidget)
    w._message_log = _FakeLog()
    return w


# ---------------------------------------------------------------------------
# Message tab rendering
# ---------------------------------------------------------------------------

def test_message_tab_renders_mtproto_conversation():
    """An MTProto flow renders the unified CONVERSATION view: a participants
    header, a CHAT-only message flow, a Participants detail block, and a
    collapsed transport summary."""
    flow = _mtproto_flow([
        {"direction": "write", "timestamp": 0, "kind": "text",
         "body": "fritapP3CLOUD2026FRESH", "method": "messages.sendMessage"},
        {"direction": "write", "timestamp": 0, "kind": "text",
         "body": "fritapP3SECRET2026FRESH", "method": "messages.sendMessage"},
        {"direction": "read", "timestamp": 0, "kind": "user", "sender": "1",
         "body": "Evil kneebel (+4915155912510) [you] · online (until 1781540223)",
         "method": "user"},
        {"direction": "read", "timestamp": 0, "kind": "user", "sender": "2",
         "body": "db Forscher (+4915738796832) [contact] [mutual] · online (until 1781540185)",
         "method": "user"},
        {"direction": "read", "timestamp": 0, "kind": "ack",
         "body": "", "method": "msgs_ack"},
    ])
    w = _make_widget()
    w._render_message_tab(flow)
    lines = w._message_log.lines
    blob = "\n".join(lines)

    assert "Not a Signal flow" not in blob
    # Header: protocol + chat descriptor + CHAT-only count (the two texts; the
    # user identities and the ack are NOT counted as chat messages).
    assert "MTProto · cloud" in blob
    assert "2 messages" in blob
    # Participants header line, derived from the user items (self = [you]).
    # The self name and "(you)" render as separate (accent / dim) spans, and the
    # two sides are joined by the dimmed "⇄" connector.
    assert "Evil kneebel" in blob
    assert "(you)" in blob
    assert "⇄" in blob
    assert "db Forscher" in blob
    # Both chat bodies surfaced in the flow as outgoing rows.
    assert "fritapP3CLOUD2026FRESH" in blob
    assert "fritapP3SECRET2026FRESH" in blob
    assert any("→" in ln for ln in lines)
    # The user items appear in the Participants detail block (full body with
    # phone/flags/last-seen), NOT as flow rows.
    assert "Participants" in blob
    assert "+4915155912510" in blob
    assert "+4915738796832" in blob
    # Exactly two chat bubbles render (one bordered box each); the user
    # identities are participants, not flow rows.
    chat_bubbles = [ln for ln in lines if "╭" in ln]
    assert len(chat_bubbles) == 2
    # The msgs_ack is collapsed into a single transport-summary line, not a row.
    assert "transport record" in blob
    assert "1 ack" in blob


def test_message_tab_empty_state_is_generic():
    """A flow with no message-bearing layer shows the generic empty state."""
    flow = Flow(flow_id="bare")
    w = _make_widget()
    w._render_message_tab(flow)
    blob = "\n".join(w._message_log.lines)
    assert "No decrypted messages in this flow" in blob
    assert "Not a Signal flow" not in blob


def test_message_tab_empty_state_when_layer_has_no_messages():
    """An MTProto layer present but carrying NO messages -> generic empty state."""
    flow = _mtproto_flow([])
    w = _make_widget()
    w._render_message_tab(flow)
    blob = "\n".join(w._message_log.lines)
    assert "No decrypted messages in this flow" in blob


def test_message_tab_secret_chat_descriptor_for_e2e():
    """A Telegram-E2E layer shows the 'Secret Chat' descriptor."""
    flow = Flow(flow_id="tg")
    flow.add_layer(MtprotoLayer(transport="abridged"))
    e2e = TelegramE2ELayer(chat_id=7)
    e2e.messages = [{"direction": "write", "timestamp": 0, "kind": "text",
                     "body": "secret-hello", "method": "sendEncrypted"}]
    flow.add_layer(e2e)
    w = _make_widget()
    w._render_message_tab(flow)
    blob = "\n".join(w._message_log.lines)
    assert "Telegram · Secret Chat" in blob
    assert "secret-hello" in blob


def test_message_tab_tolerates_missing_method_and_sender():
    """Partly-enriched dicts (no method / sender) still render without error."""
    flow = _mtproto_flow([
        {"direction": "write", "timestamp": 0, "kind": "text", "body": "hi"},
        {"direction": "read", "kind": "text", "body": "yo"},  # no timestamp either
    ])
    w = _make_widget()
    w._render_message_tab(flow)
    blob = "\n".join(w._message_log.lines)
    assert "hi" in blob and "yo" in blob
    assert "2 messages" in blob


def test_message_tab_signal_participants_from_senders():
    """A Signal-style flow (no `user` items) derives participants from the
    distinct senders of received messages plus a synthetic 'you' for outgoing."""
    from friTap.flow.layers import SignalLayer

    flow = Flow(flow_id="sig")
    layer = SignalLayer(chat_type="individual")
    layer.messages = [
        {"direction": "read", "timestamp": 0, "kind": "data",
         "body": "Technologie Forum", "sender": "uuid-zu"},
        {"direction": "write", "timestamp": 0, "kind": "data",
         "body": "reply", "sender": ""},
        {"direction": "read", "timestamp": 0, "kind": "receipt", "body": ""},
        {"direction": "read", "timestamp": 0, "kind": "receipt", "body": ""},
    ]
    flow.add_layer(layer)

    w = _make_widget()
    w._render_message_tab(flow)
    lines = w._message_log.lines
    blob = "\n".join(lines)

    assert "Signal" in blob
    # Two chat messages (data); receipts collapse to transport.
    assert "2 messages" in blob
    # Participants header: self (you) <-> the received sender, joined by "⇄".
    assert "(you)" in blob
    assert "⇄" in blob
    assert "uuid-zu" in blob
    # Sender-derived participant appears in the detail block.
    assert "Participants" in blob
    assert "uuid-zu" in blob
    # Received chat body in the flow.
    assert "Technologie Forum" in blob
    # The two receipts collapse into the transport summary.
    assert "2 receipts" in blob or "transport record" in blob


def test_message_tab_no_chat_messages_shows_no_messages_marker():
    """A layer that carries only transport/identity records (no CHAT kinds)
    shows the '(no messages)' flow marker but still renders participants."""
    flow = _mtproto_flow([
        {"direction": "read", "timestamp": 0, "kind": "user", "sender": "9",
         "body": "Solo User (+49123) [you]", "method": "user"},
        {"direction": "read", "timestamp": 0, "kind": "ack", "body": "",
         "method": "msgs_ack"},
        {"direction": "read", "timestamp": 0, "kind": "rpc", "body": "",
         "method": "users.getUsers"},
    ])
    w = _make_widget()
    w._render_message_tab(flow)
    blob = "\n".join(w._message_log.lines)

    assert "0 messages" in blob
    assert "(no messages)" in blob
    # Participants still derived from the user item (name + "(you)" spans).
    assert "Solo User" in blob
    assert "(you)" in blob
    assert "Participants" in blob
    # Transport collapsed.
    assert "transport record" in blob


def test_group_sender_id_resolves_to_name():
    """A group chat row whose ``sender`` is a numeric id is attributed to the
    matching ``kind=="user"`` record's display name, not the raw id."""
    flow = _mtproto_flow([
        {"direction": "read", "timestamp": 0, "kind": "text",
         "body": "hello group", "sender": "42", "peer_id": 100,
         "method": "updateShortChatMessage"},
        {"direction": "read", "timestamp": 0, "kind": "user", "sender": "42",
         "user_id": 42, "body": "Alice (+4915) [contact]", "method": "user"},
    ])
    w = _make_widget()
    w._render_message_tab(flow)
    blob = "\n".join(w._message_log.lines)
    assert "from Alice" in blob
    assert "from 42" not in blob


def test_transport_summary_uses_portable_glyph():
    """The transport summary line uses a portable marker, not the fullwidth
    '＋' (U+FF0B) that some terminal fonts render as a '?' box."""
    flow = _mtproto_flow([
        {"direction": "write", "timestamp": 0, "kind": "text", "body": "hi"},
        {"direction": "read", "timestamp": 0, "kind": "ack", "body": "",
         "method": "msgs_ack"},
    ])
    w = _make_widget()
    w._render_message_tab(flow)
    blob = "\n".join(w._message_log.lines)
    assert "＋" not in blob          # no fullwidth plus
    assert "transport record" in blob


def test_raw_layer_view_shows_method_for_transport():
    """The raw layer view names WHICH rpc/service/ack each transport record is
    (the TL ``method``) and prints a one-line category legend."""
    from friTap.tui.widgets.flow_detail import FlowDetailWidget
    w = FlowDetailWidget.__new__(FlowDetailWidget)
    layer = MtprotoLayer(transport="abridged")
    layer.messages = [
        {"direction": "read", "kind": "rpc", "body": "", "method": "users.getUsers"},
        {"direction": "read", "kind": "service", "body": "",
         "method": "new_session_created"},
        {"direction": "read", "kind": "ack", "body": "", "method": "msgs_ack"},
    ]
    log = _FakeLog()
    w._render_layer_parsed(log, layer, 0)
    blob = "\n".join(log.lines)
    assert "users.getUsers" in blob
    assert "new_session_created" in blob
    # Category legend present when transport kinds are shown.
    assert "rpc = rpc_result" in blob


def test_l_key_opens_raw_layer_view_from_message_tab():
    """Pressing 'l' off the Layers tab switches to it (landing on the
    message-bearing layer); on the Layers tab it flips parsed/hex."""
    from friTap.tui.widgets.flow_detail import (
        FlowDetailWidget, _TAB_MESSAGE, _TAB_LAYERS,
    )
    w = FlowDetailWidget.__new__(FlowDetailWidget)
    flow = _mtproto_flow([{"direction": "read", "kind": "text", "body": "hi"}])
    w._current_flow = flow
    w._current_layer_idx = 0
    w._layer_view = {}

    class _Tabs:
        active = _TAB_MESSAGE
    w._tabs = _Tabs()
    rerendered = {"n": 0}
    w._rerender_layers = lambda: rerendered.__setitem__("n", rerendered["n"] + 1)

    # From the Message tab: jump to the raw layer view.
    w.action_toggle_layer_view()
    assert w._tabs.active == _TAB_LAYERS
    assert rerendered["n"] == 1

    # Now on the Layers tab: 'l' flips the focused layer's view.
    default = w._default_layer_view(flow.layers[0])
    w.action_toggle_layer_view()
    assert w._layer_view[0] != default
    assert rerendered["n"] == 2


# ---------------------------------------------------------------------------
# Flow Method scalar derivation
# ---------------------------------------------------------------------------

def test_method_chat_beats_service():
    flow = _mtproto_flow([
        {"direction": "read", "kind": "ack", "method": "msgs_ack", "body": ""},
        {"direction": "write", "kind": "text", "method": "messages.sendMessage",
         "body": "x"},
    ])
    assert display.method_from_messages(flow) == "messages.sendMessage"


def test_method_rpc_beats_updates_and_service():
    flow = _mtproto_flow([
        {"direction": "read", "kind": "ack", "method": "msgs_ack", "body": ""},
        {"direction": "read", "kind": "update", "method": "updates", "body": ""},
        {"direction": "read", "kind": "rpc", "method": "users.getUsers", "body": ""},
    ])
    assert display.method_from_messages(flow) == "users.getUsers"


def test_method_updates_beats_service():
    flow = _mtproto_flow([
        {"direction": "read", "kind": "ack", "method": "msgs_ack", "body": ""},
        {"direction": "read", "kind": "update", "method": "updateNewMessage",
         "body": ""},
    ])
    # updateNewMessage is classified as a chat method (carries a message).
    assert display.method_from_messages(flow) == "updateNewMessage"


def test_method_service_only():
    flow = _mtproto_flow([
        {"direction": "read", "kind": "ack", "method": "msgs_ack", "body": ""},
        {"direction": "read", "kind": "service", "method": "pong", "body": ""},
    ])
    assert display.method_from_messages(flow) in ("msgs_ack", "pong")


def test_method_missing_yields_empty():
    flow = _mtproto_flow([
        {"direction": "write", "kind": "text", "body": "hi"},  # no method
        {"direction": "read", "kind": "text", "body": "yo", "method": None},
    ])
    assert display.method_from_messages(flow) == ""


def test_display_method_layered_falls_back_to_http():
    """With no TL method, the layered Method falls back to the HTTP method."""
    class _Req:
        method = "POST"

    class _FakeFlow:
        request = _Req()
        flow_method = ""

        def layer(self, name):
            return None

    assert display.display_method_layered(_FakeFlow()) == "POST"


def test_flow_summary_carries_flow_method_scalar():
    """FlowSummary.from_flow computes + stores the derived Method scalar, and
    surfaces it via display_method without loading messages."""
    flow = _mtproto_flow([
        {"direction": "write", "kind": "text", "method": "messages.sendMessage",
         "body": "x"},
    ])
    summary = FlowSummary.from_flow(flow)
    assert summary.flow_method == "messages.sendMessage"
    assert summary.display_method == "messages.sendMessage"
    # Survives the to_dict round-trip key set.
    assert summary.to_dict()["flow_method"] == "messages.sendMessage"


# ---------------------------------------------------------------------------
# Layered protocol display (layered-only-when-nested)
# ---------------------------------------------------------------------------

def test_layered_plain_mtproto_is_bare():
    flow = _mtproto_flow([])
    assert display.display_protocol_layered(flow) == "MTProto"


def test_layered_e2e_inside_mtproto_nests():
    flow = Flow(flow_id="tg")
    flow.add_layer(MtprotoLayer(transport="abridged"))
    flow.add_layer(TelegramE2ELayer(chat_id=1))
    assert display.display_protocol_layered(flow) == "MTProto[Telegram-E2E]"


def test_layered_summary_parity_for_nested_e2e():
    """The stored scalars reproduce the nesting offline (no live layers)."""
    flow = Flow(flow_id="tg")
    flow.add_layer(MtprotoLayer(transport="abridged"))
    flow.add_layer(TelegramE2ELayer(chat_id=1))
    summary = FlowSummary.from_flow(flow)
    assert summary.outer_app_protocol == "MTProto"
    assert summary.inner_e2e_protocol == "Telegram-E2E"
    assert summary.display_protocol_layered == "MTProto[Telegram-E2E]"


def test_layered_summary_plain_mtproto_is_bare():
    flow = _mtproto_flow([])
    summary = FlowSummary.from_flow(flow)
    assert summary.display_protocol_layered == "MTProto"


# ---------------------------------------------------------------------------
# Fixture-backed verification (device-derived .tap)
# ---------------------------------------------------------------------------

_FIXTURE = "/tmp/tg_fixtures/tcap5_verify.tap"


@pytest.mark.skipif(
    not __import__("os").path.exists(_FIXTURE),
    reason="device fixture tcap5_verify.tap not present",
)
def test_fixture_mtproto_message_tab_renders_bodies():
    """The real device .tap: its MTProto flow renders chat bodies in the
    Message tab (not the Signal placeholder)."""
    from friTap.flow.replay import ReplayController
    rc = ReplayController(_FIXTURE)
    rc.load()
    # The capture has many MTProto flows; most carry only transport/identity
    # records (acks, rpc, user). The chat bodies live in ONE flow, so select the
    # flow that actually has a CHAT-kind message rather than the first flow with
    # any messages (which is transport-only and would render "0 messages").
    chat_kinds = {"text", "data", "message"}
    target = None
    for f in rc.get_flows():
        layer = f.layer("mtproto")
        msgs = getattr(layer, "messages", None) if layer is not None else None
        if msgs and any((m.get("kind") or "") in chat_kinds for m in msgs):
            target = f
            break
    assert target is not None, "expected an mtproto flow with chat messages in fixture"

    w = _make_widget()
    w._render_message_tab(target)
    blob = "\n".join(w._message_log.lines)
    assert "Not a Signal flow" not in blob
    assert "MTProto · cloud" in blob
    assert "fritapP3CLOUD2026FRESH" in blob
