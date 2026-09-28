#!/usr/bin/env python3

"""Message tab: whole Telegram conversation + real participants (T7).

Covers the pure helpers in ``friTap.flow.telegram_conversation``, the
MainScreen cloud-chat sibling lookup, the Message tab's cloud merge and
structured participants (self user, peer, unknown-peer label), the legacy
body-string fallback, and the two cross-reference follow-ups (``contains``
heading, answering method on ``answered_by``).
"""

from __future__ import annotations

from types import SimpleNamespace

from friTap.flow import telegram_conversation as tconv
from friTap.flow.layers import MtprotoLayer, TelegramE2ELayer
from friTap.flow.models import Flow, FlowChunk
from friTap.tui.widgets.tl_tree_render import render_refs
from tests.unit._tui_flow_helpers import FakeReplay as _FakeReplay
from tests.unit._tui_flow_helpers import make_flow_detail_widget as _widget

SELF_ID, PEER_ID, OTHER_ID = 1001, 2002, 3003
SELF_USER = {"id": SELF_ID, "first_name": "Evil", "last_name": "kneebel",
             "flags": ["self"], "username": "evil"}
PEER_USER = {"id": PEER_ID, "first_name": "db", "last_name": "Forscher",
             "flags": ["contact", "mutual"]}
UNKNOWN_PEER = {"user_id": 0, "label": "peer (unknown, chat_id -1355992074)",
                "chat_id": -1355992074}


def _text(direction, body, ts, peer_id=0, sender="", **extra):
    return {"direction": direction, "kind": "text", "body": body, "timestamp": ts,
            "peer_id": peer_id, "sender": sender, "method": "sendMessage", **extra}


def _cloud_flow(flow_id, messages, users=None, flow_method="messages.sendMessage"):
    flow = Flow(flow_id=flow_id, transport="mtproto")
    flow.flow_method = flow_method
    layer = MtprotoLayer()
    layer.messages = list(messages)
    layer.users = list(users or [])
    flow.add_layer(layer)
    return flow


def _e2e_flow(flow_id, messages, users=None, peer=None):
    flow = Flow(flow_id=flow_id, transport="telegram_e2e",
                ssl_session_id="telegram_e2e:71686e79a975226b")
    for m in messages:
        flow.chunks.append(FlowChunk(b"x", m["direction"], m["timestamp"]))
    layer = TelegramE2ELayer()
    layer.messages = list(messages)
    layer.users = list(users or [])
    layer.peer = dict(peer or {})
    flow.add_layer(layer)
    return flow


def _message_tab(flow, siblings=()) -> str:
    w = _widget(siblings)
    w._render_message_tab(flow)
    return "\n".join(w._message_log.lines)


def _participants_block(text: str) -> list:
    tail = text.split("Participants", 1)[1]
    return [ln.strip() for ln in tail.splitlines() if ln.strip().startswith("•")]


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------

def test_conversation_peer_key_outbound_uses_peer_id():
    assert tconv.conversation_peer_key(_text("write", "hi", 1, peer_id=PEER_ID)) == str(PEER_ID)
    assert tconv.conversation_peer_key(_text("write", "hi", 1)) == ""


def test_conversation_peer_key_inbound_private_and_chat():
    private = _text("read", "yo", 1, peer_id=PEER_ID)
    group = _text("read", "yo", 1, peer_id=777, sender=str(PEER_ID))
    to_self = _text("read", "yo", 1, peer_id=SELF_ID, sender=str(PEER_ID))
    sender_only = _text("read", "yo", 1, sender=str(PEER_ID))
    assert tconv.conversation_peer_key(private) == str(PEER_ID)
    assert tconv.conversation_peer_key(group) == "777"
    assert tconv.conversation_peer_key(to_self, self_id=SELF_ID) == str(PEER_ID)
    assert tconv.conversation_peer_key(sender_only) == str(PEER_ID)


def test_flow_has_chat_text_for_flow_and_summary():
    assert tconv.flow_has_chat_text(_cloud_flow("a", [_text("write", "hi", 1, PEER_ID)]))
    assert not tconv.flow_has_chat_text(_cloud_flow("b", [{"kind": "ack", "body": "x"}]))
    assert tconv.flow_has_chat_text(SimpleNamespace(flow_method="updateShortMessage"))
    assert not tconv.flow_has_chat_text(SimpleNamespace(flow_method="msgs_ack"))


def test_participants_from_structured_users_self_first_with_peer():
    parts = tconv.participants_from_structured_users(
        [PEER_USER, SELF_USER, {"id": OTHER_ID, "first_name": "X"}],
        peer={"user_id": PEER_ID, "label": "db Forscher"})
    assert [(p["name"], p["is_self"]) for p in parts] == [
        ("Evil kneebel", True), ("db Forscher", False)]
    assert parts[0]["detail"].startswith("Evil kneebel (you)")


def test_participants_from_structured_users_peer_label_and_no_peer():
    parts = tconv.participants_from_structured_users([SELF_USER], peer=UNKNOWN_PEER)
    assert [p["name"] for p in parts] == ["Evil kneebel", UNKNOWN_PEER["label"]]
    everyone = tconv.participants_from_structured_users([PEER_USER, SELF_USER])
    assert [p["name"] for p in everyone] == ["Evil kneebel", "db Forscher"]


def test_heuristic_peer_is_marked_inferred():
    peer = {"user_id": PEER_ID, "label": "db Forscher", "user": PEER_USER,
            "matched_by": "heuristic", "confidence": "single"}
    parts = tconv.participants_from_structured_users([SELF_USER], peer=peer)
    inferred = parts[1]
    assert inferred["name"] == "db Forscher (likely peer — inferred)"
    assert inferred["detail"].endswith("(likely peer — inferred)")
    assert inferred["inferred"] is True
    # a wire-confirmed peer keeps its plain name
    confirmed = tconv.participants_from_structured_users(
        [SELF_USER], peer={"user_id": PEER_ID, "label": "db Forscher",
                           "user": PEER_USER, "matched_by": "key_fingerprint"})
    assert confirmed[1]["name"] == "db Forscher"
    assert "inferred" not in confirmed[1]


# ---------------------------------------------------------------------------
# Message tab: cloud merge + structured participants
# ---------------------------------------------------------------------------

def _cloud_pair():
    sent = _cloud_flow("s", [_text("write", "ping peer", 100, PEER_ID)], users=[SELF_USER])
    recv = _cloud_flow("r", [_text("read", "pong back", 200, PEER_ID)], users=[PEER_USER])
    other = _cloud_flow("o", [_text("write", "elsewhere", 150, OTHER_ID)])
    return sent, recv, other


def test_cloud_message_tab_merges_same_peer_siblings():
    sent, recv, other = _cloud_pair()
    for flow in (sent, recv):
        text = _message_tab(flow, [sent, recv, other])
        assert "2 messages" in text
        assert text.index("ping peer") < text.index("pong back")
        assert "elsewhere" not in text


def test_cloud_message_tab_dedupes_repeated_messages():
    sent, recv, _ = _cloud_pair()
    dup = _cloud_flow("d", [dict(recv.layer("mtproto").messages[0])])
    assert "2 messages" in _message_tab(sent, [sent, recv, dup])


def test_cloud_structured_participants_self_and_peer_name():
    sent, recv, _ = _cloud_pair()
    text = _message_tab(sent, [sent, recv])
    assert "Evil kneebel (you)" in text
    assert "you (you)" not in text
    bullets = _participants_block(text)
    assert bullets[0].startswith("• Evil kneebel (you)")
    assert bullets[1].startswith("• db Forscher")


def test_mtproto_flow_without_chat_text_is_not_merged():
    acks = _cloud_flow("a", [{"kind": "user", "direction": "read", "user_id": PEER_ID,
                              "body": "db Forscher (2002) [contact]", "timestamp": 1}])
    sent, _, _ = _cloud_pair()
    text = _message_tab(acks, [acks, sent])
    assert "ping peer" not in text


def test_legacy_body_string_participants_still_used_without_structured_users():
    legacy = _cloud_flow("l", [
        _text("write", "hi", 100, PEER_ID),
        {"kind": "user", "direction": "read", "user_id": SELF_ID, "timestamp": 90,
         "body": "Evil kneebel (1001) [you]", "sender": str(SELF_ID)},
        {"kind": "user", "direction": "read", "user_id": PEER_ID, "timestamp": 91,
         "body": "db Forscher (2002) [contact]", "sender": str(PEER_ID)},
    ])
    bullets = _participants_block(_message_tab(legacy))
    assert bullets == ["• Evil kneebel (1001) [you]", "• db Forscher (2002) [contact]"]


def test_legacy_flow_without_users_keeps_synthetic_you():
    text = _message_tab(_cloud_flow("l", [_text("write", "hi", 100, PEER_ID)]))
    assert "you (you)" in text


def test_sender_id_to_name_consults_structured_users():
    w = _widget()
    assert w._sender_id_to_name([], [PEER_USER]) == {str(PEER_ID): "db Forscher"}


# ---------------------------------------------------------------------------
# Secret Chat: both rows show the whole chat + participants
# ---------------------------------------------------------------------------

def test_e2e_rows_show_both_messages_and_structured_participants():
    sent = _e2e_flow("s", [_text("write", "Hi infected", 100, random_id=1)],
                     users=[SELF_USER], peer=UNKNOWN_PEER)
    recv = _e2e_flow("r", [_text("read", "hello folks", 200, random_id=2)],
                     users=[SELF_USER], peer=UNKNOWN_PEER)
    for flow in (sent, recv):
        text = _message_tab(flow, [sent, recv])
        assert "2 messages" in text
        assert text.index("Hi infected") < text.index("hello folks")
        assert "Evil kneebel (you)" in text
        bullets = _participants_block(text)
        assert bullets[0].startswith("• Evil kneebel (you)")
        assert bullets[1] == f"• {UNKNOWN_PEER['label']}"


def test_e2e_peer_label_without_self_user_keeps_you():
    sent = _e2e_flow("s", [_text("write", "Hi", 100, random_id=1)], peer=UNKNOWN_PEER)
    text = _message_tab(sent, [sent])
    assert "you (you)" in text
    assert UNKNOWN_PEER["label"] in text


def test_e2e_resolved_peer_user_is_named():
    peer = {"user_id": PEER_ID, "label": "db Forscher", "user": PEER_USER}
    sent = _e2e_flow("s", [_text("write", "Hi", 100, random_id=1)],
                     users=[SELF_USER], peer=peer)
    bullets = _participants_block(_message_tab(sent, [sent]))
    assert bullets[1].startswith("• db Forscher")


# ---------------------------------------------------------------------------
# MainScreen cloud sibling lookup
# ---------------------------------------------------------------------------

def _summary(flow):
    return SimpleNamespace(flow_id=flow.flow_id, transport=flow.transport,
                           flow_method=flow.flow_method, method="")


def test_mtproto_siblings_replay_filters_cheaply_and_by_peer():
    from friTap.tui.screens.main_screen import MainScreen
    sent, recv, other = _cloud_pair()
    ack = _cloud_flow("k", [{"kind": "ack", "body": "x"}], flow_method="msgs_ack")
    flows = [sent, recv, other, ack]
    screen = MainScreen.__new__(MainScreen)
    screen._replay_ctrl = _FakeReplay(flows, summaries=[_summary(f) for f in flows])
    sibs = screen._conversation_siblings(sent)
    assert {f.flow_id for f in sibs} == {"s", "r"}
    assert "k" not in screen._replay_ctrl.loaded_ids


def test_mtproto_siblings_live_mode_and_no_text():
    from friTap.tui.screens.main_screen import MainScreen
    sent, recv, other = _cloud_pair()
    screen = MainScreen.__new__(MainScreen)
    screen._replay_ctrl = None
    screen._capture = SimpleNamespace(
        flow_collector=SimpleNamespace(get_flows=lambda: [sent, recv, other]))
    assert {f.flow_id for f in screen._mtproto_conversation_siblings(recv)} == {"s", "r"}
    ack = _cloud_flow("k", [{"kind": "ack", "body": "x"}])
    assert screen._mtproto_conversation_siblings(ack) == []


# ---------------------------------------------------------------------------
# Cross-reference follow-ups
# ---------------------------------------------------------------------------

def _plain(lines):
    import re
    return "\n".join(re.sub(r"\[/?[a-z #0-9]*\]", "", ln) for ln in lines)


def test_render_refs_container_heading_is_contains():
    text = _plain(render_refs({"container": [{"msg_id": "0x10", "method": "pong"},
                                             {"msg_id": "0x14", "method": "msgs_ack"}]}))
    assert "contains:" in text
    assert "in container" not in text


def test_render_refs_answered_by_shows_answering_method():
    refs = {"answered_by": [{"msg_id": "0x45", "flow_id": "f69",
                             "method": "account.privacyRules"}]}
    text = _plain(render_refs(refs, row_of=lambda fid: 69 if fid == "f69" else None))
    assert "→ #69 account.privacyRules" in text
