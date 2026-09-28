"""pcap_to_tap: cross-references, users and Secret-Chat peer on Telegram flows.

The crypto backend and message parser are faked (as in
``test_offline_meta_scoping``); the cloud records carry real synthetic TL so the
T5 extraction runs end to end through the emitter, collector and finalize pass.
"""

from __future__ import annotations

from friTap.events import DatalogEvent, EventBus
from friTap.flow.collector import FlowCollector
from friTap.offline import pcap_to_tap as p2t
from tests.unit._offline_helpers import FakeWriterState as _FakeState
from tests.unit._offline_helpers import cloud_msg as _cloud_msg
from tests.unit._offline_helpers import e2e_msg as _e2e_msg
from tests.unit._offline_helpers import patch_keylog_loaders
from tests.unit._tl_helpers import (
    HELP_GET_CONFIG,
    VECTOR,
    i32,
    msgs_ack,
    pong,
    rpc_result,
    u32,
)
from tests.unit.test_tl_users import PEER_ID, contact_user, synthetic_user

REQUEST = u32(HELP_GET_CONFIG)
USERS_RESULT = rpc_result(100, u32(VECTOR) + i32(2) + synthetic_user() + contact_user())
CARRIER = pong()
ACK = msgs_ack(101, 103)


def _fake_backend(monkeypatch, cloud_msgs, e2e_by_data):
    patch_keylog_loaders(monkeypatch)
    monkeypatch.setattr("friTap.offline.mtproto.decrypt.iter_decrypted_messages",
                        lambda pcap, keymap, stats=None, obf_keys=None, obf_max_blocks=None: iter(cloud_msgs))
    monkeypatch.setattr(
        "friTap.offline.mtproto.e2e.decrypt.iter_secret_chat_messages",
        lambda msgs, keymap, stats=None: (e2e_by_data[m.message] for m in msgs
                                          if m.message in e2e_by_data))
    from friTap.offline.mtproto import content
    monkeypatch.setattr(content, "parse_mtproto_message", lambda tl: [])
    monkeypatch.setattr(content, "parse_secret_chat_message", lambda tl: [])


def _convert(monkeypatch):
    cloud = [_cloud_msg(0, "write", REQUEST), _cloud_msg(1, "read", USERS_RESULT),
             _cloud_msg(3, "read", CARRIER), _cloud_msg(4, "write", ACK)]
    _fake_backend(monkeypatch, cloud, {CARRIER: _e2e_msg(3, "read", b"E2E")})
    bus = EventBus()
    collector = FlowCollector(event_bus=bus)
    collector.use_event_clock(True)
    bus.subscribe(DatalogEvent, collector.on_data)
    state = _FakeState()
    p2t._emit_mtproto_streams("cap.pcap", "k", bus=bus, state=state,
                              result=p2t.ConvertResult(tap_path="out.tap"))
    flows = collector.live_flows()
    p2t._attach_telegram_meta(flows, state.mtproto_meta, state.telegram_e2e_meta,
                              ledger=state.telegram_ledger)
    p2t._finalize_telegram_refs(flows, state.telegram_refs)
    return {f.layer(f.transport).envelope["record_seq"]: f for f in flows
            if f.transport in ("mtproto", "telegram_e2e")}


def _layer(flow):
    return flow.layer(flow.transport)


def test_rpc_result_and_request_link_with_flow_ids(monkeypatch):
    by_seq = _convert(monkeypatch)
    answers = _layer(by_seq[2]).refs["answers"]
    assert answers == [{"msg_id": f"0x{100:016x}", "record_seq": 1,
                        "method": "help.getConfig", "flow_id": by_seq[1].flow_id}]
    assert _layer(by_seq[2]).refs["request_method"] == "help.getConfig"
    answered_by = _layer(by_seq[1]).refs["answered_by"]
    # A Vector result has no constructor name, so the method falls back to rpc_result.
    assert answered_by == [{"msg_id": f"0x{101:016x}", "record_seq": 2,
                            "method": "rpc_result", "flow_id": by_seq[2].flow_id}]


def test_ack_refs_resolve_to_flows(monkeypatch):
    by_seq = _convert(monkeypatch)
    ack_seq = max(by_seq)
    acks = _layer(by_seq[ack_seq]).refs["acks"]
    assert [a["flow_id"] for a in acks] == [by_seq[2].flow_id, by_seq[3].flow_id]
    assert _layer(by_seq[3]).refs["acked_by"][0]["flow_id"] == by_seq[ack_seq].flow_id


def test_users_are_attached_to_the_packet_that_carried_them(monkeypatch):
    by_seq = _convert(monkeypatch)
    users = _layer(by_seq[2]).users
    assert [u["first_name"] for u in users] == ["Alice", "Bob"]
    assert "self" in users[0]["flags"]
    assert _layer(by_seq[1]).users == []


def test_e2e_flow_infers_peer_when_no_encrypted_chat(monkeypatch):
    """With no ``encryptedChat*`` object on the wire, the peer is inferred from the
    single non-self user in the directory (Bob) and tagged ``heuristic``."""
    by_seq = _convert(monkeypatch)
    e2e = next(f for f in by_seq.values() if f.transport == "telegram_e2e")
    layer = _layer(e2e)
    carried = layer.refs["carried_in"]
    assert carried["record_seq"] == 3 and carried["flow_id"] == by_seq[3].flow_id
    assert _layer(by_seq[3]).refs["carries"] == [
        {"record_seq": layer.envelope["record_seq"], "flow_id": e2e.flow_id}]
    assert [u["first_name"] for u in layer.users] == ["Alice", "Bob"]
    assert layer.peer["user_id"] == PEER_ID
    assert layer.peer["label"] == "Bob"
    assert layer.peer["matched_by"] == "heuristic"
    assert layer.peer["confidence"] == "single"
    assert layer.peer["chat_id"] == 4242


def test_apply_e2e_peer_prefers_keylog_peer_id():
    """A keylog ``peer_user_id`` (4th field) beats the wire link and the heuristic,
    tagging the peer ``matched_by="keylog"`` — works for pre-existing chats."""
    from types import SimpleNamespace

    from friTap.offline.mtproto.tl import decode_tl
    from friTap.offline.mtproto.tl.users import extract_users, merge_user_directory

    directory = merge_user_directory(extract_users(decode_tl(synthetic_user()))
                                     + extract_users(decode_tl(contact_user())))
    refs_state = SimpleNamespace(e2e_chats={7: ("", 4242, PEER_ID)}, chat_nodes=[])
    layer = SimpleNamespace(peer=None, users=None)
    p2t._apply_e2e_peer(layer, refs_state, 7, directory)
    assert layer.peer["user_id"] == PEER_ID
    assert layer.peer["matched_by"] == "keylog"
    assert layer.peer["label"] == "Bob"


def test_finalize_without_refs_state_is_a_no_op():
    p2t._finalize_telegram_refs([object()], None)


def test_cloud_flow_users_add_self_and_referenced_message_users():
    class _Layer:
        messages = [{"sender_id": 987654321, "peer_id": 0}]

    directory = {123456789: {"id": 123456789, "flags": ["self"]},
                 987654321: {"id": 987654321, "flags": []}}
    users = p2t._cloud_flow_users(_Layer(), [], directory)
    assert [u["id"] for u in users] == [123456789, 987654321]
