#!/usr/bin/env python3

"""Offline Telegram side-channel messages must be scoped to their own flow.

The cloud (per 4-tuple) and Secret-Chat (per fingerprint) side-channels are
accumulated connection/chat-wide, but the collector splits that traffic into
several exchange flows. Each parsed message is tagged with the ``_chunk_key``
of the record that carried it, and ``_attach_telegram_meta`` hands each flow
only the messages whose record became one of ITS chunks.

The crypto backend and TL parser are monkeypatched with fakes (as in
``test_offline_telegram_dedup``), so no pcap fixture or dependency is needed.
"""

from __future__ import annotations

from friTap.events import DatalogEvent, EventBus
from friTap.flow.collector import FlowCollector
from friTap.flow.display import method_from_messages
from friTap.flow.models import FlowChunk
from friTap.offline import pcap_to_tap as p2t
from friTap.offline.mtproto.content import ParsedMtprotoMessage
from tests.unit._offline_helpers import TG_BASE_TS as _BASE_TS
from tests.unit._offline_helpers import TG_FINGERPRINT as _FP
from tests.unit._offline_helpers import FakeWriterState as _FakeState
from tests.unit._offline_helpers import cloud_msg as _cloud_msg
from tests.unit._offline_helpers import e2e_msg as _e2e_msg
from tests.unit._offline_helpers import patch_keylog_loaders


class _FakeFlow:
    def __init__(self, chunks) -> None:
        self.chunks = chunks


# --------------------------------------------------------------------------- #
# Unit: key + filter
# --------------------------------------------------------------------------- #

def test_chunk_key_is_deterministic_and_direction_sensitive():
    assert p2t._chunk_key("write", b"abc") == p2t._chunk_key("write", b"abc")
    assert p2t._chunk_key("write", b"abc").startswith("write:")
    assert len(p2t._chunk_key("write", b"abc").split(":")[1]) == 16
    assert p2t._chunk_key("write", b"abc") != p2t._chunk_key("read", b"abc")
    assert p2t._chunk_key("write", b"abc") != p2t._chunk_key("write", b"abd")


def test_scope_keeps_only_the_flows_own_messages_and_strips_key():
    flow = _FakeFlow([FlowChunk(data=b"A", direction="write", timestamp=1.0)])
    messages = [
        {"body": "mine", "_chunk_key": p2t._chunk_key("write", b"A")},
        {"body": "other", "_chunk_key": p2t._chunk_key("write", b"B")},
        {"body": "wrong-dir", "_chunk_key": p2t._chunk_key("read", b"A")},
    ]
    scoped = p2t._scope_messages_to_flow(flow, messages)
    assert scoped == [{"body": "mine"}]
    assert "_chunk_key" in messages[0]  # originals untouched (copies returned)


def test_scope_passes_untagged_messages_through():
    flow = _FakeFlow([FlowChunk(data=b"A", direction="write", timestamp=1.0)])
    messages = [{"body": "legacy-1"}, {"body": "legacy-2"}]
    assert p2t._scope_messages_to_flow(flow, messages) == messages


def test_accumulators_tag_every_message_of_a_record(monkeypatch):
    from friTap.offline.mtproto import content

    monkeypatch.setattr(content, "parse_mtproto_message", lambda tl: [
        ParsedMtprotoMessage(kind="text", body="a"),
        ParsedMtprotoMessage(kind="text", body="b"),
    ])
    meta: dict = {}
    key = p2t._chunk_key("write", b"x")
    p2t._accumulate_mtproto_messages(meta, "k", b"x", "write", chunk_key=key)
    assert [m["_chunk_key"] for m in meta["k"]["messages"]] == [key, key]


# --------------------------------------------------------------------------- #
# End-to-end through the emitter + collector
# --------------------------------------------------------------------------- #

def _run(monkeypatch, cloud_msgs, e2e_by_data, parse_cloud, parse_e2e,
         use_ledger=False):
    patch_keylog_loaders(monkeypatch)
    monkeypatch.setattr("friTap.offline.mtproto.decrypt.iter_decrypted_messages",
                        lambda pcap, keymap, stats=None, obf_keys=None, obf_max_blocks=None: iter(cloud_msgs))

    def _fake_iter_e2e(transport_messages, keymap, stats=None):
        for msg in transport_messages:
            sc = e2e_by_data.get(msg.message)
            if sc is not None:
                yield sc

    monkeypatch.setattr("friTap.offline.mtproto.e2e.decrypt.iter_secret_chat_messages",
                        _fake_iter_e2e)
    from friTap.offline.mtproto import content
    monkeypatch.setattr(content, "parse_mtproto_message", parse_cloud)
    monkeypatch.setattr(content, "parse_secret_chat_message", parse_e2e)

    bus = EventBus()
    collector = FlowCollector(event_bus=bus)
    collector.use_event_clock(True)
    bus.subscribe(DatalogEvent, collector.on_data)
    state = _FakeState()
    p2t._emit_mtproto_streams("cap.pcap", "k", bus=bus, state=state,
                              result=p2t.ConvertResult(tap_path="out.tap"))
    ledger = getattr(state, "telegram_ledger", None) if use_ledger else None
    p2t._attach_telegram_meta(collector.live_flows(), state.mtproto_meta,
                              state.telegram_e2e_meta, ledger=ledger)
    return collector.live_flows()


def _layer_messages(flow, name):
    layer = flow.layer(name)
    return list(getattr(layer, "messages", None) or []) if layer else []


_CLOUD_METHODS = {
    b"REQ-1": "users.getFullUser", b"RSP-1": "rpc_result",
    b"REQ-2": "messages.sendMessage", b"RSP-2": "rpc_result",
}


def _parse_cloud(tl):
    method = _CLOUD_METHODS.get(bytes(tl))
    if method is None:
        return []
    return [ParsedMtprotoMessage(kind="service", body=bytes(tl).decode(), method=method)]


def test_two_cloud_flows_on_one_connection_get_only_their_messages(monkeypatch):
    cloud = [_cloud_msg(0, "write", b"REQ-1"), _cloud_msg(1, "read", b"RSP-1"),
             _cloud_msg(2, "write", b"REQ-2"), _cloud_msg(3, "read", b"RSP-2")]
    flows = [f for f in _run(monkeypatch, cloud, {}, _parse_cloud, lambda tl: [])
             if f.transport == "mtproto"]
    # One flow per packet (T1): each record's flow carries only its own message.
    assert len(flows) == 4
    bodies = sorted(tuple(m["body"] for m in _layer_messages(f, "mtproto")) for f in flows)
    assert bodies == [("REQ-1",), ("REQ-2",), ("RSP-1",), ("RSP-2",)]
    assert all(len(f.chunks) == 1 for f in flows)
    assert {method_from_messages(f) for f in flows} >= {
        "users.getFullUser", "messages.sendMessage"}
    for flow in flows:
        assert all("_chunk_key" not in m for m in _layer_messages(flow, "mtproto"))


_E2E_BODIES = {b"E2E-S1": "sent one", b"E2E-S2": "sent two", b"E2E-R1": "got one"}


def _parse_e2e(tl):
    body = _E2E_BODIES.get(bytes(tl))
    if body is None:
        return []
    rid = sorted(_E2E_BODIES).index(bytes(tl)) + 1
    return [ParsedMtprotoMessage(kind="text", body=body, random_id=rid,
                                 method="decryptedMessage")]


def test_e2e_write_write_read_scopes_each_flow(monkeypatch):
    carriers = [(0, "write", b"C0", b"E2E-S1"), (1, "write", b"C1", b"E2E-S2"),
                (2, "read", b"C2", b"E2E-R1")]
    cloud = [_cloud_msg(i, d, c) for i, d, c, _ in carriers]
    e2e = {c: _e2e_msg(i, d, e) for i, d, c, e in carriers}
    flows = [f for f in _run(monkeypatch, cloud, e2e, lambda tl: [], _parse_e2e)
             if f.transport == "telegram_e2e"]
    per_flow = sorted(
        [(m["direction"], m["body"]) for m in _layer_messages(f, "telegram_e2e")]
        for f in flows
    )
    all_items = [item for msgs in per_flow for item in msgs]
    assert sorted(all_items) == sorted(
        [("write", "sent one"), ("write", "sent two"), ("read", "got one")])
    # One flow per packet (T1): no flow carries another packet's message.
    assert per_flow == [[("read", "got one")], [("write", "sent one")],
                        [("write", "sent two")]]


# --------------------------------------------------------------------------- #
# Record ledger (T2): exact per-packet attachment, even for identical bytes
# --------------------------------------------------------------------------- #

def _parse_ack(tl):
    return [ParsedMtprotoMessage(kind="service", body=bytes(tl).decode(),
                                 method="msgs_ack")]


def _envelope(flow, name):
    layer = flow.layer(name)
    return dict(getattr(layer, "envelope", None) or {}) if layer else {}


def test_identical_bytes_records_each_get_their_own_record(monkeypatch):
    # Two DIFFERENT packets (distinct msg_id and capture time) with the SAME
    # TL bytes: their chunk keys collide, so only the FIFO ledger can tell them
    # apart. Each flow must get exactly its own message and envelope.
    cloud = [_cloud_msg(0, "write", b"ACK"), _cloud_msg(5, "write", b"ACK")]
    flows = [f for f in _run(monkeypatch, cloud, {}, _parse_ack, lambda tl: [],
                             use_ledger=True)
             if f.transport == "mtproto"]
    assert len(flows) == 2
    per_flow = [_layer_messages(f, "mtproto") for f in flows]
    assert [len(m) for m in per_flow] == [1, 1]
    assert [m[0]["timestamp"] for m in per_flow] == [_BASE_TS, _BASE_TS + 5]
    envelopes = [_envelope(f, "mtproto") for f in flows]
    assert [e["msg_id"] for e in envelopes] == [f"0x{100:016x}", f"0x{105:016x}"]
    assert [e["record_seq"] for e in envelopes] == [1, 2]
    for flow in flows:
        layer = flow.layer("mtproto")
        assert (layer.transport, layer.dc_id, layer.auth_key_id) == (
            "abridged", 2, "1122334455667788")
        assert layer.message_count == 1


def test_identical_bytes_records_share_messages_without_ledger(monkeypatch):
    # The retained scoping fallback cannot separate colliding chunk keys.
    cloud = [_cloud_msg(0, "write", b"ACK"), _cloud_msg(5, "write", b"ACK")]
    flows = [f for f in _run(monkeypatch, cloud, {}, _parse_ack, lambda tl: [])
             if f.transport == "mtproto"]
    assert [len(_layer_messages(f, "mtproto")) for f in flows] == [2, 2]


def test_ledger_attaches_e2e_envelope_and_messages(monkeypatch):
    carriers = [(0, "write", b"C0", b"E2E-S1"), (2, "read", b"C2", b"E2E-R1")]
    cloud = [_cloud_msg(i, d, c) for i, d, c, _ in carriers]
    e2e = {c: _e2e_msg(i, d, e) for i, d, c, e in carriers}
    flows = [f for f in _run(monkeypatch, cloud, e2e, lambda tl: [], _parse_e2e,
                             use_ledger=True)
             if f.transport == "telegram_e2e"]
    assert [[m["body"] for m in _layer_messages(f, "telegram_e2e")] for f in flows] == [
        ["sent one"], ["got one"]]
    envelopes = [_envelope(f, "telegram_e2e") for f in flows]
    assert [e["carrier_msg_id"] for e in envelopes] == [
        f"0x{100:016x}", f"0x{102:016x}"]
    assert all(e["key_fingerprint"] == _FP and e["chat_id"] == 4242 for e in envelopes)
    assert [e["record_seq"] for e in envelopes] == [2, 4]  # after each carrier


def test_ledger_miss_falls_back_to_scoping():
    flow = _FakeFlow([FlowChunk(data=b"A", direction="write", timestamp=1.0)])
    flow.transport = "mtproto"
    assert p2t._meta_from_ledger(flow, p2t._telegram_ledger(_FakeState())) is False
