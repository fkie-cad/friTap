#!/usr/bin/env python3

"""Additive per-packet metadata on the Telegram layers (envelope/refs/users/peer).

Old taps (no such keys) must load with empty defaults, layers without the
metadata must serialize exactly as before, and populated layers must survive a
full tap encode/decode round-trip.
"""

from __future__ import annotations

from friTap.flow.layers import MtprotoLayer, TelegramE2ELayer
from friTap.flow.models import Flow, FlowChunk
from friTap.flow.tap_format import decode_flow, encode_flow

_ENVELOPE = {"msg_id": "0x0000000100000004", "seq_no": 3, "record_seq": 7}
_REFS = {"answers": ["0x0000000100000000"]}
_USERS = [{"id": 42, "first_name": "Evil", "self": True}]
_PEER = {"id": 43, "first_name": "Peer"}

_OLD_MTPROTO = {"name": "mtproto", "depth": 0, "transport": "abridged",
                "obfuscated": True, "fake_tls": False, "dc_id": 2,
                "auth_key_id": "11", "message_count": 0, "messages": []}
_OLD_E2E = {"name": "telegram_e2e", "depth": 0, "chat_id": 1,
            "key_fingerprint": "aa", "message_count": 0, "origin": "decrypted",
            "layer_version": 0, "messages": []}


def test_old_dicts_load_with_empty_defaults():
    cloud = MtprotoLayer.from_dict(_OLD_MTPROTO)
    assert (cloud.envelope, cloud.refs, cloud.users) == ({}, {}, [])
    e2e = TelegramE2ELayer.from_dict(_OLD_E2E)
    assert (e2e.envelope, e2e.refs, e2e.users, e2e.peer) == ({}, {}, [], {})


def test_layers_without_packet_meta_keep_their_old_shape():
    assert MtprotoLayer.from_dict(_OLD_MTPROTO).to_dict() == _OLD_MTPROTO
    assert TelegramE2ELayer.from_dict(_OLD_E2E).to_dict() == _OLD_E2E


def test_packet_meta_round_trips_through_dicts():
    cloud = MtprotoLayer(envelope=_ENVELOPE, refs=_REFS, users=_USERS)
    back = MtprotoLayer.from_dict(cloud.to_dict())
    assert (back.envelope, back.refs, back.users) == (_ENVELOPE, _REFS, _USERS)
    e2e = TelegramE2ELayer(envelope=_ENVELOPE, users=_USERS, peer=_PEER)
    back = TelegramE2ELayer.from_dict(e2e.to_dict())
    assert (back.envelope, back.users, back.peer) == (_ENVELOPE, _USERS, _PEER)


def test_packet_meta_makes_a_layer_non_empty():
    assert MtprotoLayer().is_empty()
    assert not MtprotoLayer(envelope=_ENVELOPE).is_empty()
    assert TelegramE2ELayer().is_empty()
    assert not TelegramE2ELayer(peer=_PEER).is_empty()


def test_malformed_values_fall_back_to_defaults():
    layer = MtprotoLayer.from_dict({**_OLD_MTPROTO, "envelope": "x", "users": None})
    assert (layer.envelope, layer.users) == ({}, [])


def _flow(transport: str) -> Flow:
    flow = Flow(flow_id=f"f-{transport}", connection_id="c1")
    flow.transport = transport
    flow.chunks.append(FlowChunk(data=b"TL", direction="write", timestamp=1.0))
    return flow


def test_packet_meta_survives_tap_roundtrip():
    flow = _flow("mtproto")
    flow.mtproto.envelope = dict(_ENVELOPE)
    flow.mtproto.refs = dict(_REFS)
    flow.mtproto.users = list(_USERS)
    layer = decode_flow(encode_flow(flow)).mtproto
    assert (layer.envelope, layer.refs, layer.users) == (_ENVELOPE, _REFS, _USERS)

    flow = _flow("telegram_e2e")
    flow.telegram_e2e.envelope = dict(_ENVELOPE)
    flow.telegram_e2e.peer = dict(_PEER)
    layer = decode_flow(encode_flow(flow)).telegram_e2e
    assert (layer.envelope, layer.peer) == (_ENVELOPE, _PEER)
