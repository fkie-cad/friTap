#!/usr/bin/env python3

"""Per-packet Telegram metadata: envelope builders and the record ledger."""

from __future__ import annotations

from friTap.offline.mtproto.e2e.records import SecretChatMessage
from friTap.offline.mtproto.packet_meta import (
    RecordLedger,
    build_cloud_envelope,
    build_e2e_envelope,
    msg_id_kind,
    msg_id_time,
)
from friTap.offline.mtproto.records import DecryptedMessage

_SECONDS = 1_700_000_000
_CLIENT_MSG_ID = (_SECONDS << 32) | 0x80000000  # .5 s, divisible by 4


def _cloud(direction: str = "write", msg_id: int = _CLIENT_MSG_ID, **extra):
    client = dict(src_addr="192.168.0.66", src_port=39398,
                  dst_addr="149.154.167.41", dst_port=5222)
    if direction == "read":
        client = dict(src_addr="149.154.167.41", src_port=5222,
                      dst_addr="192.168.0.66", dst_port=39398)
    fields = dict(
        ss_family="AF_INET", direction=direction, message=b"tl", dc_id=4,
        transport="intermediate", obfuscated=True, auth_key_id_hex="1122334455667788",
        msg_id=msg_id, salt=bytes.fromhex("0102030405060708"),
        session_id=bytes.fromhex("a1a2a3a4a5a6a7a8"), seq_no=3, msg_len=20,
        padding_len=12, frame_len=80,
    )
    fields.update(extra)
    return DecryptedMessage(**client, **fields)


def test_msg_id_kind_follows_the_mtproto_spec():
    assert msg_id_kind(_CLIENT_MSG_ID) == "client"
    assert msg_id_kind(_CLIENT_MSG_ID + 1) == "server_response"
    assert msg_id_kind(_CLIENT_MSG_ID + 3) == "server_notification"
    assert msg_id_kind(_CLIENT_MSG_ID + 2) == "invalid"
    assert msg_id_kind(0) == "unknown"


def test_msg_id_time_includes_the_fraction():
    assert msg_id_time(_CLIENT_MSG_ID) == _SECONDS + 0.5
    assert msg_id_time(_SECONDS << 32) == float(_SECONDS)


def test_cloud_envelope_carries_every_field():
    env = build_cloud_envelope(_cloud())
    assert env == {
        "auth_key_id": "1122334455667788",
        "salt": "0102030405060708",
        "session_id": "a1a2a3a4a5a6a7a8",
        "msg_id": f"0x{_CLIENT_MSG_ID:016x}",
        "msg_time": _SECONDS + 0.5,
        "msg_id_kind": "client",
        "seq_no": 3,
        "content_related": True,
        "msg_len": 20,
        "padding_len": 12,
        "frame_len": 80,
        "transport": "intermediate",
        "obfuscated": True,
        "dc_addr": "149.154.167.41:5222",
        "dc_id": 4,
    }


def test_cloud_envelope_dc_side_on_read_and_unknown_defaults():
    env = build_cloud_envelope(_cloud("read", msg_id=_CLIENT_MSG_ID + 1, seq_no=2,
                                      dc_id=0, salt=b"", session_id=b""))
    assert env["dc_addr"] == "149.154.167.41:5222"
    assert env["msg_id_kind"] == "server_response"
    assert env["content_related"] is False
    assert env["salt"] == "" and env["session_id"] == ""
    assert "dc_id" not in env


def test_legacy_decrypted_message_defaults():
    msg = DecryptedMessage(
        src_addr="a", src_port=1, dst_addr="b", dst_port=2, ss_family="AF_INET",
        direction="write", message=b"", dc_id=0, transport="abridged",
        obfuscated=True, auth_key_id_hex="",
    )
    assert (msg.salt, msg.session_id, msg.seq_no) == (b"", b"", 0)
    assert (msg.msg_len, msg.padding_len, msg.frame_len) == (0, 0, 0)
    assert build_cloud_envelope(msg)["msg_id"] == ""


def test_e2e_envelope_links_the_carrier():
    sc = SecretChatMessage(
        src_addr="a", src_port=1, dst_addr="b", dst_port=2, ss_family="AF_INET",
        direction="write", message=b"", chat_id=4242,
        key_fingerprint_hex="aabbccddeeff0011", msg_key_hex="cd" * 16,
    )
    env = build_e2e_envelope(sc, _cloud())
    assert env == {
        "key_fingerprint": "aabbccddeeff0011",
        "msg_key": "cd" * 16,
        "carrier_msg_id": f"0x{_CLIENT_MSG_ID:016x}",
        "carrier_auth_key_id": "1122334455667788",
        "chat_id": 4242,
    }


def test_ledger_is_fifo_per_key():
    ledger = RecordLedger()
    assert not ledger and ledger.take("mtproto", "k") is None
    ledger.add("mtproto", "k", {"record_seq": 1})
    ledger.add("mtproto", "k", {"record_seq": 2})
    ledger.add("telegram_e2e", "k", {"record_seq": 3})
    assert len(ledger) == 3 and ledger
    assert ledger.take("mtproto", "k") == {"record_seq": 1}
    assert ledger.take("telegram_e2e", "k") == {"record_seq": 3}
    assert ledger.take("mtproto", "k") == {"record_seq": 2}
    assert ledger.take("mtproto", "k") is None
    assert not ledger


def test_envelope_kwargs_copies_every_envelope_field():
    from friTap.offline.mtproto.crypto import MtprotoEnvelope
    from friTap.offline.mtproto.decrypt import _envelope_kwargs

    class _Record:
        envelope = MtprotoEnvelope(
            salt=b"s" * 8, session_id=b"i" * 8, msg_id=_CLIENT_MSG_ID, seq_no=7,
            msg_len=4, message=b"body", padding=b"p" * 12,
        )

    assert _envelope_kwargs(_Record(), b"f" * 64) == {
        "msg_id": _CLIENT_MSG_ID, "salt": b"s" * 8, "session_id": b"i" * 8,
        "seq_no": 7, "msg_len": 4, "padding_len": 12, "frame_len": 64,
    }
