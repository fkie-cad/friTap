#!/usr/bin/env python3

"""The Telegram decoder must run once per capture and never duplicate messages.

The TUI wizard fills BOTH the ``mtproto`` and ``telegram`` keylog slots with the
same Telegram keylog; each maps to a registry entry running the same decoder.
These tests pin the two guards against the resulting duplicate flows/messages:

  * ``_dedupe_independent_entries`` runs a decoder family once (merging distinct
    keylog paths into one pass);
  * the emitter + side-channel accumulators are idempotent per record/message.

The crypto backend is monkeypatched with fakes (as in
``test_offline_mtproto_e2e_tap``), so no pcap fixture or dependency is needed.
"""

from __future__ import annotations

import dataclasses

import pytest

from friTap.events import DatalogEvent, EventBus
from friTap.offline import pcap_to_tap as p2t
from friTap.offline.mtproto.content import parse_secret_chat_message
from friTap.offline.mtproto.e2e.records import SecretChatMessage
from friTap.offline.mtproto.records import DecryptedMessage

# Deliberately WITHOUT a ``telegram_emitted`` attribute.
from tests.unit._offline_helpers import FakeWriterState as _FakeState
from tests.unit._offline_helpers import patch_keylog_loaders

# decryptedMessageLayer (layer 0x97, in_seq 20, out_seq 57) wrapping a
# decryptedMessage (flags 0, random_id 0xfc5e208c0016f236, ttl 0, "Hi infected").
_LAYER_BLOB = bytes.fromhex(
    "8917e31b0fc1a2e4f91e39178d0905d8cb639122970000001400000039000000"
    "7446cc910000000036f216008c205efc000000000b48692069 6e666563746564".replace(" ", "")
)
_RANDOM_ID = 0xFC5E208C0016F236
_FP = "aabbccddeeff0011"


def _entry(name: str, family: str = ""):
    from friTap.flow.layers import MtprotoLayer
    from friTap.offline.registry import OfflineDecryptorEntry

    return OfflineDecryptorEntry(
        protocol_name=name, cli_flag=f"--{name}-keylog", cli_dest=f"{name}_keylog",
        requires_tls_strip=False, emitter=lambda **kw: None, layer_cls=MtprotoLayer,
        counter_prefix=name, decoder_family=family,
    )


# --------------------------------------------------------------------------- #
# Registry / entry de-duplication
# --------------------------------------------------------------------------- #

def test_builtin_telegram_entries_share_a_family():
    assert p2t.build_mtproto_offline_decryptor_entry().decoder_family == "telegram"
    assert p2t.build_telegram_offline_decryptor_entry().decoder_family == "telegram"


def test_same_family_same_path_keeps_one_telegram_entry(tmp_path):
    keylog = tmp_path / "tg.keys.log"
    keylog.write_text("")
    entries = [_entry("mtproto", "telegram"), _entry("telegram", "telegram")]
    keylogs = {"mtproto": str(keylog), "telegram": str(tmp_path / "." / "tg.keys.log")}

    plan = p2t._dedupe_independent_entries(entries, keylogs)

    assert [(e.protocol_name, paths) for e, paths in plan] == [
        ("telegram", [keylogs["telegram"]])
    ]


def test_different_families_are_all_kept(tmp_path):
    keylog = str(tmp_path / "k.log")
    entries = [_entry("alpha"), _entry("beta"), _entry("gamma", "delta")]
    plan = p2t._dedupe_independent_entries(
        entries, {"alpha": keylog, "beta": keylog, "gamma": keylog})
    assert [e.protocol_name for e, _paths in plan] == ["alpha", "beta", "gamma"]


def test_same_family_different_paths_merge_into_one_plan(tmp_path):
    entries = [_entry("mtproto", "telegram"), _entry("telegram", "telegram")]
    keylogs = {"mtproto": str(tmp_path / "a.log"), "telegram": str(tmp_path / "b.log")}
    plan = p2t._dedupe_independent_entries(entries, keylogs)
    assert len(plan) == 1
    entry, paths = plan[0]
    assert entry.protocol_name == "telegram"
    assert paths == [keylogs["telegram"], keylogs["mtproto"]]


def test_run_independent_entry_passes_extra_keylogs_only_when_merging():
    calls = []
    entry = dataclasses.replace(_entry("telegram"), emitter=lambda **kw: calls.append(kw))
    p2t._run_independent_entry(entry, ["a"], pcap_path="p")
    p2t._run_independent_entry(entry, ["a", "b"], pcap_path="p")
    assert calls[0] == {"proto_keylog": "a", "pcap_path": "p"}
    assert calls[1] == {"proto_keylog": "a", "pcap_path": "p", "extra_keylogs": ("b",)}


def test_different_paths_run_decoder_once_with_merged_keys(monkeypatch, tmp_path):
    """convert_pcap_to_tap: two family members + two files -> one merged pass."""
    a = tmp_path / "a.log"
    b = tmp_path / "b.log"
    a.write_text("")
    b.write_text("")
    loaded, passes = [], []
    monkeypatch.setattr(
        "friTap.offline.mtproto.keylog.load_mtproto_keylog",
        lambda path: loaded.append(path) or {path.encode(): object()},
    )
    monkeypatch.setattr("friTap.offline.mtproto.keylog.load_mtproto_obf_keylog",
                        lambda path: [])
    monkeypatch.setattr("friTap.offline.mtproto.e2e.keylog.load_secret_chat_keylog",
                        lambda path: {})

    def _fake_iter_cloud(pcap_path, keymap, stats=None, obf_keys=None, obf_max_blocks=None):
        passes.append(set(keymap))
        return iter(())

    monkeypatch.setattr("friTap.offline.mtproto.decrypt.iter_decrypted_messages",
                        _fake_iter_cloud)
    monkeypatch.setattr(p2t, "find_tshark", lambda path=None: "tshark")
    monkeypatch.setattr(p2t, "tshark_version", lambda binary: None)
    monkeypatch.setattr(p2t, "warn_if_outdated", lambda version: None)
    monkeypatch.setattr(p2t, "_emit_ssh_connections", lambda *a, **k: None)

    p2t.convert_pcap_to_tap(
        str(tmp_path / "cap.pcap"), None, str(tmp_path / "out.tap"),
        protocol_keylogs={"mtproto": str(a), "telegram": str(b)},
    )

    assert passes == [{str(b).encode(), str(a).encode()}]
    assert sorted(loaded) == sorted([str(a), str(b)])


# --------------------------------------------------------------------------- #
# Emitter / accumulator idempotency
# --------------------------------------------------------------------------- #

def _cloud_msg(msg_id: int = 77) -> DecryptedMessage:
    return DecryptedMessage(
        src_addr="10.0.0.1", src_port=12345,
        dst_addr="149.154.167.51", dst_port=443,
        ss_family="AF_INET", direction="write",
        message=b"\x00" * 16, dc_id=2, transport="abridged",
        obfuscated=True, auth_key_id_hex="1122334455667788", msg_id=msg_id,
    )


def _e2e_msg(msg_key_hex: str = "00" * 16) -> SecretChatMessage:
    return SecretChatMessage(
        src_addr="10.0.0.1", src_port=12345,
        dst_addr="149.154.167.51", dst_port=443,
        ss_family="AF_INET", direction="write",
        message=_LAYER_BLOB, chat_id=4242,
        key_fingerprint_hex=_FP, msg_key_hex=msg_key_hex,
    )


@pytest.fixture
def patched_backend(monkeypatch):
    patch_keylog_loaders(monkeypatch)

    def _fake_iter_cloud(pcap_path, keymap, stats=None, obf_keys=None, obf_max_blocks=None):
        yield _cloud_msg()

    def _fake_iter_e2e(transport_messages, keymap, stats=None):
        list(transport_messages)
        yield _e2e_msg()

    monkeypatch.setattr("friTap.offline.mtproto.decrypt.iter_decrypted_messages",
                        _fake_iter_cloud)
    monkeypatch.setattr("friTap.offline.mtproto.e2e.decrypt.iter_secret_chat_messages",
                        _fake_iter_e2e)


def test_emitting_twice_does_not_duplicate_events_or_meta(patched_backend):
    bus = EventBus()
    events: list[DatalogEvent] = []
    bus.subscribe(DatalogEvent, events.append)
    state = _FakeState()
    result = p2t.ConvertResult(tap_path="out.tap")

    p2t._emit_mtproto_streams("cap.pcap", "k", bus=bus, state=state, result=result)
    p2t._emit_telegram_streams("cap.pcap", "k", bus=bus, state=state, result=result)

    assert [ev.protocol for ev in events].count("telegram_e2e") == 1
    assert [ev.protocol for ev in events].count("mtproto") == 1
    e2e_entry = state.telegram_e2e_meta[f"telegram_e2e:{_FP}"]
    assert len(e2e_entry["messages"]) == 1
    assert isinstance(state.telegram_emitted, set)


def test_real_writer_state_has_emitted_set():
    state = p2t._WriterState(writer=None, tap_path="x.tap", target="t", keylog_path=None)
    assert state.telegram_emitted == set()


def test_secret_chat_accumulator_is_idempotent_and_surfaces_random_id():
    meta: dict = {}
    key = f"telegram_e2e:{_FP}"
    for _ in range(2):
        p2t._accumulate_secret_chat_messages(
            meta, key, _LAYER_BLOB, "write", 4242, msg_key_hex="ab" * 16)
    messages = meta[key]["messages"]
    assert len(messages) == 1
    assert messages[0]["body"] == "Hi infected"
    assert messages[0]["random_id"] & 0xFFFFFFFFFFFFFFFF == _RANDOM_ID


def test_mtproto_accumulator_dedups_by_msg_id(monkeypatch):
    from friTap.offline.mtproto import content
    from friTap.offline.mtproto.content import ParsedMtprotoMessage

    monkeypatch.setattr(content, "parse_mtproto_message",
                        lambda tl: [ParsedMtprotoMessage(kind="text", body="hi")])
    meta: dict = {}
    for msg_id in (5, 5, 6):
        p2t._accumulate_mtproto_messages(meta, "k", b"x", "write", msg_id=msg_id)
    p2t._accumulate_mtproto_messages(meta, "k", b"x", "read", msg_id=5)
    messages = meta["k"]["messages"]
    assert len(messages) == 3
    assert "random_id" not in messages[0]  # cloud dict shape unchanged


def test_mtproto_accumulator_without_msg_id_never_dedups(monkeypatch):
    from friTap.offline.mtproto import content
    from friTap.offline.mtproto.content import ParsedMtprotoMessage

    monkeypatch.setattr(content, "parse_mtproto_message",
                        lambda tl: [ParsedMtprotoMessage(kind="text", body="hi")])
    meta: dict = {}
    p2t._accumulate_mtproto_messages(meta, "k", b"x", "write")
    p2t._accumulate_mtproto_messages(meta, "k", b"x", "write")
    assert len(meta["k"]["messages"]) == 2


def test_private_seen_keys_do_not_reach_the_layer():
    from friTap.flow.layers import TelegramE2ELayer

    meta: dict = {}
    p2t._accumulate_secret_chat_messages(meta, "k", _LAYER_BLOB, "write", 1)
    layer = TelegramE2ELayer()
    p2t._apply_mtproto_meta(layer, meta["k"])
    assert layer.message_count == 1
    assert all(not key.startswith("_") for msg in layer.messages for key in msg)


# --------------------------------------------------------------------------- #
# Record fields
# --------------------------------------------------------------------------- #

def test_content_parser_surfaces_random_id():
    [parsed] = parse_secret_chat_message(_LAYER_BLOB)
    assert parsed.body == "Hi infected"
    assert parsed.random_id & 0xFFFFFFFFFFFFFFFF == _RANDOM_ID


def test_blob_msg_key_hex_is_bytes_8_to_24():
    from friTap.offline.mtproto.e2e.decrypt import _blob_msg_key_hex

    blob = bytes(range(8)) + bytes(range(100, 116)) + b"\x00" * 16
    assert _blob_msg_key_hex(blob) == bytes(range(100, 116)).hex()


def test_record_defaults_keep_old_constructors_working():
    msg = dataclasses.replace(_cloud_msg(), msg_id=0)
    assert msg.timestamp == 0.0
    assert _e2e_msg().timestamp == 0.0


def test_secret_chat_identity_prefers_msg_key_over_random_id():
    # Two DISTINCT packets (different msg_key) that reuse one random_id each
    # get their message; random_id de-duplication is left to the Message tab.
    meta: dict = {}
    key = f"telegram_e2e:{_FP}"
    for msg_key in ("ab" * 16, "cd" * 16):
        added = p2t._accumulate_secret_chat_messages(
            meta, key, _LAYER_BLOB, "write", 4242, msg_key_hex=msg_key)
        assert len(added) == 1
    assert [m["random_id"] & 0xFFFFFFFFFFFFFFFF for m in meta[key]["messages"]] == [
        _RANDOM_ID, _RANDOM_ID]


def test_secret_chat_identity_falls_back_to_random_id_without_msg_key():
    meta: dict = {}
    for _ in range(2):
        p2t._accumulate_secret_chat_messages(meta, "k", _LAYER_BLOB, "write", 1)
    assert len(meta["k"]["messages"]) == 1
