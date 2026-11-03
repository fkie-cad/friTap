"""The MTProto overflow / drop counters reach the conversion result.

``MtprotoStats.unknown_key_ids_overflow`` and the ``_TelegramRefs`` cap
counters (``users_dropped`` / ``chat_nodes_dropped``) are recorded additively
in the protocol bucket through ``ConvertResult.record_protocol``, and only
when non-zero, so a capture that hits no cap keeps the exact v1 bucket shape.
"""

from __future__ import annotations

from friTap.events import EventBus
from friTap.offline.mtproto import offline_decryptor as od
from friTap.offline.mtproto.e2e.records import SecretChatStats
from friTap.offline.mtproto.records import MtprotoStats
from friTap.offline.pipeline_api import ConvertResult
from friTap.offline.result_schema import V1_BUCKET_DEFAULTS
from tests.unit._offline_helpers import FakeWriterState, cloud_msg, patch_keylog_loaders
from tests.unit._tl_helpers import VECTOR, i32, rpc_result, synthetic_user, u32
from tests.unit.test_tl_users import contact_user

_NEW_KEYS = ("unknown_key_ids_overflow", "users_dropped", "chat_nodes_dropped")
_USERS_RESULT = rpc_result(100, u32(VECTOR) + i32(2) + synthetic_user() + contact_user())


def _record(overflow: int) -> dict:
    result = ConvertResult(tap_path="out.tap")
    stats = MtprotoStats(unknown_key_ids_overflow=overflow)
    od._record_telegram_stats(result, "mtproto", stats, SecretChatStats(), e2e_only=False)
    return result.to_dict()["per_protocol"]["mtproto"]


def test_unknown_key_ids_overflow_appears_in_the_result():
    assert _record(overflow=7)["unknown_key_ids_overflow"] == 7


def test_zero_overflow_keeps_the_v1_bucket_shape():
    assert list(_record(overflow=0)) == list(V1_BUCKET_DEFAULTS)


def test_refs_drops_record_only_this_passes_delta():
    result = ConvertResult(tap_path="out.tap")
    od._record_refs_drops(result, "mtproto", before=(2, 5), after=(6, 5))
    bucket = result.per_protocol["mtproto"]
    assert bucket["users_dropped"] == 4
    assert "chat_nodes_dropped" not in bucket


def test_refs_drops_without_drops_create_no_bucket():
    result = ConvertResult(tap_path="out.tap")
    od._record_refs_drops(result, "telegram", before=(3, 3), after=(3, 3))
    assert result.per_protocol == {}


def _fake_backend(monkeypatch, cloud_msgs, overflow: int) -> None:
    patch_keylog_loaders(monkeypatch)

    def fake_iter(pcap, keymap, stats=None, obf_keys=None, obf_max_blocks=None):
        stats.unknown_key_ids_overflow += overflow
        return iter(cloud_msgs)

    monkeypatch.setattr("friTap.offline.mtproto.decrypt.iter_decrypted_messages", fake_iter)
    monkeypatch.setattr("friTap.offline.mtproto.e2e.decrypt.iter_secret_chat_messages",
                        lambda msgs, keymap, stats=None: iter(()))


def _convert(state) -> dict:
    result = ConvertResult(tap_path="out.tap")
    od._emit_mtproto_streams("cap.pcap", "k", bus=EventBus(), state=state, result=result)
    return result.to_dict()["per_protocol"]["mtproto"]


def test_emitter_surfaces_overflow_and_dropped_users(monkeypatch):
    monkeypatch.setattr(od, "MAX_USERS_PER_RECORD", 1)
    _fake_backend(monkeypatch, [cloud_msg(1, "read", _USERS_RESULT)], overflow=3)
    bucket = _convert(FakeWriterState())
    assert bucket["unknown_key_ids_overflow"] == 3
    assert bucket["users_dropped"] == 1
    assert "chat_nodes_dropped" not in bucket


def test_repeated_pass_does_not_recount_drops(monkeypatch):
    monkeypatch.setattr(od, "MAX_USERS_PER_RECORD", 1)
    _fake_backend(monkeypatch, [cloud_msg(1, "read", _USERS_RESULT)], overflow=0)
    state = FakeWriterState()
    assert _convert(state)["users_dropped"] == 1
    # The record was already emitted: the second pass drops nothing new.
    assert not set(_NEW_KEYS) & set(_convert(state))


def test_emitter_without_caps_hit_keeps_the_v1_bucket_shape(monkeypatch):
    _fake_backend(monkeypatch, [cloud_msg(1, "read", _USERS_RESULT)], overflow=0)
    assert list(_convert(FakeWriterState())) == list(V1_BUCKET_DEFAULTS)
