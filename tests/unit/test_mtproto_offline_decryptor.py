"""MTProto/Telegram as a self-registering offline decryptor.

The Telegram emit side moved out of ``friTap.offline.pcap_to_tap`` into
``friTap.offline.mtproto.offline_decryptor``; the ``mtproto`` package now
self-registers its two entries at import, like Signal/RC4/Schannel.
"""

from __future__ import annotations

import json
import subprocess
import sys

import pytest

import friTap.offline.mtproto as mtproto_pkg
from friTap.flow.layers import MtprotoLayer, TelegramE2ELayer
from friTap.offline import pcap_to_tap, pipeline_api
from friTap.offline.mtproto import offline_decryptor
from friTap.offline.registry import get_offline_decryptor_registry

# Registration order before the move (MTProto/Telegram first, then the
# discovered subpackages in pkgutil order). Entries iterate in this order.
HISTORICAL_ORDER = ["mtproto", "telegram", "rc4", "schannel", "signal"]

# Moved names whose lazy pcap_to_tap back-compat aliases were removed; they
# live only in offline_decryptor now.
MOVED_NAMES = [
    "_accumulate_mtproto_messages", "_accumulate_secret_chat_messages",
    "_already_emitted", "_emit_mtproto_streams", "_emit_telegram_streams",
    "_load_telegram_keys", "_mark_seen", "_next_record_seq",
    "_parsed_mtproto_to_dicts", "_state_attr", "_telegram_ledger",
    "_time_ordered", "build_mtproto_offline_decryptor_entry",
    "build_telegram_offline_decryptor_entry",
]

# Moved names nobody used via pcap_to_tap: their back-compat aliases were never
# kept, they live only in offline_decryptor.
DROPPED_ALIASES = [
    "_append_mtproto_dicts_deduped", "_cloud_identity", "_collect_cloud_refs",
    "_emit_cloud_record", "_emit_e2e_record", "_emit_telegram_like_streams",
    "_ledger_record", "_mtproto_offline_emitter", "_record_telegram_stats",
    "_secret_chat_emit_identity", "_secret_chat_identity", "_set_state_attr",
    "_tag_chunk_key", "_telegram_emitted_set", "_telegram_offline_emitter",
    "_telegram_refs", "_TelegramRefs", "_user_dedup_key",
]


def _fresh_interpreter(code: str) -> str:
    return subprocess.run(
        [sys.executable, "-c", code], check=True, capture_output=True, text=True,
    ).stdout


def test_registry_order_is_unchanged_in_a_fresh_process():
    names = json.loads(_fresh_interpreter(
        "import json, friTap.offline.pcap_to_tap\n"
        "from friTap.offline.registry import get_offline_decryptor_registry as g\n"
        "print(json.dumps(g().names()))"
    ))
    assert names[:2] == ["mtproto", "telegram"]
    assert names == [n for n in HISTORICAL_ORDER if n in names]


def test_importing_pcap_to_tap_keeps_the_crypto_backend_lazy():
    loaded = json.loads(_fresh_interpreter(
        "import json, sys, friTap.offline.pcap_to_tap\n"
        "print(json.dumps(sorted(m for m in sys.modules\n"
        "    if m.startswith('friTap.offline.mtproto') or m == 'cryptography')))"
    ))
    assert loaded == [
        "friTap.offline.mtproto",
        "friTap.offline.mtproto.offline_decryptor",
        # Dependency-free per-conversion state namespace (WS2), registered at import.
        "friTap.offline.mtproto.state",
        "friTap.offline.mtproto.tap_attach",
        "friTap.offline.mtproto.transport",
    ]


def test_package_carries_the_discovery_marker():
    assert mtproto_pkg.is_fritap_offline_decryptor is True


@pytest.mark.parametrize("name, flag, dest, layer_cls, emitter", [
    ("mtproto", "--mtproto-keylog", "mtproto_keylog", MtprotoLayer,
     offline_decryptor._mtproto_offline_emitter),
    ("telegram", "--telegram-keylog", "telegram_keylog", TelegramE2ELayer,
     offline_decryptor._telegram_offline_emitter),
])
def test_registered_entry_fields(name, flag, dest, layer_cls, emitter):
    entry = get_offline_decryptor_registry().get(name)
    assert entry is not None
    assert (entry.cli_flag, entry.cli_dest, entry.counter_prefix) == (flag, dest, name)
    assert entry.requires_tls_strip is False
    assert entry.nests_in_tls is False
    assert entry.decoder_family == "telegram"
    assert entry.layer_cls is layer_cls
    assert entry.emitter is emitter


def test_reregistration_is_idempotent():
    before = get_offline_decryptor_registry().names()
    mtproto_pkg._register_mtproto_offline_decryptors()
    pcap_to_tap._register_builtin_offline_decryptors()
    assert get_offline_decryptor_registry().names() == before


@pytest.mark.parametrize("name", MOVED_NAMES + DROPPED_ALIASES)
def test_dropped_alias_lives_only_in_offline_decryptor(name):
    assert hasattr(offline_decryptor, name)
    assert not hasattr(pcap_to_tap, name)
    assert name not in dir(pcap_to_tap)


def test_unique_keylog_paths_moved_to_pipeline_api(tmp_path):
    assert not hasattr(pcap_to_tap, "_unique_keylog_paths")
    a, b = str(tmp_path / "a.log"), str(tmp_path / "b.log")
    assert pipeline_api.unique_keylog_paths(a, [b, a, "", b]) == [a, b]
    assert pipeline_api.unique_keylog_paths("", ()) == []


def test_emitter_resolves_the_decryptor_at_call_time(monkeypatch):
    """Patching ``friTap.offline.mtproto.decrypt`` reaches the moved emitter."""
    from tests.unit._offline_helpers import patch_keylog_loaders

    patch_keylog_loaders(monkeypatch)
    calls = []
    monkeypatch.setattr("friTap.offline.mtproto.decrypt.iter_decrypted_messages",
                        lambda *a, **k: calls.append(a) or iter(()))
    result = pipeline_api.ConvertResult(tap_path="x.tap")
    offline_decryptor._emit_mtproto_streams(
        "cap.pcap", "k.log", bus=None, state=object(), result=result,
    )
    assert len(calls) == 1
    assert result.per_protocol["mtproto"]["messages"] == 0
