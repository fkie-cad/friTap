#!/usr/bin/env python3

"""Unit tests for the MTProto obfuscated-transport key (MTPROTO_OBF_KEY) path.

Covers, without a device or a Frida session (Workstream F3):

  * an agent ``keylog`` message carrying an ``MTPROTO_OBF_KEY`` label turns into
    exactly one ``KeylogEvent(protocol="mtproto")`` whose line is the canonical
    obfuscation-key layout, and lands in the dedicated ``.mtproto.keylog`` sidecar
    as exactly one canonical line;
  * the shipped ``tgnet-android-arm64-2026`` profile still validates with the new
    ``MTPROTO_OBF_KEY`` label and the disabled ``E_connection_ctr_state`` tier.
"""

from __future__ import annotations

import copy
from types import SimpleNamespace

from friTap.events import EventBus, KeylogEvent
from friTap.memory_scanning import MemoryScanEngine
from friTap.memory_scanning.loader import (
    load_database,
    select_profile,
    validate_profile,
)
from friTap.protocols import mtproto_keylog_spec as spec

_MTPROTO_ID = "tgnet-android-arm64-2026"

# A canonical MTPROTO_OBF_KEY line built through the single-source-of-truth
# formatter (so the test never hand-writes the wire layout).
_OBF_LINE = spec.format_obf_line(
    key_out="ab" * 32,
    iv_out="cd" * 16,
    key_in="ef" * 32,
    iv_in="12" * 16,
    num_out=3,
    num_in=7,
    endpoint="-",
)


def _engine(bus, **kw):
    eng = MemoryScanEngine(**kw)
    eng._context = SimpleNamespace(event_bus=bus)
    return eng


def _bus():
    bus = EventBus()
    findings = {"mtproto": [], "memscan": []}
    bus.subscribe(
        KeylogEvent,
        lambda e: findings.get(e.protocol, findings.setdefault(e.protocol, [])).append(e),
    )
    return bus, findings


def _keylog_msg(line, label):
    return {"type": "send", "payload": {
        "type": "keylog", "line": line, "label": label,
        "tier": "E", "keyId": "id", "source": "src"}}


class TestObfKeyRouting:
    def test_obf_key_emits_one_mtproto_event(self):
        assert _OBF_LINE is not None
        bus, findings = _bus()
        _engine(bus).on_script_message(_keylog_msg(_OBF_LINE, "MTPROTO_OBF_KEY"), None)
        assert len(findings["mtproto"]) == 1
        assert findings["memscan"] == []
        assert findings["mtproto"][0].key_data == _OBF_LINE
        assert spec.parse_obf_line(findings["mtproto"][0].key_data) is not None

    def test_obf_key_written_once_to_sidecar(self, tmp_path):
        bus, _ = _bus()
        path = tmp_path / "t.mtproto.keylog"
        eng = _engine(bus, mtproto_path=str(path))
        eng.on_script_message(_keylog_msg(_OBF_LINE, "MTPROTO_OBF_KEY"), None)
        eng._close_mtproto()
        contents = path.read_text()
        assert contents.startswith("# friTap MTProto keylog")
        # Exactly one canonical MTPROTO_OBF_KEY line (the rest are # header lines).
        obf_lines = [ln for ln in contents.splitlines() if ln.startswith("MTPROTO_OBF_KEY")]
        assert obf_lines == [_OBF_LINE]

    def test_malformed_obf_line_emits_nothing(self):
        bus, findings = _bus()
        bad = "MTPROTO_OBF_KEY " + ("ab" * 32) + " short 0 0 -"  # too few / bad tokens
        _engine(bus).on_script_message(_keylog_msg(bad, "MTPROTO_OBF_KEY"), None)
        assert findings["mtproto"] == []


class TestObfProfile:
    def test_profile_validates_with_obf_label_and_enabled_tier(self):
        profile = copy.deepcopy(select_profile(load_database(None), _MTPROTO_ID))
        validate_profile(profile)  # must not raise
        assert "MTPROTO_OBF_KEY" in profile["keylog_labels"]
        tier = profile["tiers"]["E_connection_ctr_state"]
        # Tier E is ENABLED. The Connection vtable anchor is resolved PRIMARILY at
        # runtime from the C++ RTTI graph (scanner.ts deriveConnectionVtableViaRtti,
        # anchored on rtti_type_name_mangled), which is version-independent; the
        # measured vtable_ptr_rva is only a FALLBACK, recalibrated per Telegram build.
        # Assert its shape, not a fixed value that goes stale on every app update.
        assert tier["enabled"] is True
        assert tier["label"] == "MTPROTO_OBF_KEY"
        assert tier["rtti_type_name_mangled"] == "10Connection"
        assert isinstance(tier["vtable_ptr_rva"], int) and tier["vtable_ptr_rva"] > 0
        assert tier["vtable_ptr_rva"] == int(tier["_vtable_ptr_rva_hex"], 16)
        assert tier["module_name_regex"] == r"libtmessages\.\d+\.so"
        # Calibrated CTR-state offsets within the tgnet Connection object.
        conn = profile["struct_offsets"]["Connection"]
        expected = {
            "encrypt_key": 0x2CC, "encrypt_ivec": 0x3C0, "encrypt_num": 0x3D0,
            "decrypt_key": 0x3E4, "decrypt_ivec": 0x4D8, "decrypt_num": 0x4E8,
        }
        for field, off in expected.items():
            assert conn[field] == off, field
        assert conn["raw_key_len"] == 32
        assert conn["byteswap_schedule_words"] is False
