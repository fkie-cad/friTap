#!/usr/bin/env python3

"""Unit tests for the MTProto (Telegram) memory-scan engine, Python side.

Covers, without a device or a Frida session:

  * the shipped ``tgnet-android-arm64-2026`` profile validates and carries the
    friTap discriminators (engine/protocol/platforms/scan_target);
  * :func:`_validate_mtproto_profile` rejects malformed mtproto shapes;
  * the resolver selects the mtproto profile for ``-ms mtproto`` / ``-ms
    telegram`` (targeted) and for ``--protocol mtproto|telegram`` on Android
    (protocol/platform), and platform-gates it off elsewhere;
  * :meth:`MemoryScanEngine.on_script_message` turns a ``keylog`` message that
    carries an MTProto ``label`` into exactly one ``KeylogEvent(protocol=
    "mtproto")`` whose line is the canonical MTPROTO_* layout, writes it to the
    dedicated ``.mtproto.keylog`` sidecar, and leaves non-MTProto keylog
    messages on the standard ``memscan`` path.
"""

from __future__ import annotations

import copy
import hashlib
from types import SimpleNamespace

import pytest

from friTap.events import EventBus, KeylogEvent
from friTap.memory_scanning.loader import (
    MemoryScanPatternError,
    load_database,
    select_profile,
    select_profiles,
    validate_profile,
)
from friTap.memory_scanning import MemoryScanEngine
from friTap.protocols import mtproto_keylog_spec as spec

_MTPROTO_ID = "tgnet-android-arm64-2026"


# --- valid key material (id/fingerprint == sha1(key)[-8:], per the MTProto oracle)
_AUTH_KEY = bytes((i * 3 + 7) % 256 for i in range(256))
_AUTH_KEY_ID = hashlib.sha1(_AUTH_KEY).digest()[-8:]
_AUTH_LINE = f"MTPROTO_AUTH_KEY 2 {_AUTH_KEY_ID.hex()} {_AUTH_KEY.hex()} perm"

_SHARED_KEY = bytes((i * 5 + 11) % 256 for i in range(256))
_E2E_FP = hashlib.sha1(_SHARED_KEY).digest()[-8:]
_E2E_LINE = f"MTPROTO_E2E_KEY {_E2E_FP.hex()} {_SHARED_KEY.hex()} -1355992074"


@pytest.fixture
def mtproto_profile():
    return copy.deepcopy(select_profile(load_database(None), _MTPROTO_ID))


# ---------------------------------------------------------------------------
# Profile validation
# ---------------------------------------------------------------------------

class TestMtprotoProfileValidates:
    def test_shipped_profile_validates(self, mtproto_profile):
        validate_profile(mtproto_profile)  # must not raise
        assert mtproto_profile["engine"] == "mtproto"
        assert mtproto_profile["protocol"] == "mtproto"
        assert mtproto_profile["platforms"] == ["android"]
        assert mtproto_profile["scan_target"] == "self"

    def test_tiers_must_be_object(self, mtproto_profile):
        mtproto_profile["tiers"] = ["not", "an", "object"]
        with pytest.raises(MemoryScanPatternError):
            validate_profile(mtproto_profile)

    def test_authkey_tier_requires_label(self, mtproto_profile):
        mtproto_profile["tiers"]["B_authkeyid_roundtrip"].pop("label", None)
        with pytest.raises(MemoryScanPatternError):
            validate_profile(mtproto_profile)

    def test_e2e_tier_requires_label(self, mtproto_profile):
        mtproto_profile["tiers"]["C_art_secretchat_key"].pop("label", None)
        with pytest.raises(MemoryScanPatternError):
            validate_profile(mtproto_profile)


# ---------------------------------------------------------------------------
# Resolver
# ---------------------------------------------------------------------------

class TestMtprotoResolution:
    def test_targeted_engine_name(self):
        db = load_database(None)
        sel = select_profiles(db, ["tls"], "android", "mtproto")
        assert [p["id"] for p in sel] == [_MTPROTO_ID]

    def test_targeted_telegram_alias(self):
        db = load_database(None)
        sel = select_profiles(db, ["tls"], "android", "telegram")
        assert [p["id"] for p in sel] == [_MTPROTO_ID]

    @pytest.mark.parametrize("proto", ["mtproto", "telegram"])
    def test_protocol_selection_on_android(self, proto):
        db = load_database(None)
        sel = select_profiles(db, [proto], "android", None)
        assert any(p["engine"] == "mtproto" for p in sel)

    def test_protocol_gated_off_other_platforms(self):
        db = load_database(None)
        sel = select_profiles(db, ["mtproto"], "windows", None)
        assert all(p["engine"] != "mtproto" for p in sel)

    def test_targeted_engine_ignores_platform(self):
        # `-ms mtproto` is targeted, so it is returned regardless of platform.
        db = load_database(None)
        sel = select_profiles(db, ["tls"], "windows", "mtproto")
        assert [p["id"] for p in sel] == [_MTPROTO_ID]


# ---------------------------------------------------------------------------
# Message routing
# ---------------------------------------------------------------------------

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
        "tier": "t", "keyId": "id", "source": "src"}}


class TestMtprotoRouting:
    def test_auth_key_emits_mtproto_event(self):
        bus, findings = _bus()
        _engine(bus).on_script_message(_keylog_msg(_AUTH_LINE, "MTPROTO_AUTH_KEY"), None)
        assert len(findings["mtproto"]) == 1
        assert findings["memscan"] == []
        assert findings["mtproto"][0].key_data == _AUTH_LINE
        assert spec.parse_line(findings["mtproto"][0].key_data) is not None

    def test_e2e_key_emits_mtproto_event(self):
        bus, findings = _bus()
        _engine(bus).on_script_message(_keylog_msg(_E2E_LINE, "MTPROTO_E2E_KEY"), None)
        assert len(findings["mtproto"]) == 1
        assert spec.parse_e2e_line(findings["mtproto"][0].key_data) is not None

    def test_auth_key_written_to_sidecar(self, tmp_path):
        bus, _ = _bus()
        path = tmp_path / "t.mtproto.keylog"
        eng = _engine(bus, mtproto_path=str(path))
        eng.on_script_message(_keylog_msg(_AUTH_LINE, "MTPROTO_AUTH_KEY"), None)
        eng._close_mtproto()
        contents = path.read_text()
        assert _AUTH_LINE in contents
        assert contents.startswith("# friTap MTProto keylog")

    def test_sidecar_written_without_context(self, tmp_path):
        # The sidecar is the always-on guarantee for `-ms mtproto` and must be
        # written even without a run context; only the bus emit needs the context.
        bus, findings = _bus()
        path = tmp_path / "t.mtproto.keylog"
        eng = _engine(bus, mtproto_path=str(path))
        eng._context = None  # no run context available
        eng._publish_mtproto_finding({
            "type": "keylog", "line": _AUTH_LINE, "label": "MTPROTO_AUTH_KEY",
            "tier": "t", "keyId": "id", "source": "src",
        })
        eng._close_mtproto()
        assert _AUTH_LINE in path.read_text()   # sidecar still written
        assert findings["mtproto"] == []        # bus emit skipped (no context)

    def test_malformed_mtproto_line_emits_nothing(self):
        bus, findings = _bus()
        bad = "MTPROTO_AUTH_KEY 2 deadbeef " + ("00" * 10) + " perm"  # short key
        _engine(bus).on_script_message(_keylog_msg(bad, "MTPROTO_AUTH_KEY"), None)
        assert findings["mtproto"] == []

    def test_non_mtproto_keylog_stays_on_memscan_path(self):
        # A keylog message WITHOUT an MTProto label (e.g. a boringssl secret) must
        # keep the standard memscan routing, not the mtproto one.
        bus, findings = _bus()
        msg = {"type": "send", "payload": {
            "type": "keylog",
            "line": "CLIENT_RANDOM " + ("ab" * 32) + " " + ("cd" * 48),
            "tier": "A", "source": "s"}}
        _engine(bus).on_script_message(msg, None)
        assert findings["mtproto"] == []
        assert len(findings["memscan"]) == 1
