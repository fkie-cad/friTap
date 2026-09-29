#!/usr/bin/env python3

"""Unit tests for the TLS mid-stream secret-bundle sidecar (Phase 2.2).

When the BoringSSL memory-scan engine recovers a handshake-complete TLS 1.3 socket
it can additionally send a ``tls_secret_bundle`` agent message carrying BOTH randoms
plus the three application-epoch traffic secrets. The Python engine persists these as
a leak-safe JSONL sidecar (one JSON object per line) so an offline mid-stream
decrypter can decrypt flows that have NO ClientHello in the pcap — there is nothing on
the wire to pair the ordinary NSS keylog line against, but server_random is enough.

Covered here, without a device or a Frida session:

  * both shipped BoringSSL profiles still validate and carry the opt-in flag;
  * :meth:`MemoryScanEngine.on_script_message` turns a synthetic ``tls_secret_bundle``
    message into exactly one well-formed JSONL record with the expected fields;
  * the capture-manifest key ``tls_midstream_secrets`` is registered only once a
    bundle is actually written;
  * identical bundles are de-duplicated;
  * leak-safety: no forged ``RSA Session-ID:`` NSS lines, malformed bundles are
    dropped, and a bundle message never emits a keylog event onto the bus.
"""

from __future__ import annotations

import copy
import json
from types import SimpleNamespace

import pytest

from friTap.events import EventBus, KeylogEvent
from friTap.memory_scanning import MemoryScanEngine
from friTap.memory_scanning.loader import (
    load_database,
    select_profile,
    validate_profile,
)

_BORINGSSL_IDS = (
    "boringssl-2025-inplacevector-u8len",
    "boringssl-signal-libsignal-scudo",
)


def _bundle_payload(**overrides) -> dict:
    """A valid tls_secret_bundle payload (32-byte randoms, 32/48-byte secrets)."""
    payload = {
        "type": "tls_secret_bundle",
        "client_random": "aa" * 32,
        "server_random": "bb" * 32,
        "client_traffic_secret_0": "cc" * 32,   # 64 hex = SHA-256 tier
        "server_traffic_secret_0": "dd" * 48,   # 96 hex = SHA-384 tier
        "exporter_secret": "ee" * 32,
        "ssl": "0x7f00abcd00",
    }
    payload.update(overrides)
    return payload


def _message(payload: dict) -> dict:
    return {"type": "send", "payload": payload}


# ---------------------------------------------------------------------------
# Profile: opt-in flag present, profiles still validate
# ---------------------------------------------------------------------------

class TestProfilesStillValidate:
    @pytest.mark.parametrize("profile_id", _BORINGSSL_IDS)
    def test_profile_validates_and_has_flag(self, profile_id):
        profile = copy.deepcopy(select_profile(load_database(None), profile_id))
        validate_profile(profile)  # must not raise
        assert profile["tiers"]["B_ssl_method_ptr"]["emit_secret_bundle"] is True

    def test_non_boringssl_profiles_untouched(self):
        # The flag is a BoringSSL-only supplement; other engines must not carry it.
        db = load_database(None)
        for p in db["profiles"]:
            tier = p.get("tiers", {}).get("B_ssl_method_ptr")
            if p.get("id") not in _BORINGSSL_IDS:
                assert tier is None or "emit_secret_bundle" not in tier


# ---------------------------------------------------------------------------
# Engine: writing the JSONL sidecar
# ---------------------------------------------------------------------------

class TestBundleSidecarWrite:
    def _engine(self, path):
        engine = MemoryScanEngine(tls_secret_bundle_path=str(path))
        # A handler that does not touch the bus still gets a context for parity.
        engine._context = SimpleNamespace(event_bus=EventBus())
        return engine

    def test_writes_one_well_formed_jsonl_record(self, tmp_path):
        out = tmp_path / "cap.tls_midstream.secrets.jsonl"
        engine = self._engine(out)
        engine.on_script_message(_message(_bundle_payload()), None)
        engine._close_tls_secret_bundle()

        lines = out.read_text(encoding="utf-8").splitlines()
        assert len(lines) == 1
        record = json.loads(lines[0])
        assert set(record) == {
            "client_random",
            "server_random",
            "client_traffic_secret_0",
            "server_traffic_secret_0",
            "exporter_secret",
        }
        assert record["client_random"] == "aa" * 32
        assert record["server_random"] == "bb" * 32
        assert record["client_traffic_secret_0"] == "cc" * 32
        assert record["server_traffic_secret_0"] == "dd" * 48
        assert record["exporter_secret"] == "ee" * 32

    def test_manifest_key_registered_only_after_write(self, tmp_path):
        out = tmp_path / "cap.tls_midstream.secrets.jsonl"
        engine = self._engine(out)
        # Nothing written yet -> manifest advertises no sidecar.
        assert engine.tls_midstream_manifest_entry() == {}
        engine.on_script_message(_message(_bundle_payload()), None)
        entry = engine.tls_midstream_manifest_entry()
        assert entry == {"tls_midstream_secrets": str(out)}
        engine._close_tls_secret_bundle()

    def test_identical_bundles_are_deduped(self, tmp_path):
        out = tmp_path / "cap.tls_midstream.secrets.jsonl"
        engine = self._engine(out)
        for _ in range(3):
            engine.on_script_message(_message(_bundle_payload()), None)
        engine._close_tls_secret_bundle()
        assert len(out.read_text(encoding="utf-8").splitlines()) == 1

    def test_distinct_bundles_both_written(self, tmp_path):
        out = tmp_path / "cap.tls_midstream.secrets.jsonl"
        engine = self._engine(out)
        engine.on_script_message(_message(_bundle_payload()), None)
        engine.on_script_message(
            _message(_bundle_payload(client_random="0f" * 32)), None)
        engine._close_tls_secret_bundle()
        assert len(out.read_text(encoding="utf-8").splitlines()) == 2


# ---------------------------------------------------------------------------
# Leak-safety and robustness
# ---------------------------------------------------------------------------

class TestBundleLeakSafety:
    def _engine(self, path):
        engine = MemoryScanEngine(tls_secret_bundle_path=str(path))
        engine._context = SimpleNamespace(event_bus=EventBus())
        return engine

    def test_no_rsa_session_id_or_nss_lines(self, tmp_path):
        out = tmp_path / "cap.tls_midstream.secrets.jsonl"
        engine = self._engine(out)
        engine.on_script_message(_message(_bundle_payload()), None)
        engine._close_tls_secret_bundle()
        text = out.read_text(encoding="utf-8")
        # The sidecar is pure JSON: it can never masquerade as a forged NSS line.
        assert "RSA Session-ID" not in text
        assert "Master-Key" not in text
        for line in text.splitlines():
            assert line.startswith("{") and line.endswith("}")
            assert not line.startswith("CLIENT_RANDOM ")

    def test_bundle_message_emits_no_keylog_event(self, tmp_path):
        # A bundle is a sidecar-only artefact; it must NOT reach the shared keylog
        # bus (that path would print raw key material to the -k keylog / stdout).
        bus = EventBus()
        seen = []
        bus.subscribe(KeylogEvent, lambda e: seen.append(e))
        engine = MemoryScanEngine(
            tls_secret_bundle_path=str(tmp_path / "cap.tls_midstream.secrets.jsonl"))
        engine._context = SimpleNamespace(event_bus=bus)
        engine.on_script_message(_message(_bundle_payload()), None)
        engine._close_tls_secret_bundle()
        assert seen == []

    @pytest.mark.parametrize("overrides", [
        {"exporter_secret": ""},                 # missing field
        {"client_random": "aa" * 16},            # random too short (32 hex)
        {"server_random": "zz" * 32},            # non-hex
        {"client_traffic_secret_0": "cc" * 10},  # secret too short
        {"exporter_secret": "abc"},              # odd-length hex
    ])
    def test_malformed_bundles_are_dropped(self, tmp_path, overrides):
        out = tmp_path / "cap.tls_midstream.secrets.jsonl"
        engine = self._engine(out)
        engine.on_script_message(_message(_bundle_payload(**overrides)), None)
        engine._close_tls_secret_bundle()
        # Nothing valid was written, so the manifest advertises no sidecar and the
        # file was never even created.
        assert engine.tls_midstream_manifest_entry() == {}
        assert not out.exists()
