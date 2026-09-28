"""Tests for the --ms-emit-unconfirmed opt-in on the memory-scan engine (E4).

Hermetic (no device / Frida). Covers:

  * ``_apply_emit_unconfirmed`` stamps ``emitUnconfirmed`` onto MTProto profiles
    only, on a copy, and only when the flag is set;
  * ``_handle_unpaired`` persists an unconfirmed mtproto candidate to the
    .mtproto.keylog ONLY when the flag is set (log-only otherwise);
  * the CLI-config flag threads through ``FriTapConfig`` to the engine builder.
"""

from __future__ import annotations

import pytest

from friTap.memory_scanning import MemoryScanEngine


# --------------------------------------------------------------------------- #
# Profile stamp (E4a)
# --------------------------------------------------------------------------- #


def test_apply_emit_unconfirmed_stamps_mtproto_only_on_a_copy():
    eng = MemoryScanEngine(emit_unconfirmed=True)
    profiles = [{"engine": "mtproto", "id": "tg"}, {"engine": "boringssl", "id": "bs"}]
    out = eng._apply_emit_unconfirmed(profiles)
    assert out[0]["emitUnconfirmed"] is True
    assert "emitUnconfirmed" not in out[1]          # non-mtproto untouched
    assert "emitUnconfirmed" not in profiles[0]      # shared DB object not mutated


def test_apply_emit_unconfirmed_is_a_passthrough_when_off():
    eng = MemoryScanEngine(emit_unconfirmed=False)
    profiles = [{"engine": "mtproto", "id": "tg"}]
    assert eng._apply_emit_unconfirmed(profiles) is profiles


# --------------------------------------------------------------------------- #
# Unpaired candidate sidecar write (E4b)
# --------------------------------------------------------------------------- #


_CANDIDATE = {
    "type": "unpaired", "kind": "authkey_unconfirmed",
    "keyId": "aabbccddeeff0011", "addr": "0x7f00", "entropy": 7.85,
}


def test_candidate_written_to_mtproto_keylog_when_flag_set(tmp_path):
    path = tmp_path / "t.mtproto.keylog"
    eng = MemoryScanEngine(emit_unconfirmed=True, mtproto_path=str(path))
    eng._handle_unpaired(dict(_CANDIDATE))
    eng._close_mtproto()
    text = path.read_text()
    assert "UNCONFIRMED" in text
    assert "aabbccddeeff0011" in text
    # Written as a comment so the keylog parser skips it (no bogus key).
    assert any(line.startswith("#") and "UNCONFIRMED" in line
               for line in text.splitlines())


def test_no_candidate_written_when_flag_off(tmp_path):
    path = tmp_path / "t.mtproto.keylog"
    eng = MemoryScanEngine(emit_unconfirmed=False, mtproto_path=str(path))
    eng._handle_unpaired(dict(_CANDIDATE))
    eng._close_mtproto()
    # The sidecar is opened lazily on first write; with the flag off nothing writes.
    assert not path.exists()


def test_e2e_unconfirmed_kind_also_routed(tmp_path):
    path = tmp_path / "t.mtproto.keylog"
    eng = MemoryScanEngine(emit_unconfirmed=True, mtproto_path=str(path))
    eng._handle_unpaired({
        "type": "unpaired", "kind": "e2e_unconfirmed",
        "keyId": "0011223344556677", "addr": "0x10", "entropy": 7.9,
    })
    eng._close_mtproto()
    assert "e2e_unconfirmed" in path.read_text()


# --------------------------------------------------------------------------- #
# CLI-config wiring (argparse dest -> config -> engine flag)
# --------------------------------------------------------------------------- #


def test_config_carries_emit_unconfirmed_flag():
    from friTap.config import FriTapConfig

    on = FriTapConfig.from_legacy_params("com.example", memory_scan_emit_unconfirmed=True)
    off = FriTapConfig.from_legacy_params("com.example")
    assert on.hooking.memory_scan_emit_unconfirmed is True
    assert off.hooking.memory_scan_emit_unconfirmed is False
