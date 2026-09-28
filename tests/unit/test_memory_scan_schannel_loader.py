#!/usr/bin/env python3

"""Unit tests for the Schannel memory-scan engine (Workstream 4), Python side.

Covers, without a device or a Frida session:

  * the shipped ``schannel-win11-ncryptsslp`` profile validates;
  * per-arch offset selection (:func:`select_schannel_offsets`) returns the
    arm64 / x64 blocks, and :func:`resolve_schannel_arch` stamps the chosen block
    onto ``profile["resolved"]`` for the data-driven agent;
  * :func:`_validate_schannel_profile` rejects malformed per-arch offset sets;
  * :meth:`MemoryScanEngine.on_script_message` writes ``unpaired`` schannel
    secrets to the documented sidecar (``<kind> <secret> <session_id|-> <ver>``)
    and republishes a session-cache ``keylog`` line as a memscan KeylogEvent,
    while a BoringSSL ``orphan_session`` still only logs.
"""

from __future__ import annotations

import copy
from types import SimpleNamespace

import pytest

from friTap.events import EventBus, KeylogEvent
from friTap.memory_scanning.loader import (
    MemoryScanPatternError,
    load_database,
    resolve_schannel_arch,
    select_profile,
    select_schannel_offsets,
    validate_profile,
)
from friTap.memory_scanning import MemoryScanEngine

_SCHANNEL_ID = "schannel-win11-ncryptsslp"


@pytest.fixture
def schannel_profile():
    return copy.deepcopy(select_profile(load_database(None), _SCHANNEL_ID))


# ---------------------------------------------------------------------------
# Profile validation + per-arch selection
# ---------------------------------------------------------------------------

class TestSchannelProfileValidates:
    def test_shipped_schannel_profile_validates(self, schannel_profile):
        validate_profile(schannel_profile)
        assert schannel_profile["engine"] == "schannel"
        assert schannel_profile["scan_target"] == "lsass"
        assert schannel_profile["platforms"] == ["windows"]

    def test_arm64_is_calibrated_x64_is_not(self, schannel_profile):
        arch = schannel_profile["arch"]
        assert arch["arm64"]["calibrated"] is True
        assert arch["x64"]["calibrated"] is False
        # x64 must NOT invent verified needle rvas.
        assert arch["x64"]["needle"]["candidates"] == []
        assert len(arch["arm64"]["needle"]["candidates"]) >= 1


class TestPerArchOffsetSelection:
    def test_selects_arm64_block(self, schannel_profile):
        block = select_schannel_offsets(schannel_profile, "arm64")
        assert block is schannel_profile["arch"]["arm64"]
        assert block["tiers"]["tls12_master"]["master_at"] == 28

    def test_selects_x64_block(self, schannel_profile):
        block = select_schannel_offsets(schannel_profile, "x64")
        assert block is schannel_profile["arch"]["x64"]

    def test_unknown_arch_with_multiple_sets_raises(self, schannel_profile):
        with pytest.raises(MemoryScanPatternError):
            select_schannel_offsets(schannel_profile, "mips")

    def test_resolve_stamps_resolved_block(self, schannel_profile):
        resolved = resolve_schannel_arch(schannel_profile, "arm64")
        assert resolved["resolved"] is schannel_profile["arch"]["arm64"]
        # Original left untouched (a shallow copy is returned).
        assert "resolved" not in schannel_profile

    def test_single_arch_fallback_when_arch_unknown(self, schannel_profile):
        schannel_profile["arch"] = {"arm64": schannel_profile["arch"]["arm64"]}
        block = select_schannel_offsets(schannel_profile, None)
        assert block["tiers"]["tls12_master"]["master_len"] == 48


class TestSchannelRejectsMalformedOffsets:
    def test_non_int_offset_rejected(self, schannel_profile):
        schannel_profile["arch"]["arm64"]["tiers"]["tls12_master"]["master_at"] = "twenty-eight"
        with pytest.raises(MemoryScanPatternError):
            validate_profile(schannel_profile)

    def test_needle_without_module_rejected(self, schannel_profile):
        del schannel_profile["arch"]["arm64"]["needle"]["module"]
        with pytest.raises(MemoryScanPatternError):
            validate_profile(schannel_profile)

    def test_candidate_without_rva_rejected(self, schannel_profile):
        schannel_profile["arch"]["arm64"]["needle"]["candidates"] = [{"note": "x"}]
        with pytest.raises(MemoryScanPatternError):
            validate_profile(schannel_profile)

    def test_empty_arch_rejected(self, schannel_profile):
        schannel_profile["arch"] = {}
        with pytest.raises(MemoryScanPatternError):
            validate_profile(schannel_profile)


# ---------------------------------------------------------------------------
# Plugin message translation: unpaired sidecar + session-cache keylog
# ---------------------------------------------------------------------------

@pytest.fixture
def bus_and_memscan_findings():
    bus = EventBus()
    findings = []
    bus.subscribe(
        KeylogEvent,
        lambda e: findings.append(e) if e.protocol == "memscan" else None,
    )
    return bus, findings


class TestSchannelPluginMessages:
    def _plugin(self, bus, tmp_path):
        plugin = MemoryScanEngine(
            unpaired_path=str(tmp_path / "keys.schannel.unpaired"))
        plugin._context = SimpleNamespace(event_bus=bus)
        return plugin

    def test_unpaired_tls12_master_written_to_sidecar(self, bus_and_memscan_findings, tmp_path):
        bus, findings = bus_and_memscan_findings
        plugin = self._plugin(bus, tmp_path)
        secret = "ab" * 48
        plugin.on_script_message(
            {"type": "send", "payload": {
                "type": "unpaired", "kind": "schannel_tls12_master",
                "secret": secret, "session_id": "", "ssl_version": 771,
                "addr": "0x1234"}},
            None,
        )
        plugin._close_unpaired()
        path = tmp_path / "keys.schannel.unpaired"
        assert path.exists()
        rows = [ln for ln in path.read_text().splitlines() if not ln.startswith("#")]
        # Documented format: <kind> <secret_hex> <session_id|-> <ssl_version>
        assert rows == [f"schannel_tls12_master {secret} - 771"]
        # Unpaired secrets never become keylog events.
        assert findings == []

    def test_unpaired_tls13_secret_written_to_sidecar(self, bus_and_memscan_findings, tmp_path):
        bus, findings = bus_and_memscan_findings
        plugin = self._plugin(bus, tmp_path)
        secret = "cd" * 32
        plugin.on_script_message(
            {"type": "send", "payload": {
                "type": "unpaired", "kind": "schannel_tls13_secret",
                "secret": secret, "session_id": "", "ssl_version": 772,
                "addr": "0x9999"}},
            None,
        )
        plugin._close_unpaired()
        rows = [ln for ln in (tmp_path / "keys.schannel.unpaired").read_text().splitlines()
                if not ln.startswith("#")]
        assert rows == [f"schannel_tls13_secret {secret} - 772"]

    def test_orphan_session_not_written_to_schannel_sidecar(self, bus_and_memscan_findings, tmp_path):
        # BoringSSL Tier C orphan_session has no offline correlator: it is only
        # logged, and must NOT land in the schannel sidecar.
        bus, findings = bus_and_memscan_findings
        plugin = self._plugin(bus, tmp_path)
        plugin.on_script_message(
            {"type": "send", "payload": {
                "type": "unpaired", "kind": "orphan_session", "secret": "dead"}},
            None,
        )
        plugin._close_unpaired()
        assert not (tmp_path / "keys.schannel.unpaired").exists()
        assert findings == []

    def test_session_cache_keylog_flows_as_memscan_event(self, bus_and_memscan_findings, tmp_path):
        # The session_cache tier emits a Wireshark-ingestible NSS session-id line
        # as a keylog message; it must republish as a memscan KeylogEvent verbatim.
        bus, findings = bus_and_memscan_findings
        plugin = self._plugin(bus, tmp_path)
        line = "RSA Session-ID:aabbccdd Master-Key:" + ("ee" * 48)
        plugin.on_script_message(
            {"type": "send", "payload": {
                "type": "keylog", "line": line,
                "tier": "schannel_session_cache", "source": "session_cache"}},
            None,
        )
        assert len(findings) == 1
        assert findings[0].protocol == "memscan"
        assert findings[0].key_data == line
        assert findings[0].payload["tier"] == "schannel_session_cache"
