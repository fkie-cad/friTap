#!/usr/bin/env python3

"""Unit tests for the RC4 memory-scan engine (Workstream 3), Python side.

Covers, without a device or a Frida session:

  * the shipped ``rc4-memscan-generic`` profile validates (and its KAT actually
    holds — RC4(key, plaintext) == ciphertext);
  * :func:`_validate_rc4_profile` rejects bad rc4 shapes (out-of-bounds params,
    a wrong KAT, non-hex KAT bytes);
  * :meth:`MemoryScanEngine.on_script_message` turns an ``rc4_key`` agent
    message into exactly one ``KeylogEvent(protocol="rc4")`` whose line is the
    canonical ``RC4_KEY`` layout, and which renders through
    :class:`Rc4KeylogFormatter` to the ``.rc4`` keylog file.
"""

from __future__ import annotations

import copy
from types import SimpleNamespace

import pytest

from friTap.events import EventBus, KeylogEvent
from friTap.memory_scanning.loader import (
    MemoryScanPatternError,
    load_database,
    select_profile,
    validate_profile,
)
from friTap.memory_scanning import MemoryScanEngine
from friTap.protocols import rc4_keylog_spec as spec
from friTap.protocols.rc4_handler import Rc4KeylogFormatter

_RC4_ID = "rc4-memscan-generic"


@pytest.fixture
def rc4_profile():
    return copy.deepcopy(select_profile(load_database(None), _RC4_ID))


# ---------------------------------------------------------------------------
# Profile validation
# ---------------------------------------------------------------------------

class TestRc4ProfileValidates:
    def test_shipped_rc4_profile_validates(self, rc4_profile):
        # Must not raise; also confirms the KAT holds (validate recomputes RC4).
        validate_profile(rc4_profile)
        assert rc4_profile["engine"] == "rc4"
        assert rc4_profile["protocol"] == "rc4"
        assert rc4_profile["scan_target"] == "self"

    def test_kat_actually_holds(self, rc4_profile):
        kat = rc4_profile["kat"]
        # The reference the loader uses: RC4('Key','Plaintext') == bbf316e8d940af0ad3.
        assert kat["ciphertext"] == "bbf316e8d940af0ad3"


class TestRc4ProfileRejectsBadShapes:
    def test_min_greater_than_max_rejected(self, rc4_profile):
        rc4_profile["params"]["min_key_len"] = 64
        rc4_profile["params"]["max_key_len"] = 5
        with pytest.raises(MemoryScanPatternError):
            validate_profile(rc4_profile)

    def test_accept_fraction_out_of_range_rejected(self, rc4_profile):
        rc4_profile["params"]["accept_printable_fraction"] = 1.5
        with pytest.raises(MemoryScanPatternError):
            validate_profile(rc4_profile)

    def test_missing_required_param_rejected(self, rc4_profile):
        del rc4_profile["params"]["trial_prefix"]
        with pytest.raises(MemoryScanPatternError):
            validate_profile(rc4_profile)

    def test_wrong_kat_rejected(self, rc4_profile):
        # A ciphertext that does not match RC4(key, plaintext) must fail loudly.
        rc4_profile["kat"]["ciphertext"] = "00" * 9
        with pytest.raises(MemoryScanPatternError):
            validate_profile(rc4_profile)

    def test_non_hex_kat_rejected(self, rc4_profile):
        rc4_profile["kat"]["key"] = "nothex!"
        with pytest.raises(MemoryScanPatternError):
            validate_profile(rc4_profile)

    def test_grouped_read_non_bool_rejected(self, rc4_profile):
        rc4_profile["params"]["grouped_read"] = "yes"
        with pytest.raises(MemoryScanPatternError):
            validate_profile(rc4_profile)

    def test_needs_mapped_index_non_bool_rejected(self, rc4_profile):
        rc4_profile["params"]["needs_mapped_index"] = 1
        with pytest.raises(MemoryScanPatternError):
            validate_profile(rc4_profile)

    def test_read_group_bytes_non_positive_rejected(self, rc4_profile):
        rc4_profile["params"]["read_group_bytes"] = 0
        with pytest.raises(MemoryScanPatternError):
            validate_profile(rc4_profile)


# ---------------------------------------------------------------------------
# Plugin message translation: rc4_key -> KeylogEvent(protocol="rc4")
# ---------------------------------------------------------------------------

@pytest.fixture
def bus_and_rc4_findings():
    bus = EventBus()
    findings = []
    bus.subscribe(
        KeylogEvent,
        lambda e: findings.append(e) if e.protocol == "rc4" else None,
    )
    return bus, findings


class TestRc4KeyMessageTranslation:
    def _plugin(self, bus):
        plugin = MemoryScanEngine()
        plugin._context = SimpleNamespace(event_bus=bus)
        return plugin

    def test_rc4_key_message_emits_one_rc4_keylog_line(self, bus_and_rc4_findings):
        bus, findings = bus_and_rc4_findings
        plugin = self._plugin(bus)
        message = {
            "type": "send",
            "payload": {
                "type": "rc4_key",
                "key": "6b6579",           # "key"
                "key_len": 3,
                "source": "memscan-trial",
                "direction": "unknown",
                "assoc": "-",
            },
        }
        plugin.on_script_message(message, None)

        assert len(findings) == 1
        event = findings[0]
        assert event.protocol == "rc4"
        assert event.key_data == "RC4_KEY 6b6579 3 memscan-trial unknown -"
        # The payload carries the structured fields Rc4KeylogFormatter re-renders.
        assert event.payload["key"] == "6b6579"
        assert event.payload["source"] == "memscan-trial"

    def test_rc4_key_written_to_dedicated_sidecar(self, bus_and_rc4_findings, tmp_path):
        """A recovered RC4 key must land in the plugin's own file even when the
        run did NOT select --protocol rc4 (targeted `-ms rc4`), so it is never
        silently dropped for lack of an rc4 keylog handler."""
        bus, _ = bus_and_rc4_findings
        rc4_file = tmp_path / "t_memscan.rc4.keylog"
        plugin = MemoryScanEngine(rc4_path=str(rc4_file))
        plugin._context = SimpleNamespace(event_bus=bus)
        plugin.on_script_message(
            {"type": "send", "payload": {
                "type": "rc4_key", "key": "6b6579", "key_len": 3,
                "source": "memscan-trial", "direction": "unknown", "assoc": "-",
            }},
            None,
        )
        plugin._close_rc4()
        contents = rc4_file.read_text()
        assert "RC4_KEY 6b6579 3 memscan-trial unknown -" in contents
        assert contents.startswith("# friTap RC4 memory-scan recovered keys")

    def test_rc4_key_renders_through_formatter(self, bus_and_rc4_findings):
        bus, findings = bus_and_rc4_findings
        plugin = self._plugin(bus)
        plugin.on_script_message(
            {"type": "send", "payload": {
                "type": "rc4_key", "key": "6b6579", "key_len": 3,
                "source": "memscan-sbox", "direction": "unknown", "assoc": "-"}},
            None,
        )
        assert len(findings) == 1
        lines = Rc4KeylogFormatter().format(findings[0])
        assert lines == ["RC4_KEY 6b6579 3 memscan-sbox unknown -"]

    def test_malformed_rc4_key_emits_nothing(self, bus_and_rc4_findings):
        # key_len disagreeing with the hex is a truncated/garbled field: dropped.
        bus, findings = bus_and_rc4_findings
        plugin = self._plugin(bus)
        plugin.on_script_message(
            {"type": "send", "payload": {
                "type": "rc4_key", "key": "6b6579", "key_len": 99,
                "source": "memscan-trial", "direction": "unknown", "assoc": "-"}},
            None,
        )
        assert findings == []

    def test_sbox_256_byte_key_is_accepted(self, bus_and_rc4_findings):
        # An S-box recovery emits the 256-byte permutation as the key (max len).
        bus, findings = bus_and_rc4_findings
        plugin = self._plugin(bus)
        sbox_hex = "".join(f"{b:02x}" for b in range(256))
        plugin.on_script_message(
            {"type": "send", "payload": {
                "type": "rc4_key", "key": sbox_hex, "key_len": 256,
                "source": "memscan-sbox", "direction": "unknown", "assoc": "-"}},
            None,
        )
        assert len(findings) == 1
        assert findings[0].key_data == f"RC4_KEY {sbox_hex} 256 memscan-sbox unknown -"
