"""Generic resync-depth and back-compat keylog dispatch of ``convert_pcap_to_tap``.

The core no longer names MTProto: ``resync_search_depth`` reaches an emitter
only under the keyword its registry entry declares (``resync_param``), and
``mtproto_keylog=`` is just one of the back-compat ``<protocol>_keylog`` kwargs.
"""

from __future__ import annotations

import dataclasses

import pytest

import friTap.offline.pcap_to_tap as p2t
from friTap.offline.mtproto import offline_decryptor
from friTap.offline.registry import (
    OfflineDecryptorEntry,
    get_offline_decryptor_registry,
)


def _entry(name: str, emitter, **fields) -> OfflineDecryptorEntry:
    return OfflineDecryptorEntry(
        protocol_name=name, cli_flag=f"--{name}-keylog", cli_dest=f"{name}_keylog",
        requires_tls_strip=False, emitter=emitter, layer_cls=object,
        counter_prefix=name, **fields,
    )


def _recording_emitter(calls: list):
    def emitter(**kwargs):
        calls.append(kwargs)
    return emitter


def _fixed_emitter(calls: list):
    def emitter(*, pcap_path, proto_keylog, tls_keylog_path, tshark_bin,
                tls_ports, bus, state, result):
        calls.append({"proto_keylog": proto_keylog})
    return emitter


@pytest.fixture
def capture(monkeypatch, tmp_path):
    """An empty capture plus a keylog, with tshark and SSH stubbed out."""
    monkeypatch.setattr(p2t, "find_tshark", lambda path=None: "tshark")
    monkeypatch.setattr(p2t, "tshark_version", lambda binary: None)
    monkeypatch.setattr(p2t, "warn_if_outdated", lambda version: None)
    monkeypatch.setattr(p2t, "_emit_ssh_connections", lambda *a, **k: None)
    pcap = tmp_path / "cap.pcap"
    pcap.write_bytes(b"")
    keylog = tmp_path / "proto.log"
    keylog.write_text("KEY 1\n")
    return str(pcap), str(keylog), str(tmp_path / "out.tap")


def _use_entries(monkeypatch, *entries):
    registry = get_offline_decryptor_registry()
    monkeypatch.setattr(registry, "_entries", {e.protocol_name: e for e in entries})


# --------------------------------------------------------------------------- #
# _resync_kwargs
# --------------------------------------------------------------------------- #

def test_resync_kwargs_maps_depth_onto_the_declared_param():
    entry = _entry("x", _recording_emitter([]), resync_param="depth")
    assert p2t._resync_kwargs(entry, 9) == {"depth": 9}
    assert p2t._resync_kwargs(entry, 0) == {"depth": 0}


def test_resync_kwargs_is_empty_without_depth_or_param():
    with_param = _entry("x", _recording_emitter([]), resync_param="depth")
    assert p2t._resync_kwargs(with_param, None) == {}
    assert p2t._resync_kwargs(_entry("y", _recording_emitter([])), 9) == {}


def test_resync_kwargs_is_empty_when_the_emitter_rejects_the_param():
    entry = _entry("x", _fixed_emitter([]), resync_param="depth")
    assert p2t._resync_kwargs(entry, 9) == {}


def test_resync_kwargs_tolerates_entries_without_the_field():
    class LegacyEntry:
        emitter = staticmethod(_recording_emitter([]))

    assert p2t._resync_kwargs(LegacyEntry(), 9) == {}


# --------------------------------------------------------------------------- #
# convert_pcap_to_tap dispatch
# --------------------------------------------------------------------------- #

def test_mtproto_keylog_kwarg_still_reaches_the_mtproto_pass(monkeypatch, capture):
    pcap, keylog, tap = capture
    passes = []
    monkeypatch.setattr(
        p2t, "_run_independent_entry",
        lambda entry, keylogs, **_kw: passes.append((entry.protocol_name, list(keylogs))))

    p2t.convert_pcap_to_tap(pcap, tap_path=tap, mtproto_keylog=keylog)

    assert passes == [("mtproto", [keylog])]


def test_protocol_keylogs_entry_wins_over_mtproto_keylog_kwarg(monkeypatch, capture, tmp_path):
    pcap, keylog, tap = capture
    other = tmp_path / "other.log"
    other.write_text("KEY 2\n")
    passes = []
    monkeypatch.setattr(
        p2t, "_run_independent_entry",
        lambda entry, keylogs, **_kw: passes.append((entry.protocol_name, list(keylogs))))

    p2t.convert_pcap_to_tap(pcap, tap_path=tap, mtproto_keylog=str(other),
                            protocol_keylogs={"mtproto": keylog})

    assert passes == [("mtproto", [keylog])]


def test_resync_depth_reaches_the_telegram_emitter_as_obf_max_blocks(monkeypatch, capture):
    pcap, keylog, tap = capture
    calls = []
    monkeypatch.setattr(offline_decryptor, "_emit_telegram_streams",
                        lambda *a, **kw: calls.append(kw))
    _use_entries(monkeypatch, get_offline_decryptor_registry().get("telegram"))

    p2t.convert_pcap_to_tap(pcap, tap_path=tap, protocol_keylogs={"telegram": keylog},
                            resync_search_depth=7)

    assert [kw["obf_max_blocks"] for kw in calls] == [7]


def test_no_resync_depth_keeps_the_telegram_default(monkeypatch, capture):
    pcap, keylog, tap = capture
    calls = []
    monkeypatch.setattr(offline_decryptor, "_emit_telegram_streams",
                        lambda *a, **kw: calls.append(kw))
    _use_entries(monkeypatch, get_offline_decryptor_registry().get("telegram"))

    p2t.convert_pcap_to_tap(pcap, tap_path=tap, protocol_keylogs={"telegram": keylog})

    assert [kw["obf_max_blocks"] for kw in calls] == [
        offline_decryptor.DEFAULT_OBF_MAX_BLOCKS]


def test_kwargs_plugin_without_resync_param_gets_no_depth(monkeypatch, capture):
    pcap, keylog, tap = capture
    calls = []
    _use_entries(monkeypatch, _entry("plugin", _recording_emitter(calls)))

    p2t.convert_pcap_to_tap(pcap, tap_path=tap, protocol_keylogs={"plugin": keylog},
                            resync_search_depth=7)

    assert len(calls) == 1
    assert "obf_max_blocks" not in calls[0]
    assert 7 not in calls[0].values()


def test_kwargs_plugin_with_resync_param_gets_depth_under_its_name(monkeypatch, capture):
    pcap, keylog, tap = capture
    calls = []
    _use_entries(monkeypatch,
                 _entry("plugin", _recording_emitter(calls), resync_param="lag"))

    p2t.convert_pcap_to_tap(pcap, tap_path=tap, protocol_keylogs={"plugin": keylog},
                            resync_search_depth=0)

    assert [c.get("lag") for c in calls] == [0]
    assert "obf_max_blocks" not in calls[0]


def _stub_keyed_tshark_passes(monkeypatch):
    """A keyed capture (embedded DSB) whose tshark stage does nothing."""
    monkeypatch.setattr(p2t, "capture_has_dsb", lambda path: True)
    monkeypatch.setattr(p2t, "_run_tshark_stage", lambda ctx: None)


@pytest.mark.parametrize("resync_param, expected", [("lag", {"lag": 5}), (None, {})])
def test_tls_riding_plugin_gets_depth_only_with_resync_param(
        monkeypatch, capture, resync_param, expected):
    pcap, keylog, tap = capture
    calls = []
    entry = dataclasses.replace(
        _entry("rider", _recording_emitter(calls), resync_param=resync_param),
        requires_tls_strip=True)
    _use_entries(monkeypatch, entry)
    _stub_keyed_tshark_passes(monkeypatch)

    p2t.convert_pcap_to_tap(pcap, tap_path=tap, protocol_keylogs={"rider": keylog},
                            resync_search_depth=5)

    assert len(calls) == 1
    assert {k: v for k, v in calls[0].items() if k in ("lag", "obf_max_blocks")} == expected
