"""pcap_to_tap: memory-scan sidecars must reach decryption even when the caller
passes ``protocol_keylogs`` (the TUI always does).

Regression for M3: the wrapper merged the sidecar into its local ``mtproto`` and
passed it as ``mtproto_keylog=``, but convert_pcap_to_tap lets a
``protocol_keylogs['mtproto']`` entry win (setdefault), so the merged keylog was
silently discarded and the memscan OBF/auth keys never reached the decryptor.
"""

import json

import friTap.offline.pcap_to_tap as p2t

_HOOK_LINE = "MTPROTO_AUTH_KEY 2 " + "aa" * 8 + " " + "bb" * 256 + " perm"
_SCAN_LINE = ("MTPROTO_OBF_KEY " + "11" * 32 + " " + "22" * 16 + " "
              + "33" * 32 + " " + "44" * 16 + " 0 0 -")


def _write(path, *lines):
    path.write_text("".join(f"{ln}\n" for ln in lines), encoding="utf-8")
    return str(path)


def _write_manifest(pcap, sidecars):
    with open(f"{pcap}.fritap.json", "w", encoding="utf-8") as fh:
        json.dump({"memory_scan_keylogs": sidecars}, fh)


def _read_lines(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read().splitlines()


def _stub_conversion(monkeypatch):
    """Stub tshark + the decoders; record the keylogs each independent pass gets."""
    passes = []
    monkeypatch.setattr(p2t, "find_tshark", lambda path=None: "tshark")
    monkeypatch.setattr(p2t, "tshark_version", lambda binary: None)
    monkeypatch.setattr(p2t, "warn_if_outdated", lambda version: None)
    monkeypatch.setattr(p2t, "_emit_ssh_connections", lambda *a, **k: None)
    monkeypatch.setattr(
        p2t, "_run_independent_entry",
        lambda entry, keylogs, **_kw: passes.append((entry.protocol_name, list(keylogs))))
    return passes


def test_protocol_keylogs_mtproto_receives_merged_sidecar(monkeypatch, tmp_path):
    pcap = str(tmp_path / "cap.pcap")
    (tmp_path / "cap.pcap").write_bytes(b"")
    hook = _write(tmp_path / "hook.log", _HOOK_LINE)
    scan = _write(tmp_path / "ms.log", _SCAN_LINE)
    _write_manifest(pcap, {"mtproto": scan})
    passes = _stub_conversion(monkeypatch)

    p2t.pcap_to_tap(pcap, tap_path=str(tmp_path / "out.tap"),
                    protocol_keylogs={"mtproto": hook}, use_manifest=True)

    mt_passes = [keylogs for proto, keylogs in passes if proto == "mtproto"]
    assert len(mt_passes) == 1
    (used,) = mt_passes[0]
    assert used != hook
    assert _read_lines(used) == [_HOOK_LINE, _SCAN_LINE]


def test_telegram_sidecar_alias_merges_into_protocol_keylogs_mtproto(monkeypatch, tmp_path):
    pcap = str(tmp_path / "cap.pcap")
    (tmp_path / "cap.pcap").write_bytes(b"")
    hook = _write(tmp_path / "hook.log", _HOOK_LINE)
    scan = _write(tmp_path / "ms.log", _SCAN_LINE)
    _write_manifest(pcap, {"telegram": scan})
    passes = _stub_conversion(monkeypatch)

    p2t.pcap_to_tap(pcap, tap_path=str(tmp_path / "out.tap"),
                    protocol_keylogs={"mtproto": hook}, use_manifest=True)

    (used,) = [keylogs for proto, keylogs in passes if proto == "mtproto"][0]
    assert _read_lines(used) == [_HOOK_LINE, _SCAN_LINE]


def test_caller_protocol_keylogs_dict_is_not_mutated(monkeypatch, tmp_path):
    pcap = str(tmp_path / "cap.pcap")
    (tmp_path / "cap.pcap").write_bytes(b"")
    hook = _write(tmp_path / "hook.log", _HOOK_LINE)
    _write_manifest(pcap, {"mtproto": _write(tmp_path / "ms.log", _SCAN_LINE)})
    _stub_conversion(monkeypatch)
    caller_map = {"mtproto": hook}

    p2t.pcap_to_tap(pcap, tap_path=str(tmp_path / "out.tap"),
                    protocol_keylogs=caller_map, use_manifest=True)

    assert caller_map == {"mtproto": hook}


def test_helper_writes_generic_protocol_back_and_keeps_tls_on_base(tmp_path):
    pcap = str(tmp_path / "cap.pcap")
    hook_tls = _write(tmp_path / "hook.tls.log", "CLIENT_RANDOM aa bb")
    hook_x = _write(tmp_path / "hook.x.log", "X_KEY 1")
    scan_tls = _write(tmp_path / "ms.tls.log", "CLIENT_RANDOM cc dd")
    scan_x = _write(tmp_path / "ms.x.log", "X_KEY 2")
    protocol_keylogs = {"xproto": hook_x}
    legacy = {}

    keylog, mtproto = p2t._merge_memory_scan_sidecars_into(
        {"tls": scan_tls, "xproto": scan_x}, pcap, hook_tls, None,
        protocol_keylogs, legacy)

    assert mtproto is None
    assert "tls" not in protocol_keylogs
    assert _read_lines(keylog) == ["CLIENT_RANDOM aa bb", "CLIENT_RANDOM cc dd"]
    assert protocol_keylogs["xproto"] == legacy["xproto_keylog"]
    assert _read_lines(protocol_keylogs["xproto"]) == ["X_KEY 1", "X_KEY 2"]
