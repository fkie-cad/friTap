"""Tests for translating friTap --patterns files into the Wine GDB extractor's
flat format (agent_gdb/wine/pattern_translate.py) and for the GDB route
passing the result to both extraction entry points."""

import json
import logging
import os

import pytest

from agent_gdb.wine import pattern_translate as pt

GNUTLS_SYSV = "F3 0F 1E FA 55 49 89 D0 89 CA 48 89 E5"
GNUTLS_WIN64 = "48 83 EC 38 4C 8B 91 60 06 00 00 31 C0"
OPENSSL_WIN64 = "41 57 41 56 41 55 41 54 55 57 56 53 48 83 EC 28"
LIBRESSL_PRF = "F3 0F 1E FA 55 41 57 41 56 41 55 41 54 56 57 53"

# Shaped like the documented docs/platforms/wine.md override, plus the
# LibreSSL KDF shape from agent/shared/libressl_kdf.ts.
REALISTIC_V2 = {
    "modules": {
        "gnutls": {
            "wine": {
                "x64": {
                    "gnutls_keylog_sysv": {"primary": GNUTLS_SYSV,
                                           "fallback": "F3 0F 1E FA 55 48 89 E5"},
                    "gnutls_keylog_win64": {"primary": GNUTLS_WIN64},
                },
                "arm64": {"gnutls_keylog_aarch64": {"primary": "3F 23 03 D5 FD 7B BF A9"}},
            }
        },
        "openssl": {"wine": {"x64": {"openssl_log_secret_win64": {"primary": OPENSSL_WIN64}}}},
        "libressl": {"x64": {"prf": LIBRESSL_PRF}},
    }
}


def _write(tmp_path, data, name="p.json"):
    path = tmp_path / name
    path.write_text(json.dumps(data))
    return str(path)


def _translate(tmp_path, data, caplog):
    with caplog.at_level(logging.WARNING):
        out = pt.wine_patterns_for_gdb(_write(tmp_path, data), logging.getLogger("t"))
    return out


def _load(path):
    with open(path) as fh:
        return json.load(fh)


def test_flat_file_passes_through_unchanged(tmp_path):
    flat = {"aabbcc": {"name": "x", "offset": 4, "handler": "GnuTLSCallKeylogUnixBP"}}
    path = _write(tmp_path, flat)
    assert pt.wine_patterns_for_gdb(path) == path
    assert _load(path) == flat


def test_none_path_returns_none():
    assert pt.wine_patterns_for_gdb(None) is None


def test_v2_realistic_translation(tmp_path, caplog):
    out = _translate(tmp_path, REALISTIC_V2, caplog)
    try:
        flat = _load(out)
    finally:
        os.remove(out)
    key = GNUTLS_SYSV.replace(" ", "").lower()
    assert flat[key]["handler"] == "GnuTLSCallKeylogUnixBP"
    assert flat[key]["offset"] == 0
    assert "gnutls_keylog_sysv" in flat[key]["name"]
    assert flat["f30f1efa554889e5"]["handler"] == "GnuTLSCallKeylogUnixBP"  # fallback
    assert flat[GNUTLS_WIN64.replace(" ", "").lower()]["handler"] == "GnuTLSCallKeylogWindowsBP"
    assert flat[OPENSSL_WIN64.replace(" ", "").lower()]["handler"] == \
        "OpenSSLCallSSLLogSecretWindowsBP"
    assert flat[LIBRESSL_PRF.replace(" ", "").lower()]["handler"] == "LibreSSLTls1PrfWinBP"
    assert len(flat) == 5
    # arm64 has no x86-64 gdb handler: skipped with a warning.
    assert "gnutls_keylog_aarch64" in caplog.text
    # Every translated key is accepted by the gdb script's bytes.fromhex.
    for k in flat:
        bytes.fromhex(k)


def test_translated_handlers_exist_in_gdb_registry():
    src = open(os.path.join(os.path.dirname(pt.__file__), "gdb_script",
                            "gdb_wine_extract.py")).read()
    for handler in list(pt.WINE_SIGNATURE_HANDLERS.values()) + \
            list(pt.LIBRESSL_KDF_HANDLERS.values()):
        assert f'"{handler}": {handler},' in src


def test_unknown_id_skipped_with_warning(tmp_path, caplog):
    data = {"modules": {"gnutls": {"wine": {"x64": {
        "made_up_sig": {"primary": "AA BB"},
        "gnutls_keylog_win64": {"primary": "48 83 EC 38"},
    }}}}}
    out = _translate(tmp_path, data, caplog)
    try:
        assert list(_load(out)) == ["4883ec38"]
    finally:
        os.remove(out)
    assert "made_up_sig" in caplog.text


def test_wildcard_pattern_skipped_with_warning(tmp_path, caplog):
    data = {"modules": {"gnutls": {"wine": {"x64": {"gnutls_keylog_sysv": {
        "primary": "F3 0F ?? FA", "fallback": "F3 0F 1E FA"}}}}}}
    out = _translate(tmp_path, data, caplog)
    try:
        assert list(_load(out)) == ["f30f1efa"]
    finally:
        os.remove(out)
    assert "wildcards" in caplog.text


@pytest.mark.parametrize("data", [
    {"openssl": {"linux": {"x64": {"ssl_log_secret": ["AA BB"]}}}},
    {"modules": {"gnutls": {"wine": {"x64": {"gnutls_keylog_sysv": {"primary": "?? ??"}}}}}},
    [],
])
def test_nothing_applicable_returns_none(tmp_path, caplog, data):
    assert _translate(tmp_path, data, caplog) is None
    assert "no Wine/GDB-applicable entries; ignored" in caplog.text


def test_unreadable_file_returns_none(tmp_path, caplog):
    path = tmp_path / "bad.json"
    path.write_text("{not json")
    with caplog.at_level(logging.WARNING):
        assert pt.wine_patterns_for_gdb(str(path)) is None
    assert "Could not read --patterns" in caplog.text


def test_discard_keeps_user_file_and_removes_temp(tmp_path):
    user = _write(tmp_path, {})
    temp = _write(tmp_path, {}, "tmp.json")
    pt.discard_translated_patterns(user, user)
    pt.discard_translated_patterns(temp, user)
    assert os.path.exists(user) and not os.path.exists(temp)


# --- GDB route call sites ---------------------------------------------------

def _routing_logger(patterns, **kw):
    from tests.unit.test_wine_gdb_routing import _make_logger
    obj = _make_logger(keylog="k.log", **kw)
    obj._config.hooking.patterns = patterns
    return obj


def _capture_runner(monkeypatch, seen_files):
    """Patch both wke entry points; record kwargs plus the patterns file content
    while it still exists (the route deletes a translated temp afterwards)."""
    import agent_gdb.wine.wine_key_extract as wke
    calls = {}

    def fake(name):
        def _run(**kw):
            calls[name] = kw
            if kw.get("patterns"):
                seen_files[name] = _load(kw["patterns"])
            return 0
        return _run

    monkeypatch.setattr(wke, "launch_and_attach", fake("spawn"))
    monkeypatch.setattr(wke, "run_wine_key_extraction", fake("attach"))
    return calls


def test_spawn_call_site_receives_translated_patterns(monkeypatch, tmp_path):
    seen = {}
    calls = _capture_runner(monkeypatch, seen)
    obj = _routing_logger(_write(tmp_path, REALISTIC_V2), spawn=True,
                          target_argv=["wine", "app.exe"])
    obj._run_wine_gdb_session()
    assert obj._done_event.wait(5)
    assert seen["spawn"][LIBRESSL_PRF.replace(" ", "").lower()]["offset"] == 0
    assert not os.path.exists(calls["spawn"]["patterns"])  # temp cleaned up


def test_attach_call_site_receives_flat_patterns(monkeypatch, tmp_path):
    seen = {}
    calls = _capture_runner(monkeypatch, seen)
    flat = {"aabb": {"name": "x", "offset": 0, "handler": "GnuTLSCallKeylogUnixBP"}}
    path = _write(tmp_path, flat)
    obj = _routing_logger(path, spawn=False, target="4321")
    obj._run_wine_gdb_session()
    assert obj._done_event.wait(5)
    assert calls["attach"]["patterns"] == path
    assert os.path.exists(path)  # the user's own file is never deleted


def test_call_sites_get_none_without_patterns(monkeypatch):
    calls = _capture_runner(monkeypatch, {})
    obj = _routing_logger(None, spawn=False, target="4321")
    obj._run_wine_gdb_session()
    assert obj._done_event.wait(5)
    assert calls["attach"]["patterns"] is None
