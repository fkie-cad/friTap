"""Unit tests for the LibreSSL additions to the Wine GDB extractor.

These cover only the gdb-free parts: the static-host PID fallback in
``wine_key_extract._find_wine_app_pid`` and the well-formedness of the LibreSSL
signatures/handlers declared in ``gdb_wine_extract.py`` (parsed as text, since
that module ``sys.exit``s on import without a real ``gdb``). The in-gdb
breakpoint classes are exercised against a live target, not here."""

import glob
import os
import re

import pytest

from agent_gdb.wine import wine_key_extract as wke

GDB_SCRIPT = os.path.join(
    os.path.dirname(wke.__file__), "gdb_script", "gdb_wine_extract.py"
)


def _gdb_source():
    with open(GDB_SCRIPT) as fh:
        return fh.read()


@pytest.mark.parametrize(
    "exe, procs, expected",
    [
        # Static app: a transient launcher (no exe image mapped) and the real
        # statically linked app (maps curl.exe, no libssl/libgnutls).
        (
            "curl.exe",
            {
                "100": {"cmdline": "C:\\curl.exe\x00-sk\x00", "maps": "7f0000-7f1000 r-xp /usr/lib/wine/wine64\n"},
                "200": {"cmdline": "C:\\curl.exe\x00-sk\x00", "maps": "140000000-1403d0000 r-xp .../curl.exe\n"},
            },
            "200",
        ),
        # The app maps its OWN exe image (static AND dynamic TLS); the launcher
        # only has it in cmdline.
        (
            "app.exe",
            {
                "300": {"cmdline": "app.exe\x00", "maps": "x r-xp /usr/lib/wine/wine64\n"},
                "400": {"cmdline": "app.exe\x00", "maps": "x r-xp /path/app.exe\nx r-xp /usr/lib/x86_64-linux-gnu/libssl.so.3\n"},
            },
            "400",
        ),
        # Secondary accept: maps a TLS lib but not the exe image by name.
        (
            "app.exe",
            {
                "300": {"cmdline": "app.exe\x00", "maps": "x r-xp /usr/lib/wine/wine64\n"},
                "400": {"cmdline": "app.exe\x00", "maps": "x r-xp /usr/lib/x86_64-linux-gnu/libgnutls.so.30\n"},
            },
            "400",
        ),
    ],
    ids=["static-exe-image", "exe-image", "dynamic-tls-lib"],
)
def test_find_wine_app_pid(monkeypatch, exe, procs, expected):
    import io
    import time

    monkeypatch.setattr(glob, "glob", lambda pat: [f"/proc/{p}" for p in procs])

    def fake_open(path, *a, **k):
        pid = path.split("/")[2]
        if path.endswith("cmdline"):
            return io.BytesIO(procs[pid]["cmdline"].encode("latin1"))
        return io.StringIO(procs[pid]["maps"])

    monkeypatch.setattr("builtins.open", fake_open)
    monkeypatch.setattr(time, "sleep", lambda *_a, **_k: None)
    assert wke._find_wine_app_pid(exe, set(), deadline=time.time() + 0.05) == expected


def test_libressl_handlers_registered_and_signatures_valid():
    src = _gdb_source()
    # Handlers referenced by the LibreSSL default patterns must be registered.
    for handler in (
        "LibreSSLHkdfExpandLabelWinBP",
        "LibreSSLTls1PrfWinBP",
    ):
        assert f'"{handler}": {handler}' in src, f"{handler} not in HANDLER_REGISTRY"
        assert f"class {handler}(" in src, f"{handler} class missing"

    # client_random now comes from ws2_32!send, not a struct-walk cr_chain.
    assert "class Ws2SendClientHelloBP(" in src
    assert "def ensure_ws2_send_bp(" in src
    assert "def _pe_find_export(" in src
    assert "LibreSSLDeriveSecretsWinBP" not in src  # removed dead struct-walk

    # The shipped LibreSSL default signatures must be present and reference a
    # registered handler (TLS 1.3 HKDF leaf + TLS 1.2 PRF).
    assert "libressl tls13_hkdf_expand_label_with_length windows" in src
    assert "libressl tls1_PRF windows" in src
    # endbr64 (f30f1efa) prologue bytes present for both.
    assert "f30f1efa5541565657534881eca0000000488dac24800000" in src
    assert "f30f1efa5541574156415541545657534881ecd8000000" in src


def test_label_map_matches_agent_constants():
    src = _gdb_source()
    assert re.search(r'"c hs traffic":\s*"CLIENT_HANDSHAKE_TRAFFIC_SECRET"', src)
    assert re.search(r'"exp master":\s*"EXPORTER_SECRET"', src)
