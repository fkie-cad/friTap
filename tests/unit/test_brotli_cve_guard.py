#!/usr/bin/env python3

"""Tests for the brotli CVE-2026-111497 guard and tshark body-decompression opts."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

import friTap.parsers.decompress as decompress
from friTap.offline import tshark as tshark_mod
from friTap.offline.schannel import correlate
from friTap.parsers.decompress import (
    ALLOW_UNPATCHED_BROTLI_ENV,
    BROTLI_VULNERABLE_ERROR_FMT,
    brotli_security_warning,
    brotli_status,
    decompress_body,
    decompress_lenient,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
PAYLOAD = b"brotli guard payload " * 32
FAKE_TSHARK = "/opt/fake/tshark"
FAKE_PREFS = ("http.decompress_body", "websocket.decompress")
EXPECTED_OPTS = ["-o", "http.decompress_body:FALSE", "-o", "websocket.decompress:FALSE"]


@pytest.fixture(autouse=True)
def _no_override(monkeypatch):
    """Undo the unit-suite override so each test controls the env itself."""
    monkeypatch.delenv(ALLOW_UNPATCHED_BROTLI_ENV, raising=False)


@pytest.fixture
def brotli():
    return pytest.importorskip("brotli")


def _set_version(monkeypatch, version):
    monkeypatch.setattr(decompress, "_BROTLI_VERSION", version)


# --- version parsing ----------------------------------------------------------

@pytest.mark.parametrize("text, expected", [
    ("1.2.1", (1, 2, 1)),
    ("1.2.0.post1", (1, 2, 0)),
    ("1.1.0-2", (1, 1, 0)),
    ("1.0.9rc1", (1, 0, 9)),
    ("2", (2,)),
    (" 1.3.0 ", (1, 3, 0)),
    ("abc", ()),
    ("", ()),
    ("v1.2.1", ()),
])
def test_parse_version(text, expected):
    assert decompress._parse_version(text) == expected


@pytest.mark.parametrize("version, vulnerable", [
    ("1.0.2", False),
    ("0.9.0", False),
    ("1.0.3", True),
    ("1.0.9", True),
    ("1.1.0", True),
    ("1.2.0", True),
    ("1.2.0.post1", True),
    ("1.2.1", False),
    ("1.3.0", False),
    ("unknown", True),
    (None, True),
])
def test_vulnerable_range_boundaries(version, vulnerable):
    assert decompress._is_vulnerable_brotli(version) is vulnerable


# --- env override -------------------------------------------------------------

@pytest.mark.parametrize("value, allowed", [
    ("1", True), ("true", True), ("TRUE", True), ("Yes", True),
    ("0", False), ("no", False), ("", False),
])
def test_override_values(monkeypatch, value, allowed):
    monkeypatch.setenv(ALLOW_UNPATCHED_BROTLI_ENV, value)
    assert decompress._unpatched_brotli_allowed() is allowed


def test_brotli_status_reports_override_at_call_time(monkeypatch):
    _set_version(monkeypatch, "1.2.0")
    assert brotli_status() == ("1.2.0", True, False)
    monkeypatch.setenv(ALLOW_UNPATCHED_BROTLI_ENV, "1")
    assert brotli_status() == ("1.2.0", True, True)


def test_brotli_status_without_brotli(monkeypatch):
    _set_version(monkeypatch, None)
    assert brotli_status() == (None, False, False)
    assert brotli_security_warning() is None


# --- decompress_body / decompress_lenient -------------------------------------

def test_vulnerable_brotli_skips_decoding(monkeypatch, brotli):
    _set_version(monkeypatch, "1.2.0")
    body = brotli.compress(PAYLOAD)
    assert decompress_body(body, "br") == (
        body, BROTLI_VULNERABLE_ERROR_FMT.format(version="1.2.0"))


def test_vulnerable_error_text():
    msg = BROTLI_VULNERABLE_ERROR_FMT.format(version="1.1.0")
    assert msg == ("brotli 1.1.0 is vulnerable to CVE-2026-111497; "
                   "upgrade to brotli>=1.2.1 (decoding skipped)")


def test_override_decodes_vulnerable_brotli(monkeypatch, brotli):
    _set_version(monkeypatch, "1.2.0")
    monkeypatch.setenv(ALLOW_UNPATCHED_BROTLI_ENV, "yes")
    assert decompress_body(brotli.compress(PAYLOAD), "br") == (PAYLOAD, "")


def test_patched_brotli_decodes(monkeypatch, brotli):
    _set_version(monkeypatch, "1.2.1")
    assert decompress_body(brotli.compress(PAYLOAD), "brotli") == (PAYLOAD, "")


def test_lenient_passes_cve_error_through(monkeypatch, brotli):
    _set_version(monkeypatch, "1.0.3")
    body = brotli.compress(PAYLOAD)
    assert decompress_lenient(body, "br") == (
        body, [], BROTLI_VULNERABLE_ERROR_FMT.format(version="1.0.3"))


def test_guard_does_not_touch_other_encodings(monkeypatch):
    import gzip
    _set_version(monkeypatch, "1.2.0")
    assert decompress_body(gzip.compress(PAYLOAD), "gzip") == (PAYLOAD, "")


# --- startup warning ----------------------------------------------------------

def test_security_warning_none_when_safe(monkeypatch):
    _set_version(monkeypatch, "1.2.1")
    assert brotli_security_warning() is None


def test_security_warning_none_when_overridden(monkeypatch):
    _set_version(monkeypatch, "1.2.0")
    monkeypatch.setenv(ALLOW_UNPATCHED_BROTLI_ENV, "1")
    assert brotli_security_warning() is None


def test_security_warning_text_when_vulnerable(monkeypatch):
    _set_version(monkeypatch, "1.2.0")
    warning = brotli_security_warning()
    assert "brotli 1.2.0" in warning and "CVE-2026-111497" in warning
    assert "pip install -U 'brotli>=1.2.1'" in warning
    assert ALLOW_UNPATCHED_BROTLI_ENV in warning


def test_startup_warning_emitted_once(monkeypatch, caplog):
    from friTap import friTap as cli_mod
    _set_version(monkeypatch, "1.2.0")
    monkeypatch.setattr(cli_mod, "_BROTLI_WARNING_EMITTED", False)
    with caplog.at_level("WARNING", logger="friTap"):
        cli_mod._warn_if_vulnerable_brotli()
        cli_mod._warn_if_vulnerable_brotli()
    hits = [r for r in caplog.records if "CVE-2026-111497" in r.getMessage()]
    assert len(hits) == 1


# --- requirements floor -------------------------------------------------------

@pytest.mark.parametrize("name", ["requirements.txt", "requirements-minimal.txt"])
def test_requirements_pin_patched_brotli(name):
    text = (REPO_ROOT / name).read_text()
    match = re.search(r"^brotli\s*>=\s*([0-9][0-9.]*)\s*$", text, re.MULTILINE)
    assert match, f"{name} has no brotli floor"
    assert decompress._parse_version(match.group(1)) >= decompress._BROTLI_MIN_SAFE


# --- tshark body-decompression opts -------------------------------------------

@pytest.fixture
def fake_prefs(monkeypatch):
    """Pretend every tshark supports exactly FAKE_PREFS (no subprocess)."""
    monkeypatch.setattr(tshark_mod, "_supported_body_decompression_prefs",
                        lambda _path: FAKE_PREFS)


def _contains_run(argv, run):
    return any(argv[i:i + len(run)] == run for i in range(len(argv)))


def test_pref_probe_filters_to_known_prefs(monkeypatch):
    class _Proc:
        stdout = ("# Whether to uncompress entity bodies: x\n"
                  "#http.decompress_body: TRUE\n#websocket.decompress: TRUE\n"
                  "#tcp.try_heuristic_first: FALSE\n")

    calls = []
    monkeypatch.setattr(tshark_mod.subprocess, "run",
                        lambda argv, **kw: calls.append(argv) or _Proc())
    tshark_mod._supported_body_decompression_prefs.cache_clear()
    try:
        assert tshark_mod.no_body_decompression_opts(FAKE_TSHARK) == EXPECTED_OPTS
        tshark_mod.no_body_decompression_opts(FAKE_TSHARK)
    finally:
        tshark_mod._supported_body_decompression_prefs.cache_clear()
    assert calls == [[FAKE_TSHARK, "-G", "defaultprefs"]]  # cached per path


def test_pref_probe_failure_adds_nothing(monkeypatch):
    def _boom(*_a, **_k):
        raise FileNotFoundError("no tshark")

    monkeypatch.setattr(tshark_mod.subprocess, "run", _boom)
    tshark_mod._supported_body_decompression_prefs.cache_clear()
    try:
        assert tshark_mod.no_body_decompression_opts("/missing/tshark") == []
    finally:
        tshark_mod._supported_body_decompression_prefs.cache_clear()


def test_with_no_body_decompression_inserts_after_binary(fake_prefs):
    cmd = [FAKE_TSHARK, "-r", "x.pcap"]
    out = tshark_mod.with_no_body_decompression(cmd)
    assert out == [FAKE_TSHARK, *EXPECTED_OPTS, "-r", "x.pcap"]
    assert tshark_mod.with_no_body_decompression(out) == out  # idempotent


@pytest.mark.parametrize("build", [
    lambda: tshark_mod.build_plaintext_command("x.pcap"),
    lambda: tshark_mod.build_plaintext_command("x.pcap", include_ssh=True),
    lambda: tshark_mod.build_tls_command("x.pcap", "k.log"),
    lambda: tshark_mod.build_quic_command("x.pcap", "k.log"),
    lambda: tshark_mod.build_quic_detection_command("x.pcap"),
    lambda: tshark_mod.build_combined_command("x.pcap", "k.log"),
])
def test_ek_builders_get_opts_at_run_time(monkeypatch, fake_prefs, build):
    """The -T ek builders carry a "tshark" placeholder; stream_packets adds the opts."""
    seen = []

    class _Popen:
        def __init__(self, argv, **_kw):
            seen.append(argv)
            raise OSError("stop")

    monkeypatch.setattr(tshark_mod.subprocess, "Popen", _Popen)
    cmd = build()
    cmd[0] = FAKE_TSHARK
    with pytest.raises(OSError):
        list(tshark_mod.stream_packets(cmd))
    assert seen[0][:1 + len(EXPECTED_OPTS)] == [FAKE_TSHARK, *EXPECTED_OPTS]


def _capture_run_capture(monkeypatch, output=""):
    seen = []

    def _fake(cmd):
        seen.append(list(cmd))
        return output

    monkeypatch.setattr(tshark_mod, "_run_capture", _fake)
    return seen


def test_extract_ssh_connections_has_opts(monkeypatch, fake_prefs):
    seen = _capture_run_capture(monkeypatch)
    tshark_mod.extract_ssh_connections(FAKE_TSHARK, "x.pcap")
    assert _contains_run(seen[0], EXPECTED_OPTS)


def test_list_tls_streams_has_opts(monkeypatch, fake_prefs):
    seen = _capture_run_capture(monkeypatch, "3\n1\n")
    assert tshark_mod.list_tls_streams(FAKE_TSHARK, "x.pcap", "k.log") == [1, 3]
    assert _contains_run(seen[0], EXPECTED_OPTS)


def test_follow_tls_stream_has_opts(monkeypatch, fake_prefs):
    seen = _capture_run_capture(monkeypatch)
    try:
        tshark_mod.follow_tls_stream(FAKE_TSHARK, "x.pcap", 0, "k.log")
    except Exception:  # noqa: BLE001 - empty follow output may not parse
        pass
    assert _contains_run(seen[0], EXPECTED_OPTS)


def test_schannel_fields_pass_has_opts(monkeypatch, fake_prefs):
    seen = _capture_run_capture(monkeypatch, "row\n")
    out = correlate.run_fields_pass(FAKE_TSHARK, "x.pcap", "tls", ["tls.stream"])
    assert out == "row\n"
    assert _contains_run(seen[0], EXPECTED_OPTS)


def test_run_capture_applies_opts(monkeypatch, fake_prefs):
    import io  # _run_capture spawns via Popen (bounded, chunked stdout reads)

    seen = []

    class _Popen:
        def __init__(self, argv, **_kw):
            seen.append(argv)
            self.stdout = io.BytesIO(b"ok")
            self.stderr = io.BytesIO(b"")

        def poll(self):
            return 0

        def wait(self, timeout=None):
            return 0

    monkeypatch.setattr(tshark_mod.subprocess, "Popen", _Popen)
    assert tshark_mod._run_capture([FAKE_TSHARK, "-r", "x.pcap"]) == "ok"
    assert seen[0] == [FAKE_TSHARK, *EXPECTED_OPTS, "-r", "x.pcap"]
