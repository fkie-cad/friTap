"""Regression tests for the low-severity fixes C4, C6, C7 and C8.

C4  SChannel auto-relabel targets the file the LSASS worker writes (base -k),
    not the last split handler's path (keys.rc4.log).
C6  A stale memory-scan sidecar from an earlier run is not recorded in this
    run's capture manifest.
C7  ``--ms-rc4-ciphertext @file`` reads bytes (binary kept intact, hex text
    kept as hex) and a missing file is a clean CLI error.
C8  ``--include-loopback`` still works as a hidden alias of ``--loopback``.
"""

import json
import logging
import os
import sys
import time
from types import SimpleNamespace

import pytest

from friTap import friTap as fritap_cli
from friTap.legacy.ssl_logger_core import SSL_Logger
from friTap.pcap import PCAP, _existing_keylog_files
from friTap.protocols.registry import create_default_registry


# --------------------------------------------------------------------------- C4

def _relabel_logger(keylog, protocols, rc4_split_path):
    core = object.__new__(SSL_Logger)
    core._config = SimpleNamespace(
        output=SimpleNamespace(keylog=keylog, auto_relabel=True, tshark_path=None),
        protocols=protocols,
    )
    core._protocol_registry = create_default_registry(list(protocols))
    core.logger = logging.getLogger("test.c4")
    core.keylog_file = None
    # What _setup_output_handlers leaves behind under a split: the LAST handler.
    core.pcap_obj = SimpleNamespace(keylog_path=rc4_split_path)
    return core


@pytest.fixture
def relabel_spy(monkeypatch):
    calls = []

    class _Result:
        repaired_path = None
        message = "nothing to relabel"

    def fake_relabel(tshark_bin, pcap_name, keylog_path, progress=None):
        calls.append(keylog_path)
        return _Result()

    import friTap.fritap_utility as util
    import friTap.offline.keylog_coverage as kc
    import friTap.offline.tshark as tshark
    monkeypatch.setattr(util, "are_we_running_on_windows", lambda: True)
    monkeypatch.setattr(tshark, "find_tshark", lambda *_a, **_k: "tshark")
    monkeypatch.setattr(kc, "relabel_keylog", fake_relabel)
    return calls


def test_relabel_targets_lsass_base_keylog_not_last_split_file(tmp_path, relabel_spy):
    base = tmp_path / "keys.log"
    rc4 = tmp_path / "keys.rc4.log"
    pcap = tmp_path / "cap.pcap"
    base.write_text("CLIENT_RANDOM ??? aa\n")  # written by the LSASS worker
    rc4.write_text("RC4_KEY x\n")
    pcap.write_bytes(b"\0")
    core = _relabel_logger(str(base), ["tls", "rc4"], str(rc4))

    core._auto_relabel_schannel_keylog(str(pcap))

    assert relabel_spy == [str(base)]


def test_relabel_also_covers_tls_split_but_never_non_tls(tmp_path, relabel_spy):
    base = tmp_path / "keys.log"
    tls = tmp_path / "keys.tls.log"
    rc4 = tmp_path / "keys.rc4.log"
    pcap = tmp_path / "cap.pcap"
    for path in (base, tls, rc4):
        path.write_text("x\n")
    pcap.write_bytes(b"\0")
    core = _relabel_logger(str(base), ["tls", "rc4"], str(rc4))

    core._auto_relabel_schannel_keylog(str(pcap))

    assert relabel_spy == [str(base), str(tls)]


def test_relabel_skips_empty_candidates(tmp_path, relabel_spy):
    base = tmp_path / "keys.log"
    pcap = tmp_path / "cap.pcap"
    base.write_text("")
    pcap.write_bytes(b"\0")
    core = _relabel_logger(str(base), ["tls"], None)

    core._auto_relabel_schannel_keylog(str(pcap))

    assert relabel_spy == []


# --------------------------------------------------------------------------- C6

def _age(path, seconds):
    old = time.time() - seconds
    os.utime(path, (old, old))


def test_existing_keylog_files_drops_stale_and_empty(tmp_path):
    fresh = tmp_path / "a.memscan.mtproto.keylog"
    stale = tmp_path / "b.memscan.rc4.keylog"
    empty = tmp_path / "c.memscan.keylog"
    fresh.write_text("# mtproto\nMTPROTO_AUTH x\n")
    stale.write_text("RC4_KEY old\n")
    empty.write_text("")
    _age(stale, 3600)
    started = time.time() - 1

    kept = _existing_keylog_files(
        {"mtproto": str(fresh), "rc4": str(stale), "tls": str(empty)},
        not_before=started)

    assert kept == {"mtproto": str(fresh)}


def test_manifest_ignores_sidecar_from_earlier_run(tmp_path):
    pcap_path = tmp_path / "cap.pcap"
    sidecar = tmp_path / "cap.memscan.mtproto.keylog"
    sidecar.write_text("# mtproto\nMTPROTO_AUTH stale\n")
    _age(sidecar, 3600)
    stub = SimpleNamespace(
        pcap_file_name=str(pcap_path), keylog_path=None, capture_protocol="mtproto",
        _observed_server_ports={"tcp": set(), "udp": set()},
        memory_scan_keylogs={"mtproto": str(sidecar)},
        active_keylogs={}, _session_started_at=time.time(),
        logger=logging.getLogger("test.c6"),
    )
    for name, attr in vars(PCAP).items():
        if isinstance(attr, staticmethod):
            setattr(stub, name, attr.__func__)
    PCAP._write_capture_manifest(stub)

    with open(str(pcap_path) + ".fritap.json", encoding="utf-8") as handle:
        manifest = json.load(handle)
    assert "memory_scan_keylogs" not in manifest
    assert "mtproto_keylog" not in manifest


def test_pcap_records_session_start_time():
    before = time.time()
    pcap = PCAP("x.pcap", 1, 2, False, False)
    assert before <= pcap._session_started_at <= time.time()


# --------------------------------------------------------------------------- C7

def test_ciphertext_file_binary_is_hex_encoded_byte_for_byte(tmp_path):
    raw = bytes([0x00, 0xff, 0x80, 0x0a, 0xc3, 0x28])  # invalid UTF-8 + newline
    path = tmp_path / "ct.bin"
    path.write_bytes(raw)
    assert fritap_cli._resolve_ms_rc4_ciphertext(f"@{path}") == raw.hex()


def test_ciphertext_file_hex_text_is_kept_as_hex(tmp_path):
    path = tmp_path / "ct.hex"
    path.write_text("DEADbeef\n0011\n")
    assert fritap_cli._resolve_ms_rc4_ciphertext(f"@{path}") == "deadbeef0011"


def test_ciphertext_inline_value_unchanged():
    assert fritap_cli._resolve_ms_rc4_ciphertext("deadbeef") == "deadbeef"
    assert fritap_cli._resolve_ms_rc4_ciphertext(None) is None


@pytest.mark.parametrize("make", ["missing", "empty"])
def test_ciphertext_file_problem_raises_value_error(tmp_path, make):
    path = tmp_path / "ct.bin"
    if make == "empty":
        path.write_bytes(b"")
    with pytest.raises(ValueError, match="--ms-rc4-ciphertext"):
        fritap_cli._resolve_ms_rc4_ciphertext(f"@{path}")


def test_cli_missing_ciphertext_file_is_clean_usage_error(tmp_path, monkeypatch, capsys):
    missing = tmp_path / "nope.bin"
    monkeypatch.setattr(sys, "argv", [
        "fritap", "-ms", "--ms-rc4-ciphertext", f"@{missing}", "target"])
    with pytest.raises(SystemExit) as exc:
        fritap_cli.cli()
    assert exc.value.code == 2
    out = capsys.readouterr().out
    assert "--ms-rc4-ciphertext: cannot read" in out
    assert str(missing) in out


# --------------------------------------------------------------------------- C8

def _parse_only(monkeypatch, argv):
    """Run cli() up to parse_args and return the parsed namespace."""
    captured = {}

    class _Stop(Exception):
        pass

    real_parse = fritap_cli.ArgParser.parse_args

    def spy(self, *a, **k):
        captured["ns"] = real_parse(self, *a, **k)
        raise _Stop

    monkeypatch.setattr(fritap_cli.ArgParser, "parse_args", spy)
    monkeypatch.setattr(sys, "argv", ["fritap"] + argv)
    with pytest.raises(_Stop):
        fritap_cli.cli()
    return captured["ns"]


@pytest.mark.parametrize("flag", ["--loopback", "--include-loopback"])
def test_loopback_flag_and_deprecated_alias_share_dest(monkeypatch, flag):
    ns = _parse_only(monkeypatch, [flag, "target"])
    assert ns.include_loopback is True


def test_loopback_defaults_off(monkeypatch):
    assert _parse_only(monkeypatch, ["target"]).include_loopback is False


def test_include_loopback_hidden_from_help(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["fritap", "-h"])
    with pytest.raises(SystemExit):
        fritap_cli.cli()
    out = capsys.readouterr().out
    assert "--loopback" in out
    assert "--include-loopback" not in out
