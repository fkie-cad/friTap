"""Shipped example files and CLI help routing.

* ``offsets_example.json`` must be valid JSON in the shape the agent consumes
  (``resolveOffsets`` / ``IOffsets``), otherwise ``JSON.parse`` fails in the
  agent and the offsets are silently ignored.
* ``--offsets <file>`` with non-JSON content must warn on the host side.
* ``fritap analyze|report -h|--help`` must show the subcommand's own help,
  not the capture help.
"""

import json
import logging
import re
import sys
from types import SimpleNamespace

import pytest

from friTap import friTap as fritap_cli
from friTap.friTap import _dispatch_special_mode
from friTap.legacy.ssl_logger_core import SSL_Logger

# libKeys passed to resolveOffsets() by the agent hooks, plus "sockets".
_KNOWN_OFFSET_KEYS = {
    "openssl", "wolfssl", "gnutls", "mbedtls", "nss", "sspi", "s2n", "rustls",
    "matrixssl", "gotls", "google_quiche", "libsignal_jni", "sockets",
}


@pytest.fixture
def offsets_example(fritap_root):
    with open(fritap_root / "offsets_example.json", "r", encoding="utf-8") as f:
        return json.load(f)


# --- offsets_example.json ---------------------------------------------------

def test_offsets_example_uses_known_library_keys(offsets_example):
    assert set(offsets_example) <= _KNOWN_OFFSET_KEYS
    assert {"openssl", "wolfssl", "sockets"} <= set(offsets_example)


def test_offsets_example_entries_have_ioffsets_shape(offsets_example):
    absolute_flags = set()
    for lib, functions in offsets_example.items():
        assert isinstance(functions, dict) and functions, lib
        for name, entry in functions.items():
            assert set(entry) == {"address", "absolute"}, (lib, name)
            assert re.fullmatch(r"0x[0-9a-fA-F]+", entry["address"]), (lib, name)
            assert isinstance(entry["absolute"], bool), (lib, name)
            absolute_flags.add(entry["absolute"])
    assert absolute_flags == {True, False}, "example should show both modes"


def test_offsets_example_uses_function_names_the_hooks_look_up(offsets_example):
    assert {"SSL_read", "SSL_write"} <= set(offsets_example["openssl"])
    assert "wolfSSL_read" in offsets_example["wolfssl"]
    assert set(offsets_example["sockets"]) <= {"getpeername", "getsockname", "ntohs", "ntohl"}
    assert set(offsets_example["sspi"]) == {"EncryptMessage", "DecryptMessage"}


# --- --offsets loader warning -------------------------------------------------

def _offsets_logger(offsets):
    obj = SSL_Logger.__new__(SSL_Logger)
    obj.logger = logging.getLogger("test.offsets_loader")
    obj._config = SimpleNamespace(hooking=SimpleNamespace(offsets=offsets))
    obj.offsets_data = None
    return obj


def test_offsets_file_with_invalid_json_warns(tmp_path, caplog):
    path = tmp_path / "offsets.json"
    path.write_text('{"openssl": {"SSL_read": {...}}}', encoding="utf-8")
    obj = _offsets_logger(str(path))
    with caplog.at_level(logging.WARNING, logger="test.offsets_loader"):
        obj._load_offsets_data()
    assert obj.offsets_data == path.read_text(encoding="utf-8")  # still forwarded
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert "not valid JSON" in warnings[0].getMessage()
    assert str(path) in warnings[0].getMessage()


def test_offsets_example_file_loads_without_warning(fritap_root, caplog):
    obj = _offsets_logger(str(fritap_root / "offsets_example.json"))
    with caplog.at_level(logging.WARNING, logger="test.offsets_loader"):
        obj._load_offsets_data()
    assert json.loads(obj.offsets_data)["openssl"]
    assert caplog.records == []


def test_inline_offsets_json_string_is_still_accepted(caplog):
    inline = '{"openssl": {"SSL_read": {"address": "0x10", "absolute": false}}}'
    obj = _offsets_logger(inline)
    with caplog.at_level(logging.WARNING, logger="test.offsets_loader"):
        obj._load_offsets_data()
    assert obj.offsets_data == inline
    assert caplog.records == []


# --- analyze / report help routing --------------------------------------------

@pytest.mark.parametrize("command", ["analyze", "report"])
@pytest.mark.parametrize("flag", ["-h", "--help"])
def test_help_flag_routes_to_subcommand(command, flag):
    assert _dispatch_special_mode(["fritap", command, flag]) == (command, [flag])


def test_help_after_tap_still_routes_to_analyze():
    argv = ["fritap", "analyze", "foo.tap", "--help"]
    assert _dispatch_special_mode(argv) == ("analyze", ["foo.tap", "--help"])


@pytest.mark.parametrize("argv", [
    ["fritap", "analyze"],
    ["fritap", "analyze", "-m"],
    ["fritap", "analyze", "-k", "keys.log"],
    ["fritap", "report", "-m", "--help"],
])
def test_process_named_analyze_still_captures(argv):
    assert _dispatch_special_mode(argv) is None


@pytest.mark.parametrize("command, specific_option", [
    ("analyze", "--list-analyzers"),
    ("report", "--focus"),
])
def test_subcommand_help_prints_its_own_options(command, specific_option,
                                                 monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["fritap", command, "--help"])
    with pytest.raises(SystemExit) as excinfo:
        fritap_cli.main()
    assert excinfo.value.code == 0
    out = capsys.readouterr().out
    assert f"usage: fritap {command}" in out
    assert specific_option in out
    assert "--memory-scan" not in out  # not the capture help
