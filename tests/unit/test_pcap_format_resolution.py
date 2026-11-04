"""One decision for the -p container, resolved once when the config is built.

The plaintext PCAP object, the -p output handler, the full-capture finalizer
(and its DSB key collector) and the LSASS helper session used to decide pcap vs
pcapng separately -- pcap.py by extension only, the factory by extension *then*
``output_format`` -- so ``-p out.bin --pcap-format pcapng`` wrote a classic
pcap header and a pcapng SHB into the same file. Now an explicit format wins,
else ``.pcapng`` selects pcapng, else classic pcap: OutputConfig resolves it
into ``pcap_container`` and every writer reads that value.
Frida-free: real SSL_Loggers are constructed without a device.
"""

from __future__ import annotations

import logging
import struct
from unittest.mock import patch

import pytest

import friTap.friTap as fritap
from friTap.api import FriTap
from friTap.config import FriTapConfig, OutputConfig
from friTap.events import DatalogEvent
from friTap.legacy.ssl_logger_core import SSL_Logger
from friTap.pcap import PCAP
from friTap.pcap_utility import normalize_pcap_format, resolve_pcap_format

PCAP_MAGICS = (0xA1B2C3D4, 0xD4C3B2A1)
PCAPNG_SHB = 0x0A0D0D0A
SECRET = "CLIENT_RANDOM " + "11" * 32 + " " + "22" * 48


def _magic(path):
    return struct.unpack("<I", path.read_bytes()[:4])[0]


def _container(path):
    magic = _magic(path)
    if magic == PCAPNG_SHB:
        return "pcapng"
    assert magic in PCAP_MAGICS, hex(magic)
    return "pcap"


# ---------------------------------------------------------------------------
# The resolver
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("path, requested, expected", [
    ("out.bin", "auto", "pcap"),
    ("out.pcap", "auto", "pcap"),
    ("out.pcapng", "auto", "pcapng"),
    ("OUT.PCAPNG", None, "pcapng"),
    (None, "auto", "pcap"),
    ("out.bin", "pcapng", "pcapng"),
    ("out.pcap", "pcapng", "pcapng"),
    ("out.pcapng", "pcap", "pcap"),
    ("out.pcapng", "PCAPNG", "pcapng"),
])
def test_explicit_format_wins_else_extension(path, requested, expected):
    assert resolve_pcap_format(path, requested) == expected


def test_unknown_format_is_rejected():
    with pytest.raises(ValueError, match="pcap-ng"):
        normalize_pcap_format("pcap-ng")


def _conflict_warnings(caplog):
    return [r for r in caplog.records if "explicit format wins" in r.getMessage()]


def test_resolver_is_pure(caplog):
    with caplog.at_level(logging.WARNING, logger="friTap"):
        assert resolve_pcap_format("out.pcap", "pcapng") == "pcapng"
    assert not _conflict_warnings(caplog)


def test_config_resolves_the_container_and_warns_once(caplog):
    with caplog.at_level(logging.WARNING, logger="friTap"):
        config = FriTapConfig.from_legacy_params(
            app="target", pcap_name="out.pcap", output_format="pcapng",
            install_lsass_hook=False)
    assert config.output.pcap_container == "pcapng"
    warnings = _conflict_warnings(caplog)
    assert len(warnings) == 1
    assert warnings[0].getMessage() == (
        "out.pcap has a .pcap extension but the pcapng format was requested; "
        "writing pcapng (the explicit format wins).")


@pytest.mark.parametrize("path, requested", [
    ("out.bin", "pcapng"), ("out.pcapng", "pcapng"), ("out.pcap", "auto"), ("x.bin", "pcap"),
])
def test_no_warning_without_a_contradiction(caplog, path, requested):
    with caplog.at_level(logging.WARNING, logger="friTap"):
        FriTapConfig(target="t", output=OutputConfig(pcap=path, output_format=requested))
    assert not caplog.records


@pytest.mark.parametrize("path, requested, expected", [
    ("out.pcapng", "auto", "pcapng"), ("out.bin", "pcapng", "pcapng"), (None, "auto", "pcap"),
])
def test_standalone_output_config_is_resolved(path, requested, expected):
    assert OutputConfig(pcap=path, output_format=requested).pcap_container == expected


# ---------------------------------------------------------------------------
# Plaintext -p (PCAP object + factory handler agree), checked by magic bytes
# ---------------------------------------------------------------------------

def _datalog(payload):
    return DatalogEvent(data=payload, function="SSL_write", src_addr="10.0.0.1",
                        src_port=40000, dst_addr="10.0.0.2", dst_port=443,
                        src_addr_raw=0x0A000001, dst_addr_raw=0x0A000002)


def _plaintext_capture(tmp_path, name, fmt):
    config = FriTapConfig.from_legacy_params(
        app="target", pcap_name=str(tmp_path / name), output_format=fmt,
        install_lsass_hook=False)
    logger = SSL_Logger(config=config)
    try:
        logger._event_bus.emit(_datalog(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
    finally:
        logger.close_output_handlers()
    return tmp_path / name


@pytest.mark.parametrize("name, fmt, expected", [
    ("out.bin", "pcapng", "pcapng"),
    ("out.pcapng", "auto", "pcapng"),
    ("out.pcap", "auto", "pcap"),
    ("out.pcap", "pcapng", "pcapng"),
    ("out.bin", "auto", "pcap"),
    ("out.pcapng", "pcap", "pcap"),
])
def test_plaintext_capture_container_matches_the_resolver(tmp_path, name, fmt, expected):
    path = _plaintext_capture(tmp_path, name, fmt)
    assert _container(path) == expected
    assert b"Host: example.com" in path.read_bytes()


def test_pcapng_plaintext_file_holds_no_classic_pcap_header(tmp_path):
    """The PCAP object no longer writes a classic header the handler then clobbers."""
    raw = _plaintext_capture(tmp_path, "out.bin", "pcapng").read_bytes()
    assert struct.pack("<I", 0xA1B2C3D4) not in raw[:64]


# ---------------------------------------------------------------------------
# Full capture (-f) finalization
# ---------------------------------------------------------------------------

def _classic_source(path):
    """A one-packet LINKTYPE_ETHERNET classic pcap, as tcpdump would stage it."""
    frame = bytes(12) + b"\x08\x00" + bytes(20)
    header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    record = struct.pack("<IIII", 1, 0, len(frame), len(frame)) + frame
    path.write_bytes(header + record)
    return path


def _finalizer(final_path, fmt):
    pcap = object.__new__(PCAP)
    pcap.pcap_file_name = str(final_path)
    pcap.pcap_container = resolve_pcap_format(str(final_path), fmt)
    pcap.logger = logging.getLogger("friTap.tests.pcap_format")
    return pcap


@pytest.mark.parametrize("name, fmt, expected", [
    ("out.bin", "pcapng", "pcapng"),
    ("out.pcapng", "auto", "pcapng"),
    ("out.pcap", "auto", "pcap"),
    ("out.pcap", "pcapng", "pcapng"),
])
def test_full_capture_finalize_uses_the_resolver(tmp_path, name, fmt, expected):
    final = tmp_path / name
    pcap = _finalizer(final, fmt)
    pcap._emit_final(str(_classic_source(tmp_path / "_staged.pcap")), [SECRET])
    assert _container(final) == expected
    assert (SECRET.encode() in final.read_bytes()) is (expected == "pcapng")


@pytest.mark.parametrize("name, fmt, expected", [
    ("out.bin", "pcapng", "pcapng"), ("out.pcapng", None, "pcapng"), ("out.pcap", "pcap", "pcap"),
])
def test_pcap_object_resolves_its_container_once(tmp_path, name, fmt, expected):
    pcap = PCAP(str(tmp_path / name), ["SSL_read"], ["SSL_write"], False, False,
                pcap_format=fmt)
    assert pcap.pcap_container == expected
    assert pcap.writes_pcapng() is (expected == "pcapng")


# ---------------------------------------------------------------------------
# Entry points: CLI, LSASS helper, Python API
# ---------------------------------------------------------------------------

def test_lsass_helper_shares_the_target_container(tmp_path):
    config = fritap._build_lsass_config(
        684, pcap_name=str(tmp_path / "cap.bin"), verbose=False, keylog=None, live=False,
        debug_mode=False, host=False, debug_output=False, enable_default_fd=False,
        patterns=None, custom_hook_script=None, json_output=None, full_capture=False,
        pcap_format="pcapng")
    assert config.output.output_format == "pcapng"
    assert config.output.pcap_container == "pcapng"


def test_lsass_helper_does_not_repeat_the_conflict_warning(caplog):
    with caplog.at_level(logging.WARNING, logger="friTap"):
        config = fritap._build_lsass_config(
            684, pcap_name="cap.pcap", verbose=False, keylog=None, live=False,
            debug_mode=False, host=False, debug_output=False, enable_default_fd=False,
            patterns=None, custom_hook_script=None, json_output=None, full_capture=False,
            pcap_format="pcapng")
    assert config.output.pcap_container == "pcapng"
    assert not _conflict_warnings(caplog)


def test_api_pcapng_is_explicit_and_pcap_resets_to_auto():
    session = FriTap("target")
    session.pcapng("out.bin")
    assert session._output.output_format == "pcapng"
    assert session.build_config().output.pcap_container == "pcapng"
    session.pcap("out.pcap")
    assert session._output.output_format == "auto"
    assert session.build_config().output.pcap_container == "pcap"


def test_cli_rejects_pcap_format_without_pcap(monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["fritap", "--pcap-format", "pcapng", "target"])
    with pytest.raises(SystemExit) as exc:
        fritap.main()
    assert exc.value.code == 2
    captured = capsys.readouterr()
    assert "--pcap-format requires -p" in captured.out + captured.err


@pytest.mark.parametrize("name, fmt", [
    ("out.bin", "pcapng"),
    ("out.pcapng", "auto"),
    ("out.pcap", "auto"),
])
def test_full_capture_finalize_removes_the_temp_capture(tmp_path, name, fmt):
    final = tmp_path / name
    staged = _classic_source(tmp_path / f"_{name}")
    _finalizer(final, fmt)._emit_final(str(staged), [SECRET])
    assert final.exists()
    assert not staged.exists()


def test_filtered_full_capture_finalize_removes_the_temp_capture(tmp_path):
    final = tmp_path / "out.pcap"
    staged = _classic_source(tmp_path / "_out.pcap")
    with patch("friTap.pcap.sniff", return_value=[]), patch("friTap.pcap.wrpcap") as wr:
        wr.side_effect = lambda path, pkts: final.write_bytes(b"x")
        _finalizer(final, "auto")._emit_final(str(staged), [], bpf_filter="tcp port 443")
    assert final.exists()
    assert not staged.exists()


def test_full_capture_finalize_keeps_the_temp_when_writing_raises(tmp_path):
    final = tmp_path / "out.pcapng"
    staged = _classic_source(tmp_path / "_out.pcapng")
    pcap = _finalizer(final, "auto")
    with patch("friTap.pcap.PcapReader", side_effect=OSError("disk full")):
        with pytest.raises(OSError):
            pcap._emit_final(str(staged), [SECRET])
    assert staged.exists()


def test_full_capture_finalize_keeps_an_unreadable_temp(tmp_path):
    final = tmp_path / "out.pcapng"
    staged = tmp_path / "_out.pcapng"
    staged.write_bytes(b"\x00" * 64)                  # not a capture
    _finalizer(final, "auto")._emit_final(str(staged), [SECRET])
    assert final.exists()                              # keys-only output
    assert staged.exists()                             # packets not lost
