#!/usr/bin/env python3

"""Memory-scan-only full capture: ``fritap -f -p cap.pcapng -ms --protocol mtproto``.

Full capture's pcap comes from tcpdump, so with ``-ms`` and no ``-k`` the main
agent is skipped and the heap scanner supplies the keys. Covers:

* the CLI no longer blocks on ``input()`` for ``-f`` without ``-k`` when ``-ms``
  records the keys (and still asks without ``-ms``);
* the output factory: in memory-scan-only mode with ``-k`` the scanner owns the
  ``-k`` path and no hook keylog handler opens it a second time, while the
  hooks-on split (``keys.memscan.log``) is unchanged;
* the MTProto sidecar naming derived from the memscan keylog;
* the capture manifest pointing ``mtproto_keylog`` at the ``.mtproto.keylog``
  sidecar instead of the TLS memscan keylog.

No ``caplog``: friTap's loggers do not propagate, so stub loggers are used.
"""

from __future__ import annotations

import json
import logging
import sys
import types

import pytest

import friTap.friTap as fritap_cli
from friTap.config import FriTapConfig, HookingConfig, OutputConfig, memory_scan_only
from friTap.memory_scanning import (
    memory_scan_protocol_keylogs,
    memory_scan_sidecar_paths,
)
from friTap.output.factory import OutputHandlerFactory, memory_scan_keylog_path
from friTap.output.keylog_handler import KeylogOutputHandler
from friTap.pcap import PCAP
from friTap.protocols.registry import create_default_registry


class RecordingLogger:
    def __init__(self):
        self.records = []

    def _record(self, level, message, *args):
        self.records.append((level, str(message) % args if args else str(message)))

    def info(self, message, *args):
        self._record("info", message, *args)

    def warning(self, message, *args):
        self._record("warning", message, *args)


def _forbid_input(*_args, **_kwargs):
    raise AssertionError("input() must not be called")


# ---------------------------------------------------------------------------
# CLI: no blocking prompt when -ms records the keys
# ---------------------------------------------------------------------------

class TestConfirmFullCaptureWithoutKeylog:
    def test_memory_scan_skips_the_prompt(self, monkeypatch):
        monkeypatch.setattr("builtins.input", _forbid_input)
        logger = RecordingLogger()
        parsed = types.SimpleNamespace(memory_scan=True)
        fritap_cli._confirm_full_capture_without_keylog(parsed, logger)
        assert [lvl for lvl, _ in logger.records] == ["info"]
        assert "memory scanner" in logger.records[0][1]

    def test_without_memory_scan_still_prompts(self, monkeypatch):
        calls = []
        monkeypatch.setattr("builtins.input", lambda *a: calls.append(a) or "")
        logger = RecordingLogger()
        parsed = types.SimpleNamespace(memory_scan=False)
        fritap_cli._confirm_full_capture_without_keylog(parsed, logger)
        assert calls == [()]
        assert any(lvl == "warning" for lvl, _ in logger.records)


class _FakeSSLLogger:
    """Stands in for SSL_Logger so cli() stops before touching a device."""

    instances: list = []

    def __init__(self, config=None, **_kwargs):
        self.config = config
        _FakeSSLLogger.instances.append(self)

    def install_signal_handler(self):
        pass

    def start_fritap_session(self):
        pass

    def wait_for_completion(self):
        pass

    def pcap_cleanup(self, *_args):
        pass

    def cleanup(self, *_args):
        pass


def _run_cli(monkeypatch, tmp_path, *args):
    _FakeSSLLogger.instances = []
    monkeypatch.setattr(fritap_cli, "SSL_Logger", _FakeSSLLogger)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", ["fritap", *args])
    fritap_cli.cli()
    assert len(_FakeSSLLogger.instances) == 1
    return _FakeSSLLogger.instances[0].config


class TestCliFullCaptureMemoryScan:
    def test_full_capture_memory_scan_does_not_call_input(self, monkeypatch, tmp_path):
        monkeypatch.setattr("builtins.input", _forbid_input)
        config = _run_cli(
            monkeypatch, tmp_path,
            "-p", "mempcap.pcapng", "-f", "-ms", "--protocol", "mtproto", "Telegram",
        )
        assert config.output.full_capture is True
        assert memory_scan_only(config) is True

    def test_full_capture_memory_scan_with_keylog_keeps_hooks(self, monkeypatch, tmp_path):
        monkeypatch.setattr("builtins.input", _forbid_input)
        config = _run_cli(
            monkeypatch, tmp_path,
            "-p", "mempcap.pcapng", "-f", "-ms", "-k", "keys.log", "Telegram",
        )
        assert memory_scan_only(config) is False
        assert memory_scan_keylog_path(config) == "keys.memscan.log"


# ---------------------------------------------------------------------------
# Output factory: one writer per keylog file
# ---------------------------------------------------------------------------

def _keylog_handlers(config, protocol="tls"):
    reg = create_default_registry([protocol])
    handlers, live_info = OutputHandlerFactory.create_handlers(
        config, None, reg.get(protocol), {}, logging.getLogger("friTap.tests.ms"),
        protocol_registry=reg,
    )
    return [h for h in handlers if isinstance(h, KeylogOutputHandler)], live_info


class TestFactoryMemoryScanOnly:
    def test_memory_scan_only_with_keylog_has_single_writer(self, tmp_path):
        keylog = str(tmp_path / "keys.log")
        config = FriTapConfig(
            target="Telegram",
            output=OutputConfig(keylog=keylog),
            hooking=HookingConfig(memory_scan=True, intercept=False),
        )
        handlers, live_info = _keylog_handlers(config)
        assert [h._path for h in handlers] == [keylog]
        assert handlers[0]._formatter.protocol == "memscan"
        assert live_info["memory_scan_keylog"] == keylog

    def test_hooks_on_keeps_the_memscan_split(self, tmp_path):
        keylog = str(tmp_path / "keys.log")
        config = FriTapConfig(
            target="Telegram",
            output=OutputConfig(keylog=keylog),
            hooking=HookingConfig(memory_scan=True),
        )
        handlers, _ = _keylog_handlers(config)
        paths = {h._formatter.protocol: h._path for h in handlers}
        assert paths == {"tls": keylog, "memscan": str(tmp_path / "keys.memscan.log")}

    def test_full_capture_without_keylog_writes_target_memscan_file(self):
        config = FriTapConfig(
            target="Telegram",
            output=OutputConfig(pcap="mempcap.pcapng", full_capture=True),
            hooking=HookingConfig(memory_scan=True),
        )
        handlers, _ = _keylog_handlers(config)
        assert [h._path for h in handlers] == ["Telegram_memscan.keylog"]


# ---------------------------------------------------------------------------
# Sidecar naming + manifest
# ---------------------------------------------------------------------------

def _mtproto_full_capture_config(keylog=None, intercept=True):
    return FriTapConfig(
        target="Telegram",
        output=OutputConfig(pcap="mempcap.pcapng", full_capture=True, keylog=keylog),
        hooking=HookingConfig(memory_scan=True, intercept=intercept),
        protocol="mtproto",
    )


class TestSidecarNaming:
    def test_sidecar_beside_target_memscan_keylog(self):
        sidecars = memory_scan_sidecar_paths(_mtproto_full_capture_config())
        assert sidecars["mtproto"] == "Telegram_memscan.mtproto.keylog"

    def test_sidecar_beside_owned_keylog(self):
        config = _mtproto_full_capture_config(keylog="keys.log", intercept=False)
        assert memory_scan_sidecar_paths(config)["mtproto"] == "keys.mtproto.keylog"

    def test_sidecar_beside_split_memscan_keylog(self):
        config = _mtproto_full_capture_config(keylog="keys.log")
        assert memory_scan_sidecar_paths(config)["mtproto"] == "keys.memscan.mtproto.keylog"

    def test_off_without_memory_scan(self):
        assert memory_scan_sidecar_paths(FriTapConfig(target="a")) == {}
        assert memory_scan_protocol_keylogs(FriTapConfig(target="a")) == {}

    def test_telegram_resolves_to_the_mtproto_sidecar(self):
        config = FriTapConfig(
            target="Telegram", hooking=HookingConfig(memory_scan=True),
            protocol="telegram",
        )
        mapping = memory_scan_protocol_keylogs(config)
        assert mapping["tls"] == "Telegram_memscan.keylog"
        assert mapping["telegram"] == mapping["mtproto"] == "Telegram_memscan.mtproto.keylog"


def _manifest_stub(pcap_file_name):
    stub = types.SimpleNamespace(
        pcap_file_name=pcap_file_name,
        logger=logging.getLogger("friTap.tests.ms_manifest"),
        _observed_server_ports={"tcp": set(), "udp": set()},
        keylog_path=None,
        capture_protocol=None,
        active_keylogs={},
        memory_scan_keylogs={},
    )
    stub.set_memory_scan_keylogs = PCAP.set_memory_scan_keylogs.__get__(stub)
    stub._write_capture_manifest = PCAP._write_capture_manifest.__get__(stub)
    _bind_pcap_staticmethods(stub)
    return stub


def _bind_pcap_staticmethods(stub):
    """Expose every PCAP staticmethod (e.g. ``_keylog_with_content``) on the
    stub, so a new helper used by a bound method cannot silently break it."""
    for name, attr in vars(PCAP).items():
        if isinstance(attr, staticmethod):
            setattr(stub, name, attr.__func__)


def _read_manifest(pcap):
    with open(f"{pcap}.fritap.json", encoding="utf-8") as fh:
        return json.load(fh)


class TestManifestMemoryScanKeylogs:
    def test_mtproto_keylog_points_at_the_sidecar(self, tmp_path):
        tls = tmp_path / "Telegram_memscan.keylog"
        sidecar = tmp_path / "Telegram_memscan.mtproto.keylog"
        tls.write_text("# tls\n")
        sidecar.write_text("# mtproto\n")
        pcap = str(tmp_path / "mempcap.pcapng")
        stub = _manifest_stub(pcap)
        stub.capture_protocol = "mtproto"
        stub.set_memory_scan_keylogs({"tls": str(tls), "mtproto": str(sidecar)})
        stub._write_capture_manifest()
        manifest = _read_manifest(pcap)
        assert manifest["mtproto_keylog"] == str(sidecar)
        assert manifest["keylog"] == str(tls)
        assert manifest["memory_scan_keylogs"] == {"tls": str(tls), "mtproto": str(sidecar)}

    def test_unwritten_memscan_files_are_not_recorded(self, tmp_path):
        pcap = str(tmp_path / "mempcap.pcapng")
        stub = _manifest_stub(pcap)
        stub.capture_protocol = "mtproto"
        stub.set_memory_scan_keylogs({
            "tls": str(tmp_path / "missing.keylog"),
            "mtproto": str(tmp_path / "missing.mtproto.keylog"),
        })
        stub._write_capture_manifest()
        manifest = _read_manifest(pcap)
        assert "mtproto_keylog" not in manifest
        assert "keylog" not in manifest
        assert "memory_scan_keylogs" not in manifest

    def test_hooked_keylog_still_wins(self, tmp_path):
        sidecar = tmp_path / "keys.memscan.mtproto.keylog"
        sidecar.write_text("# mtproto\n")
        pcap = str(tmp_path / "cap.pcapng")
        stub = _manifest_stub(pcap)
        stub.capture_protocol = "mtproto"
        stub.keylog_path = str(tmp_path / "keys.log")
        stub.set_memory_scan_keylogs({"mtproto": str(sidecar)})
        stub._write_capture_manifest()
        manifest = _read_manifest(pcap)
        assert manifest["mtproto_keylog"] == str(tmp_path / "keys.log")
        assert manifest["memory_scan_keylogs"] == {"mtproto": str(sidecar)}


# ---------------------------------------------------------------------------
# SSL_Logger: the memscan handler no longer masquerades as the hook keylog
# ---------------------------------------------------------------------------

class TestCoreRecordsMemoryScanKeylogs:
    def _core(self, config):
        from friTap.legacy.ssl_logger_core import SSL_Logger

        core = SSL_Logger.__new__(SSL_Logger)
        core._config = config
        core.pcap_obj = types.SimpleNamespace(
            keylog_path=None, capture_protocol=None, memory_scan_keylogs={},
        )
        core.pcap_obj.set_memory_scan_keylogs = \
            PCAP.set_memory_scan_keylogs.__get__(core.pcap_obj)
        return core

    def test_memscan_handler_is_identified(self):
        from friTap.legacy.ssl_logger_core import SSL_Logger
        from friTap.memory_scanning.formatter import MemoryScanKeylogFormatter
        from friTap.protocols.tls_handler import TlsKeylogFormatter

        assert SSL_Logger._is_memory_scan_handler(
            KeylogOutputHandler("x", formatter=MemoryScanKeylogFormatter()))
        assert not SSL_Logger._is_memory_scan_handler(
            KeylogOutputHandler("x", formatter=TlsKeylogFormatter()))

    def test_record_memory_scan_keylogs_hands_sidecar_to_pcap(self):
        core = self._core(_mtproto_full_capture_config())
        core._record_memory_scan_keylogs()
        assert core.pcap_obj.capture_protocol == "mtproto"
        assert core.pcap_obj.memory_scan_keylogs == {
            "tls": "Telegram_memscan.keylog",
            "mtproto": "Telegram_memscan.mtproto.keylog",
        }
        assert core.pcap_obj.keylog_path is None

    def test_no_pcap_object_is_a_no_op(self):
        core = self._core(_mtproto_full_capture_config())
        core.pcap_obj = None
        core._record_memory_scan_keylogs()


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
