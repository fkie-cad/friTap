#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Tests for the keylog routing branch of :class:`OutputHandlerFactory`."""

import importlib.util
import logging

import pytest

_signal_spec = importlib.util.find_spec("friTap.offline.signal")
# `.loader is not None` guards against a stale __pycache__ leftover turning the
# stripped signal dir into an importable namespace package (false positive).
_SIGNAL_AVAILABLE = _signal_spec is not None and _signal_spec.loader is not None

from friTap.config import FriTapConfig, OutputConfig  # noqa: E402
from friTap.events import EventBus, KeylogEvent  # noqa: E402
from friTap.output.factory import OutputHandlerFactory, _active_keylog_formatters  # noqa: E402
from friTap.output.keylog_handler import KeylogOutputHandler  # noqa: E402
from friTap.protocols.registry import create_default_registry  # noqa: E402
from friTap.protocols.tls_handler import TlsKeylogFormatter  # noqa: E402
from friTap.protocols.ssh_handler import SshKeylogFormatter  # noqa: E402


@pytest.fixture
def silent_logger():
    return logging.getLogger("friTap.tests.factory")


def _keylog_handlers(handlers):
    return [h for h in handlers if isinstance(h, KeylogOutputHandler)]


class TestActiveKeylogFormatters:
    def test_single_tls(self):
        reg = create_default_registry(["tls"])
        formatters = _active_keylog_formatters("tls", reg)
        assert [f.protocol for f in formatters] == ["tls"]

    def test_single_ssh(self):
        reg = create_default_registry(["ssh"])
        formatters = _active_keylog_formatters("ssh", reg)
        assert [f.protocol for f in formatters] == ["ssh"]

    def test_all_includes_every_keylog_protocol(self):
        reg = create_default_registry()  # full registry
        formatters = _active_keylog_formatters("all", reg)
        expected = ["mtproto", "ssh", "telegram", "tls"]
        if _SIGNAL_AVAILABLE:
            expected = sorted(expected + ["signal"])
        assert sorted(f.protocol for f in formatters) == expected

    def test_auto_matches_all(self):
        reg = create_default_registry()
        expected = ["mtproto", "ssh", "telegram", "tls"]
        if _SIGNAL_AVAILABLE:
            expected = sorted(expected + ["signal"])
        assert sorted(f.protocol for f in _active_keylog_formatters("auto", reg)) == expected

    def test_unknown_protocol_returns_empty(self):
        reg = create_default_registry()
        assert _active_keylog_formatters("nonsense", reg) == []

    def test_no_registry_returns_empty(self):
        assert _active_keylog_formatters("all", None) == []


class TestFactoryKeylogRouting:
    def _config(self, keylog, protocol):
        return FriTapConfig(
            target="dummy",
            output=OutputConfig(keylog=keylog),
            protocol=protocol,
        )

    def test_tls_only_writes_single_file_at_verbatim_path(self, silent_logger, tmp_path):
        keylog = str(tmp_path / "k.log")
        reg = create_default_registry(["tls"])
        config = self._config(keylog, "tls")

        handlers, _ = OutputHandlerFactory.create_handlers(
            config, None, reg.get("tls"), {}, silent_logger,
            protocol_registry=reg,
        )

        keylog_h = _keylog_handlers(handlers)
        assert len(keylog_h) == 1
        assert keylog_h[0]._path == keylog
        assert isinstance(keylog_h[0]._formatter, TlsKeylogFormatter)

    def test_ssh_only_writes_single_file_at_verbatim_path(self, silent_logger, tmp_path):
        keylog = str(tmp_path / "k.log")
        reg = create_default_registry(["ssh"])
        config = self._config(keylog, "ssh")

        handlers, _ = OutputHandlerFactory.create_handlers(
            config, None, reg.get("ssh"), {}, silent_logger,
            protocol_registry=reg,
        )

        keylog_h = _keylog_handlers(handlers)
        assert len(keylog_h) == 1
        assert keylog_h[0]._path == keylog
        assert isinstance(keylog_h[0]._formatter, SshKeylogFormatter)

    def test_protocol_all_splits_per_protocol(self, silent_logger, tmp_path):
        keylog = str(tmp_path / "mykeys.log")
        reg = create_default_registry()  # tls + ssh + mtproto
        config = self._config(keylog, "all")

        handlers, _ = OutputHandlerFactory.create_handlers(
            config, None, reg.get("tls"), {}, silent_logger,
            protocol_registry=reg,
        )

        keylog_h = _keylog_handlers(handlers)
        paths = {h._formatter.protocol: h._path for h in keylog_h}
        expected = {
            "tls": str(tmp_path / "mykeys.tls.log"),
            "ssh": str(tmp_path / "mykeys.ssh.log"),
            "mtproto": str(tmp_path / "mykeys.mtproto.log"),
            "telegram": str(tmp_path / "mykeys.telegram.log"),
        }
        if _SIGNAL_AVAILABLE:
            expected["signal"] = str(tmp_path / "mykeys.signal.log")
        assert paths == expected

    def test_protocol_auto_same_as_all(self, silent_logger, tmp_path):
        keylog = str(tmp_path / "mykeys.log")
        reg = create_default_registry()
        config = self._config(keylog, "auto")

        handlers, _ = OutputHandlerFactory.create_handlers(
            config, None, reg.get("tls"), {}, silent_logger,
            protocol_registry=reg,
        )
        paths = {h._formatter.protocol: h._path for h in _keylog_handlers(handlers)}
        expected = {
            "tls": str(tmp_path / "mykeys.tls.log"),
            "ssh": str(tmp_path / "mykeys.ssh.log"),
            "mtproto": str(tmp_path / "mykeys.mtproto.log"),
            "telegram": str(tmp_path / "mykeys.telegram.log"),
        }
        if _SIGNAL_AVAILABLE:
            expected["signal"] = str(tmp_path / "mykeys.signal.log")
        assert paths == expected

    def test_no_keylog_means_no_keylog_handler(self, silent_logger):
        reg = create_default_registry(["tls"])
        config = self._config(keylog=None, protocol="tls")
        handlers, _ = OutputHandlerFactory.create_handlers(
            config, None, reg.get("tls"), {}, silent_logger,
            protocol_registry=reg,
        )
        assert _keylog_handlers(handlers) == []

    def test_protocol_all_lazy_creates_only_files_that_fire(self, silent_logger, tmp_path):
        """End-to-end: with ``--protocol all -k mykeys.log``, hook both handlers
        to a shared :class:`EventBus`, emit ONLY an SSH event, and confirm the
        TLS file is never created on disk while the SSH file is.

        This composes two unit-tested behaviours that were previously only
        covered separately: the factory's per-protocol split paths, and the
        handler's lazy file open. Without this test the lazy-creation
        guarantee under multi-protocol could regress silently.
        """
        keylog = str(tmp_path / "mykeys.log")
        reg = create_default_registry()  # tls + ssh
        config = self._config(keylog, "all")

        handlers, _ = OutputHandlerFactory.create_handlers(
            config, None, reg.get("tls"), {}, silent_logger,
            protocol_registry=reg,
        )

        bus = EventBus()
        try:
            for h in _keylog_handlers(handlers):
                h.setup(bus)

            # Nothing emitted yet — no files should exist.
            assert not (tmp_path / "mykeys.tls.log").exists()
            assert not (tmp_path / "mykeys.ssh.log").exists()

            # Fire ONLY an SSH event.
            bus.emit(KeylogEvent(
                protocol="ssh",
                payload={
                    "cookie": "aa" * 16,
                    "shared_secret": "bb" * 32,
                },
            ))

            # SSH file appeared; TLS file did NOT.
            assert (tmp_path / "mykeys.ssh.log").exists(), \
                "lazy open: SSH file must materialize on first matching event"
            assert not (tmp_path / "mykeys.tls.log").exists(), \
                "lazy open: TLS file must not be created when only SSH fires"

            # SSH file content sanity check.
            with open(tmp_path / "mykeys.ssh.log") as f:
                contents = f.read()
            assert f"{'aa' * 16} SHARED_SECRET {'bb' * 32}" in contents
        finally:
            for h in _keylog_handlers(handlers):
                h.close()

    @pytest.mark.skipif(not _SIGNAL_AVAILABLE, reason="signal protocol is private/stripped in public build")
    def test_signal_splits_tls_and_signal_files(self, silent_logger, tmp_path):
        """``--protocol signal`` implies tls, so both split files exist."""
        keylog = str(tmp_path / "keys.log")
        reg = create_default_registry(["signal"])
        config = self._config(keylog, "signal")

        handlers, _ = OutputHandlerFactory.create_handlers(
            config, None, reg.get("signal"), {}, silent_logger,
            protocol_registry=reg,
        )
        paths = {h._formatter.protocol: h._path for h in _keylog_handlers(handlers)}
        assert paths == {
            "tls": str(tmp_path / "keys.tls.log"),
            "signal": str(tmp_path / "keys.signal.log"),
        }

    @pytest.mark.skipif(not _SIGNAL_AVAILABLE, reason="signal protocol is private/stripped in public build")
    def test_signal_tls_keylog_routes_to_tls_file(self, silent_logger, tmp_path):
        """Regression for the keylog mis-tagging bug: under ``--protocol signal``
        the TLS hooks emit NSS keylog lines tagged ``protocol="tls"`` (the agent's
        sendKeylog now always tags "tls"). Those must materialize ``keys.tls.log``,
        not be dropped — previously they were tagged "signal", the Signal formatter
        could not parse the raw NSS line, and the .tls.log was never opened.

        Conversely a structured ``signal``-tagged event must land in keys.signal.log.
        """
        keylog = str(tmp_path / "keys.log")
        reg = create_default_registry(["signal"])
        config = self._config(keylog, "signal")

        handlers, _ = OutputHandlerFactory.create_handlers(
            config, None, reg.get("signal"), {}, silent_logger,
            protocol_registry=reg,
        )

        bus = EventBus()
        try:
            for h in _keylog_handlers(handlers):
                h.setup(bus)

            assert not (tmp_path / "keys.tls.log").exists()

            # TLS hook emits an NSS keylog line tagged "tls" (post-fix behavior).
            bus.emit(KeylogEvent(
                key_data=f"CLIENT_RANDOM {'ab' * 32} {'cd' * 48}",
                protocol="tls",
            ))

            tls_file = tmp_path / "keys.tls.log"
            assert tls_file.exists(), \
                "TLS keylog tagged 'tls' under --protocol signal must reach keys.tls.log"
            assert "CLIENT_RANDOM" in tls_file.read_text()

            # A structured Signal key still routes to the signal file.
            from friTap.protocols import signal_keylog_spec as spec
            bus.emit(KeylogEvent(
                protocol="signal",
                payload={
                    "chat_type": spec.CHAT_1TO1,
                    "eph_pub": "05" + "ab" * 32,
                    "static_cipher": "11" * 32,
                    "static_mac": "22" * 32,
                    "cipher": "33" * 32,
                    "mac": "44" * 32,
                    "iv": "55" * 16,
                },
            ))
            assert (tmp_path / "keys.signal.log").exists()
        finally:
            for h in _keylog_handlers(handlers):
                h.close()

    def test_warns_when_no_formatter_active(self, silent_logger, tmp_path, caplog):
        """``--protocol ipsec`` has no formatter today — warn and create no handler."""
        keylog = str(tmp_path / "k.log")
        reg = create_default_registry()  # tls + ssh
        config = self._config(keylog, "ipsec")

        with caplog.at_level(logging.WARNING):
            handlers, _ = OutputHandlerFactory.create_handlers(
                config, None, None, {}, silent_logger,
                protocol_registry=reg,
            )

        assert _keylog_handlers(handlers) == []
        # Warning is logged via the passed-in logger, which propagates through
        # caplog. Tolerate exact wording but require core substring.
        assert any("-k has no effect" in rec.getMessage() for rec in caplog.records) or \
               any("no active protocol emits key material" in rec.getMessage() for rec in caplog.records)
