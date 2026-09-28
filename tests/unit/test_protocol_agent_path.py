#!/usr/bin/env python3

"""Selecting a protocol never forces the modern agent path.

Every protocol's hooks are installed on both the default legacy agent and the
explicit ``--modern`` agent, so ``--protocol <x>`` must leave ``use_modern`` as
the user chose it. Only an explicit ``--modern`` switches paths (and is then
propagated onto the SSL_Logger). Non-path side effects of protocol selection
(e.g. sshd child-gating) are kept.
"""

from __future__ import annotations

import sys

import pytest

import friTap.friTap as fritap_cli


class _FakeSSLLogger:
    """Stands in for SSL_Logger so cli() stops before touching a device."""

    instances: list = []

    def __init__(self, config=None, **_kwargs):
        self.config = config
        self.use_modern = False
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
    """Run ``fritap <args>`` with a fake logger; return (parsed-state, logger)."""
    _FakeSSLLogger.instances = []
    monkeypatch.setattr(fritap_cli, "SSL_Logger", _FakeSSLLogger)
    captured = {}
    real_probe_warnings = fritap_cli._probe_conflict_warnings

    def _capture_parsed(parsed):
        captured["parsed"] = parsed
        return real_probe_warnings(parsed)

    monkeypatch.setattr(fritap_cli, "_probe_conflict_warnings", _capture_parsed)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", ["fritap", *args])
    fritap_cli.cli()
    assert len(_FakeSSLLogger.instances) == 1
    return captured["parsed"], _FakeSSLLogger.instances[0]


@pytest.mark.parametrize("protocol", ["tls", "ssh", "mtproto", "telegram", "rc4", "tls,custom"])
def test_protocol_selection_keeps_legacy_agent(monkeypatch, tmp_path, protocol):
    parsed, ssl_log = _run_cli(
        monkeypatch, tmp_path, "--protocol", protocol, "-k", "keys.log", "-s", "target"
    )
    assert parsed.use_modern is False
    assert ssl_log.use_modern is False


def test_signal_selection_keeps_legacy_agent(monkeypatch, tmp_path):
    pytest.importorskip("friTap.protocols.signal_handler")
    from friTap.protocols.registry import available_protocol_names

    if "signal" not in available_protocol_names():
        pytest.skip("signal protocol not available in this build")
    parsed, ssl_log = _run_cli(
        monkeypatch, tmp_path, "--protocol", "signal", "-k", "keys.log", "target"
    )
    assert parsed.use_modern is False
    assert ssl_log.use_modern is False


def test_ssh_sshd_target_still_enables_child_gating(monkeypatch, tmp_path):
    parsed, ssl_log = _run_cli(
        monkeypatch, tmp_path, "--protocol", "ssh", "-k", "keys.log", "/usr/sbin/sshd"
    )
    assert parsed.enable_child_gating is True
    assert parsed.use_modern is False
    assert ssl_log.use_modern is False


def test_explicit_modern_is_set_and_propagated(monkeypatch, tmp_path):
    parsed, ssl_log = _run_cli(
        monkeypatch, tmp_path, "--modern", "--protocol", "rc4", "-k", "keys.log", "target"
    )
    assert parsed.use_modern is True
    assert ssl_log.use_modern is True
