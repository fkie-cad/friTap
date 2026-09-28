#!/usr/bin/env python3

"""Per-cipher keylog split for custom ciphers.

Contract: every ``custom_cipher`` handler exposes a keylog formatter whose
``protocol`` equals the handler ``name``, so a multi-protocol run splits
``-k keys.log`` into one file per protocol/cipher (``keys.tls.log``,
``keys.rc4.log``, ``keys.aes.log``, ...) — never a grouped "custom" file.
A single-protocol run still writes the ``-k`` path verbatim.

Future ciphers (aes, chacha20) are simulated with fake handlers registered
into the extension factory table via ``monkeypatch.setitem`` (auto-restored).
"""

from types import SimpleNamespace

import pytest

from friTap.output.factory import active_keylog_paths
from friTap.output.keylog_format import KeylogFormatter
from friTap.protocols import registry

FAKE_CIPHERS = ("aes", "chacha20")


def _rc4_available():
    return "rc4" in registry.available_protocol_names()


class _FakeFormatter(KeylogFormatter):
    def __init__(self, protocol):
        self._protocol = protocol

    @property
    def protocol(self):
        return self._protocol


class _FakeCipherHandler:
    """Duck-typed custom-cipher handler (what an aes/chacha20 plugin would be)."""

    category = "custom_cipher"
    upcoming = False
    description = ""

    def __init__(self, name):
        self.name = name
        self.display_name = name.upper()

    def keylog_formatter(self):
        return _FakeFormatter(self.name)


@pytest.fixture
def fake_ciphers(monkeypatch):
    if not _rc4_available():
        pytest.skip("rc4 not available in this build")
    registry._all_handler_factories()  # run discovery before patching
    for name in FAKE_CIPHERS:
        monkeypatch.setitem(
            registry._EXTENSION_HANDLER_FACTORIES, name,
            lambda name=name: _FakeCipherHandler(name),
        )
    return registry


def _paths(protocols, base="keys.log"):
    reg = registry.create_default_registry(protocols)
    return active_keylog_paths(base, protocols, reg), reg


# --- naming contract -------------------------------------------------------- #

def test_every_custom_cipher_formatter_protocol_matches_name():
    handlers = registry.custom_cipher_handlers(include_upcoming=True)
    for handler in handlers:
        fmt = handler.keylog_formatter()
        assert fmt is not None, f"{handler.name}: custom cipher needs a keylog formatter"
        assert fmt.protocol == handler.name, (
            f"{handler.name}: formatter.protocol={fmt.protocol!r} breaks "
            f"keys.<cipher>.log naming"
        )


def test_contract_holds_with_future_ciphers(fake_ciphers):
    names = [h.name for h in registry.custom_cipher_handlers()]
    assert names == ["aes", "chacha20", "rc4"]
    test_every_custom_cipher_formatter_protocol_matches_name()


# --- split ------------------------------------------------------------------ #

def test_tls_plus_all_custom_ciphers_splits_per_cipher(fake_ciphers):
    protocols = registry.expand_custom_group(["tls", "custom"])
    assert protocols == ["tls", "aes", "chacha20", "rc4"]
    paths, _ = _paths(protocols)
    assert paths == {
        "tls": "keys.tls.log",
        "aes": "keys.aes.log",
        "chacha20": "keys.chacha20.log",
        "rc4": "keys.rc4.log",
    }


def test_tls_plus_rc4_splits():
    if not _rc4_available():
        pytest.skip("rc4 not available in this build")
    paths, _ = _paths(["tls", "rc4"])
    assert paths == {"tls": "keys.tls.log", "rc4": "keys.rc4.log"}


def test_single_cipher_writes_base_path():
    if not _rc4_available():
        pytest.skip("rc4 not available in this build")
    paths, _ = _paths(["rc4"])
    assert paths == {"rc4": "keys.log"}


def test_factory_wires_one_handler_per_cipher_file(fake_ciphers, tmp_path):
    """The WRITE side (OutputHandlerFactory) opens exactly the split files."""
    import logging

    from friTap.config import FriTapConfig, OutputConfig
    from friTap.output.factory import OutputHandlerFactory
    from friTap.output.keylog_handler import KeylogOutputHandler

    base = str(tmp_path / "keys.log")
    protocols = ["tls", "aes", "chacha20", "rc4"]
    reg = registry.create_default_registry(protocols)
    config = FriTapConfig(
        target="dummy", output=OutputConfig(keylog=base), protocols=protocols,
    )
    handlers, live_info = OutputHandlerFactory.create_handlers(
        config, None, reg.get("tls"), {}, logging.getLogger("test"),
        protocol_registry=reg,
    )
    written = {
        h._formatter.protocol: h._path
        for h in handlers if isinstance(h, KeylogOutputHandler)
    }
    expected = {p: str(tmp_path / f"keys.{p}.log") for p in protocols}
    assert written == expected
    assert live_info["keylogs"] == expected


# --- TUI post-capture resolution ------------------------------------------- #

def test_tui_resolves_every_cipher_keylog(fake_ciphers, tmp_path):
    from friTap.tui.capture_controller import CaptureController

    base = str(tmp_path / "keys.log")
    protocols = registry.expand_custom_group(["tls", "custom"])
    reg = registry.create_default_registry(protocols)
    for p in protocols:
        (tmp_path / f"keys.{p}.log").write_text("x\n")

    controller = CaptureController.__new__(CaptureController)
    controller._ssl_logger = SimpleNamespace(_protocol_registry=reg)
    assert controller._resolve_keylog_files(base, protocols) == {
        p: str(tmp_path / f"keys.{p}.log") for p in protocols
    }
