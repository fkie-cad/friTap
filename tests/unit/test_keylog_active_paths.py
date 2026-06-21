"""Tests for keylog-file resolution shared by the results modal and the
post-capture decrypt-to-flow offer.

Root cause of the bug these guard: ``--protocol signal`` also emits TLS keys, so
the base ``-k`` path (e.g. ``keys_signal.log``) is split into
``keys_signal.tls.log`` + ``keys_signal.signal.log`` and the base is never
written. Code that checked ``os.path.isfile(base)`` therefore skipped Signal
(but not single-protocol Telegram/MTProto, whose base file does exist).
"""

from __future__ import annotations

import importlib.util
import os
from types import SimpleNamespace

import pytest

_SIGNAL_AVAILABLE = importlib.util.find_spec("friTap.offline.signal") is not None

from friTap.output.factory import active_keylog_paths
from friTap.protocols.registry import create_default_registry


def _registry(protocol):
    if protocol in ("all", "auto"):
        return create_default_registry()
    return create_default_registry([protocol])


# --- active_keylog_paths --------------------------------------------------- #

@pytest.mark.skipif(not _SIGNAL_AVAILABLE, reason="signal protocol is private/stripped in public build")
def test_signal_splits_into_tls_and_signal():
    paths = active_keylog_paths("keys_signal.log", "signal", _registry("signal"))
    assert paths == {
        "signal": "keys_signal.signal.log",
        "tls": "keys_signal.tls.log",
    }


def test_single_protocol_uses_base_path():
    # MTProto / Telegram / TLS are single-formatter -> no split -> base path.
    for proto in ("mtproto", "telegram", "tls"):
        assert active_keylog_paths("keys.log", proto, _registry(proto)) == {
            proto: "keys.log"
        }


def test_all_protocols_split_each():
    paths = active_keylog_paths("k.log", "all", _registry("all"))
    if _SIGNAL_AVAILABLE:
        assert paths["signal"] == "k.signal.log"
    assert paths["tls"] == "k.tls.log"
    assert len(paths) >= 2


@pytest.mark.skipif(not _SIGNAL_AVAILABLE, reason="signal protocol is private/stripped in public build")
def test_empty_base_returns_empty():
    assert active_keylog_paths("", "signal", _registry("signal")) == {}


def test_no_registry_returns_empty():
    assert active_keylog_paths("keys.log", "signal", None) == {}


# --- CaptureController._resolve_keylog_files (the on-disk gate input) ------- #

def _make_controller(protocol):
    """A CaptureController stub with just the attrs _resolve_keylog_files reads."""
    from friTap.tui.capture_controller import CaptureController
    ctrl = CaptureController.__new__(CaptureController)
    ctrl._ssl_logger = SimpleNamespace(_protocol_registry=_registry(protocol))
    return ctrl


@pytest.mark.skipif(not _SIGNAL_AVAILABLE, reason="signal protocol is private/stripped in public build")
def test_resolve_finds_split_signal_files(tmp_path):
    base = str(tmp_path / "keys_signal.log")
    tls = tmp_path / "keys_signal.tls.log"
    sig = tmp_path / "keys_signal.signal.log"
    tls.write_text("CLIENT_RANDOM aa bb\n")
    sig.write_text("05ab cd ef\n")

    ctrl = _make_controller("signal")
    resolved = ctrl._resolve_keylog_files(base, "signal")
    assert resolved == {"signal": str(sig), "tls": str(tls)}
    # The base path itself was never written — the old isfile(base) gate failed here.
    assert not os.path.isfile(base)


def test_resolve_single_protocol_base(tmp_path):
    base = tmp_path / "keys.log"
    base.write_text("AUTH_KEY ...\n")
    ctrl = _make_controller("mtproto")
    assert ctrl._resolve_keylog_files(str(base), "mtproto") == {"mtproto": str(base)}


@pytest.mark.skipif(not _SIGNAL_AVAILABLE, reason="signal protocol is private/stripped in public build")
def test_resolve_empty_when_nothing_on_disk(tmp_path):
    base = str(tmp_path / "keys_signal.log")  # no files created
    ctrl = _make_controller("signal")
    assert ctrl._resolve_keylog_files(base, "signal") == {}
