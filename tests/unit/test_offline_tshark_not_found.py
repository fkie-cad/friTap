#!/usr/bin/env python3

"""The single-source 'tshark is missing' contract.

Unlike the calibration harness, these tests do NOT need a real tshark: they
verify the detection gate (:func:`find_tshark`) raises the dedicated
:class:`TsharkNotFoundError` with the one shared install message, so both
front-ends (CLI print / TUI modal) can key off it consistently.
"""

from __future__ import annotations

import pytest

from friTap.offline import TSHARK_INSTALL_MESSAGE, TsharkNotFoundError
from friTap.offline import tshark as tshark_mod


def test_exception_is_a_runtimeerror_subclass():
    # Subclassing RuntimeError keeps every existing `except RuntimeError` working.
    assert issubclass(TsharkNotFoundError, RuntimeError)


def test_install_message_is_actionable():
    assert TSHARK_INSTALL_MESSAGE
    msg = TSHARK_INSTALL_MESSAGE.lower()
    assert "tshark" in msg
    # Mentions how to get it on the common platforms + the escape hatches.
    assert "brew install" in msg
    assert "apt install" in msg
    assert "--tshark-path" in TSHARK_INSTALL_MESSAGE
    assert "FRITAP_TSHARK" in TSHARK_INSTALL_MESSAGE


def test_bad_explicit_path_raises_tshark_not_found():
    with pytest.raises(TsharkNotFoundError):
        tshark_mod.find_tshark("/definitely/not/a/real/tshark")


def test_not_located_raises_with_single_source_message(monkeypatch):
    # Force the "cannot be located anywhere" branch: no env vars, empty PATH,
    # no fallback install locations.
    monkeypatch.delenv("FRITAP_TSHARK", raising=False)
    monkeypatch.delenv("TSHARK_PATH", raising=False)
    monkeypatch.setenv("PATH", "")
    monkeypatch.setattr(tshark_mod, "_TSHARK_FALLBACK_PATHS", ())

    with pytest.raises(TsharkNotFoundError) as excinfo:
        tshark_mod.find_tshark(None)
    # The message the user sees is the one shared constant, verbatim.
    assert str(excinfo.value) == TSHARK_INSTALL_MESSAGE


def test_cli_returns_exit_code_3_when_tshark_missing(tmp_path, monkeypatch, capsys):
    """The CLI pre-flight prints the message and returns 3 (no real tshark)."""
    from friTap.offline import cli

    monkeypatch.setattr(
        cli, "find_tshark",
        lambda *a, **k: (_ for _ in ()).throw(TsharkNotFoundError(TSHARK_INSTALL_MESSAGE)),
    )
    pcap = tmp_path / "cap.pcapng"
    pcap.write_bytes(b"\x00" * 8)

    rc = cli.run_offline_pcap_to_tap([
        "--from-pcap", str(pcap), "--tap", str(tmp_path / "o.tap"),
    ])
    assert rc == 3
    assert "tshark could not be located" in capsys.readouterr().out
