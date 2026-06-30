#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""TUI spawn-argv tests (issue #66 follow-up, TUI leg).

The TUI spawn modal receives one free-text string (no shell to tokenize it), so
the controller tokenizes it shell-style into config.target_argv. This preserves
a spawn target path containing spaces (when quoted) and Windows backslash paths,
mirroring the CLI fix. Attach mode never tokenizes (the target is a verbatim
process name/PID).
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

pytest.importorskip("textual")  # capture_controller imports textual widgets

from friTap.tui.capture_controller import (  # noqa: E402
    CaptureController,
    _tokenize_spawn_command,
)


# ---- the tokenizer -------------------------------------------------------

def test_tokenize_single_token():
    assert _tokenize_spawn_command("com.example.app") == ["com.example.app"]
    assert _tokenize_spawn_command("/usr/bin/curl") == ["/usr/bin/curl"]


def test_tokenize_quoted_spaced_linux_path():
    cmd = 'wine "/home/u/.wine/drive_c/Program Files/App/app.exe"'
    assert _tokenize_spawn_command(cmd) == [
        "wine",
        "/home/u/.wine/drive_c/Program Files/App/app.exe",
    ]


def test_tokenize_windows_backslash_path_not_mangled():
    cmd = r'wine "C:\Program Files\App\app.exe"'
    assert _tokenize_spawn_command(cmd) == ["wine", r"C:\Program Files\App\app.exe"]


def test_tokenize_unbalanced_quotes_returns_none():
    assert _tokenize_spawn_command('wine "/oops') is None


# ---- build_config wiring (build_config does not use self) ----------------

def _state(**overrides):
    base = dict(
        spawn=False, target="", device_id="", device_type="local",
        pcap_path="", keylog_path="", json_path="", verbose=False,
        live=False, live_mode="", full_capture=False,
    )
    base.update(overrides)
    return SimpleNamespace(**base)


def test_build_config_spawn_preserves_spaced_path():
    cmd = 'wine "/home/u/.wine/drive_c/Program Files/App/app.exe"'
    cfg = CaptureController.build_config(None, _state(spawn=True, target=cmd))
    assert cfg.target == cmd                      # string kept for display
    assert cfg.target_argv == [
        "wine", "/home/u/.wine/drive_c/Program Files/App/app.exe",
    ]


def test_build_config_attach_does_not_tokenize():
    # Attach: target is a verbatim process name/PID; no argv tokenizing.
    cfg = CaptureController.build_config(None, _state(spawn=False, target="My App"))
    assert cfg.target == "My App"
    assert cfg.target_argv is None


def test_build_config_spawn_single_token():
    cfg = CaptureController.build_config(None, _state(spawn=True, target="/usr/bin/curl"))
    assert cfg.target_argv == ["/usr/bin/curl"]
