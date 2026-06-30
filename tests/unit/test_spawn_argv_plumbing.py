#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Plumbing tests for spawn argv preservation (issue #66 follow-up).

The CLI target positional is nargs="+", so `fritap -s wine /p/My Game/app.exe`
parses into argv tokens. friTap keeps `config.target` as the space-joined string
(for attach-by-name / display) but carries the original tokens in
`config.target_argv` so spawn passes the real argv to device.spawn() — instead
of re-splitting the joined string on spaces and shredding a path that contains
a space. These tests pin that contract without a frida-server.
"""

from __future__ import annotations

from friTap.config import FriTapConfig


SPACED_ARGV = ["wine", "/home/u/.wine/drive_c/Program Files/My Game/app.exe"]
SPACED_JOINED = " ".join(SPACED_ARGV)


def _select_spawn_target(cfg: FriTapConfig):
    # Mirrors friTap/legacy/session_manager.py: prefer preserved argv, else split.
    return cfg.target_argv or cfg.target.split(" ")


def test_from_legacy_params_keeps_target_string_and_argv_list():
    cfg = FriTapConfig.from_legacy_params(
        app=SPACED_JOINED, spawn_argv=SPACED_ARGV, spawn=True
    )
    # target stays a single string (attach-by-name / display contract)
    assert cfg.target == SPACED_JOINED
    # argv tokens preserved for spawn
    assert cfg.target_argv == SPACED_ARGV


def test_spawn_target_selection_preserves_spaced_path():
    cfg = FriTapConfig.from_legacy_params(
        app=SPACED_JOINED, spawn_argv=SPACED_ARGV, spawn=True
    )
    # The spaced path must remain a SINGLE token, not be split on its spaces.
    assert _select_spawn_target(cfg) == SPACED_ARGV


def test_missing_argv_falls_back_to_split():
    # Programmatic / TUI configs supply no argv → old split behavior preserved
    # (no regression for callers that never had argv tokens).
    cfg = FriTapConfig.from_legacy_params(app=SPACED_JOINED, spawn=True)
    assert cfg.target_argv is None
    assert _select_spawn_target(cfg) == SPACED_JOINED.split(" ")


def test_single_token_spawn_unaffected():
    cfg = FriTapConfig.from_legacy_params(
        app="./app", spawn_argv=["./app"], spawn=True
    )
    assert _select_spawn_target(cfg) == ["./app"]
