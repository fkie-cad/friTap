#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""TUI --pairip-safe toggle tests (fkie-cad/friTap#64, TUI leg).

The CLI --pairip-safe path (argparse -> HookingConfig.pairip_safe -> config_batch
-> agent) already exists; these tests cover the TUI layer that lets a wizard user
enable it from the final "Ready to Capture" screen. The toggle is Android-only:
it is forwarded into HookingConfig.pairip_safe, and it only renders / reacts when
the selected device's platform is "android".
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

pytest.importorskip("textual")  # TUI modules import textual widgets

from friTap.tui.capture_controller import CaptureController  # noqa: E402
from friTap.tui.modals.start_confirm_modal import StartConfirmModal  # noqa: E402


# ---- build_config forwarding --------------------------------------------

def _state(**overrides):
    base = dict(
        spawn=False, target="", device_id="", device_type="local",
        pcap_path="", keylog_path="", json_path="", verbose=False,
        live=False, live_mode="", full_capture=False,
    )
    base.update(overrides)
    return SimpleNamespace(**base)


def test_build_config_forwards_pairip_safe():
    cfg = CaptureController.build_config(None, _state(pairip_safe=True))
    assert cfg.hooking.pairip_safe is True


def test_build_config_pairip_safe_defaults_false():
    # State without the attribute at all -> getattr default keeps it off.
    cfg = CaptureController.build_config(None, _state())
    assert cfg.hooking.pairip_safe is False


# ---- modal Android gating ------------------------------------------------

def _summary(platform: str, **overrides):
    base = dict(
        device_name="Pixel 7", device_type="usb", device_platform=platform,
        target_name="App", target_mode="attach", capture_mode_display="Keys",
        keylog_path="keys.log", pcap_path="", live=False,
        capture_mode_id="keys", pairip_safe=False,
    )
    base.update(overrides)
    return base


@pytest.mark.parametrize("platform,device_type,row_present", [
    ("android", "usb", True),
    ("linux", "local", False),
])
def test_summary_row_gated_on_android(platform, device_type, row_present):
    modal = StartConfirmModal(summary=_summary(platform, device_type=device_type))
    assert ("PairIP Safe:" in modal._build_summary_text()) is row_present


def test_is_android_gate():
    # Drives all three gated sites (hint line, summary row, toggle action).
    assert StartConfirmModal(summary=_summary("android"))._is_android() is True
    assert StartConfirmModal(summary=_summary("Android"))._is_android() is True  # case-insensitive
    assert StartConfirmModal(summary=_summary("linux"))._is_android() is False
    assert StartConfirmModal(summary=_summary("unknown"))._is_android() is False
    # Missing/empty platform must not crash the gate.
    assert StartConfirmModal(summary=_summary(""))._is_android() is False


def test_toggle_flips_only_on_android():
    android = StartConfirmModal(summary=_summary("android"))
    assert android.pairip_safe is False
    android.action_toggle_pairip_safe()
    assert android.pairip_safe is True

    other = StartConfirmModal(summary=_summary("linux", device_type="local"))
    other.action_toggle_pairip_safe()
    assert other.pairip_safe is False  # guarded: no-op off Android
