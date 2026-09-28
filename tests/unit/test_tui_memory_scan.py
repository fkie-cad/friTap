#!/usr/bin/env python3

"""TUI --memory-scan toggle tests (TUI leg).

HookingConfig.memory_scan / memory_scan_patterns already exist on the config
side; these tests cover the TUI layer that forwards the wizard's "Key
Extraction Method" choice (intercept / memory scan, plus the optional pattern
file) into HookingConfig, and the read-only Method row on the final "Ready to
Capture" screen.
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


def test_build_config_forwards_memory_scan():
    cfg = CaptureController.build_config(
        None, _state(memory_scan=True, memory_scan_patterns="foo.json")
    )
    assert cfg.hooking.memory_scan is True
    assert cfg.hooking.memory_scan_patterns == "foo.json"


def test_build_config_forwards_intercept():
    cfg = CaptureController.build_config(None, _state(intercept=False, memory_scan=True))
    assert cfg.hooking.intercept is False
    assert cfg.hooking.memory_scan is True


def test_build_config_intercept_defaults_true():
    cfg = CaptureController.build_config(None, _state())
    assert cfg.hooking.intercept is True


def test_build_config_memory_scan_defaults():
    # State without the attributes at all -> getattr defaults keep it off.
    cfg = CaptureController.build_config(None, _state())
    assert cfg.hooking.memory_scan is False
    assert cfg.hooking.memory_scan_patterns is None


# ---- modal summary: read-only Method row -----------------------------------------

def _summary(**overrides):
    base = dict(
        device_name="Pixel 7", device_type="usb", device_platform="android",
        target_name="App", target_mode="attach", capture_mode_display="Keys",
        keylog_path="keys.log", pcap_path="", live=False,
        capture_mode_id="keys", memory_scan=False,
    )
    base.update(overrides)
    return base


def _method_row(summary_text):
    return next(line for line in summary_text.splitlines() if "Method:" in line)


def test_summary_method_row_intercepting_only():
    modal = StartConfirmModal(summary=_summary(intercept=True, memory_scan=False))
    assert _method_row(modal._build_summary_text()).endswith("Intercepting")


def test_summary_method_row_memory_scan_only():
    modal = StartConfirmModal(summary=_summary(intercept=False, memory_scan=True))
    assert _method_row(modal._build_summary_text()).endswith("Memory scan")


def test_summary_method_row_both():
    modal = StartConfirmModal(summary=_summary(intercept=True, memory_scan=True))
    assert _method_row(modal._build_summary_text()).endswith(
        "Intercepting + Memory scan"
    )


def test_summary_method_row_defaults_to_intercepting():
    # A summary without the "intercept" key (older callers) means hooks on.
    modal = StartConfirmModal(summary=_summary())
    assert _method_row(modal._build_summary_text()).endswith("Intercepting")


def test_summary_method_row_follows_protocol_row_aligned():
    text = StartConfirmModal(summary=_summary(protocols_display="TLS"))._build_summary_text()
    lines = text.splitlines()
    protocol_idx = next(i for i, line in enumerate(lines) if "Protocol:" in line)
    assert "Method:" in lines[protocol_idx + 1]
    # Values start in the same column as the other rows.
    assert lines[protocol_idx + 1].index("Intercepting") == lines[protocol_idx].index("TLS")


def test_memory_scan_toggle_removed():
    modal = StartConfirmModal(summary=_summary(memory_scan=True))
    assert not hasattr(modal, "action_toggle_memory_scan")
    assert all(binding.key != "m" for binding in StartConfirmModal.BINDINGS)
    assert "Memory scan (secrets)" not in modal._build_summary_text()


# ---- F3: post-capture keylog resolution matches the multi-protocol WRITE side --

def test_resolve_keylog_files_finds_all_split_protocol_files(tmp_path):
    """F3: a multi-protocol run splits the -k path into <stem>.<proto>.log per
    protocol on the WRITE side; the post-capture resolver must find ALL of them,
    not just the base path. It reuses the SAME active_keylog_paths helper the
    factory uses, so read side == write side by construction.
    """
    from friTap.output.factory import active_keylog_paths
    from friTap.protocols.registry import create_default_registry

    base = str(tmp_path / "keys.log")
    registry = create_default_registry(["tls", "rc4"])
    # WRITE side: what the factory would split the base -k path into.
    write_paths = active_keylog_paths(base, ["tls", "rc4"], registry)
    assert set(write_paths) == {"tls", "rc4"}  # sanity: this run really splits
    for path in write_paths.values():
        open(path, "w").close()  # simulate the keys the capture wrote

    controller = CaptureController(None)
    controller._ssl_logger = SimpleNamespace(_protocol_registry=registry)

    # READ side: resolving with the protocol SET must return every split file.
    resolved = controller._resolve_keylog_files(base, ["tls", "rc4"])
    assert resolved == write_paths


def test_resolve_keylog_files_scalar_protocol_back_compat(tmp_path):
    """A single protocol (scalar or 1-element list) still resolves the one file."""
    base = str(tmp_path / "keys.log")
    open(base, "w").close()
    controller = CaptureController(None)
    controller._ssl_logger = SimpleNamespace(_protocol_registry=None)

    assert controller._resolve_keylog_files(base, "tls") == {"tls": base}
    assert controller._resolve_keylog_files(base, ["tls"]) == {"tls": base}
