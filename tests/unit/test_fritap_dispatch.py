#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Unit tests for the pre-argparse special-mode dispatcher in ``friTap.friTap``.

These tests exercise :func:`friTap.friTap._dispatch_special_mode` directly so
they never touch a device, spawn the TUI, or run argparse. The key behaviors
covered are the routing of each special invocation form and the disambiguation
rule that protects a capture target literally named ``analyze``.
"""

from __future__ import annotations

from friTap.friTap import _dispatch_special_mode, _looks_like_tap_input


def _argv(*rest):
    """Build an argv vector with a synthetic program name in slot 0."""
    return ["fritap", *rest]


# ---------------------------------------------------------------------------
# analyze routing + disambiguation
# ---------------------------------------------------------------------------

def test_analyze_with_tap_routes_to_analyze():
    # (a) 'analyze foo.tap' -> analyze mode, payload is args after the token.
    assert _dispatch_special_mode(_argv("analyze", "foo.tap")) == (
        "analyze", ["foo.tap"])


def test_analyze_with_tap_and_extra_flags_routes_to_analyze():
    assert _dispatch_special_mode(
        _argv("analyze", "foo.tap", "--json")) == ("analyze", ["foo.tap", "--json"])


def test_bare_analyze_is_not_hijacked():
    # (b) 'fritap analyze' meaning capture a process named 'analyze' falls
    # through (no special mode) so the normal capture parser handles it.
    assert _dispatch_special_mode(_argv("analyze")) is None


def test_analyze_followed_by_non_tap_is_not_hijacked():
    # (b) 'analyze' followed by a non-.tap token (e.g. a capture flag or a
    # process name) is also not hijacked.
    assert _dispatch_special_mode(_argv("analyze", "-m")) is None
    assert _dispatch_special_mode(_argv("analyze", "com.example.app")) is None


def test_explicit_analyze_flag_always_routes_to_analyze():
    # (c) '--analyze' is the explicit flag and always routes, with or without
    # a following .tap argument.
    assert _dispatch_special_mode(_argv("--analyze", "foo.tap")) == (
        "analyze", ["foo.tap"])
    assert _dispatch_special_mode(_argv("--analyze")) == ("analyze", [])


# ---------------------------------------------------------------------------
# install-backend / from-pcap / replay routing
# ---------------------------------------------------------------------------

def test_install_backend_routes_with_payload():
    # (d) install-backend keeps the backend name as payload.
    assert _dispatch_special_mode(
        _argv("install-backend", "wireshark")) == ("install-backend", "wireshark")


def test_install_backend_without_name_is_not_special():
    assert _dispatch_special_mode(_argv("install-backend")) is None


def test_from_pcap_routes_and_forwards_args():
    # (d) --from-pcap forwards the full argv[1:] to the offline CLI.
    assert _dispatch_special_mode(
        _argv("--from-pcap", "cap.pcapng", "--keylog", "k.log")) == (
            "from-pcap", ["--from-pcap", "cap.pcapng", "--keylog", "k.log"])


def test_from_pcap_anywhere_in_argv():
    assert _dispatch_special_mode(
        _argv("cap.pcapng", "--from-pcap"))[0] == "from-pcap"


def test_replay_dash_r_routes():
    # (d) -r <file> and --replay <file> route to replay with the path payload.
    assert _dispatch_special_mode(_argv("-r", "cap.tap")) == ("replay", "cap.tap")
    assert _dispatch_special_mode(
        _argv("--replay", "cap.tap")) == ("replay", "cap.tap")


def test_replay_dash_r_without_file_yields_none_payload():
    assert _dispatch_special_mode(_argv("-r")) == ("replay", None)


def test_bare_tap_path_routes_to_replay():
    assert _dispatch_special_mode(_argv("cap.tap")) == ("replay", "cap.tap")


# ---------------------------------------------------------------------------
# fall-through (normal capture) + helper
# ---------------------------------------------------------------------------

def test_normal_capture_target_is_not_special():
    assert _dispatch_special_mode(_argv("com.example.app")) is None
    assert _dispatch_special_mode(_argv("com.example.app", "-m")) is None


def test_no_arguments_is_not_special():
    assert _dispatch_special_mode(_argv()) is None


def test_looks_like_tap_input():
    assert _looks_like_tap_input("foo.tap") is True
    assert _looks_like_tap_input("-m") is False
    assert _looks_like_tap_input("foo.pcap") is False
    assert _looks_like_tap_input("") is False
