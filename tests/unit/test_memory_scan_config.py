#!/usr/bin/env python3

"""Unit tests for the config-side surface of the "memory scan for secrets"
feature (``--memory-scan`` / ``-ms``).

Covers the pure, device-free config helpers:
  * :meth:`FriTapConfig.from_legacy_params` threading the three ``memory_scan*``
    params into ``hooking``;
  * :func:`effective_script_load_timeout` tripling the bound when ``-ms`` is on;
  * :func:`memory_scan_only` truth table;
  * :func:`memory_scan_keylog_path` path resolution + target sanitization.
"""

from __future__ import annotations

import pytest

from friTap.config import (
    FriTapConfig,
    HookingConfig,
    OutputConfig,
    effective_script_load_timeout,
    memory_scan_only,
)
from friTap.output.factory import memory_scan_keylog_path


# ---------------------------------------------------------------------------
# from_legacy_params round-trip
# ---------------------------------------------------------------------------

class TestFromLegacyParams:
    def test_defaults_off(self):
        config = FriTapConfig.from_legacy_params(app="com.example.app")
        assert config.hooking.memory_scan is False
        assert config.hooking.memory_scan_patterns is None
        assert config.hooking.memory_scan_interval == 2.0

    def test_threads_all_three_fields(self):
        config = FriTapConfig.from_legacy_params(
            app="com.example.app",
            memory_scan=True,
            memory_scan_patterns="/tmp/custom_patterns.json",
            memory_scan_interval=5.5,
        )
        assert config.hooking.memory_scan is True
        assert config.hooking.memory_scan_patterns == "/tmp/custom_patterns.json"
        assert config.hooking.memory_scan_interval == 5.5


# ---------------------------------------------------------------------------
# effective_script_load_timeout
# ---------------------------------------------------------------------------

class TestEffectiveScriptLoadTimeout:
    def test_memory_scan_triples_base(self):
        config = FriTapConfig.from_legacy_params(
            app="a", memory_scan=True, script_load_timeout=20.0
        )
        assert effective_script_load_timeout(config) == 60.0

    def test_no_memory_scan_leaves_base(self):
        config = FriTapConfig.from_legacy_params(app="a", script_load_timeout=20.0)
        assert effective_script_load_timeout(config) == 20.0

    def test_non_positive_opts_out_even_with_memory_scan(self):
        config = FriTapConfig.from_legacy_params(
            app="a", memory_scan=True, script_load_timeout=0.0
        )
        assert effective_script_load_timeout(config) is None


# ---------------------------------------------------------------------------
# memory_scan_only truth table
# ---------------------------------------------------------------------------

class TestMemoryScanOnly:
    def test_off_when_memory_scan_disabled(self):
        config = FriTapConfig.from_legacy_params(app="a")
        assert memory_scan_only(config) is False

    def test_true_when_alone(self):
        config = FriTapConfig.from_legacy_params(app="a", memory_scan=True)
        assert memory_scan_only(config) is True

    # Each other capture/hook surface must flip memory_scan_only back to False.
    @pytest.mark.parametrize(
        "kwargs",
        [
            {"keylog": "keys.log"},
            {"pcap_name": "out.pcap"},
            {"json_output": "out.json"},
            # -f is not a surface of its own (tcpdump writes its pcap); it only
            # stays hook-backed together with -k. See TestMemoryScanOnlyFullCapture.
            {"full_capture": True, "pcap_name": "out.pcapng", "keylog": "keys.log"},
            {"socket_trace": True},
            {"live": True},
            {"scan": "all"},
            {"custom_hook_script": "/tmp/hook.js"},
            {"scan_keys_region": "heap"},
            {"probe": True},
            {"payload_modification": True},
            # Offset/pattern hooking and the library scan run in the main agent,
            # so they must also pull it back in alongside -ms.
            {"offsets": "/tmp/off.json"},
            {"patterns": "/tmp/p.json"},
            {"library_scan": True},
        ],
    )
    def test_other_surface_flips_to_false(self, kwargs):
        config = FriTapConfig.from_legacy_params(app="a", memory_scan=True, **kwargs)
        assert memory_scan_only(config) is False


class TestMemoryScanOnlyFullCapture:
    """-f takes its pcap from tcpdump, so only -k pulls the agent back in."""

    def test_full_capture_pcap_ms_is_memory_scan_only(self):
        config = FriTapConfig.from_legacy_params(
            app="a", memory_scan=True, full_capture=True, pcap_name="mempcap.pcapng"
        )
        assert memory_scan_only(config) is True

    def test_full_capture_pcap_ms_with_keylog_keeps_hooks(self):
        config = FriTapConfig.from_legacy_params(
            app="a", memory_scan=True, full_capture=True,
            pcap_name="mempcap.pcapng", keylog="keys.log",
        )
        assert memory_scan_only(config) is False

    def test_plaintext_pcap_without_full_capture_keeps_hooks(self):
        config = FriTapConfig.from_legacy_params(
            app="a", memory_scan=True, pcap_name="out.pcapng"
        )
        assert memory_scan_only(config) is False

    def test_full_capture_with_socket_trace_keeps_hooks(self):
        config = FriTapConfig.from_legacy_params(
            app="a", memory_scan=True, full_capture=True,
            pcap_name="out.pcapng", socket_trace=True,
        )
        assert memory_scan_only(config) is False


class TestMemoryScanOnlyInterceptSwitch:
    def test_intercept_false_forces_memory_scan_only(self):
        config = FriTapConfig(
            target="a",
            output=OutputConfig(keylog="keys.log", pcap="out.pcap"),
            hooking=HookingConfig(memory_scan=True, intercept=False),
        )
        assert memory_scan_only(config) is True

    def test_intercept_false_without_memory_scan_is_not_memory_scan_only(self):
        config = FriTapConfig(
            target="a", hooking=HookingConfig(memory_scan=False, intercept=False)
        )
        assert memory_scan_only(config) is False

    def test_intercept_defaults_true(self):
        assert HookingConfig().intercept is True


# ---------------------------------------------------------------------------
# memory_scan_keylog_path
# ---------------------------------------------------------------------------

class TestMemoryScanKeylogPath:
    def test_none_when_off(self):
        config = FriTapConfig(target="com.example.app")
        assert memory_scan_keylog_path(config) is None

    def test_auto_path_from_str_target(self):
        config = FriTapConfig(
            target="com.example.app", hooking=HookingConfig(memory_scan=True)
        )
        assert memory_scan_keylog_path(config) == "com.example.app_memscan.keylog"

    def test_auto_path_from_list_target(self):
        config = FriTapConfig(
            target=["wine", "app.exe"], hooking=HookingConfig(memory_scan=True)
        )
        assert memory_scan_keylog_path(config) == "wine_app.exe_memscan.keylog"

    def test_dedicated_file_beside_keylog_when_k_set(self):
        # With -k set, the memory-scan keylog is a co-located but SEPARATE file
        # (never a second handle onto the -k file, which would truncate it).
        config = FriTapConfig(
            target="com.example.app",
            output=OutputConfig(keylog="keys.log"),
            hooking=HookingConfig(memory_scan=True),
        )
        assert memory_scan_keylog_path(config) == "keys.memscan.log"

    def test_memory_scan_only_owns_the_keylog_path(self):
        # No hook handler writes -k in memory-scan-only mode, so the scanner
        # takes the -k path itself instead of a .memscan split.
        config = FriTapConfig(
            target="com.example.app",
            output=OutputConfig(keylog="keys.log"),
            hooking=HookingConfig(memory_scan=True, intercept=False),
        )
        assert memory_scan_keylog_path(config) == "keys.log"

    def test_dedicated_file_never_equals_keylog(self):
        config = FriTapConfig(
            target="com.example.app",
            output=OutputConfig(keylog="/tmp/out/session.keylog"),
            hooking=HookingConfig(memory_scan=True),
        )
        path = memory_scan_keylog_path(config)
        assert path != "/tmp/out/session.keylog"
        assert path == "/tmp/out/session.memscan.keylog"

    def test_odd_characters_in_target_are_sanitized(self):
        config = FriTapConfig(
            target="weird name/with:odd*chars",
            hooking=HookingConfig(memory_scan=True),
        )
        path = memory_scan_keylog_path(config)
        # basename strips the directory part, then non [A-Za-z0-9._-] runs collapse.
        assert path == "with_odd_chars_memscan.keylog"
        assert "/" not in path and ":" not in path and "*" not in path


