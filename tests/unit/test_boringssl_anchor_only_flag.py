#!/usr/bin/env python3
"""Unit tests for ``--boringssl-anchor-only`` (host-side plumbing).

The flag forces friTap's last-resort BoringSSL keylog tier (the anchor locator,
tier 4) by skipping the byte-pattern tier. These tests cover the host half of the
wire contract only: the flag round-tripping through :class:`HookingConfig` /
``from_legacy_params`` and reaching the agent inside ``config_batch`` as
``force_anchor_locator``. The agent-side behaviour is covered by
``agent/shared/boringssl_anchor_locator.test.ts``.

The logger is built via ``SSL_Logger.__new__`` (as in ``test_probe_mode.py``) so
no device, frida session or agent bundle is needed.
"""

from friTap.config import FriTapConfig, HookingConfig
from friTap.legacy.ssl_logger_core import SSL_Logger


def _config_batch_logger(force_anchor_locator: bool) -> SSL_Logger:
    """A bare SSL_Logger carrying only what _build_config_batch() reads."""
    obj = SSL_Logger.__new__(SSL_Logger)
    obj.offsets_data = None
    obj.pattern_data = None
    obj.scan_results_data = None
    obj._config = FriTapConfig.from_legacy_params(
        app="com.example.app", force_anchor_locator=force_anchor_locator
    )
    return obj


class TestHookingConfigRoundTrip:
    def test_defaults_off(self):
        assert HookingConfig().force_anchor_locator is False

    def test_round_trips_through_from_legacy_params(self):
        cfg = FriTapConfig.from_legacy_params(app="a", force_anchor_locator=True)
        assert cfg.hooking.force_anchor_locator is True
        assert FriTapConfig.from_legacy_params(app="a").hooking.force_anchor_locator is False


class TestConfigBatchCarriesFlag:
    def test_defaults_to_false(self):
        batch = _config_batch_logger(force_anchor_locator=False)._build_config_batch()
        assert batch["force_anchor_locator"] is False

    def test_true_when_requested(self):
        batch = _config_batch_logger(force_anchor_locator=True)._build_config_batch()
        assert batch["force_anchor_locator"] is True
