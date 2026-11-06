#!/usr/bin/env python3
"""Unit tests for ``--attribute-sdk`` (host-side plumbing, Phase 3b).

Opt-in SDK / caller attribution: when enabled, the agent captures the calling
thread's backtrace ONCE per connection at the first TLS plaintext hook and emits
an additive ``caller_stack`` message. These tests cover the host half of the
wire contract only:

* the flag round-tripping through :class:`HookingConfig` / ``from_legacy_params``
  (default OFF), and reaching the agent inside ``config_batch`` as
  ``attribute_sdk``; and
* the additive ``CallerStackMessage`` schema validating through the
  ``AgentMessage`` discriminated union with the expected defaults.

The agent-side behaviour (symbolization, dedup, flag-off no-op) is covered by
``agent/shared/sdk_backtrace.test.ts``.

The logger is built via ``SSL_Logger.__new__`` (as in ``test_probe_mode.py`` /
``test_boringssl_anchor_only_flag.py``) so no device, frida session or agent
bundle is needed.
"""

from pydantic import TypeAdapter

from friTap.config import FriTapConfig, HookingConfig
from friTap.legacy.ssl_logger_core import SSL_Logger
from friTap.schemas.agent_messages import (
    AgentMessage,
    CallerFrame,
    CallerStackMessage,
)


def _config_batch_logger(attribute_sdk: bool) -> SSL_Logger:
    """A bare SSL_Logger carrying only what _build_config_batch() reads."""
    obj = SSL_Logger.__new__(SSL_Logger)
    obj.offsets_data = None
    obj.pattern_data = None
    obj.scan_results_data = None
    obj._config = FriTapConfig.from_legacy_params(
        app="com.example.app", attribute_sdk=attribute_sdk
    )
    return obj


class TestHookingConfigRoundTrip:
    def test_defaults_off(self):
        assert HookingConfig().attribute_sdk is False

    def test_round_trips_through_from_legacy_params(self):
        cfg = FriTapConfig.from_legacy_params(app="a", attribute_sdk=True)
        assert cfg.hooking.attribute_sdk is True
        assert FriTapConfig.from_legacy_params(app="a").hooking.attribute_sdk is False


class TestConfigBatchCarriesFlag:
    def test_defaults_to_false(self):
        batch = _config_batch_logger(attribute_sdk=False)._build_config_batch()
        assert batch["attribute_sdk"] is False

    def test_true_when_requested(self):
        batch = _config_batch_logger(attribute_sdk=True)._build_config_batch()
        assert batch["attribute_sdk"] is True


class TestCallerStackMessageSchema:
    def test_defaults(self):
        msg = CallerStackMessage()
        assert msg.contentType == "caller_stack"
        assert msg.protocol == "tls"
        assert msg.ssl_session_id == ""
        assert msg.ss_family == "AF_INET"
        assert msg.java_frames == []
        assert msg.native_frames == []

    def test_validates_through_agent_message_union(self):
        adapter = TypeAdapter(AgentMessage)
        msg = adapter.validate_python(
            {
                "contentType": "caller_stack",
                "ssl_session_id": "deadbeef",
                "src_addr": "10.0.0.1",
                "dst_addr": "93.184.216.34",
                "src_port": 51000,
                "dst_port": 443,
                "ss_family": "AF_INET",
                "java_frames": ["com.example.Api", "okhttp3.RealCall"],
                "native_frames": [
                    {"module": "libssl.so", "symbol": "SSL_write", "address": "0x1000"},
                    {"module": "libapp.so", "address": "0x2000"},
                ],
            }
        )
        assert isinstance(msg, CallerStackMessage)
        assert msg.ssl_session_id == "deadbeef"
        assert msg.dst_port == 443
        assert msg.java_frames[1] == "okhttp3.RealCall"
        assert isinstance(msg.native_frames[0], CallerFrame)
        assert msg.native_frames[0].symbol == "SSL_write"
        # symbol/address are optional and default to None.
        assert msg.native_frames[1].symbol is None
