#!/usr/bin/env python3
"""Unit tests for ``--probe`` (host side).

Probe mode is a dry-run diagnostic: friTap loads the agent, the agent reports
which platform branch it selected, and nothing is hooked. These tests cover the
host half of that wire contract — the config flag reaching the agent, the
``platform_report`` message becoming a :class:`PlatformReportEvent`, the
unconditional one-line summary, the probe acknowledgement guard, and the CLI
conflict warnings.

The logger is built via ``SSL_Logger.__new__`` (as in
``test_crash_attribution.py``) so no device, frida session or agent bundle is
needed.
"""

import argparse
import logging
import threading
import types

import pytest

from friTap.config import FriTapConfig, HookingConfig
from friTap.constants import ContentType
from friTap.events import EventBus, PlatformReportEvent
from friTap.friTap import _probe_conflict_warnings
from friTap.legacy.ssl_logger_core import SSL_Logger
from friTap.message_router import MessageRouter

# ---------------------------------------------------------------------------
# config_batch
# ---------------------------------------------------------------------------

def _config_batch_logger(probe: bool) -> SSL_Logger:
    """A bare SSL_Logger carrying only what _build_config_batch() reads."""
    obj = SSL_Logger.__new__(SSL_Logger)
    obj.offsets_data = None
    obj.pattern_data = None
    obj.scan_results_data = None
    obj._config = FriTapConfig.from_legacy_params(app="com.example.app", probe=probe)
    return obj


class TestConfigBatchCarriesProbe:
    def test_defaults_to_false(self):
        batch = _config_batch_logger(probe=False)._build_config_batch()
        assert batch["probe"] is False

    def test_true_when_requested(self):
        batch = _config_batch_logger(probe=True)._build_config_batch()
        assert batch["probe"] is True


class TestHookingConfigRoundTrip:
    def test_probe_defaults_off(self):
        assert HookingConfig().probe is False

    def test_probe_round_trips_through_from_legacy_params(self):
        assert FriTapConfig.from_legacy_params(app="a", probe=True).hooking.probe is True
        assert FriTapConfig.from_legacy_params(app="a").hooking.probe is False


# ---------------------------------------------------------------------------
# MessageRouter -> PlatformReportEvent
# ---------------------------------------------------------------------------

class TestRouterEmitsPlatformReport:
    def test_full_payload_is_parsed(self):
        bus = EventBus()
        seen = []
        bus.subscribe(PlatformReportEvent, seen.append)
        MessageRouter(bus).route({
            "contentType": ContentType.PLATFORM_REPORT,
            "platform": "MacOS",
            "target": "macos",
            "probe": True,
            "abi": 1,
        }, b"")

        assert len(seen) == 1
        assert seen[0].platform == "MacOS"
        assert seen[0].target == "macos"
        assert seen[0].probe is True
        assert seen[0].abi == 1

    def test_missing_fields_fall_back_to_defaults(self):
        bus = EventBus()
        seen = []
        bus.subscribe(PlatformReportEvent, seen.append)
        MessageRouter(bus).route({"contentType": "platform_report"}, b"")

        assert len(seen) == 1
        assert seen[0].platform == ""
        assert seen[0].target == ""
        assert seen[0].probe is False
        assert seen[0].abi == 0

    def test_non_numeric_abi_does_not_drop_the_report(self):
        bus = EventBus()
        seen = []
        bus.subscribe(PlatformReportEvent, seen.append)
        MessageRouter(bus).route({
            "contentType": "platform_report",
            "platform": "iOS",
            "target": "ios",
            "abi": "not-a-number",
        }, b"")

        assert len(seen) == 1
        assert seen[0].platform == "iOS"
        assert seen[0].abi == 0


# ---------------------------------------------------------------------------
# SSL_Logger handler + probe-ack guard
# ---------------------------------------------------------------------------

def _probe_logger() -> SSL_Logger:
    """A bare SSL_Logger carrying only the platform-report state."""
    obj = SSL_Logger.__new__(SSL_Logger)
    obj.logger = logging.getLogger("test.probe")
    obj.logger.setLevel(logging.DEBUG)
    obj.special_logger = logging.getLogger("test.probe.special")
    obj._platform_report = None
    obj._platform_report_received = threading.Event()
    obj.agent_script = "fritap_agent.js"
    # Hermetic: ignore a locally built full bundle next to the package.
    obj._resolve_full_agent_bundle = lambda default_bundle: None
    return obj


class TestPlatformReportHandler:
    def test_logs_one_line_unconditionally(self, caplog):
        obj = _probe_logger()
        with caplog.at_level(logging.INFO, logger="test.probe"):
            obj._on_platform_report(PlatformReportEvent(
                platform="MacOS", target="macos", probe=True, abi=1,
            ))
        text = caplog.text
        assert "Agent platform report: MacOS" in text
        assert "target=macos" in text
        assert "agent ABI 1" in text

    def test_unknown_platform_still_logs(self, caplog):
        obj = _probe_logger()
        with caplog.at_level(logging.INFO, logger="test.probe"):
            obj._on_platform_report(PlatformReportEvent())
        assert "unknown platform" in caplog.text

    def test_stores_report_and_sets_ack_event(self):
        obj = _probe_logger()
        assert obj._platform_report_received.is_set() is False
        event = PlatformReportEvent(platform="iOS", target="ios", probe=True, abi=1)
        obj._on_platform_report(event)
        assert obj._platform_report is event
        assert obj._platform_report_received.is_set() is True


class TestWaitForPlatformReport:
    def test_returns_true_once_the_report_arrived(self):
        obj = _probe_logger()
        obj._on_platform_report(PlatformReportEvent(platform="Android", target="android"))
        assert obj.wait_for_platform_report(timeout=0.05) is True

    def test_returns_false_on_timeout(self):
        obj = _probe_logger()
        assert obj.wait_for_platform_report(timeout=0.05) is False

    def test_returns_true_for_a_report_that_lands_during_the_wait(self):
        obj = _probe_logger()
        timer = threading.Timer(
            0.02, obj._on_platform_report,
            args=(PlatformReportEvent(platform="Linux", target="linux"),),
        )
        timer.start()
        try:
            assert obj.wait_for_platform_report(timeout=0.3) is True
        finally:
            timer.cancel()


class TestProbeUnsupportedBundleMessage:
    """An old bundle must fail loudly — a diagnostic that can silently lie is
    worse than no diagnostic."""

    def test_names_the_bundle_and_the_rebuild_command(self):
        obj = _probe_logger()
        lines = obj._probe_unsupported_bundle_lines()
        text = "\n".join(lines)
        assert "does not implement probe mode" in text
        assert "never sent a platform report" in text
        assert "fritap_agent.js" in text
        assert "./dev/compile_agent.sh" in text

    def test_report_without_probe_ack_is_also_a_failure(self):
        obj = _probe_logger()
        obj._on_platform_report(PlatformReportEvent(
            platform="iOS", target="ios", probe=False, abi=1,
        ))
        text = "\n".join(obj._probe_unsupported_bundle_lines())
        assert "did not acknowledge probe mode" in text
        assert "iOS" in text


# ---------------------------------------------------------------------------
# CLI conflict warnings
# ---------------------------------------------------------------------------

def _parsed(**overrides) -> argparse.Namespace:
    values = {
        "probe": False,
        "keylog": None,
        "pcap": None,
        "full_capture": False,
        "live": False,
        "json": None,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


class TestProbeConflictWarnings:
    def test_silent_when_probe_is_off(self):
        assert _probe_conflict_warnings(_parsed(keylog="keys.log", pcap="out.pcap")) == []

    def test_silent_when_probe_alone(self):
        assert _probe_conflict_warnings(_parsed(probe=True)) == []

    @pytest.mark.parametrize("overrides,label", [
        ({"keylog": "keys.log"}, "-k/--keylog"),
        ({"pcap": "out.pcap"}, "-p/--pcap"),
        ({"full_capture": True}, "-f/--full_capture"),
        ({"live": True}, "--live"),
        ({"json": "out.json"}, "-j/--json"),
    ])
    def test_each_capture_flag_is_named(self, overrides, label):
        lines = _probe_conflict_warnings(_parsed(probe=True, **overrides))
        text = "\n".join(lines)
        assert label in text
        assert "dry run" in text

    def test_all_flags_named_in_one_message(self):
        lines = _probe_conflict_warnings(_parsed(
            probe=True, keylog="k", pcap="p", full_capture=True, live=True, json="j",
        ))
        text = "\n".join(lines)
        for label in ("-k/--keylog", "-p/--pcap", "-f/--full_capture", "--live", "-j/--json"):
            assert label in text

    def test_tolerates_a_namespace_without_the_probe_attribute(self):
        assert _probe_conflict_warnings(types.SimpleNamespace()) == []
