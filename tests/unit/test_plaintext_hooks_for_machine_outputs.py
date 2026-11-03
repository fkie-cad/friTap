"""--tap and -j (stdout or file) must turn on the agent's plaintext read/write hooks.

Regression (found on an Android emulator): ``pcap_enabled`` in the startup
config batch was driven by ``-p`` alone, so ``fritap --tap cap.tap target`` and
``fritap -j - target`` captured no data events at all (empty .tap, no
``"type": "data"`` lines) unless ``-p`` was also given.
"""

from __future__ import annotations

import pytest

from friTap.config import FriTapConfig
from friTap.legacy.ssl_logger_core import SSL_Logger


def _batch(tap_output=None, **legacy_params) -> dict:
    """The startup config batch for a CLI-like config (``--tap`` is set after
    construction, exactly as ``friTap.friTap`` does)."""
    obj = SSL_Logger.__new__(SSL_Logger)
    obj.offsets_data = None
    obj.pattern_data = None
    obj.scan_results_data = None
    obj._config = FriTapConfig.from_legacy_params(app="com.example.app", **legacy_params)
    obj._config.output.tap_output = tap_output
    return obj._build_config_batch()


def test_no_plaintext_consumer_keeps_hooks_off():
    assert _batch(keylog="keys.log")["pcap_enabled"] is False


def test_pcap_enables_hooks():
    assert _batch(pcap_name="out.pcap")["pcap_enabled"] is True


def test_json_stdout_stream_enables_hooks():
    assert _batch(json_output="-")["pcap_enabled"] is True


@pytest.mark.parametrize("json_output", ["session.json", "session.jsonl"])
def test_json_file_alone_enables_hooks(json_output):
    """-j <file> serialises data events too (the main AI-agent input), so a
    JSON/JSONL file on its own must capture plaintext."""
    assert _batch(json_output=json_output)["pcap_enabled"] is True


@pytest.mark.parametrize("json_output", ["f.json", "f.jsonl", "-"])
def test_factory_reports_plaintext_needed_for_json(json_output):
    from friTap.output.factory import OutputHandlerFactory
    config = FriTapConfig.from_legacy_params(app="com.example.app",
                                             json_output=json_output)
    assert OutputHandlerFactory.plaintext_hooks_needed(config.output) is True


def test_tap_output_enables_hooks():
    assert _batch(tap_output="cap.tap")["pcap_enabled"] is True


@pytest.mark.parametrize("extra", [{"json_output": "-"}, {"pcap_name": "out.pcap"}])
def test_full_capture_never_enables_hooks(extra):
    assert _batch(full_capture=True, keylog="k.log", **extra)["pcap_enabled"] is False
    assert _batch(tap_output="cap.tap", full_capture=True, keylog="k.log")["pcap_enabled"] is False
