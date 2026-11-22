"""-l (live Wireshark pipe) must turn on the agent's plaintext read/write hooks.

Regression (found live on a Pixel 5, 2026-11-22): ``fritap -m <dev> -l -k
keys.log <pid>`` wrote a pcapng with one Decryption Secrets Block per key and
0 packets. The default -l handler writes the decrypted DatalogEvents as
packets, but ``pcap_enabled`` in the startup config batch ignored -l, so the
agent never installed the plaintext hooks and no DatalogEvent ever arrived.
"""

from __future__ import annotations

import pytest

from friTap.config import FriTapConfig
from friTap.legacy.ssl_logger_core import SSL_Logger
from friTap.output.factory import OutputHandlerFactory


def _config(live_mode: str = "", **legacy_params) -> FriTapConfig:
    config = FriTapConfig.from_legacy_params(app="com.example.app", **legacy_params)
    config.output.live_mode = live_mode
    return config


def _batch(live_mode: str = "", **legacy_params) -> dict:
    """The startup config batch, built the way test_plaintext_hooks_for_machine_outputs does."""
    obj = SSL_Logger.__new__(SSL_Logger)
    obj.offsets_data = None
    obj.pattern_data = None
    obj.scan_results_data = None
    obj._config = _config(live_mode, **legacy_params)
    return obj._build_config_batch()


def test_cli_live_enables_plaintext_hooks():
    """The S9 command line: -l -k with no -p."""
    assert _batch(live=True, keylog="keys.log")["pcap_enabled"] is True


@pytest.mark.parametrize("live_mode", ["", "wireshark"])
def test_plaintext_live_modes_need_hooks(live_mode):
    """Both live modes that stream decrypted DatalogEvents need the hooks."""
    config = _config(live_mode, live=True)
    assert OutputHandlerFactory.plaintext_hooks_needed(config.output) is True


def test_raw_capture_live_mode_keeps_hooks_off():
    """The TUI's auto-decrypt live mode streams a raw capture plus keys only."""
    config = _config("live_pcapng", live=True, keylog="keys.log")
    assert OutputHandlerFactory.plaintext_hooks_needed(config.output) is False


def test_live_with_full_capture_keeps_hooks_off():
    """-f records raw packets with tcpdump, so plaintext hooks stay off as before."""
    assert _batch(live=True, full_capture=True, keylog="k.log",
                  pcap_name="o.pcap")["pcap_enabled"] is False


def test_keylog_only_still_keeps_hooks_off():
    assert _batch(keylog="keys.log")["pcap_enabled"] is False


@pytest.mark.parametrize("handler_path", [
    "friTap.output.live_pcapng_handler.LivePcapngHandler",
    "friTap.output.live_wireshark_handler.LiveWiresharkHandler",
])
def test_plaintext_live_handlers_declare_consumes_plaintext(handler_path):
    import importlib
    module_name, class_name = handler_path.rsplit(".", 1)
    handler_cls = getattr(importlib.import_module(module_name), class_name)
    assert handler_cls.consumes_plaintext is True


def test_modern_notice_is_info_not_warning():
    """--modern's "modern hooks active" notice is status, so it must not get the "[-]" prefix."""
    from types import SimpleNamespace
    from unittest.mock import MagicMock
    from friTap.friTap import _validate_capture_options
    from friTap.pcap_utility import PCAP_FORMAT_AUTO

    parsed = SimpleNamespace(use_modern=True, full_capture=False, pcap=None,
                             pcap_format=PCAP_FORMAT_AUTO)
    logger = MagicMock()
    try:
        _validate_capture_options(parsed, MagicMock(), logger)
    except AttributeError:
        pass  # later checks read flags this stub omits; the notice comes first
    infos = [c.args[0] for c in logger.info.call_args_list]
    warnings = [c.args[0] for c in logger.warning.call_args_list]
    assert any("modern hooks active" in m for m in infos)
    assert not any("modern hooks active" in m for m in warnings)
