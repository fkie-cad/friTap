"""-l turns on the plaintext hooks only where a live handler is really created.

Windows has no named pipes for the live view, so the factory skips the -l
handler there; installing the plaintext hooks for it would hook for nothing.
"""

from __future__ import annotations

import pytest

from friTap import fritap_utility
from friTap.config import FriTapConfig
from friTap.output.factory import OutputHandlerFactory


def _live_only_config(live_mode: str = "") -> FriTapConfig:
    config = FriTapConfig.from_legacy_params(app="com.example.app", live=True,
                                             keylog="keys.log")
    config.output.live_mode = live_mode
    return config


@pytest.fixture
def on_windows(monkeypatch):
    monkeypatch.setattr(fritap_utility, "are_we_running_on_windows", lambda: True)


@pytest.fixture
def on_posix(monkeypatch):
    monkeypatch.setattr(fritap_utility, "are_we_running_on_windows", lambda: False)


@pytest.mark.parametrize("live_mode", ["", "wireshark"])
def test_live_enables_plaintext_hooks_on_posix(on_posix, live_mode):
    assert OutputHandlerFactory.plaintext_hooks_needed(_live_only_config(live_mode).output)


@pytest.mark.parametrize("live_mode", ["", "wireshark", "live_pcapng"])
def test_live_does_not_enable_plaintext_hooks_on_windows(on_windows, live_mode):
    assert not OutputHandlerFactory.plaintext_hooks_needed(_live_only_config(live_mode).output)


def test_windows_still_enables_hooks_for_other_plaintext_outputs(on_windows):
    config = _live_only_config()
    config.output.pcap = "out.pcap"
    assert OutputHandlerFactory.plaintext_hooks_needed(config.output)
