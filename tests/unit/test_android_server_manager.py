#!/usr/bin/env python3

"""Unit tests for AndroidServerManager.ensure_running and friends.

AndroidFridaManager is replaced by a Mock injected into ``mgr._fm``; frida
devices are fakes reporting ``access: full`` (real frida-server) or
``access: jailed`` with an ADB-sized process list (frida 17's fallback).
"""

from __future__ import annotations

from unittest.mock import Mock, patch

import pytest

from friTap.server_manager import ServerState
from friTap.server_manager.android import AndroidServerManager
from friTap.server_manager.base import BaseFridaServerManager
from friTap.server_manager.factory import get_server_manager

SERIAL = "emulator-5554"
ADB_PROCESS_LIST = [object() for _ in range(300)]

# Public FridaManager API of AndroidFridaManager 2.0.4 (no get_device_arch,
# is_frida_server_ready, get_frida_server_status).
AFRIM_204_API = [
    "run_frida_server", "stop_frida_server", "is_frida_server_running",
    "get_installed_server_version", "install_frida_server", "is_device_rooted",
    "remove_frida_server", "download_frida_server",
]


def _device(access="full", os_id="android"):
    device = Mock()
    device.id = SERIAL
    device.query_system_parameters.return_value = {
        "access": access, "os": {"id": os_id}, "arch": "arm64",
    }
    device.enumerate_processes.return_value = ADB_PROCESS_LIST
    return device


def _flip_to_full(device):
    """Side effect: make *device* report a real frida-server from now on."""
    def _run():
        device.query_system_parameters.return_value = {"access": "full"}
        return True
    return _run


class FakeClock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


@pytest.fixture
def mgr():
    manager = AndroidServerManager(device_serial=SERIAL)
    manager._fm = Mock(spec=AFRIM_204_API)
    manager._fm.is_device_rooted = True
    manager._fm.is_frida_server_running.return_value = False
    manager._fm.get_installed_server_version.return_value = manager._frida_version
    manager._fm.run_frida_server.return_value = True
    clock = FakeClock()
    manager._clock = clock
    manager._sleep = Mock(side_effect=clock.sleep)
    with patch.object(AndroidServerManager, "_fresh_device", return_value=None):
        yield manager


def test_already_running_makes_no_afrim_calls(mgr):
    assert mgr.ensure_running(_device("full")) is ServerState.RUNNING
    assert mgr._fm.method_calls == []


def test_jailed_device_is_started_and_polled_until_full(mgr):
    device = _device("jailed")
    mgr._fm.run_frida_server.side_effect = _flip_to_full(device)
    messages = []
    assert mgr.ensure_running(device, callback=messages.append) is ServerState.RUNNING
    mgr._fm.install_frida_server.assert_not_called()
    mgr._fm.stop_frida_server.assert_not_called()
    assert any("Starting" in m for m in messages)


def test_version_mismatch_installs_pinned_version(mgr):
    device = _device("jailed")
    mgr._fm.get_installed_server_version.return_value = "16.0.0"
    mgr._fm.run_frida_server.side_effect = _flip_to_full(device)
    messages = []
    mgr.ensure_running(device, callback=messages.append)
    mgr._fm.install_frida_server.assert_called_once_with(version=mgr._frida_version)
    assert any("Installing" in m and mgr._frida_version in m for m in messages)


def test_missing_binary_installs(mgr):
    device = _device("jailed")
    mgr._fm.get_installed_server_version.return_value = None
    mgr._fm.run_frida_server.side_effect = _flip_to_full(device)
    mgr.ensure_running(device)
    mgr._fm.install_frida_server.assert_called_once()


def test_stale_process_is_stopped_before_run(mgr):
    device = _device("jailed")
    order = []
    mgr._fm.is_frida_server_running.return_value = True
    mgr._fm.stop_frida_server.side_effect = lambda: order.append("stop")
    flip = _flip_to_full(device)
    mgr._fm.run_frida_server.side_effect = lambda: (order.append("run"), flip())[1]
    mgr.ensure_running(device)
    assert order == ["stop", "run"]


def test_run_returning_false_raises(mgr):
    mgr._fm.run_frida_server.return_value = False
    with pytest.raises(RuntimeError, match="failed to start on emulator-5554.*logcat"):
        mgr.ensure_running(_device("jailed"))


def test_timeout_raises_jailed_explanation(mgr):
    with pytest.raises(RuntimeError, match="jailed access"):
        mgr.ensure_running(_device("jailed"), timeout=3.0)
    assert mgr._clock.now >= 3.0


def test_not_rooted_raises_clear_error(mgr):
    mgr._fm.is_device_rooted = False
    with pytest.raises(RuntimeError, match="not rooted"):
        mgr.ensure_running(_device("jailed"))
    mgr._fm.run_frida_server.assert_not_called()


def test_install_failure_is_wrapped(mgr):
    mgr._fm.get_installed_server_version.return_value = None
    mgr._fm.install_frida_server.side_effect = RuntimeError("boom")
    with pytest.raises(RuntimeError, match="Installing frida-server .* failed: boom"):
        mgr.ensure_running(_device("jailed"))


def test_fresh_device_is_probed_when_passed_one_stays_jailed(mgr):
    fresh = _device("full")
    with patch.object(AndroidServerManager, "_fresh_device", return_value=fresh):
        assert mgr.ensure_running(_device("jailed")) is ServerState.RUNNING


def test_start_raises_on_false(mgr):
    mgr._fm.run_frida_server.return_value = False
    with pytest.raises(RuntimeError):
        mgr.start()


def test_start_accepts_none_return(mgr):
    mgr._fm.run_frida_server.return_value = None
    mgr.start()


def test_is_running_with_device_uses_probe(mgr):
    mgr._fm.is_frida_server_running.return_value = True
    assert mgr.is_running(_device("jailed")) is False
    assert mgr.is_running(_device("full")) is True


def test_is_running_without_device_uses_afrim(mgr):
    mgr._fm.is_frida_server_running.return_value = True
    assert mgr.is_running() is True


def test_detect_arch_falls_back_without_get_device_arch(mgr):
    assert not hasattr(mgr._fm, "get_device_arch")
    assert mgr.detect_arch(_device()) == "arm64"


def test_detect_arch_uses_get_device_arch_when_present(mgr):
    mgr._fm = Mock(spec=AFRIM_204_API + ["get_device_arch"])
    mgr._fm.get_device_arch.return_value = "x86_64"
    assert mgr.detect_arch(_device()) == "x86_64"


def test_factory_picks_android_under_jailed_access():
    manager = get_server_manager(_device("jailed"))
    assert isinstance(manager, AndroidServerManager)
    assert manager._device_serial == SERIAL


class _StubManager(BaseFridaServerManager):
    platform_name = "stub"

    def __init__(self, device):
        super().__init__()
        self._device = device
        self.started = 0

    def detect_arch(self, device=None):
        return "arm64"

    def deploy(self, binary_path, device=None):
        pass

    def start(self, device=None):
        self.started += 1
        device.query_system_parameters.return_value = {"access": "full"}

    def stop(self, device=None):
        pass

    def is_running(self, device=None):
        return False

    def needs_server(self):
        return True


def test_base_ensure_running_starts_then_polls():
    device = _device("jailed")
    manager = _StubManager(device)
    manager._sleep = Mock()
    assert manager.ensure_running(device) is ServerState.RUNNING
    assert manager.started == 1


def test_base_ensure_running_skips_start_when_capable():
    device = _device("full")
    manager = _StubManager(device)
    assert manager.ensure_running(device) is ServerState.RUNNING
    assert manager.started == 0
