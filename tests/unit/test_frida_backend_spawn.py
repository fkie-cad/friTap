#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Unit tests for FridaBackend.spawn_raw aux/env forwarding.

spawn_raw is the layer that turns a friTap spawn request into a Frida
``device.spawn`` call. The Android "launch a specific activity" feature relies
on aux options reaching Frida verbatim (Frida routes the unrecognized
``activity`` kwarg into its spawn aux dictionary), so these tests pin that
contract with a mock device — no real frida-server required.
"""

from __future__ import annotations

from unittest.mock import MagicMock

from friTap.backends.frida_backend import FridaBackend


def _backend_with_mock_device():
    backend = FridaBackend()
    device = MagicMock()
    device.spawn.return_value = 1234
    return backend, device


def test_spawn_raw_plain_package():
    backend, device = _backend_with_mock_device()
    pid = backend.spawn_raw(device, "com.example.app")
    device.spawn.assert_called_once_with("com.example.app")
    assert pid == 1234


def test_spawn_raw_forwards_activity_aux():
    backend, device = _backend_with_mock_device()
    backend.spawn_raw(device, "com.example.app", aux={"activity": ".SomeActivity"})
    device.spawn.assert_called_once_with("com.example.app", activity=".SomeActivity")


def test_spawn_raw_forwards_env_and_aux_together():
    backend, device = _backend_with_mock_device()
    backend.spawn_raw(
        device, "com.example.app",
        env={"FOO": "bar"}, aux={"activity": ".A"},
    )
    device.spawn.assert_called_once_with(
        "com.example.app", activity=".A", env={"FOO": "bar"}
    )


def test_spawn_raw_env_only():
    backend, device = _backend_with_mock_device()
    backend.spawn_raw(device, "/usr/bin/app", env={"FOO": "bar"})
    device.spawn.assert_called_once_with("/usr/bin/app", env={"FOO": "bar"})


def test_spawn_raw_argv_list_passed_verbatim():
    # A spawn command supplied as argv tokens must reach device.spawn() as a
    # list, NOT be re-joined/re-split — otherwise a target path containing a
    # space (common under Wine, e.g. ".../Program Files/...") gets shredded.
    backend, device = _backend_with_mock_device()
    argv = ["wine", "/home/u/.wine/drive_c/Program Files/My Game/app.exe"]
    backend.spawn_raw(device, argv)
    device.spawn.assert_called_once_with(argv)


def test_spawn_raw_argv_list_with_env():
    backend, device = _backend_with_mock_device()
    argv = ["wine", "/p/My App/app.exe"]
    backend.spawn_raw(device, argv, env={"WINEDEBUG": "-all"})
    device.spawn.assert_called_once_with(argv, env={"WINEDEBUG": "-all"})
