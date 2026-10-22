#!/usr/bin/env python3

"""Unit tests for friTap.server_manager.probe."""

from __future__ import annotations

from unittest.mock import Mock

import pytest

from friTap.server_manager import ServerState, is_attach_capable, probe_frida_server

ADB_PROCESS_LIST = [object() for _ in range(300)]


def _device(params=None, processes=None, query_error=None, enum_error=None):
    device = Mock()
    if query_error is not None:
        device.query_system_parameters.side_effect = query_error
    else:
        device.query_system_parameters.return_value = params or {}
    if enum_error is not None:
        device.enumerate_processes.side_effect = enum_error
    else:
        device.enumerate_processes.return_value = processes or []
    return device


def test_none_device_is_unreachable():
    assert probe_frida_server(None) is ServerState.UNREACHABLE


def test_query_raising_is_unreachable():
    device = _device(query_error=RuntimeError("gone"))
    assert probe_frida_server(device) is ServerState.UNREACHABLE


def test_full_access_is_running_without_enumerating():
    device = _device(params={"access": "full"})
    assert probe_frida_server(device) is ServerState.RUNNING
    device.enumerate_processes.assert_not_called()


def test_missing_access_key_with_enumeration_is_running():
    device = _device(params={"os": {}}, processes=ADB_PROCESS_LIST)
    assert probe_frida_server(device) is ServerState.RUNNING


def test_missing_access_key_with_enumeration_failure_is_not_running():
    device = _device(params={}, enum_error=RuntimeError("closed"))
    assert probe_frida_server(device) is ServerState.NOT_RUNNING


def test_jailed_single_process_is_gadget():
    device = _device(params={"access": "jailed"}, processes=[object()])
    assert probe_frida_server(device) is ServerState.GADGET


def test_jailed_adb_fallback_is_not_running():
    """Frida-17 trap: no server, yet the whole ADB process list comes back."""
    params = {"arch": "arm64", "platform": "linux", "api-level": 37, "access": "jailed"}
    device = _device(params=params, processes=ADB_PROCESS_LIST)
    assert probe_frida_server(device) is ServerState.NOT_RUNNING


def test_jailed_empty_process_list_is_not_running():
    device = _device(params={"access": "jailed"}, processes=[])
    assert probe_frida_server(device) is ServerState.NOT_RUNNING


def test_jailed_enumeration_failure_is_not_running():
    device = _device(params={"access": "jailed"}, enum_error=RuntimeError("closed"))
    assert probe_frida_server(device) is ServerState.NOT_RUNNING


def test_unknown_access_value_is_not_running():
    device = _device(params={"access": "weird"}, processes=ADB_PROCESS_LIST)
    assert probe_frida_server(device) is ServerState.NOT_RUNNING


@pytest.mark.parametrize(
    "state, expected",
    [
        (ServerState.RUNNING, True),
        (ServerState.GADGET, True),
        (ServerState.NOT_RUNNING, False),
        (ServerState.UNREACHABLE, False),
    ],
)
def test_is_attach_capable(state, expected):
    assert is_attach_capable(state) is expected


def test_state_string_values():
    assert [s.value for s in ServerState] == ["running", "gadget", "not running", "unreachable"]
