"""Hint for the frida-server 17.24.0-17.24.3 remote "> 128 KiB message" bug.

frida-server 17.24.0-17.24.3 closes a remote (-H) session on any host->server
message above 128 KiB (fixed in 17.25.0, frida/frida-core#1267). The closed
link looks like a dead target, so friTap adds a hint -- for remote devices only.
"""

from __future__ import annotations

import logging
import types

import pytest

from friTap.backends import BackendTransportError
from friTap.backends import frida_remote_limits as limits
from friTap.exit_codes import EXIT_RUNTIME_ERROR
from friTap.legacy.ssl_logger_core import SSL_Logger


# --------------------------------------------------------------------------
# pure helpers
# --------------------------------------------------------------------------

@pytest.mark.parametrize("text, expected", [
    ("17.24.3", (17, 24, 3)),
    ("frida-server 17.25.0-dev", (17, 25, 0)),
    ("unknown", None),
    (None, None),
])
def test_parse_version(text, expected):
    assert limits.parse_version(text) == expected


@pytest.mark.parametrize("version, expected", [
    ("17.23.9", False), ("17.24.0", True), ("17.24.3", True), ("17.24.4", False),
    ("17.25.0", False), (None, None), ("garbage", None),
])
def test_affected_range(version, expected):
    assert limits.is_affected_server_version(version) is expected


@pytest.mark.parametrize("params, expected", [
    ({"arch": "arm64", "access": "full"}, None),            # what frida 17.24 reports
    ({"frida": {"version": "17.24.2"}}, "17.24.2"),
    ({"frida_version": "17.25.0"}, "17.25.0"),
    ("not a dict", None),
])
def test_server_version_from_params(params, expected):
    assert limits.server_version_from_params(params) == expected


@pytest.mark.parametrize("error, expected", [
    ("the connection is closed", True),
    (BackendTransportError("the connection is closed"), True),
    ("connection-terminated", True),
    ("process-terminated", False),
    ("unable to find process", False),
])
def test_is_connection_closed(error, expected):
    assert limits.is_connection_closed(error) is expected


def test_hint_for_affected_server_names_version_and_fix():
    hint = limits.remote_message_limit_hint("17.24.3")
    assert "17.24.3" in hint and "128 KiB" in hint and "≥ 17.25.0" in hint


def test_no_hint_for_fixed_or_older_server():
    assert limits.remote_message_limit_hint("17.25.0") is None
    assert limits.remote_message_limit_hint("16.7.19") is None


def test_unknown_server_version_gives_neutral_hint():
    hint = limits.remote_message_limit_hint(None, "17.24.3")
    assert "If it runs frida-server 17.24.0–17.24.3" in hint
    assert "≥ 17.25.0" in hint
    assert "Server version not reported; host frida 17.24.3" in hint


# --------------------------------------------------------------------------
# SSL_Logger wiring
# --------------------------------------------------------------------------

class _Device:
    def __init__(self, type_="remote", params=None, error=None):
        self.type = type_
        self._params = params if params is not None else {"access": "full"}
        self._error = error
        self.queries = 0

    def query_system_parameters(self):
        self.queries += 1
        if self._error:
            raise self._error
        return self._params


def _logger(host=None, device=None, spawn=True):
    obj = SSL_Logger.__new__(SSL_Logger)
    obj.logger = logging.getLogger("test.remote_limits")
    obj._config = types.SimpleNamespace(
        target="com.example.app", target_argv=None,
        device=types.SimpleNamespace(spawn=spawn, host=host, device_id=None))
    obj.device = device
    obj.pid = 4242
    obj._exit_status = 0
    return obj


def test_usb_device_gets_no_hint_and_no_query():
    device = _Device(type_="usb")
    log = _logger(device=device)
    log.note_remote_frida_server_version()
    assert device.queries == 0
    assert log.remote_message_limit_hint_for("the connection is closed") is None


def test_local_device_gets_no_hint():
    assert _logger(device=_Device(type_="local")).remote_message_limit_hint_for(
        "the connection is closed") is None


def test_remote_host_closed_connection_gets_neutral_hint():
    log = _logger(host="192.168.1.5:27042", device=_Device())
    log.note_remote_frida_server_version()
    hint = log.remote_message_limit_hint_for(BackendTransportError("the connection is closed"))
    assert hint is not None and "17.24.0–17.24.3" in hint and "≥ 17.25.0" in hint


def test_remote_device_id_counts_as_remote():
    log = _logger(device=_Device(type_="remote"))
    assert log.remote_message_limit_hint_for("connection-terminated") is not None


def test_remote_but_unrelated_error_gets_no_hint():
    log = _logger(host="10.0.0.1", device=_Device())
    assert log.remote_message_limit_hint_for("process-terminated") is None


def test_reported_server_version_selects_precise_or_no_hint():
    affected = _logger(host="h", device=_Device(params={"frida": {"version": "17.24.1"}}))
    affected.note_remote_frida_server_version()
    assert "The remote frida-server is 17.24.1" in affected.remote_message_limit_hint_for(
        "the connection is closed")
    fixed = _logger(host="h", device=_Device(params={"frida": {"version": "17.25.0"}}))
    fixed.note_remote_frida_server_version()
    assert fixed.remote_message_limit_hint_for("the connection is closed") is None


def test_server_query_failure_is_swallowed():
    log = _logger(host="h", device=_Device(error=RuntimeError("gone")))
    log.note_remote_frida_server_version()   # must not raise
    assert "Server version not reported" in log.remote_message_limit_hint_for(
        "the connection is closed")


def test_death_before_capture_on_remote_carries_the_hint(caplog):
    log = _logger(host="h", device=_Device())
    with caplog.at_level(logging.ERROR, logger="test.remote_limits"):
        log._report_death_before_capture("transport error: the connection is closed")
    assert log._exit_status == EXIT_RUNTIME_ERROR
    assert "≥ 17.25.0" in caplog.text
    assert log._remote_limit_hint_reported is True


def test_death_before_capture_on_usb_has_no_hint(caplog):
    log = _logger(device=_Device(type_="usb"))
    with caplog.at_level(logging.ERROR, logger="test.remote_limits"):
        log._report_death_before_capture("transport error: the connection is closed")
    assert "17.25.0" not in caplog.text


def test_detach_during_capture_warns_once(caplog):
    log = _logger(host="h", device=_Device())
    with caplog.at_level(logging.WARNING, logger="test.remote_limits"):
        log._warn_remote_message_limit("connection-terminated")
        log._warn_remote_message_limit("connection-terminated")
    assert caplog.text.count("≥ 17.25.0") == 1
