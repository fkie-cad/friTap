"""Numeric-PID attach resolves the real process name for the flow collector.

``fritap -m -p out.pcap --tap x.tap --attribute-sdk 12345`` used to leave the
collector's ``_process_name`` as "12345", so the transport classifier could not
tell Chrome from WebView (libmonochrome flows in Chrome were labelled
``webview``). After a successful numeric attach the session manager now asks
the backend once for the name (an Android package id when frida's metadata
scope carries one) and hands it to every reachable collector.
"""

from __future__ import annotations

import logging
import types
from unittest.mock import MagicMock

import pytest

from friTap.backends.base import Backend
from friTap.backends.frida_backend import FridaBackend
from friTap.flow.collector import FlowCollector
from friTap.legacy.session_manager import SessionManager
from friTap.legacy.ssl_logger_core import SSL_Logger
from friTap.output.tap_handler import TapOutputHandler
from tests.unit._log_helpers import attach_log_capture


# ------------------------------------------------------------ fakes

def _frida_process(pid, name, parameters=None):
    return types.SimpleNamespace(pid=pid, name=name, parameters=parameters or {})


class _FakeFridaDevice:
    """Records enumerate_processes calls; returns the configured processes."""

    def __init__(self, processes=(), dtype="usb", error=None):
        self.type = dtype
        self._processes = list(processes)
        self._error = error
        self.calls = []

    def enumerate_processes(self, **kwargs):
        self.calls.append(kwargs)
        if self._error is not None:
            raise self._error
        return list(self._processes)


def _frida_backend():
    backend = FridaBackend.__new__(FridaBackend)  # skip the frida version check
    backend._logger = logging.getLogger("friTap.backend.frida")
    return backend


def _attach_logger(target, device, process_name_side_effect=None):
    """A start_session-ready logger in plain attach mode (no spawn/gating)."""
    logger = MagicMock()
    logger.device_id = None
    logger.mobile = False
    logger.host = None
    logger.spawn = False
    logger.enable_spawn_gating = False
    logger.spawn_gating_all = False
    logger.timeout = 0
    logger._agent_script_path = None
    logger.target_app = target
    logger._backend.get_device.return_value = device
    logger._backend.attach.return_value = types.SimpleNamespace(pid=4242)
    if process_name_side_effect is not None:
        logger._backend.process_name.side_effect = process_name_side_effect
    return logger


@pytest.fixture
def session_log():
    logger, capture = attach_log_capture("friTap.session")
    yield capture
    logger.removeHandler(capture)


# ------------------------------------------------- session manager seam

def test_numeric_attach_hands_resolved_name_to_logger():
    device = object()
    logger = _attach_logger("4242", device)
    logger._backend.process_name.return_value = "com.android.chrome"

    SessionManager(logger).start_session()

    logger._backend.process_name.assert_called_once_with(device, 4242)
    logger.apply_resolved_process_name.assert_called_once_with("com.android.chrome")


def test_numeric_attach_survives_failing_lookup(session_log):
    logger = _attach_logger("4242", object(), process_name_side_effect=RuntimeError("boom"))

    process, _script = SessionManager(logger).start_session()

    assert process is logger.process and logger.pid == 4242
    logger.instrument.assert_called_once()
    logger.apply_resolved_process_name.assert_not_called()
    assert "Could not resolve process name for pid 4242" in session_log.text


def test_unresolved_name_is_not_applied():
    logger = _attach_logger("4242", object())
    logger._backend.process_name.return_value = None

    SessionManager(logger).start_session()

    logger.apply_resolved_process_name.assert_not_called()


def test_name_target_makes_no_lookup():
    device = _FakeFridaDevice()
    logger = _attach_logger("com.android.chrome", device)

    SessionManager(logger).start_session()

    logger._backend.process_name.assert_not_called()
    logger.apply_resolved_process_name.assert_not_called()
    assert device.calls == []


# ------------------------------------------------- backend lookup

def test_frida_lookup_prefers_android_package_from_metadata():
    device = _FakeFridaDevice([_frida_process(
        2030, "Chrome", {"applications": ["com.android.chrome"]})])

    assert _frida_backend().process_name(device, 2030) == "com.android.chrome"
    assert device.calls == [{"pids": [2030], "scope": "metadata"}]


def test_frida_lookup_falls_back_to_process_name():
    device = _FakeFridaDevice([_frida_process(77, "curl", {"path": "/usr/bin/curl"})])

    assert _frida_backend().process_name(device, 77) == "curl"


def test_frida_lookup_remote_device_never_reads_local_proc(monkeypatch):
    opened = []
    monkeypatch.setattr("builtins.open", lambda *a, **k: opened.append(a) or 1 / 0)
    device = _FakeFridaDevice([], dtype="usb")

    assert _frida_backend().process_name(device, 77) is None
    assert opened == []


def test_frida_lookup_local_device_falls_back_to_proc_comm(tmp_path, monkeypatch):
    comm = tmp_path / "comm"
    comm.write_text("nginx\n")
    real_open = open
    monkeypatch.setattr(
        "builtins.open",
        lambda path, *a, **k: real_open(comm if path == "/proc/77/comm" else path, *a, **k))
    device = _FakeFridaDevice(dtype="local", error=RuntimeError("enumerate failed"))

    assert _frida_backend().process_name(device, 77) == "nginx"


def test_base_backend_default_is_unsupported():
    assert Backend.process_name(MagicMock(), object(), 1) is None


# ------------------------------------------------- collector fan-out

def _tap_handler_with_collector(target):
    handler = TapOutputHandler("x.tap", target=target)
    handler._collector = FlowCollector(retain_completed=False)
    handler._collector.set_capture_target(target)
    return handler


def test_tap_handler_retargets_its_collector():
    handler = _tap_handler_with_collector("4242")

    handler.set_process_name("com.android.chrome")

    assert handler._collector._process_name == "com.android.chrome"
    assert handler._collector._package_name == "com.android.chrome"
    assert handler._collector._capture_target == "4242"


def test_logger_applies_name_to_own_collector_and_output_handlers():
    own_collector = FlowCollector()
    own_collector.set_capture_target("4242")
    tap = _tap_handler_with_collector("4242")
    plain_handler = object()  # handlers without set_process_name are skipped
    logger = types.SimpleNamespace(
        _flow_collector=own_collector,
        _config=types.SimpleNamespace(target="4242"),
        _output_handlers=[plain_handler, tap],
        resolved_process_name=None,
    )

    SSL_Logger.apply_resolved_process_name(logger, "com.android.chrome")

    assert logger.resolved_process_name == "com.android.chrome"
    assert own_collector._process_name == "com.android.chrome"
    assert tap._collector._process_name == "com.android.chrome"


def test_logger_without_collector_only_records_name():
    logger = types.SimpleNamespace(
        _flow_collector=None, _config=types.SimpleNamespace(target="4242"),
        _output_handlers=[], resolved_process_name=None)

    SSL_Logger.apply_resolved_process_name(logger, "curl")

    assert logger.resolved_process_name == "curl"
