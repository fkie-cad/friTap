#!/usr/bin/env python3

"""Unit tests for the unattended / automation CLI flags.

Covers ``--duration``, ``-q/--quiet``, ``--non-interactive`` and the live-capture
exit codes in ``friTap/exit_codes.py``. Frida is never touched: ``cli()`` runs
against a fake ``SSL_Logger`` and the teardown tests use a bare
``SSL_Logger.__new__`` instance like the other teardown suites.
"""

from __future__ import annotations

import io
import logging
import sys
import threading
import types

import pytest

import friTap.friTap as fritap_cli
from friTap import exit_codes
from friTap.exit_codes import (
    EXIT_OK,
    EXIT_RUNTIME_ERROR,
    EXIT_TARGET_DETACHED,
    EXIT_USAGE_ERROR,
)
from friTap.fritap_utility import Failure
from friTap.legacy.session_manager import SessionManager
from friTap.legacy.ssl_logger_core import SSL_Logger
from tests.unit.test_memory_scan_teardown import _FakePcap, _make_logger
from tests.unit import test_memory_scan_teardown as _teardown

exits = _teardown.exits


# --------------------------------------------------------------------------
# exit code constants
# --------------------------------------------------------------------------

def test_exit_code_values_are_the_documented_ones():
    assert (EXIT_OK, EXIT_RUNTIME_ERROR, EXIT_USAGE_ERROR, EXIT_TARGET_DETACHED) == (0, 1, 2, 3)


def test_exit_codes_are_distinct_and_exported():
    values = [getattr(exit_codes, name) for name in exit_codes.__all__]
    assert len(set(values)) == len(values) == 4


def test_argparse_usage_error_exits_with_usage_code(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["fritap", "--no-such-flag", "target"])
    with pytest.raises(SystemExit) as exc:
        fritap_cli.cli()
    assert exc.value.code == EXIT_USAGE_ERROR


# --------------------------------------------------------------------------
# cli() against a fake SSL_Logger
# --------------------------------------------------------------------------

class _FakeSSLLogger:
    instances: list = []
    # The real exit-status rule (first non-zero wins), not a re-implementation.
    _EXIT_STATUS_LOCK = SSL_Logger._EXIT_STATUS_LOCK
    set_exit_status = SSL_Logger.set_exit_status

    def __init__(self, config=None):
        self.config = config
        self._exit_status = EXIT_OK
        self.calls = []
        _FakeSSLLogger.instances.append(self)

    def install_signal_handler(self):
        self.calls.append("install_signal_handler")

    def start_fritap_session(self):
        self.calls.append("start")
        if getattr(self, "fail_with", None) is not None:
            raise self.fail_with

    def wait_for_completion(self):
        self.calls.append("wait")

    def pcap_cleanup(self, *a, **k):
        self.calls.append("pcap_cleanup")

    def cleanup(self, *a, **k):
        self.calls.append("cleanup")


@pytest.fixture
def fake_cli(monkeypatch):
    """Run cli() with the given argv against _FakeSSLLogger; returns
    (logger_instance, recorded duration timers)."""
    _FakeSSLLogger.instances = []
    timers = []
    monkeypatch.setattr(fritap_cli, "SSL_Logger", _FakeSSLLogger)
    monkeypatch.setattr(fritap_cli, "are_we_running_on_windows", lambda: False)
    monkeypatch.setattr(fritap_cli, "_start_duration_timer",
                        lambda ssl_log, seconds, logger: timers.append(seconds))
    monkeypatch.setattr("builtins.input", _input_must_not_be_called)
    saved_levels = _console_handler_levels()

    def run(*argv, fail_with=None):
        monkeypatch.setattr(sys, "argv", ["fritap", *argv])
        if fail_with is not None:
            monkeypatch.setattr(_FakeSSLLogger, "fail_with", fail_with, raising=False)
        fritap_cli.cli()
        return _FakeSSLLogger.instances[-1], timers

    yield run
    for handler, level in saved_levels:
        handler.setLevel(level)


def _input_must_not_be_called(*_a, **_k):
    raise AssertionError("input() must not be called in non-interactive mode")


def _console_handler_levels():
    return [(h, h.level) for name in fritap_cli._CONSOLE_LOGGER_NAMES
            for h in logging.getLogger(name).handlers]


def test_duration_is_parsed_and_arms_the_timer(fake_cli, tmp_path):
    ssl_log, timers = fake_cli("--duration", "2.5", "-k", str(tmp_path / "k.log"), "target")
    assert timers == [2.5]
    assert ssl_log.calls[:3] == ["install_signal_handler", "start", "wait"]


def test_no_duration_means_timer_not_armed_with_a_value(fake_cli, tmp_path):
    _, timers = fake_cli("-k", str(tmp_path / "k.log"), "target")
    assert timers == [None]


def test_duration_does_not_change_timeout(fake_cli, tmp_path):
    ssl_log, _ = fake_cli("--duration", "5", "-t", "3", "-k", str(tmp_path / "k.log"), "target")
    assert ssl_log.config.device.timeout == 3


@pytest.mark.parametrize("value", ["0", "-1", "abc"])
def test_invalid_duration_is_a_usage_error(monkeypatch, capsys, value):
    monkeypatch.setattr(sys, "argv", ["fritap", "--duration", value, "target"])
    with pytest.raises(SystemExit) as exc:
        fritap_cli.cli()
    assert exc.value.code == EXIT_USAGE_ERROR


def test_non_interactive_full_capture_without_keylog_never_prompts(fake_cli, tmp_path):
    ssl_log, _ = fake_cli("--non-interactive", "-f", "-p", str(tmp_path / "c.pcap"), "target")
    assert "start" in ssl_log.calls


def test_quiet_raises_console_handlers_to_warning(fake_cli, tmp_path):
    fake_cli("-q", "-k", str(tmp_path / "k.log"), "target")
    console = [h for name in fritap_cli._CONSOLE_LOGGER_NAMES
               for h in logging.getLogger(name).handlers
               if fritap_cli._is_console_handler(h)]
    assert console, "setup_fritap_logging installs console handlers"
    assert all(h.level == logging.WARNING for h in console)


def test_runtime_error_sets_runtime_exit_status(fake_cli, tmp_path):
    from friTap.backends import BackendProcessNotFoundError
    with pytest.raises(Failure) as exc:
        fake_cli("-k", str(tmp_path / "k.log"), "target",
                 fail_with=BackendProcessNotFoundError("no such process"))
    assert exc.value.code == EXIT_RUNTIME_ERROR
    assert _FakeSSLLogger.instances[-1]._exit_status == EXIT_RUNTIME_ERROR


def test_transport_error_sets_target_detached_status(fake_cli, tmp_path):
    from friTap.backends import BackendTransportError
    with pytest.raises(Failure) as exc:
        fake_cli("-k", str(tmp_path / "k.log"), "target",
                 fail_with=BackendTransportError("connection closed"))
    assert exc.value.code == EXIT_TARGET_DETACHED
    assert _FakeSSLLogger.instances[-1]._exit_status == EXIT_TARGET_DETACHED


def test_unknown_error_exits_with_runtime_code(fake_cli, tmp_path):
    with pytest.raises(Failure) as exc:
        fake_cli("-k", str(tmp_path / "k.log"), "target", fail_with=RuntimeError("boom"))
    assert exc.value.code == EXIT_RUNTIME_ERROR


def test_normal_return_keeps_exit_ok(fake_cli, tmp_path):
    ssl_log, _ = fake_cli("-k", str(tmp_path / "k.log"), "target")
    assert ssl_log._exit_status == EXIT_OK


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

class _RecordingLogger:
    def __init__(self):
        self.records = []

    def info(self, msg, *a):
        self.records.append(("info", msg))

    def warning(self, msg, *a):
        self.records.append(("warning", msg))


def _parsed(**kw):
    defaults = dict(memory_scan=False, non_interactive=False, yes=False)
    defaults.update(kw)
    return types.SimpleNamespace(**defaults)


class _Stdin(io.StringIO):
    def __init__(self, tty):
        super().__init__("")
        self._tty = tty

    def isatty(self):
        return self._tty


def test_confirm_helper_non_interactive_warns_and_continues(monkeypatch):
    monkeypatch.setattr(sys, "stdin", _Stdin(tty=True))
    monkeypatch.setattr("builtins.input", _input_must_not_be_called)
    log = _RecordingLogger()
    fritap_cli._confirm_full_capture_without_keylog(_parsed(non_interactive=True), log)
    assert [lvl for lvl, _ in log.records] == ["warning"]


def test_confirm_helper_auto_non_interactive_without_tty(monkeypatch):
    monkeypatch.setattr(sys, "stdin", _Stdin(tty=False))
    monkeypatch.setattr("builtins.input", _input_must_not_be_called)
    log = _RecordingLogger()
    fritap_cli._confirm_full_capture_without_keylog(_parsed(), log)
    assert log.records and log.records[0][0] == "warning"


def test_confirm_helper_still_prompts_on_a_tty(monkeypatch):
    monkeypatch.setattr(sys, "stdin", _Stdin(tty=True))
    prompted = []
    monkeypatch.setattr("builtins.input", lambda *a: prompted.append(True) or "")
    fritap_cli._confirm_full_capture_without_keylog(_parsed(), _RecordingLogger())
    assert prompted == [True]


def test_confirm_helper_memory_scan_skips_prompt(monkeypatch):
    monkeypatch.setattr("builtins.input", _input_must_not_be_called)
    log = _RecordingLogger()
    fritap_cli._confirm_full_capture_without_keylog(_parsed(memory_scan=True), log)
    assert log.records[0][0] == "info"


def test_non_interactive_implies_yes():
    parsed = _parsed(non_interactive=True)
    fritap_cli._apply_non_interactive_flag(parsed)
    assert parsed.yes is True


def test_without_non_interactive_yes_is_untouched():
    parsed = _parsed()
    fritap_cli._apply_non_interactive_flag(parsed)
    assert parsed.yes is False


def test_quiet_leaves_non_console_handlers_alone():
    logger = logging.getLogger("friTap")
    file_like = logging.StreamHandler(io.StringIO())
    file_like.setLevel(logging.DEBUG)
    logger.addHandler(file_like)
    try:
        fritap_cli._apply_quiet_console(True)
        assert file_like.level == logging.DEBUG
    finally:
        logger.removeHandler(file_like)


def test_quiet_false_is_a_no_op():
    console = logging.StreamHandler(sys.stderr)
    console.setLevel(logging.INFO)
    logger = logging.getLogger("friTap")
    logger.addHandler(console)
    try:
        fritap_cli._apply_quiet_console(False)
        assert console.level == logging.INFO
    finally:
        logger.removeHandler(console)


# --------------------------------------------------------------------------
# duration timer -> graceful stop
# --------------------------------------------------------------------------

class _StoppableLogger:
    def __init__(self):
        self.stopped = threading.Event()

    def stop_capture_gracefully(self):
        self.stopped.set()
        return True


def test_duration_timer_triggers_graceful_stop():
    ssl_log = _StoppableLogger()
    timer = fritap_cli._start_duration_timer(ssl_log, 0.05, logging.getLogger("test.duration"))
    assert timer is not None and timer.daemon
    assert ssl_log.stopped.wait(2.0)


def test_duration_timer_not_started_without_duration():
    assert fritap_cli._start_duration_timer(_StoppableLogger(), None, logging.getLogger("t")) is None


def test_stop_capture_gracefully_uses_the_ctrl_c_path(monkeypatch):
    obj = _make_logger(_FakePcap())
    obj._session_manager = types.SimpleNamespace(
        request_graceful_stop=lambda: calls.append("stop"))
    calls = []
    assert obj.stop_capture_gracefully() is True
    assert calls == ["stop"]


def test_stop_capture_gracefully_is_noop_once_teardown_started():
    obj = _make_logger(_FakePcap())
    obj._cleanup_done = True
    obj._session_manager = types.SimpleNamespace(
        request_graceful_stop=lambda: pytest.fail("must not stop twice"))
    assert obj.stop_capture_gracefully() is False


def test_request_graceful_stop_runs_sigint_teardown(exits, monkeypatch):
    import signal
    from friTap.legacy import session_manager as sm_mod
    monkeypatch.setattr(sm_mod.os, "_exit", lambda code: exits.append(code))
    seen = []
    manager = SessionManager.__new__(SessionManager)
    monkeypatch.setattr(manager, "_on_termination_signal",
                        lambda signum, frame: seen.append(signum), raising=False)
    manager.request_graceful_stop()
    assert seen == [signal.SIGINT]


# --------------------------------------------------------------------------
# exit code 3 on unexpected detach
# --------------------------------------------------------------------------

def test_unexpected_detach_exits_with_target_detached(exits):
    obj = _make_logger(_FakePcap())
    obj._is_memory_scan_only = lambda: False
    obj.on_detach("process-terminated")
    assert exits == [EXIT_TARGET_DETACHED]


def test_detach_after_user_stop_keeps_exit_ok(exits):
    obj = _make_logger(_FakePcap())
    obj._is_memory_scan_only = lambda: False
    obj._session_manager = types.SimpleNamespace(_exit_signal_received=True)
    obj.on_detach("process-terminated")
    assert exits == [EXIT_OK]


def test_detach_does_not_override_a_signal_status(exits):
    obj = _make_logger(_FakePcap())
    obj._is_memory_scan_only = lambda: False
    obj._exit_status = 143
    obj.on_detach("process-terminated")
    assert exits == [143]
