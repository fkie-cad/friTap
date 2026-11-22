"""Embedded (API) sessions never take over, or exit on, SIGINT/SIGTERM.

``FriTap.start()`` used to install the CLI's signal handler unconditionally:
Ctrl+C/SIGTERM in the embedding program then ran the CLI teardown and
``os._exit``-ed the whole host. Now the API installs nothing unless the caller
opts in (``FriTap.signal_handler()``), and an opted-in handler runs the
embedded stop (``stop_fritap_session``) instead of exiting. Installation only
ever happens on the main thread. CLI and TUI are unchanged.
"""

from __future__ import annotations

import json
import logging
import signal
import threading
import types
from unittest.mock import MagicMock

import pytest

import friTap.legacy.session_manager as session_manager_mod
import friTap.legacy.ssl_logger_core as core
from friTap.legacy.session_manager import SessionManager
from friTap.legacy.ssl_logger_core import SSL_Logger

REPORT = {"version": 1, "repeat": False, "total_ms": 3,
          "steps": [{"name": "detachAll", "ok": True, "ms": 1}],
          "logs": [], "dropped_logs": 0}


class _FakeSignalTable:
    """Stands in for signal.signal/getsignal so no real handler is touched."""

    def __init__(self, monkeypatch):
        self.handlers = {signal.SIGINT: "host-int", signal.SIGTERM: "host-term"}
        self.calls = []
        monkeypatch.setattr(session_manager_mod.signal, "signal", self._signal)
        monkeypatch.setattr(session_manager_mod.signal, "getsignal", self.handlers.get)

    def _signal(self, signum, handler):
        self.calls.append((signum, handler))
        previous = self.handlers.get(signum)
        self.handlers[signum] = handler
        return previous


@pytest.fixture
def signals(monkeypatch):
    return _FakeSignalTable(monkeypatch)


@pytest.fixture
def no_exit(monkeypatch):
    calls = []
    monkeypatch.setattr(core.os, "_exit", calls.append)
    monkeypatch.setattr(session_manager_mod.os, "_exit", calls.append)
    return calls


def _embedded_stub():
    logger = types.SimpleNamespace(_embedded=True, _tui_mode=False,
                                   stop_fritap_session=MagicMock(),
                                   cleanup=MagicMock())
    return SessionManager(logger), logger


# ----------------------------------------------------------------------
# API: no handler unless asked
# ----------------------------------------------------------------------

def _start_with_fake(monkeypatch, configure=lambda ft: ft):
    import friTap.api as api
    import friTap.ssl_logger as ssl_logger_mod
    from friTap.events import EventBus

    created = []

    class _Fake:
        def __init__(self, config=None):
            self._event_bus = EventBus()
            self._plugin_loader = None
            self.running = False
            self._embedded = False
            self.calls = []
            created.append(self)

        def install_signal_handler(self):
            self.calls.append(("install_signal_handler", self._embedded))
            return True

        def start_fritap_session(self):
            self.calls.append(("start", self._embedded))

    monkeypatch.setattr(ssl_logger_mod, "SSL_Logger", _Fake)
    configure(api.FriTap("com.example")).start()
    return created[0]


def test_api_start_installs_no_signal_handler_by_default(monkeypatch):
    fake = _start_with_fake(monkeypatch)
    assert fake.calls == [("start", True)]


def test_api_signal_handler_opt_in_installs_it_already_embedded(monkeypatch):
    fake = _start_with_fake(monkeypatch, lambda ft: ft.signal_handler())
    assert fake.calls == [("install_signal_handler", True), ("start", True)]


def test_api_signal_handler_opt_out_is_honoured(monkeypatch):
    fake = _start_with_fake(monkeypatch, lambda ft: ft.signal_handler().signal_handler(False))
    assert fake.calls == [("start", True)]


# ----------------------------------------------------------------------
# Installation: main thread only, prior handlers restorable
# ----------------------------------------------------------------------

def test_install_off_the_main_thread_installs_nothing(signals):
    manager, _ = _embedded_stub()
    result = []
    worker = threading.Thread(target=lambda: result.append(manager.install_signal_handler()))
    worker.start()
    worker.join(5)

    assert result == [False]
    assert signals.calls == []


def test_install_on_the_main_thread_covers_sigint_and_sigterm(signals):
    manager, _ = _embedded_stub()

    assert manager.install_signal_handler() is True
    assert signals.handlers[signal.SIGINT] == manager._on_termination_signal
    assert signals.handlers[signal.SIGTERM] == manager._on_termination_signal


def test_restore_gives_the_host_its_handlers_back(signals):
    manager, _ = _embedded_stub()
    manager.install_signal_handler()

    manager.restore_signal_handlers()

    assert signals.handlers == {signal.SIGINT: "host-int", signal.SIGTERM: "host-term"}


def test_restore_leaves_a_handler_the_host_reinstalled_alone(signals):
    manager, _ = _embedded_stub()
    manager.install_signal_handler()
    signals.handlers[signal.SIGINT] = "host-new"

    manager.restore_signal_handlers()

    assert signals.handlers[signal.SIGINT] == "host-new"
    assert signals.handlers[signal.SIGTERM] == "host-term"


def test_restore_without_install_is_a_noop(signals):
    manager, _ = _embedded_stub()
    manager.restore_signal_handlers()
    assert signals.calls == []


def test_restore_off_the_main_thread_is_a_noop(signals):
    manager, _ = _embedded_stub()
    manager.install_signal_handler()
    calls_before = list(signals.calls)
    worker = threading.Thread(target=manager.restore_signal_handlers)
    worker.start()
    worker.join(5)

    assert signals.calls == calls_before


# ----------------------------------------------------------------------
# The handler: embedded stop, never an exit
# ----------------------------------------------------------------------

@pytest.mark.parametrize("signum", [signal.SIGINT, signal.SIGTERM])
def test_embedded_signal_runs_the_embedded_stop_without_exiting(no_exit, signum):
    manager, logger = _embedded_stub()

    manager._on_termination_signal(signum, None)

    logger.stop_fritap_session.assert_called_once_with()
    logger.cleanup.assert_not_called()
    assert no_exit == []


def test_second_embedded_signal_neither_repeats_nor_exits(no_exit):
    manager, logger = _embedded_stub()

    manager._on_termination_signal(signal.SIGINT, None)
    manager._on_termination_signal(signal.SIGINT, None)

    logger.stop_fritap_session.assert_called_once_with()
    assert no_exit == []


def test_embedded_graceful_stop_request_does_not_exit(no_exit):
    manager, logger = _embedded_stub()

    manager.request_graceful_stop()

    logger.stop_fritap_session.assert_called_once_with()
    assert no_exit == []


def test_tui_keeps_its_previous_signal_path(no_exit):
    """TUI is embedded too, but its (never-installed) handler path is unchanged."""
    logger = MagicMock(_embedded=True, _tui_mode=True, install_lsass_hook=False,
                       _done_event=threading.Event())
    logger._done_event.set()
    manager = SessionManager(logger)
    manager.pcap_cleanup = MagicMock()

    manager._on_termination_signal(signal.SIGINT, None)

    logger.cleanup.assert_called_once()
    logger.stop_fritap_session.assert_not_called()


def test_mock_logger_without_a_real_flag_stays_on_the_cli_path(no_exit):
    logger = MagicMock(install_lsass_hook=False, _done_event=threading.Event())
    logger._done_event.set()
    manager = SessionManager(logger)
    manager.pcap_cleanup = MagicMock()

    manager._on_termination_signal(signal.SIGINT, None)

    logger.cleanup.assert_called_once()
    assert no_exit == [0]


# ----------------------------------------------------------------------
# End to end on a real SSL_Logger
# ----------------------------------------------------------------------

class _FakeScript:
    def __init__(self):
        self.is_destroyed = False
        self.exports_sync = types.SimpleNamespace(graceful_detach=lambda: REPORT)


def test_opted_in_ctrl_c_finalizes_outputs_keeps_running_and_restores(tmp_path, signals,
                                                                     no_exit):
    obj = SSL_Logger("test_app", json_output=str(tmp_path / "out.json"))
    obj.logger = logging.getLogger("test.embedded_signals")
    obj._backend = MagicMock()
    obj.script = _FakeScript()
    obj.process = None
    obj._start_consumer_thread()
    obj._embedded = True

    assert obj.install_signal_handler() is True
    handler = signals.handlers[signal.SIGINT]
    handler(signal.SIGINT, None)

    assert no_exit == []
    assert json.loads((tmp_path / "out.json").read_text())["detach_report"] == REPORT
    assert obj.running is False
    assert obj._done_event.is_set()
    assert signals.handlers == {signal.SIGINT: "host-int", signal.SIGTERM: "host-term"}
