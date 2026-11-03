"""Remote spawn+attach retry and the off-main-loop Frida detach handler.

Spawn regression (`fritap -m emulator-5556 -s com.android.chrome`): the spawn
returned pid 8904, Frida's attach then took >10 s on the loaded emulator, and
ActivityManager killed the still-suspended app ("8904 failed to attach" ->
"Killing 8904: start timeout"), so the attach raised ProcessNotFoundError. The
remote spawn now retries once when the spawned pid vanished before the attach.

Detach regression: on target death friTap hung forever because the frida
``detached`` handler ran its crash report on Frida's main-loop thread and made
a synchronous Frida call (``query_system_parameters``) there -- a self-deadlock.
"""

from __future__ import annotations

import inspect
import threading
import types
from unittest.mock import MagicMock

import pytest

from friTap.backends import BackendProcessNotFoundError, BackendTransportError
from friTap.legacy.session_manager import SessionManager
from tests.unit._log_helpers import attach_log_capture


def _logger_with_backend(attach_side_effect):
    logger = types.SimpleNamespace(
        device="dev", target_app="com.android.chrome", pid=None, process=None)
    logger._backend = MagicMock()
    logger._backend.spawn_raw.side_effect = [101, 202, 303]
    logger._backend.attach.side_effect = attach_side_effect
    return logger


@pytest.fixture
def session_log():
    logger, capture = attach_log_capture("friTap.session")
    yield capture
    logger.removeHandler(capture)


def test_vanished_spawn_is_spawned_again(session_log):
    logger = _logger_with_backend([BackendProcessNotFoundError("process not found"), "session"])

    pid = SessionManager(logger)._spawn_and_attach_remote(logger)

    assert pid == 202
    assert logger.pid == 202 and logger.process == "session"
    assert logger._backend.spawn_raw.call_count == 2
    logger._backend.attach.assert_called_with("dev", "202")
    assert "spawning it again" in session_log.text


def test_gives_up_after_the_retry_and_leaves_no_pid_to_resume(session_log):
    logger = _logger_with_backend(BackendProcessNotFoundError("process not found"))

    with pytest.raises(BackendProcessNotFoundError):
        SessionManager(logger)._spawn_and_attach_remote(logger)

    assert logger._backend.spawn_raw.call_count == SessionManager.SPAWN_ATTACH_ATTEMPTS
    # A dead pid must not trigger the "resuming spawned pid ... running WITHOUT
    # instrumentation" message of _resume_uninstrumented_spawn.
    assert logger.pid is None
    assert "start the app first and attach" in session_log.text


def test_successful_attach_spawns_once():
    logger = _logger_with_backend(["session"])

    assert SessionManager(logger)._spawn_and_attach_remote(logger) == 101
    logger._backend.spawn_raw.assert_called_once_with("dev", "com.android.chrome")


def test_other_attach_errors_are_not_retried():
    logger = _logger_with_backend(BackendTransportError("closed"))

    with pytest.raises(BackendTransportError):
        SessionManager(logger)._spawn_and_attach_remote(logger)

    logger._backend.spawn_raw.assert_called_once()
    assert logger.pid == 101, "still resumable by the caller's failure path"


# ------------------------------------------------ detach off the main loop

class _FakeFridaSession:
    def __init__(self):
        self.handlers = {}

    def on(self, signal_name, handler):
        self.handlers[signal_name] = handler


def test_detached_callback_runs_off_the_frida_main_loop():
    from friTap.backends.frida_backend import FridaBackend

    seen = {}
    done = threading.Event()

    def on_detach(reason, crash=None):
        seen["thread"] = threading.current_thread()
        seen["args"] = (reason, crash)
        done.set()

    session = _FakeFridaSession()
    FridaBackend.on_detached(MagicMock(), session, on_detach)
    session.handlers["detached"]("process-terminated", None)  # "frida main loop"

    assert done.wait(5)
    assert seen["thread"] is not threading.current_thread()
    assert seen["thread"].name == "fritap-detach"
    assert seen["args"] == ("process-terminated", None)


def test_detached_wrapper_keeps_the_callback_signature():
    """frida-python reads the handler's signature (handler.__signature__)."""
    from friTap.backends.frida_backend import FridaBackend

    def on_detach(reason, crash=None):
        pass

    session = _FakeFridaSession()
    FridaBackend.on_detached(MagicMock(), session, on_detach)

    assert inspect.signature(session.handlers["detached"]) == inspect.signature(on_detach)


def test_detach_handler_may_block_on_the_main_loop_without_deadlocking():
    """The handler can wait for work only the calling thread would complete."""
    from friTap.backends.frida_backend import FridaBackend

    main_loop_reply = threading.Event()
    handled = threading.Event()

    def on_detach(reason, crash=None):
        main_loop_reply.wait(5)  # e.g. a synchronous frida RPC
        handled.set()

    session = _FakeFridaSession()
    FridaBackend.on_detached(MagicMock(), session, on_detach)
    session.handlers["detached"]("process-terminated", None)
    main_loop_reply.set()  # only reachable because the handler returned at once

    assert handled.wait(5)
