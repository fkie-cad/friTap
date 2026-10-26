#!/usr/bin/env python3
"""A spawned target must never be left suspended by a failed instrumentation.

``session_manager.start_session()`` spawns the target suspended and resumes it
only *after* instrumentation succeeds. Anything raising in between — an agent
``script.load()`` timeout, a failed hook install, Ctrl+C during the pre-resume
wait — used to leave the process suspended forever. The platform then kills it
by watchdog and reports the *target's* crash (``0x8badf00d`` on iOS) rather than
friTap's failure to instrument it: exactly the misattribution that friTap
discussion #65 was filed as.

These tests pin the guard in ``SSL_Logger.start_fritap_session``. They follow
the construction idiom in ``test_crash_attribution.py`` (``SSL_Logger.__new__``
plus only the attributes the path touches — no device, no frida).
"""

from __future__ import annotations

import logging
import types
from unittest.mock import MagicMock

import pytest

from friTap.legacy.ssl_logger_core import SSL_Logger


def _make_logger(spawn=True, pid=4242, device="dev"):
    obj = SSL_Logger.__new__(SSL_Logger)
    obj.logger = logging.getLogger("test.spawn_resume")
    obj._backend = MagicMock()
    obj.device = device
    obj.pid = pid
    # start_fritap_session's preamble — stubbed so nothing real happens.
    obj.connect_live = lambda: None
    obj._setup_live_scan = lambda: None
    obj._start_consumer_thread = lambda: None
    obj._start_instrument_thread = lambda: None
    obj._session_manager = MagicMock()
    # Not a Wine target: keep the Frida path (on a Linux host these checks would
    # otherwise read device/backend config these tests don't stub).
    obj._should_use_wine_gdb = lambda: False
    obj._should_use_wine_frida_watch = lambda: False
    # spawn / the three gating flags are read-only properties over the config.
    obj._config = types.SimpleNamespace(
        device=types.SimpleNamespace(
            spawn=spawn,
            enable_child_gating=False,
            enable_spawn_gating=False,
            spawn_gating_all=False,
        ),
    )
    return obj


def test_failed_instrumentation_resumes_the_spawned_target():
    obj = _make_logger()
    obj._session_manager.start_session.side_effect = RuntimeError("agent load failed")

    with pytest.raises(RuntimeError):
        obj.start_fritap_session()

    # Resumed, so the OS watchdog never gets to blame the target for our failure.
    obj._backend.resume.assert_called_once_with("dev", 4242)


def test_the_original_error_still_propagates():
    """Resuming must not swallow the diagnosis — the CLI needs it to print hints."""
    obj = _make_logger()
    obj._session_manager.start_session.side_effect = RuntimeError("agent load failed")

    with pytest.raises(RuntimeError, match="agent load failed"):
        obj.start_fritap_session()


def test_keyboard_interrupt_also_resumes():
    """The pre-resume wait (-t/--timeout) is interruptible; Ctrl+C there must not
    strand the target either, hence a BaseException guard rather than Exception."""
    obj = _make_logger()
    obj._session_manager.start_session.side_effect = KeyboardInterrupt()

    with pytest.raises(KeyboardInterrupt):
        obj.start_fritap_session()

    obj._backend.resume.assert_called_once_with("dev", 4242)


def test_attach_mode_is_never_resumed():
    """In attach mode friTap did not suspend the process, so it must not touch it."""
    obj = _make_logger(spawn=False)
    obj._session_manager.start_session.side_effect = RuntimeError("boom")

    with pytest.raises(RuntimeError):
        obj.start_fritap_session()

    obj._backend.resume.assert_not_called()


def test_failure_before_the_spawn_is_not_resumed():
    """A failure while resolving the device happens before a pid exists."""
    obj = _make_logger(pid=None)
    obj._session_manager.start_session.side_effect = RuntimeError("no device")

    with pytest.raises(RuntimeError):
        obj.start_fritap_session()

    obj._backend.resume.assert_not_called()


def test_failure_without_a_device_is_not_resumed():
    obj = _make_logger(device=None)
    obj._session_manager.start_session.side_effect = RuntimeError("boom")

    with pytest.raises(RuntimeError):
        obj.start_fritap_session()

    obj._backend.resume.assert_not_called()


def test_successful_session_is_not_double_resumed():
    """start_session already resumes on the happy path."""
    obj = _make_logger()
    obj._session_manager.start_session.return_value = ("process", "script")

    assert obj.start_fritap_session() == ("process", "script")
    obj._backend.resume.assert_not_called()


def test_a_raising_resume_does_not_mask_the_original_error():
    """_resume_quietly swallows its own failure so the real diagnosis survives."""
    obj = _make_logger()
    obj._session_manager.start_session.side_effect = RuntimeError("agent load failed")
    obj._backend.resume.side_effect = OSError("process already gone")

    with pytest.raises(RuntimeError, match="agent load failed"):
        obj.start_fritap_session()
