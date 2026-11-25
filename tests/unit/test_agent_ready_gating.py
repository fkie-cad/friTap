#!/usr/bin/env python3
"""A spawn-gated process is resumed only once its agent reports hooks-installed.

``instrument()`` returns when ``script.load()`` does, but the agent installs part
of its hooks in setTimeout-phased steps afterwards (agent/platforms/android.ts).
Resuming right after load let a delegate's startup handshakes run before the
keylog hooks existed (Pixel 5, Gemini -> GSA ``:search``: 0 keys for them). The
agent now sends ``{"contentType": "agent_ready"}``; the worker waits for it,
bounded by ``AGENT_READY_RESUME_TIMEOUT_S``.
"""

import logging
import threading
import time

import pytest

from friTap.constants import ContentType
from friTap.legacy.ssl_logger_core import _InstrumentRequest
from friTap.legacy.ssl_logger_messages import AGENT_READY_RESUME_TIMEOUT_S
from tests.unit.test_gated_instrumentation import FAKE_DEVICE, _make_logger


def _ready_message():
    return {"type": "send", "payload": {"contentType": ContentType.AGENT_READY}}


class _LoadingInstrument:
    """``instrument`` stub that registers its script like the real one, then returns it."""

    def __init__(self, obj, on_loaded=None):
        self._obj = obj
        self._on_loaded = on_loaded
        self.script = object()

    def __call__(self, _session, _handler, is_main=None):
        self._obj._expect_agent_ready(self.script)
        if self._on_loaded is not None:
            self._on_loaded(self.script)
        return self.script


def test_timeout_is_a_named_bound_under_the_android_start_timeout():
    assert 0 < AGENT_READY_RESUME_TIMEOUT_S < 10


def test_message_wrapper_sets_the_scripts_ready_event_and_does_not_queue_it():
    obj = _make_logger()
    obj._message_queue = None  # put_nowait on it would raise: the message must not be queued
    script = object()
    obj._expect_agent_ready(script)

    obj._internal_callback_wrapper(script)(_ready_message(), None)

    assert obj._agent_ready_event(script).is_set()


def test_ready_report_for_an_unawaited_script_is_ignored():
    obj = _make_logger()
    obj._message_queue = None
    obj._internal_callback_wrapper(object())(_ready_message(), None)  # must not raise


def test_resume_waits_for_the_ready_event():
    obj = _make_logger()
    order = []
    obj._backend.resume.side_effect = lambda *_a: order.append("resume")

    def report_ready_later(script):
        def send_ready():
            order.append("ready")
            obj._internal_callback_wrapper(script)(_ready_message(), None)
        threading.Timer(0.2, send_ready).start()

    obj.instrument = _LoadingInstrument(obj, on_loaded=report_ready_later)
    started = time.monotonic()
    obj._instrument_gated_process(_InstrumentRequest(pid=31, label="spawned process"))

    assert order == ["ready", "resume"]
    assert time.monotonic() - started < AGENT_READY_RESUME_TIMEOUT_S / 2  # released by the report
    obj._backend.resume.assert_called_once_with(FAKE_DEVICE, 31)


def test_ready_before_the_wait_resumes_immediately():
    obj = _make_logger()
    obj.instrument = _LoadingInstrument(obj, on_loaded=obj._note_agent_ready)

    obj._instrument_gated_process(_InstrumentRequest(pid=32, label="spawned process"))

    obj._backend.resume.assert_called_once_with(FAKE_DEVICE, 32)


def test_resume_after_timeout_with_a_warning(caplog, monkeypatch):
    obj = _make_logger()
    obj.instrument = _LoadingInstrument(obj)
    original = obj.wait_for_agent_ready
    monkeypatch.setattr(obj, "wait_for_agent_ready",
                        lambda script, desc: original(script, desc, timeout=0.05))

    with caplog.at_level(logging.WARNING, logger=obj.logger.name):
        obj._instrument_gated_process(_InstrumentRequest(pid=33, label="spawned process"))

    obj._backend.resume.assert_called_once_with(FAKE_DEVICE, 33)
    assert any("did not report its hooks installed" in r.getMessage()
               and "pid 33" in r.getMessage() for r in caplog.records)


def test_default_wait_uses_the_named_timeout(monkeypatch):
    obj = _make_logger()
    script = object()
    obj._expect_agent_ready(script)
    seen = []
    event = obj._agent_ready_events[script]
    monkeypatch.setattr(event, "wait", lambda timeout: seen.append(timeout) or True)

    assert obj.wait_for_agent_ready(script, "x") is True
    assert seen == [AGENT_READY_RESUME_TIMEOUT_S]
    assert obj._agent_ready_event(script) is None  # forgotten after its wait


def test_no_wait_without_an_awaited_agent():
    """A custom message handler / memory-scan-only run loads no awaited agent: resume at once."""
    obj = _make_logger()
    assert obj.wait_for_agent_ready(None, "x") is True
    assert obj.wait_for_agent_ready(object(), "x") is True


def test_running_process_is_not_held_for_readiness():
    obj = _make_logger()
    obj.instrument = _LoadingInstrument(obj)
    obj.wait_for_agent_ready = pytest.fail  # resume=False: nothing is suspended

    obj._instrument_gated_process(
        _InstrumentRequest(pid=34, label="running process", resume=False))

    obj._backend.resume.assert_not_called()


def test_resume_still_happens_when_the_wait_raises():
    obj = _make_logger()
    obj.instrument = _LoadingInstrument(obj)

    def boom(*_a, **_k):
        raise RuntimeError("wait failed")

    obj.wait_for_agent_ready = boom
    with pytest.raises(RuntimeError):
        obj._instrument_gated_process(_InstrumentRequest(pid=35, label="spawned process"))
    obj._backend.resume.assert_called_once_with(FAKE_DEVICE, 35)


# ----------------------------------------------------------------------
# exit log for tracked children / delegates
# ----------------------------------------------------------------------

def test_terminated_delegate_logs_one_info_line(caplog):
    obj = _make_logger()
    obj.set_process_origin(22725, "com.google.android.googlequicksearchbox:search", "delegate")
    obj._forget_process = lambda pid, session=None: True
    obj._end_if_last_child_gone = lambda: None

    with caplog.at_level(logging.INFO, logger=obj.logger.name):
        obj._on_child_detached(22725, object(), "process-terminated")

    infos = [r.getMessage() for r in caplog.records if r.levelno == logging.INFO]
    assert infos == ["delegate pid 22725 (com.google.android.googlequicksearchbox:search) exited"]


def test_own_detach_is_not_reported_as_an_exit(caplog):
    obj = _make_logger()
    obj._forget_process = lambda pid, session=None: True
    obj._end_if_last_child_gone = lambda: None

    with caplog.at_level(logging.INFO, logger=obj.logger.name):
        obj._on_child_detached(40, object(), "application-requested")

    assert not [r for r in caplog.records if r.levelno == logging.INFO]


def test_unknown_child_exit_uses_the_default_role(caplog):
    obj = _make_logger()
    obj._forget_process = lambda pid, session=None: True
    obj._end_if_last_child_gone = lambda: None

    with caplog.at_level(logging.INFO, logger=obj.logger.name):
        obj._on_child_detached(41, object(), "process-terminated")

    assert "child pid 41 (unknown) exited" in [r.getMessage() for r in caplog.records]


# ----------------------------------------------------------------------
# a process that dies during the wait releases it early, without the warning
# ----------------------------------------------------------------------

def _wait_released_by(obj, release, timeout=AGENT_READY_RESUME_TIMEOUT_S):
    """Run ``wait_for_agent_ready`` while *release* fires on another thread; return (result, seconds)."""
    threading.Timer(0.05, release).start()
    started = time.monotonic()
    result = obj.wait_for_agent_ready(obj._awaited_script, "spawned target pid 50", timeout=timeout)
    return result, time.monotonic() - started


def _expect_script_in_session(obj, session):
    obj._awaited_script = object()
    obj._expect_agent_ready(obj._awaited_script, session=session)
    return obj._awaited_script


def test_release_marks_gone_and_wait_returns_early_without_warning(caplog):
    obj = _make_logger()
    script = _expect_script_in_session(obj, object())

    with caplog.at_level(logging.DEBUG, logger=obj.logger.name):
        result, elapsed = _wait_released_by(obj, lambda: obj._release_agent_ready(script))

    assert result is False
    assert elapsed < AGENT_READY_RESUME_TIMEOUT_S / 2
    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]
    assert any("process ended" in r.getMessage() for r in caplog.records)
    assert obj._agent_ready_event(script) is None
    assert not obj._agent_process_gone(script)  # bookkeeping forgotten after the wait


def test_release_without_gone_counts_as_ready():
    obj = _make_logger()
    script = _expect_script_in_session(obj, object())
    obj._release_agent_ready(script, gone=False)
    assert obj.wait_for_agent_ready(script, "x", timeout=0.01) is True


def test_release_of_an_unawaited_script_is_ignored():
    obj = _make_logger()
    obj._release_agent_ready(object())  # must not raise
    obj._release_agent_ready_for_session(None)


def test_session_release_only_touches_that_sessions_scripts():
    obj = _make_logger()
    dead, alive = object(), object()
    dead_script = _expect_script_in_session(obj, dead)
    alive_script = object()
    obj._expect_agent_ready(alive_script, session=alive)

    obj._release_agent_ready_for_session(dead)

    assert obj._agent_ready_event(dead_script).is_set()
    assert obj._agent_process_gone(dead_script)
    assert not obj._agent_ready_event(alive_script).is_set()


def test_main_detach_releases_the_spawn_wait(caplog):
    obj = _make_logger()
    obj.running = False  # keep on_detach to the release; teardown is not under test
    session = object()
    obj.process = session
    _expect_script_in_session(obj, session)

    with caplog.at_level(logging.WARNING, logger=obj.logger.name):
        result, elapsed = _wait_released_by(
            obj, lambda: obj.on_detach("process-terminated"))

    assert result is False
    assert elapsed < AGENT_READY_RESUME_TIMEOUT_S / 2
    assert not caplog.records


def test_child_detach_releases_the_gated_wait(caplog):
    obj = _make_logger()
    obj._forget_process = lambda pid, session=None: False
    session = object()
    _expect_script_in_session(obj, session)

    with caplog.at_level(logging.WARNING, logger=obj.logger.name):
        result, elapsed = _wait_released_by(
            obj, lambda: obj._on_child_detached(51, session, "process-terminated"))

    assert result is False
    assert elapsed < AGENT_READY_RESUME_TIMEOUT_S / 2
    assert not caplog.records


def test_gated_child_dying_during_wait_resumes_early_without_warning(caplog):
    obj = _make_logger()
    obj._forget_process = lambda pid, session=None: False

    class _DyingInstrument(_LoadingInstrument):
        def __call__(self, sess, _handler, is_main=None):
            self._obj._expect_agent_ready(self.script, session=sess)
            threading.Timer(0.05, self._obj._on_child_detached,
                            (52, sess, "process-terminated")).start()
            return self.script

    obj.instrument = _DyingInstrument(obj)
    started = time.monotonic()
    with caplog.at_level(logging.WARNING, logger=obj.logger.name):
        obj._instrument_gated_process(_InstrumentRequest(pid=52, label="spawned process"))

    assert time.monotonic() - started < AGENT_READY_RESUME_TIMEOUT_S / 2
    assert not [r for r in caplog.records if "did not report" in r.getMessage()]
    obj._backend.resume.assert_called_once_with(FAKE_DEVICE, 52)


# ----------------------------------------------------------------------
# "Attached to" is logged only after the attach succeeded
# ----------------------------------------------------------------------

def test_attached_info_is_logged_after_attach(caplog):
    obj = _make_logger()
    attached_before_attach = []

    def attach(*_a):
        attached_before_attach.extend(
            r for r in caplog.records if r.getMessage().startswith("Attached to"))
        return object()

    obj._backend.attach.side_effect = attach
    obj.instrument = _LoadingInstrument(obj, on_loaded=obj._note_agent_ready)
    with caplog.at_level(logging.DEBUG, logger=obj.logger.name):
        obj._instrument_gated_process(_InstrumentRequest(pid=53, label="spawned process"))

    messages = [r.getMessage() for r in caplog.records]
    assert not attached_before_attach
    assert "Attaching to spawned process with pid 53" in messages
    assert "Attached to spawned process with pid 53" in messages


def test_failed_attach_logs_no_attached_info(caplog):
    obj = _make_logger()
    obj._backend.attach.side_effect = RuntimeError("process not found")

    with caplog.at_level(logging.INFO, logger=obj.logger.name):
        with pytest.raises(RuntimeError):
            obj._instrument_gated_process(_InstrumentRequest(pid=54, label="spawned process"))

    assert not [r for r in caplog.records if r.getMessage().startswith("Attached to")]
