#!/usr/bin/env python3
"""Spawn mode follows the target across exec(), and startup deaths exit 1.

**Exec following.** A launcher such as Homebrew's ``python3`` exec()s the real
binary. Frida ends the old session with ``process-replaced`` and, with child
gating on, reports the new image as a child of origin ``"exec"`` with the same
pid, held suspended. friTap must instrument that image through the gated-child
worker, make it the main session, resume it, and NOT tear the capture down. Fork
and spawn children it was not asked to gate must be resumed untouched.

**Exit-code classification.** A target lost before the capture start point (the
spawned target's resume) is a startup failure, exit 1; afterwards it is a
detach, exit 3.

Like ``test_gated_instrumentation.py`` the logger is built with
``SSL_Logger.__new__`` and only the attributes these paths touch.
"""

import logging
import queue
import threading
import types
from unittest.mock import MagicMock

import pytest

from friTap.backends.base import BackendTransportError
from friTap.exit_codes import EXIT_RUNTIME_ERROR, EXIT_TARGET_DETACHED
from friTap.legacy.ssl_logger_core import SSL_Logger

FAKE_DEVICE = "FAKE-DEVICE"
TARGET_PID = 4242
WAIT = 2.0


class FakeChild:
    """Mimics frida's ``_frida.Child`` (only the fields friTap reads)."""

    def __init__(self, pid, origin, path=None):
        self.pid = pid
        self.origin = origin
        self.path = path
        self.identifier = None


class RecordingInstrument:
    """``instrument`` stub: records the sessions, optionally blocks or raises."""

    def __init__(self, block=None, error=None):
        self.sessions = []
        self.called = threading.Event()
        self._block = block
        self._error = error

    def __call__(self, session, handler):
        self.sessions.append(session)
        self.called.set()
        if self._block is not None:
            self._block.wait(WAIT)
        if self._error is not None:
            raise self._error


def _make_logger(instrument=None, enable_child_gating=False, spawn=True):
    obj = SSL_Logger.__new__(SSL_Logger)
    obj.logger = logging.getLogger("test.exec_following")
    obj.logger.setLevel(logging.DEBUG)
    obj._backend = MagicMock()
    obj._backend.attach.side_effect = lambda device, pid: MagicMock(name=f"session-{pid}")
    obj.device = FAKE_DEVICE
    obj.own_message_handler = None
    obj.running = True
    obj.process = MagicMock(name="original-session")
    obj.pid = TARGET_PID
    obj._instrument_queue = queue.Queue(maxsize=16)
    obj._instrument_stop = threading.Event()
    obj._instrument_thread = None
    obj._instrument_thread_lock = threading.Lock()
    obj._suspended_pids = set()
    obj._suspended_pids_lock = threading.Lock()
    obj._exec_lock = threading.Lock()
    obj._exec_replaced_count = 0
    obj._exec_image_count = 0
    obj._event_bus = MagicMock()
    obj._end_session = MagicMock(return_value=True)
    obj._report_target_crash = MagicMock()
    obj._pending_crash = None
    obj.instrument = RecordingInstrument() if instrument is None else instrument
    obj._config = types.SimpleNamespace(
        target="/opt/homebrew/bin/python3",
        device=types.SimpleNamespace(
            spawn=spawn, mobile=False, enable_child_gating=enable_child_gating,
            enable_spawn_gating=False, spawn_gating_all=False,
        ),
    )
    obj.follow_exec_of(obj.process)
    return obj


def _resumed(obj):
    return [c.args for c in obj._backend.resume.call_args_list]


def _wait_resumed(obj, pid, times=1):
    for _ in range(int(WAIT / 0.01)):
        if _resumed(obj).count((FAKE_DEVICE, pid)) >= times:
            return True
        threading.Event().wait(0.01)
    return False


@pytest.fixture
def stop_worker():
    loggers = []
    yield loggers.append
    for obj in loggers:
        obj._stop_instrument_thread()


# ----------------------------------------------------------------------
# exec hand-over
# ----------------------------------------------------------------------

@pytest.mark.parametrize("detach_first", [True, False])
def test_exec_hands_over_to_the_new_image(stop_worker, detach_first):
    obj = _make_logger()
    stop_worker(obj)
    original = obj.process
    exec_child = FakeChild(TARGET_PID, "exec", "/usr/lib/Python.app/Python")

    if detach_first:
        obj.on_detach("process-replaced")
        obj.on_child_added(exec_child)
    else:
        obj.on_child_added(exec_child)
        obj.on_detach("process-replaced")

    assert _wait_resumed(obj, TARGET_PID), "the exec'd image was never resumed"
    new_session = obj.instrument.sessions[0]
    assert obj.process is new_session and new_session is not original
    obj._backend.enable_child_gating.assert_any_call(new_session)
    obj._backend.on_detached.assert_called_once_with(new_session, obj.on_detach)
    # A hand-over, not a termination: no teardown, no exit status.
    obj._end_session.assert_not_called()
    assert obj._exit_status == 0
    assert obj._suspended_pids == set()


def test_chained_exec_is_followed_twice(stop_worker):
    obj = _make_logger()
    stop_worker(obj)

    for hop in (1, 2):
        obj.on_detach("process-replaced")
        obj.on_child_added(FakeChild(TARGET_PID, "exec", f"/wrapper{hop}"))
        assert _wait_resumed(obj, TARGET_PID, times=hop), f"hop {hop} not resumed"

    assert len(obj.instrument.sessions) == 2
    assert obj.process is obj.instrument.sessions[1]
    # Each image gates its children, so the next exec is caught as well.
    for session in obj.instrument.sessions:
        obj._backend.enable_child_gating.assert_any_call(session)
    obj._end_session.assert_not_called()
    assert obj._exit_status == 0


def test_exec_without_an_image_ends_the_capture_as_detached(monkeypatch):
    obj = _make_logger()
    monkeypatch.setattr(obj, "EXEC_HANDOVER_TIMEOUT", 0.05)
    ended = threading.Event()
    obj._end_session.side_effect = lambda reason: ended.set()

    obj.on_detach("process-replaced")

    assert ended.wait(WAIT), "a lost hand-over must end the capture"
    assert obj._exit_status == EXIT_TARGET_DETACHED


def test_failed_handover_ends_the_capture_and_resumes(stop_worker):
    obj = _make_logger(instrument=RecordingInstrument(error=RuntimeError("load failed")))
    stop_worker(obj)
    ended = threading.Event()
    obj._end_session.side_effect = lambda reason: ended.set()

    obj.on_detach("process-replaced")
    obj.on_child_added(FakeChild(TARGET_PID, "exec"))

    assert ended.wait(WAIT)
    assert _wait_resumed(obj, TARGET_PID)
    assert obj._exit_status == EXIT_RUNTIME_ERROR


def test_teardown_during_handover_still_resumes_the_pid():
    release = threading.Event()
    obj = _make_logger(instrument=RecordingInstrument(block=release))

    obj.on_detach("process-replaced")
    obj.on_child_added(FakeChild(TARGET_PID, "exec"))
    assert obj.instrument.called.wait(WAIT)

    # The worker is stuck in the exec'd image's agent load; teardown runs.
    obj._resume_suspended_pids()
    assert (FAKE_DEVICE, TARGET_PID) in _resumed(obj)
    release.set()
    obj._stop_instrument_thread()


def test_exec_image_arriving_during_teardown_is_resumed_not_instrumented():
    obj = _make_logger()
    obj.on_detach("process-replaced")
    obj._stop_instrument_thread()  # teardown started meanwhile

    obj.on_child_added(FakeChild(TARGET_PID, "exec"))

    assert _wait_resumed(obj, TARGET_PID)
    assert obj.instrument.sessions == []


def test_process_replaced_without_exec_following_is_a_detach():
    obj = _make_logger(spawn=False)
    obj._follow_exec = False

    obj.on_detach("process-replaced")

    obj._end_session.assert_called_once_with("process-replaced")
    assert obj._exit_status == EXIT_TARGET_DETACHED


# ----------------------------------------------------------------------
# non-exec children
# ----------------------------------------------------------------------

@pytest.mark.parametrize("origin", ["fork", "spawn"])
def test_ungated_child_is_resumed_untouched(origin):
    obj = _make_logger(enable_child_gating=False)

    obj.on_child_added(FakeChild(5150, origin))

    assert _wait_resumed(obj, 5150)
    assert obj._instrument_thread is None and obj._instrument_queue.empty()
    assert obj.instrument.sessions == []
    assert obj._suspended_pids == set()


def test_ungated_child_is_not_resumed_on_the_event_thread():
    """A synchronous resume on Frida's event loop deadlocks it."""
    obj = _make_logger(enable_child_gating=False)
    caller = threading.current_thread()
    threads = []
    obj._backend.resume.side_effect = lambda *a: threads.append(threading.current_thread())

    obj.on_child_added(FakeChild(5151, "fork"))

    assert _wait_resumed(obj, 5151)
    assert threads and caller not in threads


def test_child_with_enable_child_gating_is_instrumented(stop_worker):
    obj = _make_logger(enable_child_gating=True)
    stop_worker(obj)

    obj.on_child_added(FakeChild(5152, "fork"))

    assert obj.instrument.called.wait(WAIT)
    assert _wait_resumed(obj, 5152)
    obj._backend.on_detached.assert_not_called()  # a child never ends the capture


def test_exec_of_another_pid_is_not_a_handover(stop_worker):
    obj = _make_logger(enable_child_gating=True)
    stop_worker(obj)

    obj.on_child_added(FakeChild(5153, "exec"))

    assert obj.instrument.called.wait(WAIT)
    assert _wait_resumed(obj, 5153)
    assert obj.process is not obj.instrument.sessions[0]


# ----------------------------------------------------------------------
# early death -> 1, late death -> 3
# ----------------------------------------------------------------------

def test_detach_before_the_capture_started_exits_1(caplog):
    obj = _make_logger()
    obj.begin_startup()

    with caplog.at_level(logging.ERROR):
        obj.on_detach("process-terminated")

    assert obj._exit_status == EXIT_RUNTIME_ERROR
    assert "before the capture started" in caplog.text
    obj._end_session.assert_called_once()


def test_detach_after_the_capture_started_exits_3():
    obj = _make_logger()
    obj.begin_startup()
    obj.start_capture(lambda: None)

    obj.on_detach("process-terminated")

    assert obj._exit_status == EXIT_TARGET_DETACHED


def test_failed_resume_keeps_the_startup_phase():
    obj = _make_logger()
    obj.begin_startup()

    with pytest.raises(BackendTransportError):
        obj.start_capture(MagicMock(side_effect=BackendTransportError("gone")))

    assert not obj.capture_started()


def _race_detach_against_resume(obj, resume_outcome):
    """Start a resume that blocks until a detach callback has *returned* (as a
    real Frida resume would: it needs the event loop the callback runs on), then
    deliver the detach. Returns (starter thread, error box)."""
    obj.begin_startup()
    in_resume, detach_returned = threading.Event(), threading.Event()
    errors = []

    def blocking_resume():
        in_resume.set()
        # Would deadlock forever if on_detach blocked on the capture lock.
        assert detach_returned.wait(WAIT), "detach callback blocked during resume"
        resume_outcome()

    def run_start():
        try:
            obj.start_capture(blocking_resume)
        except BaseException as exc:  # noqa: BLE001 - surfaced to the test
            errors.append(exc)

    starter = threading.Thread(target=run_start)
    starter.start()
    assert in_resume.wait(WAIT)
    detacher = threading.Thread(target=obj.on_detach, args=("process-terminated",))
    detacher.start()
    detacher.join(WAIT)
    assert not detacher.is_alive(), "on_detach must not block while the resume runs"
    detach_returned.set()
    starter.join(WAIT)
    assert not starter.is_alive(), "start_capture deadlocked"
    return errors


def _wait_end_session(obj):
    for _ in range(int(WAIT / 0.01)):
        if obj._end_session.called:
            return True
        threading.Event().wait(0.01)
    return False


def test_detach_racing_a_successful_resume_is_a_death_during_capture():
    """The resume succeeded, so a detach racing it is a death during capture."""
    obj = _make_logger()

    errors = _race_detach_against_resume(obj, lambda: None)

    assert errors == []
    assert obj._exit_status == EXIT_TARGET_DETACHED
    assert obj.capture_started()
    assert _wait_end_session(obj)
    obj._end_session.assert_called_once_with("process-terminated")


def test_detach_racing_a_failed_resume_is_a_startup_failure(caplog):
    """The resume raised, so a detach racing it is a death before the capture."""
    obj = _make_logger()

    def failed_resume():
        raise BackendTransportError("process not found")

    with caplog.at_level(logging.ERROR):
        errors = _race_detach_against_resume(obj, failed_resume)

    assert len(errors) == 1 and isinstance(errors[0], BackendTransportError)
    assert obj._exit_status == EXIT_RUNTIME_ERROR
    assert not obj.capture_started()
    assert "before the capture started" in caplog.text
    assert _wait_end_session(obj)


def test_capture_start_lock_is_per_instance():
    first, second = _make_logger(), _make_logger()
    assert first._capture_start_lock is first._capture_start_lock
    assert first._capture_start_lock is not second._capture_start_lock


def test_transport_error_during_startup_exits_1(caplog):
    obj = _make_logger()
    obj.connect_live = MagicMock()
    obj._setup_live_scan = MagicMock()
    obj._start_consumer_thread = MagicMock()
    obj._should_use_wine_frida_watch = MagicMock(return_value=False)
    obj._should_use_wine_gdb = MagicMock(return_value=False)
    obj._session_manager = MagicMock()

    def start_session(handler):
        obj.begin_startup()
        raise BackendTransportError("the connection is closed")

    obj._session_manager.start_session.side_effect = start_session
    obj._track_suspended(TARGET_PID)

    with caplog.at_level(logging.ERROR), pytest.raises(BackendTransportError):
        obj.start_fritap_session()

    # friTap.py later proposes 3 for the transport error; the first wins.
    obj.set_exit_status(EXIT_TARGET_DETACHED)
    assert obj._exit_status == EXIT_RUNTIME_ERROR
    assert "before the capture started" in caplog.text
    assert "Instrumentation failed" not in caplog.text
    assert obj._suspended_pids == set()
