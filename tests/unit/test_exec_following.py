#!/usr/bin/env python3
"""Every instrumented process is followed across exec(); startup deaths exit 1.

**Exec following.** A launcher such as Homebrew's ``python3`` exec()s the real
binary. Frida ends the old session with ``process-replaced`` and, with child
gating on, reports the new image as a child of origin ``"exec"`` with the same
pid, held suspended. friTap must instrument that image through the gated-child
worker, make it the main session, resume it, and NOT tear the capture down --
in spawn and attach mode alike, and for every instrumented child too (with
``--enable_child_gating``). Fork and spawn children it was not asked to gate
must be resumed untouched.

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
from tests.unit.test_cli_unattended import fake_cli  # noqa: F401  (fixture)

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


def _make_logger(instrument=None, enable_child_gating=False, spawn=True,
                 follow_exec=True):
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
    obj._event_bus = MagicMock()
    obj._end_session = MagicMock(return_value=True)
    obj._report_target_crash = MagicMock()
    obj._pending_crash = None
    obj.instrument = RecordingInstrument() if instrument is None else instrument
    obj._config = types.SimpleNamespace(
        target="/opt/homebrew/bin/python3",
        device=types.SimpleNamespace(
            spawn=spawn, mobile=False, enable_child_gating=enable_child_gating,
            enable_spawn_gating=False, spawn_gating_all=False, follow_exec=follow_exec,
        ),
    )
    # No real process paths: the held-exec watchdog then sees no process.
    obj._backend.process_paths.return_value = {}
    obj._init_process_following()
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
    obj = _make_logger(follow_exec=False)

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


def test_fork_child_untouched_even_when_target_gating_failed():
    """Without --enable_child_gating a fork child (e.g. of a spawn-gated process)
    is never instrumented, also when the target's own gating failed."""
    obj = _make_logger(enable_child_gating=False)
    obj._backend.enable_child_gating.side_effect = RuntimeError("cannot gate")
    assert obj.follow_exec_of(obj.process) is False

    obj.on_child_added(FakeChild(5153, "fork"))

    assert _wait_resumed(obj, 5153)
    assert obj._instrument_thread is None and obj._instrument_queue.empty()
    assert obj.instrument.sessions == []


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
    # Watched for its own exec(), with a handler that never ends the capture.
    child_session = obj.instrument.sessions[0]
    obj._backend.enable_child_gating.assert_any_call(child_session)
    (session, handler), _ = obj._backend.on_detached.call_args
    assert session is child_session and handler != obj.on_detach
    assert obj.process is not child_session


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


# ----------------------------------------------------------------------
# --no-follow-exec
# ----------------------------------------------------------------------

def _gating_logger(spawn=True, follow_exec=True, enable_child_gating=False):
    """A logger reduced to what SessionManager's gating decision reads."""
    obj = SSL_Logger.__new__(SSL_Logger)
    obj.logger = logging.getLogger("test.exec_following")
    obj._backend = MagicMock()
    obj._backend.process_paths.return_value = {}
    obj.device = FAKE_DEVICE
    obj.process = MagicMock(name="spawned-session")
    obj.pid = TARGET_PID
    obj._config = types.SimpleNamespace(device=types.SimpleNamespace(
        spawn=spawn, follow_exec=follow_exec, enable_child_gating=enable_child_gating))
    obj._init_process_following()
    return obj


def _gate(obj):
    from friTap.legacy.session_manager import SessionManager
    obj.follow_exec_of(obj.process)
    SessionManager(obj)._register_child_handler(obj)


def test_spawn_follows_exec_by_default():
    obj = _gating_logger()
    _gate(obj)
    obj._backend.enable_child_gating.assert_called_once_with(obj.process)
    obj._backend.on_child_added.assert_called_once()
    assert obj._gates_only_to_follow_exec is True


def test_no_follow_exec_does_not_enable_child_gating():
    obj = _gating_logger(follow_exec=False)
    _gate(obj)
    obj._backend.enable_child_gating.assert_not_called()
    obj._backend.on_child_added.assert_not_called()
    assert obj._gates_only_to_follow_exec is False


def test_no_follow_exec_keeps_explicit_child_gating():
    obj = _gating_logger(follow_exec=False, enable_child_gating=True)
    _gate(obj)
    obj._backend.enable_child_gating.assert_called_once_with(obj.process)
    obj._backend.on_child_added.assert_called_once()
    assert obj._gates_only_to_follow_exec is False  # children are gated, exec is not followed


@pytest.mark.parametrize("enable_child_gating", [False, True])
def test_backend_without_child_events(enable_child_gating):
    """Exec following alone tolerates a backend without child events; an
    explicit --enable_child_gating still fails loudly."""
    from friTap.legacy.session_manager import SessionManager
    obj = _gating_logger(enable_child_gating=enable_child_gating)
    obj._backend.on_child_added.side_effect = NotImplementedError
    manager = SessionManager(obj)
    if enable_child_gating:
        with pytest.raises(NotImplementedError):
            manager._register_child_handler(obj)
    else:
        manager._register_child_handler(obj)


def test_attach_mode_follows_exec_by_default():
    obj = _gating_logger(spawn=False)
    _gate(obj)
    obj._backend.enable_child_gating.assert_called_once_with(obj.process)
    obj._backend.on_child_added.assert_called_once()
    assert obj.exec_following_requested is True


def test_no_follow_exec_in_attach_mode_gates_nothing():
    obj = _gating_logger(spawn=False, follow_exec=False)
    _gate(obj)
    obj._backend.enable_child_gating.assert_not_called()
    obj._backend.on_child_added.assert_not_called()
    assert obj.exec_following_requested is False


def test_follow_exec_config_defaults_on():
    from friTap.api import FriTap
    from friTap.config import DeviceConfig, FriTapConfig
    assert DeviceConfig().follow_exec is True
    assert FriTapConfig.from_legacy_params(app="t").device.follow_exec is True
    assert FriTap("t").build_config().device.follow_exec is True
    assert FriTap("t").follow_exec(False).build_config().device.follow_exec is False


def test_cli_no_follow_exec_flag_reaches_the_config(fake_cli):  # noqa: F811
    ssl_log, _ = fake_cli("--non-interactive", "-s", "--no-follow-exec", "target")
    assert ssl_log.config.device.follow_exec is False


def test_cli_follows_exec_by_default(fake_cli):  # noqa: F811
    ssl_log, _ = fake_cli("--non-interactive", "-s", "target")
    assert ssl_log.config.device.follow_exec is True


# ----------------------------------------------------------------------
# attach mode follows exec() too
# ----------------------------------------------------------------------

@pytest.mark.parametrize("detach_first", [True, False])
def test_attach_mode_hands_over_to_the_exec_image(stop_worker, detach_first):
    obj = _make_logger(spawn=False)
    stop_worker(obj)
    exec_child = FakeChild(TARGET_PID, "exec", "/opt/homebrew/opt/curl/bin/curl")

    events = [lambda: obj.on_detach("process-replaced"),
              lambda: obj.on_child_added(exec_child)]
    for event in events if detach_first else reversed(events):
        event()

    assert _wait_resumed(obj, TARGET_PID)
    assert obj.process is obj.instrument.sessions[0]
    obj._end_session.assert_not_called()
    assert obj._exit_status == 0


def test_without_gating_process_replaced_reattaches(stop_worker):
    """Fallback when the session cannot gate: re-attach to the same pid. The
    new image was never held, so there is nothing to resume."""
    obj = _make_logger(spawn=False)
    stop_worker(obj)
    obj._backend.enable_child_gating.side_effect = RuntimeError("no gating here")
    obj.follow_exec_of(obj.process)
    assert obj._tracker.get(TARGET_PID).gated is False

    obj.on_detach("process-replaced")

    assert obj.instrument.called.wait(WAIT)
    assert obj.process is obj.instrument.sessions[0]
    obj._backend.attach.assert_called_with(FAKE_DEVICE, str(TARGET_PID))
    obj._end_session.assert_not_called()
    obj._stop_instrument_thread()
    assert (FAKE_DEVICE, TARGET_PID) not in _resumed(obj)


def test_no_follow_exec_in_attach_mode_ends_on_exec():
    obj = _make_logger(spawn=False, follow_exec=False)
    obj._backend.enable_child_gating.assert_not_called()

    obj.on_detach("process-replaced")

    obj._end_session.assert_called_once_with("process-replaced")
    assert obj._exit_status == EXIT_TARGET_DETACHED


# ----------------------------------------------------------------------
# --enable_child_gating: children are instrumented AND followed across exec()
# ----------------------------------------------------------------------

CHILD_PID = 6001


def _wait_sessions(obj, count):
    for _ in range(int(WAIT / 0.01)):
        if len(obj.instrument.sessions) >= count:
            return True
        threading.Event().wait(0.01)
    return False


def _child_detach_handler(obj, session):
    for (watched, handler), _ in obj._backend.on_detached.call_args_list:
        if watched is session:
            return handler
    raise AssertionError("child session was never watched for detach")


@pytest.mark.parametrize("origin", ["fork", "spawn"])
def test_child_exec_is_followed(stop_worker, origin):
    obj = _make_logger(enable_child_gating=True)
    stop_worker(obj)

    obj.on_child_added(FakeChild(CHILD_PID, origin))
    assert _wait_sessions(obj, 1) and _wait_resumed(obj, CHILD_PID)
    child_session = obj.instrument.sessions[0]
    obj._backend.enable_child_gating.assert_any_call(child_session)

    # git's fork child exec()s git-remote-https: detach + exec image, any order.
    _child_detach_handler(obj, child_session)("process-replaced")
    obj.on_child_added(FakeChild(CHILD_PID, "exec", "/usr/libexec/git-remote-https"))

    assert _wait_sessions(obj, 2) and _wait_resumed(obj, CHILD_PID, times=2)
    exec_session = obj.instrument.sessions[1]
    assert obj._tracker.get(CHILD_PID).session is exec_session
    obj._backend.enable_child_gating.assert_any_call(exec_session)
    # A child's exec never touches the main session or the capture.
    assert obj.process is not exec_session
    obj._end_session.assert_not_called()
    assert obj._exit_status == 0


def test_grandchildren_of_an_instrumented_child_are_instrumented(stop_worker):
    obj = _make_logger(enable_child_gating=True)
    stop_worker(obj)

    obj.on_child_added(FakeChild(CHILD_PID, "fork"))
    assert _wait_sessions(obj, 1)
    obj.on_child_added(FakeChild(CHILD_PID + 1, "fork"))  # reported via its gating

    assert _wait_sessions(obj, 2) and _wait_resumed(obj, CHILD_PID + 1)
    assert obj._tracker.pids() == {TARGET_PID, CHILD_PID, CHILD_PID + 1}


def test_child_detach_forgets_the_child_without_ending_the_capture(stop_worker):
    obj = _make_logger(enable_child_gating=True)
    stop_worker(obj)
    obj.on_child_added(FakeChild(CHILD_PID, "fork"))
    assert _wait_sessions(obj, 1)

    _child_detach_handler(obj, obj.instrument.sessions[0])("process-terminated")

    assert not obj._tracker.is_tracked(CHILD_PID)
    obj._end_session.assert_not_called()
    assert obj._exit_status == 0


def test_late_detach_of_the_old_image_keeps_the_exec_image(stop_worker):
    obj = _make_logger(enable_child_gating=True)
    stop_worker(obj)
    obj.on_child_added(FakeChild(CHILD_PID, "fork"))
    assert _wait_sessions(obj, 1)
    old_handler = _child_detach_handler(obj, obj.instrument.sessions[0])
    obj.on_child_added(FakeChild(CHILD_PID, "exec"))
    assert _wait_sessions(obj, 2)

    old_handler("process-terminated")  # the old image's session, late

    assert obj._tracker.get(CHILD_PID).session is obj.instrument.sessions[1]


def test_failed_child_exec_handover_never_ends_the_capture(stop_worker):
    failing = RecordingInstrument()
    obj = _make_logger(enable_child_gating=True, instrument=failing)
    stop_worker(obj)
    obj.on_child_added(FakeChild(CHILD_PID, "fork"))
    assert _wait_sessions(obj, 1)
    failing._error = BackendTransportError("child died during load")

    obj.on_child_added(FakeChild(CHILD_PID, "exec"))

    assert _wait_resumed(obj, CHILD_PID, times=2)
    for _ in range(int(WAIT / 0.01)):
        if not obj._tracker.is_tracked(CHILD_PID):
            break
        threading.Event().wait(0.01)
    assert not obj._tracker.is_tracked(CHILD_PID)
    obj._end_session.assert_not_called()
    assert obj._exit_status == 0


def test_child_handover_timeout_forgets_only_the_child(monkeypatch, stop_worker):
    obj = _make_logger(enable_child_gating=True)
    stop_worker(obj)
    monkeypatch.setattr(obj, "EXEC_HANDOVER_TIMEOUT", 0.05)
    obj.on_child_added(FakeChild(CHILD_PID, "fork"))
    assert _wait_sessions(obj, 1)

    _child_detach_handler(obj, obj.instrument.sessions[0])("process-replaced")

    for _ in range(int(WAIT / 0.01)):
        if not obj._tracker.is_tracked(CHILD_PID):
            break
        threading.Event().wait(0.01)
    assert not obj._tracker.is_tracked(CHILD_PID)
    obj._end_session.assert_not_called()
    assert obj._exit_status == 0


def test_no_follow_exec_resumes_a_childs_exec_image_untouched(stop_worker):
    obj = _make_logger(enable_child_gating=True, follow_exec=False)
    stop_worker(obj)
    obj.on_child_added(FakeChild(CHILD_PID, "fork"))
    assert _wait_sessions(obj, 1) and _wait_resumed(obj, CHILD_PID)

    obj.on_child_added(FakeChild(CHILD_PID, "exec"))

    assert _wait_resumed(obj, CHILD_PID, times=2)
    assert len(obj.instrument.sessions) == 1


# ----------------------------------------------------------------------
# children friTap does not follow are resumed -- also at teardown
# ----------------------------------------------------------------------

def test_no_follow_exec_resumes_the_targets_exec_image():
    obj = _make_logger(follow_exec=False, enable_child_gating=True)

    obj.on_child_added(FakeChild(TARGET_PID, "exec"))

    assert _wait_resumed(obj, TARGET_PID)
    assert obj.instrument.sessions == []


def test_teardown_resumes_a_child_whose_resume_is_still_pending():
    obj = _make_logger()
    release = threading.Event()
    calls = []

    def slow_first_resume(device, pid):
        calls.append(pid)
        if len(calls) == 1:
            release.wait(WAIT)  # the off-thread resume is stuck in Frida

    obj._backend.resume.side_effect = slow_first_resume
    obj.on_child_added(FakeChild(5170, "fork"))
    for _ in range(int(WAIT / 0.01)):
        if calls:
            break
        threading.Event().wait(0.01)

    obj._stop_instrument_thread()  # teardown, before that resume returned

    assert calls.count(5170) == 2
    release.set()


def test_teardown_resumes_every_queued_child():
    release = threading.Event()
    obj = _make_logger(enable_child_gating=True,
                       instrument=RecordingInstrument(block=release))
    for pid in (5180, 5181, 5182):
        obj.on_child_added(FakeChild(pid, "fork"))
    assert obj.instrument.called.wait(WAIT)

    obj._stop_instrument_thread()
    release.set()

    for pid in (5180, 5181, 5182):
        assert _wait_resumed(obj, pid), f"pid {pid} left suspended"


def test_child_arriving_after_teardown_is_resumed():
    obj = _make_logger(enable_child_gating=True)
    obj._stop_instrument_thread()

    obj.on_child_added(FakeChild(5190, "fork"))

    assert _wait_resumed(obj, 5190)
    assert obj.instrument.sessions == []


# ----------------------------------------------------------------------
# exit status: first non-zero wins; 3 = the TARGET went away
# ----------------------------------------------------------------------

def test_main_exec_image_dying_during_load_exits_3(stop_worker):
    obj = _make_logger(instrument=RecordingInstrument(
        error=BackendTransportError("the connection is closed")))
    stop_worker(obj)
    ended = threading.Event()
    obj._end_session.side_effect = lambda reason: ended.set()

    obj.on_child_added(FakeChild(TARGET_PID, "exec"))

    assert ended.wait(WAIT)
    assert obj._exit_status == EXIT_TARGET_DETACHED


def test_first_non_zero_exit_status_wins_over_a_later_handover_failure(stop_worker):
    obj = _make_logger(instrument=RecordingInstrument(error=RuntimeError("load failed")))
    stop_worker(obj)
    obj.set_exit_status(EXIT_TARGET_DETACHED)
    ended = threading.Event()
    obj._end_session.side_effect = lambda reason: ended.set()

    obj.on_child_added(FakeChild(TARGET_PID, "exec"))

    assert ended.wait(WAIT)
    assert obj._exit_status == EXIT_TARGET_DETACHED


# ----------------------------------------------------------------------
# exec'd images Frida holds without announcing them (macOS, close_fds=True)
# ----------------------------------------------------------------------

def test_held_exec_image_of_a_child_is_taken_over(stop_worker):
    obj = _make_logger(enable_child_gating=True)
    stop_worker(obj)
    obj.on_child_added(FakeChild(CHILD_PID, "fork"))
    assert _wait_sessions(obj, 1) and _wait_resumed(obj, CHILD_PID)

    obj._on_held_exec_image(CHILD_PID, "/opt/homebrew/opt/curl/bin/curl")

    assert _wait_sessions(obj, 2) and _wait_resumed(obj, CHILD_PID, times=2)
    assert obj._tracker.get(CHILD_PID).session is obj.instrument.sessions[1]


def test_held_exec_image_of_an_unknown_pid_is_ignored():
    obj = _make_logger()
    obj._on_held_exec_image(9999, "/bin/x")
    assert obj._instrument_thread is None and obj._backend.resume.call_count == 0


def test_gated_processes_are_watched_for_held_images(stop_worker):
    obj = _make_logger(enable_child_gating=True)
    stop_worker(obj)
    obj._held_exec_watchdog._query_paths = lambda pids: {pid: "/same" for pid in pids}
    assert TARGET_PID in obj._held_exec_watchdog.watched()

    obj.on_child_added(FakeChild(CHILD_PID, "fork"))
    assert _wait_sessions(obj, 1)
    assert CHILD_PID in obj._held_exec_watchdog.watched()

    obj._stop_instrument_thread()
    assert obj._held_exec_watchdog.watched() == set()


class _FakeClock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


def _manual(dog):
    """No poll thread: the test drives poll_once() by hand (watch() would
    otherwise wake the thread to poll at once)."""
    dog._start_locked = lambda: None
    return dog


def _watchdog(paths, held, clock=None):
    from friTap.legacy.exec_follow import HeldExecWatchdog
    return _manual(HeldExecWatchdog(lambda pids: dict(paths),
                                    lambda pid, path: held.append((pid, path)),
                                    interval=3600, grace=2.0, clock=clock or _FakeClock()))


def test_watchdog_reports_an_unannounced_exec_once():
    clock, held, paths = _FakeClock(), [], {7: "/py/Python"}
    dog = _watchdog(paths, held, clock)
    dog.watch(7)
    dog.poll_once()  # learns the path
    paths[7] = "/opt/homebrew/opt/curl/bin/curl"
    dog.poll_once()  # change seen, grace starts
    clock.now = 1.0
    dog.poll_once()
    assert held == []
    clock.now = 2.5
    dog.poll_once()
    assert held == [(7, "/opt/homebrew/opt/curl/bin/curl")]
    clock.now = 10.0
    dog.poll_once()
    assert len(held) == 1
    dog.stop()


def test_watchdog_ignores_an_announced_exec():
    clock, held, paths = _FakeClock(), [], {7: "/bin/git"}
    dog = _watchdog(paths, held, clock)
    dog.watch(7)
    dog.poll_once()
    paths[7] = "/git-core/git-remote-https"
    dog.poll_once()
    dog.note_exec(7)  # Frida announced it
    clock.now = 5.0
    dog.poll_once()
    dog.poll_once()
    assert held == []
    dog.stop()


def test_watchdog_forgets_exited_processes_and_unsupported_backends():
    held = []
    dog = _watchdog({}, held)
    dog.watch(7)
    dog.poll_once()
    assert dog.watched() == set()

    def unsupported(pids):
        raise NotImplementedError

    from friTap.legacy.exec_follow import HeldExecWatchdog
    dog = _manual(HeldExecWatchdog(unsupported, lambda *a: held.append(a), interval=3600))
    dog.watch(8)
    dog.poll_once()
    dog.watch(9)
    assert dog.watched() == set() and held == []


def test_tracker_counts_replaced_and_images_per_pid():
    from friTap.legacy.exec_follow import ProcessTracker
    tracker = ProcessTracker()
    tracker.track(1, session="a", is_main=True, gated=True)
    tracker.track(2, session="b", is_main=False, gated=True)

    assert tracker.note_replaced(2) is True  # image still due
    assert tracker.awaiting_image(2) and not tracker.awaiting_image(1)
    tracker.note_image(2)
    assert not tracker.awaiting_image(2)
    tracker.track(2, session="b2", is_main=False, gated=True)  # exec'd image
    assert tracker.forget(2, session="b") is False
    assert tracker.forget(2, session="b2") is True
    assert tracker.pids() == {1}


def _backoff_dog(paths, held, clock=None):
    from friTap.legacy.exec_follow import HeldExecWatchdog
    return _manual(HeldExecWatchdog(lambda pids: dict(paths),
                                    lambda pid, path: held.append((pid, path)),
                                    interval=1.0, grace=2.0, clock=clock or _FakeClock(),
                                    max_interval=8.0))


def test_watchdog_backs_off_while_idle_up_to_the_cap():
    dog = _backoff_dog({}, [])
    assert [dog._next_interval(w, active=False) for w in (1.0, 2.0, 4.0, 8.0)] == \
        [2.0, 4.0, 8.0, 8.0]


def test_watchdog_backoff_resets_on_pending_change_and_held_report():
    clock, held, paths = _FakeClock(), [], {7: "/py/Python"}
    dog = _backoff_dog(paths, held, clock)
    dog.watch(7)
    assert dog.poll_once() is False  # learns the path: idle
    paths[7] = "/usr/bin/curl"
    assert dog.poll_once() is True  # change pending: keep base cadence
    clock.now = 2.5
    assert dog.poll_once() is True and held == [(7, "/usr/bin/curl")]
    assert dog.poll_once() is False  # settled again
    dog._next_interval(1.0, active=False)  # consume the reset from watch()
    assert dog._next_interval(8.0, active=True) == 1.0
    dog.stop()


def test_watchdog_backoff_resets_on_watch_and_note_exec():
    dog = _backoff_dog({7: "/bin/git"}, [])
    dog.watch(7)
    assert dog._next_interval(8.0, active=False) == 1.0  # watch() resets
    assert dog._next_interval(1.0, active=False) == 2.0
    dog.note_exec(7)
    assert dog._next_interval(8.0, active=False) == 1.0  # note_exec() resets
    dog.watch(8)
    assert dog._next_interval(4.0, active=False) == 1.0
    dog.stop()


def test_watchdog_thread_waits_with_the_backed_off_interval(monkeypatch):
    dog = _backoff_dog({7: "/bin/git"}, [])
    waits = []

    def fake_wait(timeout=None):
        waits.append(timeout)
        if len(waits) > 4:
            dog._stop.set()
        return False

    monkeypatch.setattr(dog._wake, "wait", fake_wait)
    with dog._lock:
        dog._watched[7] = __import__("friTap.legacy.exec_follow",
                                     fromlist=["_WatchState"])._WatchState()
    dog._run()
    assert waits == [1.0, 2.0, 4.0, 8.0, 8.0]


def test_watchdog_default_backoff_cap_is_five_seconds():
    from friTap.legacy.exec_follow import HeldExecWatchdog
    dog = _manual(HeldExecWatchdog(lambda pids: {}, lambda *a: None))
    assert dog._next_interval(4.0, active=False) == 5.0
    assert dog._next_interval(5.0, active=False) == 5.0


def test_watchdog_watch_wakes_a_backed_off_poll_thread():
    """A newly watched pid is polled at once, not after the backed-off wait,
    so its path is learnt before it can exec()."""
    from friTap.legacy.exec_follow import HeldExecWatchdog
    polled = threading.Event()

    def query(pids):
        if 8 in pids:
            polled.set()
        return {pid: "/bin/sh" for pid in pids}

    dog = HeldExecWatchdog(query, lambda *a: None, interval=60, max_interval=60)
    dog.watch(7)
    threading.Event().wait(0.2)  # the thread is now in its 60 s wait
    started = __import__("time").monotonic()
    dog.watch(8)
    assert polled.wait(WAIT)
    assert __import__("time").monotonic() - started < WAIT
    dog.stop()


def test_watchdog_stop_ends_the_poll_thread_promptly():
    from friTap.legacy.exec_follow import HeldExecWatchdog
    dog = HeldExecWatchdog(lambda pids: {pid: "/bin/sh" for pid in pids},
                           lambda *a: None, interval=60, max_interval=60)
    dog.watch(7)
    thread = dog._thread
    dog.stop()
    thread.join(WAIT)
    assert not thread.is_alive()


# ----------------------------------------------------------------------
# ResumeWorker: one resumer thread instead of one thread per child
# ----------------------------------------------------------------------

def test_resume_worker_resumes_every_pid_in_order_on_one_thread():
    from friTap.legacy.exec_follow import ResumeWorker
    resumed, threads, done = [], set(), threading.Event()

    def resume(pid):
        resumed.append(pid)
        threads.add(threading.current_thread().name)
        if len(resumed) == 30:
            done.set()

    worker = ResumeWorker(resume)
    for pid in range(30):
        worker.submit(pid)
    assert done.wait(WAIT)
    assert resumed == list(range(30))
    assert threads == {"fritap-resume"} and len({id(t) for t in [worker._thread]}) == 1


def test_resume_worker_never_runs_on_the_submitting_thread():
    from friTap.legacy.exec_follow import ResumeWorker
    seen, done = [], threading.Event()
    worker = ResumeWorker(lambda pid: (seen.append(threading.current_thread()), done.set()))
    worker.submit(1)
    assert done.wait(WAIT)
    assert seen[0] is not threading.current_thread()


def test_resume_worker_survives_a_failing_resume_and_retires_when_idle():
    from friTap.legacy.exec_follow import ResumeWorker
    resumed, done = [], threading.Event()

    def resume(pid):
        if pid == 1:
            raise RuntimeError("frida says no")
        resumed.append(pid)
        done.set()

    worker = ResumeWorker(resume, idle_timeout=0.05)
    worker.submit(1)
    worker.submit(2)
    assert done.wait(WAIT) and resumed == [2]
    for _ in range(int(WAIT / 0.01)):
        if worker._thread is None:
            break
        threading.Event().wait(0.01)
    assert worker._thread is None  # retired
    done.clear()
    worker.submit(3)  # restarts on demand
    assert done.wait(WAIT) and resumed == [2, 3]


def test_unasked_fork_children_share_one_resumer_thread(stop_worker):
    obj = _make_logger()
    stop_worker(obj)
    before = threading.active_count()
    for pid in range(5000, 5030):
        obj.on_child_added(FakeChild(pid, "fork"))
    for pid in range(5000, 5030):
        assert _wait_resumed(obj, pid)
    assert threading.active_count() <= before + 1
    assert obj._suspended_pids == set()
