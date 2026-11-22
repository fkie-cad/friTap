"""Edge cases of the forced exit and the post-detach crash check (D7).

Review findings on the D1/D2/D5/D6 teardown fixes:
1. the 60 s force-exit timer could fire during a long (up to 600 s) device pull:
   the forced exit then killed nothing useful, never logged the recovery
   command, and orphaned the local ``adb pull`` (it has its own session);
2. other adb children in their own session (AppTap) survived a forced exit;
3. the post-detach crash check set exit 3 only after the slow device
   enrichment, so the main thread's 10 s grace could exit 0 first;
4. a target that died before the detach (e.g. during the pull) was reported
   as dying "during or right after friTap's detach";
5. a forced exit returned 130/143 even when 3 was already recorded.
"""

from __future__ import annotations

import logging
import os
import signal
import stat
import subprocess
import threading
import time
import types
from unittest.mock import MagicMock

import pytest

from friTap import android as android_mod
from friTap.android import ADB, Android
from friTap.exit_codes import EXIT_TARGET_DETACHED
from friTap.legacy.session_manager import SessionManager
from friTap.legacy.ssl_logger_core import SSL_Logger
from friTap.pcap import PCAP

posix_only = pytest.mark.skipif(os.name != "posix", reason="process groups are POSIX")
DEVICE_FILE = "/data/local/tmp/_cap.1-abcdef.pcap"


class _Exited(BaseException):
    """Stands in for os._exit."""


@pytest.fixture
def exits(monkeypatch):
    calls = []

    def fake_exit(status):
        calls.append(status)
        raise _Exited(status)

    monkeypatch.setattr("friTap.legacy.session_manager.os._exit", fake_exit)
    return calls


def _android(device_id="emulator-5562"):
    android = Android.__new__(Android)
    android.logger = MagicMock()
    android.device_id = device_id
    android.pcap_name = "_cap.1-abcdef.pcap"
    android.__dict__["is_Android"] = True
    android.__dict__["adb"] = MagicMock()
    return android


def _pcap(android, output="/tmp/out/cap.pcap"):
    pcap = object.__new__(PCAP)
    pcap.pcap_file_name = output
    pcap.is_Mobile = True
    pcap.logger = MagicMock()
    pcap._device_capture_lock = threading.RLock()
    pcap.android_Instance = android
    pcap.apptap_session = None
    pcap.full_capture_thread = MagicMock(android_capture_process=MagicMock())
    return pcap


def _running_process():
    process = MagicMock()
    process.poll.return_value = None
    process.pid = 99999
    return process


def _manager(pcap_obj, exit_status=0):
    ssl_log = MagicMock()
    ssl_log._embedded = False
    ssl_log._tui_mode = False
    ssl_log._exit_status = exit_status
    ssl_log.pcap_obj = pcap_obj
    manager = SessionManager(ssl_log)
    manager._exit_signal_received = True  # the 1st signal's teardown is running
    return manager, ssl_log


def _recovery_lines(android):
    return [c.args[0] for c in android.logger.error.call_args_list
            if "recover it with" in c.args[0]]


# ------------------------------------------------ 1. forced exit during a pull

def test_forced_exit_during_a_pull_kills_it_and_logs_the_recovery_command(monkeypatch):
    killed = []
    monkeypatch.setattr(android_mod, "kill_adb_child", lambda p, *a: killed.append(p) or True)
    android = _android()
    android._pull_process = _running_process()
    pcap = _pcap(android)
    manager, _ = _manager(pcap)

    manager._force_exit_steps()

    assert killed and killed[0] is android._pull_process
    lines = _recovery_lines(android)
    assert len(lines) == 1
    assert f"adb -s emulator-5562 pull {DEVICE_FILE} /tmp/out/_cap.pcap" in lines[0]


def test_forced_exit_before_the_pull_still_logs_the_recovery_command():
    android = _android()
    pcap = _pcap(android)

    assert pcap.abort_device_capture_pull() is True
    assert len(_recovery_lines(android)) == 1
    # Local only: the pidfile stays for the tcpdump kill, no adb call is made.
    android.adb.shell.assert_not_called()


def test_no_recovery_line_after_a_complete_pull_or_twice():
    android = _android()
    pcap = _pcap(android)
    pcap._device_capture_pulled = True
    assert pcap.abort_device_capture_pull() is False

    android = _android()
    pcap = _pcap(android)
    android.keep_device_capture_for_recovery("/tmp/out/_cap.pcap")  # failed-pull path
    assert pcap.abort_device_capture_pull() is False
    assert len(_recovery_lines(android)) == 1


def test_no_recovery_line_when_no_device_capture_ran():
    android = _android()
    pcap = _pcap(android)
    pcap.full_capture_thread = MagicMock(android_capture_process=-1)
    assert pcap.abort_device_capture_pull() is False
    assert not _recovery_lines(android)


def _fake_adb_on_path(tmp_path, monkeypatch, body):
    script = tmp_path / "adb"
    script.write_text("#!/bin/sh\n" + body)
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{tmp_path}{os.pathsep}{os.environ['PATH']}")


def _alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


@posix_only
def test_a_real_slow_pull_is_tracked_reports_progress_and_dies_with_its_helpers(
        tmp_path, monkeypatch):
    # The fake adb writes 4 bytes, starts a helper and keeps "pulling".
    _fake_adb_on_path(tmp_path, monkeypatch,
                      'printf abcd > "$5"; sleep 60 & echo $! > "$5.helper"; wait\n')
    android = Android.__new__(Android)
    android.logger = MagicMock()
    android.__dict__["adb"] = ADB(device_id="emulator-5562")
    target = tmp_path / "_cap.pcap"
    result = {}
    puller = threading.Thread(target=lambda: result.update(
        cp=android._adb_pull_file(DEVICE_FILE, str(target), timeout=30)))
    puller.start()
    deadline = time.monotonic() + 5
    while not (tmp_path / "_cap.pcap.helper").exists() and time.monotonic() < deadline:
        time.sleep(0.05)
    helper = int((tmp_path / "_cap.pcap.helper").read_text())

    assert android.pull_progress() == 4
    assert android.abort_pull() is True
    puller.join(5)

    assert not puller.is_alive() and result["cp"].returncode != 0
    assert android.pull_progress() is None
    time.sleep(0.2)
    assert not _alive(helper), "the pull's helper process was orphaned"


@posix_only
def test_a_timed_out_pull_is_killed_not_left_running(tmp_path, monkeypatch):
    _fake_adb_on_path(tmp_path, monkeypatch, 'sleep 60 & echo $! > "$5.helper"; wait\n')
    android = Android.__new__(Android)
    android.logger = MagicMock()
    android.__dict__["adb"] = ADB(device_id="emulator-5562")
    target = tmp_path / "_cap.pcap"

    with pytest.raises(subprocess.TimeoutExpired):
        android._adb_pull_file(DEVICE_FILE, str(target), timeout=0.5)
    time.sleep(0.2)
    assert not _alive(int((tmp_path / "_cap.pcap.helper").read_text()))


class _ProgressingPcap:
    def __init__(self, *readings):
        self.readings = list(readings)

    def device_pull_progress(self):
        return self.readings.pop(0) if len(self.readings) > 1 else self.readings[0]


@pytest.fixture
def timer_calls(monkeypatch):
    rearmed, forced = [], []
    monkeypatch.setattr(SessionManager, "_start_force_exit_timer",
                        lambda self, status, delay=None: rearmed.append(delay))
    monkeypatch.setattr(SessionManager, "_force_exit",
                        lambda self, status, reason: forced.append((status, reason)))
    return rearmed, forced


def test_timer_waits_while_the_pull_progresses_and_forces_once_it_stalls(timer_calls):
    rearmed, forced = timer_calls
    manager, _ = _manager(_ProgressingPcap(0, 4096, 4096))

    manager._on_force_exit_timer(130)   # pull running, nothing written yet
    manager._on_force_exit_timer(130)   # grew
    assert forced == [] and rearmed == [SessionManager.PULL_PROGRESS_RECHECK_SECONDS] * 2

    manager._on_force_exit_timer(130)   # stalled
    assert len(forced) == 1 and "still running" in forced[0][1]


def test_after_the_pull_the_rest_of_the_teardown_gets_a_fresh_budget_once(timer_calls):
    rearmed, forced = timer_calls
    manager, _ = _manager(_ProgressingPcap(100, None))

    manager._on_force_exit_timer(130)   # pull progressing: suspended
    manager._on_force_exit_timer(130)   # pull ended: finalize/detach get a fresh 60 s
    assert forced == [] and rearmed == [SessionManager.PULL_PROGRESS_RECHECK_SECONDS, None]

    manager._on_force_exit_timer(130)   # still hanging after that: force
    assert len(forced) == 1


def test_timer_forces_when_no_pull_runs(timer_calls):
    rearmed, forced = timer_calls
    manager, _ = _manager(_ProgressingPcap(None))
    manager._on_force_exit_timer(130)
    assert rearmed == [] and len(forced) == 1


def test_third_signal_forces_at_once_even_while_the_pull_progresses(exits, monkeypatch):
    monkeypatch.setattr(SessionManager, "_start_force_exit_timer",
                        lambda self, status, delay=None: None)
    monkeypatch.setattr(SessionManager, "_force_exit_steps", lambda self: None)
    manager, _ = _manager(_ProgressingPcap(0, 10, 20, 30))
    manager._on_termination_signal(signal.SIGINT, None)      # 2nd
    with pytest.raises(_Exited):
        manager._on_termination_signal(signal.SIGINT, None)  # 3rd
    assert exits == [130]


def test_second_signal_arms_the_timer_with_the_progress_check(monkeypatch):
    monkeypatch.setattr(SessionManager, "FORCE_EXIT_AFTER_SECONDS", 0.05)
    monkeypatch.setattr(SessionManager, "PULL_PROGRESS_RECHECK_SECONDS", 0.05)
    forced = threading.Event()
    monkeypatch.setattr(SessionManager, "_force_exit",
                        lambda self, status, reason: forced.set())
    manager, _ = _manager(_ProgressingPcap(1, 2, 3, 3))
    manager._on_termination_signal(signal.SIGINT, None)

    assert forced.wait(3)
    assert manager._last_pull_progress == 3   # it waited through the growing readings


# --------------------------------------- 2. other adb children on forced exit

def test_forced_exit_stops_the_apptap_session_bounded(monkeypatch):
    monkeypatch.setattr(PCAP, "FORCED_OWNER_CAPTURE_STOP_SECONDS", 0.2)
    pcap = _pcap(_android())
    pcap.full_capture_thread = MagicMock(android_capture_process=-1)
    session = MagicMock()
    session.stop.side_effect = lambda: time.sleep(5)   # a wedged AppTap stop
    pcap.apptap_session = session
    manager, _ = _manager(pcap)

    t0 = time.monotonic()
    manager._force_exit_steps()

    assert time.monotonic() - t0 < 2.0
    session.stop.assert_called_once()
    assert pcap.apptap_session is None


@posix_only
def test_forced_exit_kills_background_adb_children(tmp_path, monkeypatch):
    _fake_adb_on_path(tmp_path, monkeypatch, "sleep 60 & wait\n")
    child = ADB().shell("tcpdump -w x", background=True)   # e.g. AppTap's capture client
    pcap = _pcap(_android())
    pcap.full_capture_thread = MagicMock(android_capture_process=-1)
    manager, _ = _manager(pcap)

    manager._force_exit_steps()

    assert child.poll() is not None


# ------------------------------------ 3. exit 3 before the slow enrichment

class _ListHandler(logging.Handler):
    def __init__(self):
        super().__init__(logging.DEBUG)
        self.records = []

    def emit(self, record):
        self.records.append(record)


class _Backend:
    def __init__(self, *pid_lists):
        self.pid_lists = list(pid_lists)
        self.calls = 0

    def enumerate_processes(self, device):
        self.calls += 1
        pids = self.pid_lists.pop(0) if len(self.pid_lists) > 1 else self.pid_lists[0]
        return [types.SimpleNamespace(pid=p, name="x") for p in pids]


@pytest.fixture(autouse=True)
def _no_debug_log(monkeypatch):
    monkeypatch.setattr("friTap.fritap_utility.open_debug_log", lambda *a, **k: None)
    monkeypatch.setattr("friTap.fritap_utility.attach_file_handlers", lambda *a, **k: None)
    monkeypatch.setattr("friTap.fritap_utility.get_debug_log_writer", lambda *a, **k: None)


def _ssl_logger(backend, enrich=None):
    obj = SSL_Logger.__new__(SSL_Logger)
    obj.logger = logging.getLogger("test.forced_exit_edge_cases")
    obj.logger.setLevel(logging.DEBUG)
    obj.logger.propagate = False
    handler = _ListHandler()
    obj.logger.handlers = [handler]
    obj.pid = 1234
    obj.device = object()
    obj._backend = backend
    obj._android_target_cached = True
    obj._main_session_detached = True
    obj._crash_reported = False
    obj._pending_crash = None
    obj._event_bus = types.SimpleNamespace(emit=lambda *a, **k: None)
    obj.POST_DETACH_POLL_SECONDS = 0
    obj._enrich_crash_log_android = enrich or (lambda crash, writer: (None, None))
    obj._enrich_crash_log_ios = lambda crash, writer: (None, None)
    obj._enrich_crash_log_macos = lambda crash, writer: (None, None)
    return obj, handler


def test_frida_crash_sets_exit_3_before_the_device_enrichment():
    seen = {}

    def slow_enrichment(crash, writer):
        seen["status_during_enrichment"] = obj._exit_status
        return None, None

    obj, _ = _ssl_logger(_Backend([1]), enrich=slow_enrichment)
    obj._pending_crash = types.SimpleNamespace(report="", summary="SIGSEGV", pid=1234)

    obj._report_crash_after_detach()

    assert seen["status_during_enrichment"] == EXIT_TARGET_DETACHED
    assert obj._exit_status == EXIT_TARGET_DETACHED


def test_main_thread_waits_longer_only_while_the_crash_check_runs():
    obj = SSL_Logger.__new__(SSL_Logger)
    obj._cleanup_done = True
    obj.TEARDOWN_FINISH_GRACE_SECONDS = 0.1
    obj.CRASH_CHECK_GRACE_SECONDS = 5.0
    obj._post_detach_check_running = True
    threading.Timer(0.5, obj._teardown_finished.set).start()

    t0 = time.monotonic()
    obj._let_running_teardown_finish()
    assert 0.4 <= time.monotonic() - t0 < 4.0   # past the base grace, until it finished

    idle = SSL_Logger.__new__(SSL_Logger)
    idle._cleanup_done = True
    idle.TEARDOWN_FINISH_GRACE_SECONDS = 0.1
    idle.CRASH_CHECK_GRACE_SECONDS = 5.0
    t0 = time.monotonic()
    idle._let_running_teardown_finish()
    assert time.monotonic() - t0 < 1.0          # no crash check: the base grace only


def test_crash_check_flag_is_cleared_when_the_check_ends():
    obj, _ = _ssl_logger(_Backend([1]))
    obj._report_crash_after_detach()
    assert obj._post_detach_check_running is False


# ---------------------------- 4. died before the detach: say "teardown"

def test_target_dead_before_the_detach_is_reported_as_a_teardown_death():
    obj, handler = _ssl_logger(_Backend([1]))
    obj._main_session_detached = False
    obj._note_target_alive_at_detach()          # pid already gone when the detach begins
    obj._main_session_detached = True
    obj._pending_crash = types.SimpleNamespace(report="", summary="SIGABRT", pid=1234)

    obj._report_crash_after_detach()

    errors = [r.getMessage() for r in handler.records if r.levelno == logging.ERROR]
    assert any("1234 crashed during friTap's teardown, before its detach" in m for m in errors), errors
    assert not any("right after friTap's detach" in m for m in errors)


def test_target_alive_at_the_detach_keeps_the_detach_wording():
    obj, handler = _ssl_logger(_Backend([1234], [1]))
    obj._note_target_alive_at_detach()
    assert obj._target_alive_at_detach is True
    obj._pending_crash = types.SimpleNamespace(report="", summary="SIGABRT", pid=1234)

    obj._report_crash_after_detach()

    errors = [r.getMessage() for r in handler.records if r.levelno == logging.ERROR]
    assert any("crashed during or right after friTap's detach" in m for m in errors), errors


def test_detach_with_timeout_records_the_liveness_before_detaching(monkeypatch):
    order = []
    obj = SSL_Logger.__new__(SSL_Logger)
    obj._note_target_alive_at_detach = lambda: order.append("note")
    obj._detach_main_agent = lambda timeout: order.append("detach")
    obj._release_child_agents = lambda: None
    obj._config = types.SimpleNamespace(debug=False, debug_output=False)

    obj.detach_with_timeout(timeout=2)

    assert order == ["note", "detach"]


def test_liveness_note_skips_non_android_targets():
    backend = _Backend([1])
    obj, _ = _ssl_logger(backend)
    obj._android_target_cached = False
    obj._note_target_alive_at_detach()
    assert backend.calls == 0 and obj._target_alive_at_detach is None


# ----------------------------------- 5. first non-zero exit status wins

@pytest.mark.parametrize("recorded, forced, expected", [
    (0, 130, 130),
    (EXIT_TARGET_DETACHED, 130, EXIT_TARGET_DETACHED),
    (143, 143, 143),
    (1, 143, 1),
])
def test_forced_exit_keeps_an_earlier_non_zero_status(exits, monkeypatch, recorded, forced, expected):
    monkeypatch.setattr(SessionManager, "_force_exit_steps", lambda self: None)
    manager, _ = _manager(None, exit_status=recorded)
    with pytest.raises(_Exited):
        manager._force_exit(forced, "test")
    assert exits == [expected]


def test_a_signal_while_forcing_also_keeps_the_earlier_status(exits):
    manager, _ = _manager(None, exit_status=EXIT_TARGET_DETACHED)
    manager._force_exit_lock.acquire()          # a forced exit is already under way
    with pytest.raises(_Exited):
        manager._force_exit(130, "test")
    assert exits == [EXIT_TARGET_DETACHED]
