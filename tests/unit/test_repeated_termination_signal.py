"""Repeated SIGINT/SIGTERM during the CLI teardown.

1st signal: graceful teardown. 2nd: a warning, the teardown continues (capture
pull, manifest, keylog flush). 3rd, or FORCE_EXIT_AFTER_SECONDS after the 2nd:
forced exit 128+signum after the bounded must-do steps (kill the device
tcpdump, close the outputs). Before the fix the 2nd signal exited 0 at once.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import textwrap
import threading
import time
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from friTap.legacy.session_manager import SessionManager
from friTap.pcap import PCAP
from tests.unit._log_helpers import attach_log_capture

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


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


@pytest.fixture
def no_timer(monkeypatch):
    started = []
    monkeypatch.setattr(SessionManager, "_start_force_exit_timer",
                        lambda self, status: started.append(status))
    return started


def _tearing_down_manager():
    ssl_log = MagicMock()
    ssl_log._embedded = False
    ssl_log._tui_mode = False
    manager = SessionManager(ssl_log)
    manager._exit_signal_received = True  # the 1st signal's teardown is running
    return manager, ssl_log


def test_second_sigint_warns_and_does_not_exit(exits, no_timer):
    manager, ssl_log = _tearing_down_manager()
    logger, capture = attach_log_capture("friTap.session")
    try:
        manager._on_termination_signal(signal.SIGINT, None)
    finally:
        logger.removeHandler(capture)

    assert exits == []
    assert "Press Ctrl+C again to force quit" in capture.text
    ssl_log.cleanup.assert_not_called()
    ssl_log.pcap_obj.kill_device_capture.assert_not_called()
    assert no_timer == [128 + signal.SIGINT]


def test_third_sigint_forces_exit_130_after_the_safety_steps(exits, no_timer):
    manager, ssl_log = _tearing_down_manager()
    manager._on_termination_signal(signal.SIGINT, None)

    with pytest.raises(_Exited):
        manager._on_termination_signal(signal.SIGINT, None)

    assert exits == [130]
    ssl_log.pcap_obj.kill_device_capture.assert_called_once()
    ssl_log._close_output_handlers_safely.assert_called_once()


def test_third_sigterm_forces_exit_143(exits, no_timer):
    manager, _ = _tearing_down_manager()
    manager._on_termination_signal(signal.SIGTERM, None)

    with pytest.raises(_Exited):
        manager._on_termination_signal(signal.SIGTERM, None)

    assert exits == [128 + signal.SIGTERM]


def test_a_signal_while_forcing_exits_at_once(exits):
    manager, ssl_log = _tearing_down_manager()
    manager._force_exit_lock.acquire()  # a forced exit is already running

    with pytest.raises(_Exited):
        manager._force_exit(130, "test")

    ssl_log.pcap_obj.kill_device_capture.assert_not_called()


def test_a_failing_kill_still_closes_the_outputs(exits):
    manager, ssl_log = _tearing_down_manager()
    ssl_log.pcap_obj.kill_device_capture.side_effect = RuntimeError("adb gone")

    with pytest.raises(_Exited):
        manager._force_exit(130, "test")

    ssl_log._close_output_handlers_safely.assert_called_once()
    assert exits == [130]


def test_hanging_safety_steps_cannot_block_the_forced_exit(exits, monkeypatch):
    monkeypatch.setattr(SessionManager, "FORCE_EXIT_STEPS_SECONDS", 0.2)
    manager, ssl_log = _tearing_down_manager()
    release = threading.Event()
    ssl_log._close_output_handlers_safely.side_effect = lambda: release.wait(5)

    started = time.monotonic()
    with pytest.raises(_Exited):
        manager._force_exit(130, "test")
    release.set()

    assert time.monotonic() - started < 2
    assert exits == [130]


def test_force_exit_timer_fires_when_the_teardown_hangs(monkeypatch):
    monkeypatch.setattr(SessionManager, "FORCE_EXIT_AFTER_SECONDS", 0.05)
    forced = []
    fired = threading.Event()

    def fake_force(self, status, reason):
        forced.append((status, reason))
        fired.set()

    monkeypatch.setattr(SessionManager, "_force_exit", fake_force)
    manager, _ = _tearing_down_manager()
    manager._on_termination_signal(signal.SIGINT, None)

    assert fired.wait(2)
    assert forced[0][0] == 130 and "still running" in forced[0][1]


def test_embedded_sessions_keep_ignoring_repeated_signals(exits, no_timer):
    ssl_log = MagicMock()
    ssl_log._embedded = True
    ssl_log._tui_mode = False
    manager = SessionManager(ssl_log)

    for _ in range(3):
        manager._on_termination_signal(signal.SIGINT, None)

    assert exits == [] and no_timer == []
    ssl_log.stop_fritap_session.assert_called_once()


# --- PCAP.kill_device_capture ----------------------------------------------

def _pcap_with_device_capture(tcpdump_pid=None, process=None):
    pcap = PCAP.__new__(PCAP)
    pcap.logger = MagicMock()
    android = MagicMock()
    android.tcpdump_pid = tcpdump_pid
    android._capture_pidfile.return_value = "/data/local/tmp/_cap.1-ab.pcap.pid"
    pcap.android_Instance = android
    pcap.full_capture_thread = SimpleNamespace(
        android_capture_process=process if process is not None else MagicMock())
    return pcap, android


def test_kill_device_capture_kills_the_known_pid_only_if_still_tcpdump():
    pcap, android = _pcap_with_device_capture(tcpdump_pid=4242)

    assert pcap.kill_device_capture() is True

    command = android.adb.shell.call_args.args[0]
    assert command.startswith("sh -c ")
    assert "p=4242;" in command and "/proc/$p/comm" in command and "kill -9 $p" in command
    assert android.adb.shell.call_args.kwargs["timeout"] == PCAP.FORCED_KILL_ADB_TIMEOUT
    pcap.full_capture_thread.android_capture_process.kill.assert_called_once()


def test_kill_device_capture_names_the_unpulled_device_file_only_after_a_kill():
    pcap, android = _pcap_with_device_capture(tcpdump_pid=4242)
    android.dst_path, android.pcap_name = "/data/local/tmp/", "_cap.1-ab.pcap"
    android.adb.shell.return_value = SimpleNamespace(stdout="")
    pcap.kill_device_capture()
    pcap.logger.info.assert_not_called()

    android.adb.shell.return_value = SimpleNamespace(stdout="killed\n")
    pcap.kill_device_capture()
    assert "/data/local/tmp/_cap.1-ab.pcap" in pcap.logger.info.call_args.args[0]


def test_kill_device_capture_reads_the_pidfile_when_the_pid_is_unknown():
    pcap, android = _pcap_with_device_capture(tcpdump_pid=None)

    pcap.kill_device_capture()

    assert 'cat "/data/local/tmp/_cap.1-ab.pcap.pid"' in android.adb.shell.call_args.args[0]


def test_kill_device_capture_is_a_noop_without_a_started_tcpdump():
    pcap, android = _pcap_with_device_capture(process=-1)

    assert pcap.kill_device_capture() is False
    android.adb.shell.assert_not_called()


def test_kill_device_capture_never_raises_and_ignores_the_teardown_lock():
    pcap, android = _pcap_with_device_capture(tcpdump_pid=7)
    android.adb.shell.side_effect = subprocess.TimeoutExpired("adb", 5)
    pcap._device_capture_lock = threading.RLock()
    holder_ready, release = threading.Event(), threading.Event()

    def hold_lock():
        with pcap._device_capture_lock:
            holder_ready.set()
            release.wait(5)

    holder = threading.Thread(target=hold_lock)
    holder.start()
    holder_ready.wait(2)
    try:
        assert pcap.kill_device_capture() is False
    finally:
        release.set()
        holder.join(2)


# --- real signals to a subprocess --------------------------------------------

_CHILD = textwrap.dedent("""
    import logging, os, sys, threading, time
    from types import SimpleNamespace
    from friTap.legacy.session_manager import SessionManager

    out = sys.argv[1]
    logging.basicConfig(stream=sys.stderr, level=logging.INFO, format="%(message)s")

    def mark(name):
        open(os.path.join(out, name), "w").close()

    class FakeLogger(SimpleNamespace):
        def set_exit_status(self, status):
            if not self._exit_status:
                self._exit_status = status

        def cleanup(self, *args):
            # A slow teardown (device pull, manifest); signals land in here.
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                time.sleep(0.05)
            mark("manifest")
            os._exit(self._exit_status)

        def _close_output_handlers_safely(self):
            mark("outputs_closed")

    pcap_obj = SimpleNamespace(kill_device_capture=lambda: mark("tcpdump_killed"))
    log = FakeLogger(_embedded=False, _tui_mode=False, _exit_status=0,
                     install_lsass_hook=False, full_capture=False, mobile=None,
                     pcap_name=None, pcap_obj=pcap_obj, live=False, socket_trace=False,
                     debug_output=False, debug=False, _done_event=threading.Event())
    manager = SessionManager(log)
    manager.install_signal_handler()
    print("ready", flush=True)
    while True:
        time.sleep(0.1)
""")


def _run_child(tmp_path, signum, count, gap=0.5):
    script = tmp_path / "child.py"
    script.write_text(_CHILD)
    env = dict(os.environ, PYTHONPATH=REPO_ROOT)
    child = subprocess.Popen([sys.executable, str(script), str(tmp_path)], cwd=REPO_ROOT,
                             env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        assert child.stdout.readline().strip() == "ready"
        for i in range(count):
            child.send_signal(signum)
            if i < count - 1:
                time.sleep(gap)
        _, stderr = child.communicate(timeout=30)
    finally:
        if child.poll() is None:
            child.kill()
    made = {name for name in ("manifest", "tcpdump_killed", "outputs_closed")
            if (tmp_path / name).exists()}
    return child.returncode, stderr, made


def test_real_double_sigint_finishes_the_teardown(tmp_path):
    rc, stderr, made = _run_child(tmp_path, signal.SIGINT, 2)

    assert rc == 0
    assert "Ctrl+C detected" in stderr and "force quit" in stderr
    assert made == {"manifest"}


def test_real_triple_sigint_forces_exit_130_and_kills_the_device_tcpdump(tmp_path):
    rc, stderr, made = _run_child(tmp_path, signal.SIGINT, 3)

    assert rc == 130
    assert "Forcing exit" in stderr
    assert made == {"tcpdump_killed", "outputs_closed"}


def test_real_double_sigterm_finishes_the_teardown_with_143(tmp_path):
    rc, _, made = _run_child(tmp_path, signal.SIGTERM, 2)

    assert rc == 128 + signal.SIGTERM
    assert made == {"manifest"}
