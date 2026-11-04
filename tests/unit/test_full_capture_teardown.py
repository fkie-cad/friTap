"""Full-capture temp paths and the idempotent device-capture teardown.

Live regressions this pins:
* the log said ``saved to _/private/.../cap.pcap`` -- "_" prefixed to the whole
  path instead of ``dirname/_basename``;
* after the target died, friTap left ``tcpdump`` running on the device and the
  pcap unfinalized: the teardown must run exactly once from every exit path
  (SIGINT, SIGTERM/script error, target detach, normal exit, atexit);
* finalizing a capture that never started raised an errno traceback.
"""

from __future__ import annotations

import logging
import os
import signal
import subprocess
import threading
from unittest.mock import MagicMock

import pytest

from friTap.legacy.session_manager import SessionManager
from friTap.pcap import PCAP, temp_capture_basename, temp_capture_path
from tests.unit._log_helpers import attach_log_capture

# ----------------------------------------------------------- temp path names

@pytest.mark.parametrize("output, expected", [
    ("cap.pcap", "_cap.pcap"),
    ("out/cap.pcap", os.path.join("out", "_cap.pcap")),
    ("/private/tmp/x/cap.pcap", "/private/tmp/x/_cap.pcap"),
    ("/cap.pcapng", "/_cap.pcapng"),
])
def test_temp_capture_path_prefixes_the_basename_only(output, expected):
    assert temp_capture_path(output) == expected
    assert not temp_capture_path(output).startswith("_/")


def test_temp_capture_basename_is_the_device_file_name():
    assert temp_capture_basename("/private/tmp/x/cap.pcap") == "_cap.pcap"


def test_thread_and_finalizer_agree_on_the_temp_path():
    pcap = _pcap("/private/tmp/x/cap.pcap")
    thread = pcap.get_instance_of_FullCaptureThread()

    assert thread._get_tmp_pcap_name() == pcap._temp_pcap_path() == "/private/tmp/x/_cap.pcap"


# ------------------------------------------------------- device teardown

def _pcap(output="/tmp/out/cap.pcap", process=None):
    """A PCAP wired to a fake Android device whose tcpdump is running."""
    pcap = object.__new__(PCAP)
    pcap.pcap_file_name = output
    pcap.is_Mobile = True
    pcap.owner_capture = False
    pcap.logger = MagicMock()
    pcap._device_capture_lock = threading.RLock()
    pcap.android_Instance = MagicMock()
    pcap.android_Instance.pull_pcap_from_device.return_value = "/tmp/out/_cap.pcap"
    pcap.full_capture_thread = MagicMock(
        android_capture_process=process if process is not None else MagicMock())
    return pcap


def test_device_teardown_runs_once_from_many_paths():
    pcap = _pcap()

    results = [pcap.stop_device_capture() for _ in range(3)]  # SIGINT, detach, atexit
    threads = [threading.Thread(target=pcap.stop_device_capture) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    android = pcap.android_Instance
    android.stop_tcpdump_gracefully.assert_called_once()
    android.pull_pcap_from_device.assert_called_once_with(
        "/tmp/out", local_path="/tmp/out/_cap.pcap")
    android.remove_device_capture.assert_called_once()
    assert results == ["/tmp/out/_cap.pcap"] * 3


def test_device_teardown_order_is_stop_pull_remove():
    pcap = _pcap()
    android = pcap.android_Instance

    pcap.stop_device_capture()

    names = [c[0] for c in android.method_calls]
    assert names == ["stop_tcpdump_gracefully", "pull_pcap_from_device", "remove_device_capture"]


def test_teardown_of_a_capture_that_never_started_is_a_quiet_no_op():
    pcap = _pcap(process=-1)

    assert pcap.stop_device_capture() is None
    assert pcap.android_Instance.method_calls == []
    pcap.logger.error.assert_not_called()
    assert "not started" in pcap.logger.info.call_args[0][0]


def test_teardown_never_raises_and_still_removes_the_device_file():
    pcap = _pcap()
    pcap.android_Instance.pull_pcap_from_device.side_effect = subprocess.TimeoutExpired("adb", 30)

    assert pcap.stop_device_capture() is None
    pcap.android_Instance.remove_device_capture.assert_called_once()


def test_tcpdump_is_not_started_once_the_teardown_ran():
    pcap = _pcap()
    android = pcap.android_Instance
    android.is_Android = True
    android.adb_check_root.return_value = True
    android.is_tcpdump_available = True
    thread = pcap.get_instance_of_FullCaptureThread()
    pcap.stop_device_capture()  # session ended before the capture thread got going

    assert thread.full_mobile_capture() == -1
    android.run_tcpdump_capture.assert_not_called()


def test_capture_thread_join_delegates_to_the_shared_teardown():
    pcap = _pcap()
    process = MagicMock()
    process.poll.return_value = None
    thread = pcap.get_instance_of_FullCaptureThread()
    thread.run = lambda: None  # the real run() would start a capture
    thread.start()
    thread.android_capture_process = process
    pcap.full_capture_thread = thread

    thread.join(1.0)
    thread.join(1.0)

    pcap.android_Instance.stop_tcpdump_gracefully.assert_called_once_with(process)


# --------------------------------------------------- finalize, no capture

def test_finalizing_a_capture_that_never_started_is_informational(tmp_path):
    pcap = object.__new__(PCAP)
    pcap.pcap_file_name = str(tmp_path / "cap.pcap")
    pcap.logger = MagicMock()
    pcap._write_capture_manifest = MagicMock()

    pcap.finalize_full_capture()

    pcap.logger.error.assert_not_called()
    assert "never started" in pcap.logger.info.call_args[0][0]
    pcap._write_capture_manifest.assert_not_called()
    assert not os.path.exists(pcap.pcap_file_name)


def test_full_capture_info_logs_name_only_the_existing_output(tmp_path):
    """Teardown + finalize: the one "written to" line names the file that exists.

    A live ``-f -p cap.pcap`` run used to log "saved to _cap.pcap" (the staging
    copy, renamed away at finalize) before "Full capture written to cap.pcap".
    """
    output = tmp_path / "cap.pcap"
    temp = tmp_path / "_cap.pcap"
    temp.write_bytes(b"\xd4\xc3\xb2\xa1")
    logger, capture = attach_log_capture("friTap.session")
    try:
        pcap_obj = MagicMock()
        pcap_obj.stop_device_capture.return_value = str(temp)
        _session(pcap_obj)[0].pcap_cleanup(True, "emu", str(output))
    finally:
        logger.removeHandler(capture)
    pcap = object.__new__(PCAP)
    pcap.pcap_file_name = str(output)
    pcap.pcap_container = "pcap"
    pcap.logger = MagicMock()
    pcap._write_capture_manifest = MagicMock()
    pcap._observed_server_ports = {}

    pcap.finalize_full_capture()

    info = capture.messages(logging.INFO) + [c[0][0] for c in pcap.logger.info.call_args_list]
    written = [m for m in info if "written to" in m or "saved to" in m]
    assert written == [f"Full capture written to {output}"]
    assert output.exists() and not temp.exists()


# ------------------------------------------- Android tcpdump stop sequence

class _FakeAndroid:
    """Just the attributes stop_tcpdump_gracefully touches."""

    def __init__(self, pid_answers):
        from friTap.android import Android

        self._impl = Android.__new__(Android)
        self._impl.logger = MagicMock()
        self._impl.__dict__["is_tcpdump_available"] = True
        self._impl.__dict__["adb"] = MagicMock()
        self.answers = list(pid_answers)
        self._impl.get_pids = self._get_pids

    def _get_pids(self, name, timeout=10):
        answer = self.answers.pop(0) if len(self.answers) > 1 else self.answers[0]
        if answer is TimeoutError:
            raise subprocess.TimeoutExpired("adb", timeout)
        return answer

    def shell_commands(self):
        return [c.args[0] for c in self._impl.adb.shell.call_args_list]


def test_tcpdump_stop_retries_a_timed_out_pidof_instead_of_giving_up():
    fake = _FakeAndroid([TimeoutError, [4242], []])
    process = MagicMock()

    fake._impl.stop_tcpdump_gracefully(process, grace_seconds=0)

    assert fake.shell_commands() == ["kill -INT 4242"]
    process.terminate.assert_called_once()


def test_tcpdump_that_ignores_sigint_is_killed():
    fake = _FakeAndroid([[4242], [4242], []])

    fake._impl.stop_tcpdump_gracefully(None, grace_seconds=0)

    assert fake.shell_commands() == ["kill -INT 4242", "kill -KILL 4242"]


def test_tcpdump_stop_never_raises_even_if_adb_keeps_timing_out():
    fake = _FakeAndroid([TimeoutError])

    fake._impl.stop_tcpdump_gracefully(MagicMock(), grace_seconds=0)

    assert "may still be running" in fake._impl.logger.warning.call_args[0][0]


def test_remove_device_capture_deletes_the_temp_file():
    from friTap.android import Android

    android = Android.__new__(Android)
    android.logger = MagicMock()
    android.pcap_name = "_cap.pcap"
    android.__dict__["adb"] = MagicMock()

    android.remove_device_capture()

    android.adb.shell.assert_called_once_with(
        'rm -f "/data/local/tmp/_cap.pcap" "/data/local/tmp/_cap.pcap.pid"', timeout=10)


def test_pull_returns_the_local_path_and_logs_adbs_stderr_summary():
    from friTap.android import Android

    android = Android.__new__(Android)
    android.logger = MagicMock()
    android.pcap_name = "_cap.pcap"
    android.__dict__["is_Android"] = True
    android.__dict__["adb"] = MagicMock()
    android.adb.run.return_value = MagicMock(
        returncode=0, stdout="", stderr="/data/local/tmp/_cap.pcap: 1 file pulled\n")

    assert android.pull_pcap_from_device("/tmp/out") == "/tmp/out/_cap.pcap"
    assert "1 file pulled" in android.logger.info.call_args[0][0]


# ------------------------------------------------ SessionManager wiring

def _session(pcap_obj, mobile="emulator-5556"):
    ssl_log = MagicMock()
    # Real PCAP attributes the decryption hint reads.
    pcap_obj.pcap_file_name = "cap.pcap"
    pcap_obj.pcap_container = "pcap"
    ssl_log.pcap_obj = pcap_obj
    ssl_log.keylog_file = None
    ssl_log.full_capture = True
    ssl_log.mobile = mobile
    ssl_log._exit_status = 0
    ssl_log._done_event = threading.Event()
    return SessionManager(ssl_log), ssl_log


def test_pcap_cleanup_is_idempotent_across_exit_paths(tmp_path):
    pcap_obj = MagicMock()
    temp = tmp_path / "_cap.pcap"
    temp.write_bytes(b"\xd4\xc3\xb2\xa1")
    pcap_obj.stop_device_capture.return_value = str(temp)
    manager, _ = _session(pcap_obj)

    threads = [threading.Thread(target=manager.pcap_cleanup, args=(True, "emu", "cap.pcap"))
               for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    manager.pcap_cleanup(True, "emu", "cap.pcap")

    pcap_obj.stop_device_capture.assert_called_once()
    pcap_obj.full_capture_thread.join.assert_called_once()


def test_pcap_cleanup_logs_the_real_temp_path(tmp_path):
    logger, capture = attach_log_capture("friTap.session")
    try:
        pcap_obj = MagicMock()
        temp = tmp_path / "_cap.pcap"
        temp.write_bytes(b"\xd4\xc3\xb2\xa1")
        pcap_obj.stop_device_capture.return_value = str(temp)
        manager, _ = _session(pcap_obj)

        manager.pcap_cleanup(True, "emu", str(tmp_path / "cap.pcap"))
    finally:
        logger.removeHandler(capture)

    assert f"staged at {temp}" in capture.text
    assert "saved to _/" not in capture.text


def test_pcap_cleanup_info_log_names_no_temp_file(tmp_path):
    """The staging copy is renamed away at finalize: the user-facing (INFO)
    log must not claim the capture was saved to it ("saved to _cap.pcap")."""
    logger, capture = attach_log_capture("friTap.session")
    try:
        pcap_obj = MagicMock()
        temp = tmp_path / "_cap.pcap"
        temp.write_bytes(b"\xd4\xc3\xb2\xa1")
        pcap_obj.stop_device_capture.return_value = str(temp)
        manager, _ = _session(pcap_obj)
        manager.pcap_cleanup(True, "emu", str(tmp_path / "cap.pcap"))
    finally:
        logger.removeHandler(capture)

    info = "\n".join(capture.messages(logging.INFO))
    assert str(temp) not in info and "saved to" not in info


def test_pcap_cleanup_without_capture_data_says_so(tmp_path):
    logger, capture = attach_log_capture("friTap.session")
    try:
        pcap_obj = MagicMock()
        pcap_obj.stop_device_capture.return_value = None
        manager, _ = _session(pcap_obj)
        manager.pcap_cleanup(True, "emu", "cap.pcap")
    finally:
        logger.removeHandler(capture)

    assert "no capture data was recorded" in capture.text
    assert "saved to" not in capture.text


class _Exited(BaseException):
    """Stands in for os._exit: records the status and stops the handler."""


@pytest.fixture
def exits(monkeypatch):
    calls = []

    def fake_exit(status):
        calls.append(status)
        raise _Exited(status)

    monkeypatch.setattr("friTap.legacy.session_manager.os._exit", fake_exit)
    return calls


def test_signal_handler_covers_sigint_and_sigterm(monkeypatch):
    installed = {}
    monkeypatch.setattr(signal, "signal", lambda signum, handler: installed.setdefault(signum, handler))
    manager, _ = _session(MagicMock())

    manager.install_signal_handler()

    assert set(installed) == {signal.SIGINT, signal.SIGTERM}


def test_sigterm_runs_the_full_teardown_with_a_failure_status(exits):
    pcap_obj = MagicMock()
    pcap_obj.stop_device_capture.return_value = None
    manager, ssl_log = _session(pcap_obj)
    ssl_log.install_lsass_hook = False
    ssl_log._done_event.set()

    with pytest.raises(_Exited):
        manager._on_termination_signal(signal.SIGTERM, None)

    pcap_obj.stop_device_capture.assert_called_once()
    ssl_log.cleanup.assert_called_once()
    ssl_log.set_exit_status.assert_called_once_with(128 + signal.SIGTERM)
    assert exits == [128 + signal.SIGTERM]


def test_sigint_keeps_exit_status_zero(exits):
    manager, ssl_log = _session(MagicMock())
    ssl_log.install_lsass_hook = False
    ssl_log._done_event.set()

    with pytest.raises(_Exited):
        manager._on_termination_signal(signal.SIGINT, None)

    assert exits == [0]


def test_a_failing_capture_stop_does_not_skip_cleanup(exits):
    pcap_obj = MagicMock()
    pcap_obj.stop_device_capture.side_effect = RuntimeError("adb exploded")
    manager, ssl_log = _session(pcap_obj)
    ssl_log.install_lsass_hook = False
    ssl_log._done_event.set()

    with pytest.raises(_Exited):
        manager._on_termination_signal(signal.SIGINT, None)

    ssl_log.cleanup.assert_called_once()


def test_second_signal_forces_the_exit_immediately(exits):
    manager, ssl_log = _session(MagicMock())
    manager._exit_signal_received = True

    with pytest.raises(_Exited):
        manager._on_termination_signal(signal.SIGINT, None)

    assert exits == [0]
    ssl_log.cleanup.assert_not_called()
