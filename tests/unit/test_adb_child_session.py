"""friTap's adb children run in their own session, so a terminal Ctrl+C misses them.

The terminal delivers Ctrl+C to the whole foreground process group. A 2nd
Ctrl+C during teardown used to SIGINT the `adb pull` of the full capture too
and lose the pcap. Every adb child is now started with start_new_session=True
(POSIX); friTap still stops them itself with terminate()/kill().
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import textwrap
import time
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

import friTap.android as android_mod
from friTap.android import ADB, Android, adb_child_kwargs

posix_only = pytest.mark.skipif(os.name != "posix", reason="POSIX sessions only")


@posix_only
def test_posix_children_get_their_own_session():
    assert adb_child_kwargs() == {"start_new_session": True}


def test_windows_children_keep_the_default(monkeypatch):
    monkeypatch.setattr(android_mod, "os", SimpleNamespace(name="nt"))
    assert adb_child_kwargs() == {}


@posix_only
@pytest.mark.parametrize("call", [
    lambda adb: adb.run("pull", "/data/local/tmp/_x.pcap", "/tmp/_x.pcap", timeout=30),
    lambda adb: adb.shell("kill -INT 1234", timeout=20),
    lambda adb: adb.shell('rm -f "/data/local/tmp/_x.pcap"', timeout=10),
])
def test_teardown_adb_calls_run_in_their_own_session(call):
    with patch.object(android_mod.subprocess, "run") as run:
        call(ADB(device_id="emulator-5562"))
    argv = run.call_args.args[0]
    assert argv[:3] == ["adb", "-s", "emulator-5562"]
    assert run.call_args.kwargs["start_new_session"] is True


@posix_only
def test_full_capture_pull_runs_in_its_own_session():
    android = Android.__new__(Android)
    android._adb = ADB(device_id="emulator-5562")
    with patch.object(Android, "adb", new=android._adb), \
            patch.object(android_mod.subprocess, "Popen") as popen:
        popen.return_value.communicate.return_value = ("", "1 file pulled")
        android._adb_pull_file("/data/local/tmp/_x.pcap", "/tmp/_x.pcap")
    # A tracked Popen since D7 (a forced exit kills it), still in its own session.
    assert popen.call_args.args[0][3] == "pull"
    assert popen.call_args.kwargs["start_new_session"] is True


@posix_only
def test_background_tcpdump_client_runs_in_its_own_session():
    with patch.object(android_mod.subprocess, "Popen") as popen:
        ADB().shell("tcpdump -w /data/local/tmp/x.pcap", background=True)
    kwargs = popen.call_args.kwargs
    assert kwargs["start_new_session"] is True
    assert kwargs["stdout"] is subprocess.PIPE  # the existing defaults are kept


@posix_only
def test_device_probes_run_in_their_own_session():
    android = Android.__new__(Android)
    android.logger = MagicMock()
    completed = subprocess.CompletedProcess([], 0, stdout="List of devices attached\n", stderr="")
    with patch.object(android_mod.subprocess, "run", return_value=completed) as run:
        android.check_adb_availability()
        android.list_devices()
    assert [c.kwargs["start_new_session"] for c in run.call_args_list] == [True, True]


def test_an_explicit_caller_kwarg_wins():
    with patch.object(android_mod.subprocess, "run") as run:
        android_mod.run_adb(["adb", "devices"], start_new_session=False)
    assert run.call_args.kwargs["start_new_session"] is False


# A stand-in for friTap: the leader of its own process group (like a shell job)
# with one child started through popen_adb and one plain child.
_GROUP_LEADER = textwrap.dedent("""
    import json, subprocess, sys, time
    from friTap.android import popen_adb
    protected = popen_adb(["sleep", "30"])
    plain = subprocess.Popen(["sleep", "30"])
    print(json.dumps({"protected": protected.pid, "plain": plain.pid}), flush=True)
    time.sleep(30)
""")


def _alive(pid):
    try:
        finished, _status = os.waitpid(pid, os.WNOHANG)
    except ChildProcessError:  # not our child: probe it instead
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        return _not_zombie(pid)
    return finished == 0


def _not_zombie(pid):
    state = subprocess.run(["ps", "-o", "stat=", "-p", str(pid)],
                           capture_output=True, text=True).stdout.strip()
    return bool(state) and not state.startswith("Z")


def _wait_until_dead(pid, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not _alive(pid):
            return True
        time.sleep(0.05)
    return False


@posix_only
def test_group_sigint_spares_the_adb_child():
    repo_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    leader = subprocess.Popen([sys.executable, "-c", _GROUP_LEADER], cwd=repo_root,
                              stdout=subprocess.PIPE, text=True, start_new_session=True)
    pids = {}
    try:
        pids = json.loads(leader.stdout.readline())
        os.killpg(leader.pid, signal.SIGINT)  # what the terminal does on Ctrl+C
        leader.wait(timeout=10)
        assert _wait_until_dead(pids["plain"]), "control child should die on the group SIGINT"
        time.sleep(0.3)
        assert _alive(pids["protected"]), "adb child must survive the group SIGINT"
    finally:
        for pid in pids.values():
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        if leader.poll() is None:
            leader.kill()


@posix_only
def test_friTaps_own_kill_paths_still_reach_the_child():
    """The teardown reaps the adb client explicitly; a new session must not hide it."""
    import psutil
    android = Android.__new__(Android)
    android.logger = MagicMock()
    reaped = android_mod.popen_adb(["sleep", "30"])
    android._reap_local_process(reaped, timeout=5)
    assert reaped.poll() is not None
    # pcap.terminate_lingering_processes() walks psutil's child list; the new
    # session leaves the parent/child link intact, so it still finds the client.
    lingering = android_mod.popen_adb(["sleep", "30"])
    try:
        assert lingering.pid in [c.pid for c in psutil.Process().children(recursive=True)]
    finally:
        lingering.kill()
        lingering.wait(timeout=5)
