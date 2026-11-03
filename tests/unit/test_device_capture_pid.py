"""Device capture isolation between concurrent friTap runs.

Live regressions this pins:
* two runs with the same ``-p`` basename both wrote ``/data/local/tmp/_cap.pcap``
  -- the device file name is now unique per run and used for start, pull and
  remove;
* the tcpdump stop killed every tcpdump on the device -- only the pid friTap
  recorded (pidfile next to the temp file) is stopped; the name-based kill is a
  warned fallback when that pid is unknown.
"""

from __future__ import annotations

import os
import re
import shlex
from types import SimpleNamespace
from unittest.mock import MagicMock

from friTap.pcap import device_capture_basename

# ----------------------------------------------------------- unique names

def test_device_name_is_unique_per_run_and_keeps_the_extension():
    names = {device_capture_basename("/tmp/x/cap.pcap") for _ in range(50)}
    assert len(names) == 50
    for name in names:
        assert re.fullmatch(rf"_cap\.{os.getpid()}-[0-9a-f]{{6}}\.pcap", name)


def test_device_name_is_shell_safe():
    name = device_capture_basename("/tmp/my cap's;rm.pcapng")
    assert re.fullmatch(r"[A-Za-z0-9._-]+", name)
    assert name.endswith(".pcapng")


# ------------------------------------------------------- fake device

def _android(shell_answers=None, pcap_name="_cap.1-abcdef.pcap"):
    """An Android whose adb.shell answers by command prefix."""
    from friTap.android import Android

    android = Android.__new__(Android)
    android.logger = MagicMock()
    android.pcap_name = pcap_name
    android.__dict__["is_tcpdump_available"] = True
    android.__dict__["adb"] = MagicMock()
    answers = dict(shell_answers or {})

    def shell(cmd, **_kwargs):
        for prefix, reply in answers.items():
            if cmd.startswith(prefix):
                value = reply.pop(0) if isinstance(reply, list) and len(reply) > 1 else (
                    reply[0] if isinstance(reply, list) else reply)
                if isinstance(value, Exception):
                    raise value
                return SimpleNamespace(stdout=value, stderr="", returncode=0)
        return SimpleNamespace(stdout="", stderr="", returncode=0)

    android.adb.shell.side_effect = shell
    android.get_pids = MagicMock(return_value=[111, 222])
    return android


def _shell_commands(android):
    return [c.args[0] for c in android.adb.shell.call_args_list]


# ------------------------------------------------------------- start

def test_start_records_the_pid_via_pidfile_and_unique_name():
    android = _android()
    android.__dict__["adb"] = MagicMock()
    android.is_Android = True

    android.run_tcpdump_capture("_cap.42-a1b2c3.pcap")

    (cmd,), kwargs = android.adb.shell.call_args
    assert kwargs == {"background": True}
    sh, dash_c, script = shlex.split(cmd)
    assert (sh, dash_c) == ("sh", "-c")
    assert script.startswith('echo $$ > "/data/local/tmp/_cap.42-a1b2c3.pcap.pid"; exec ')
    assert "-w /data/local/tmp/_cap.42-a1b2c3.pcap" in script
    assert android.tcpdump_pid is None   # read lazily from the pidfile at stop


def test_pidfile_command_survives_the_magisk_elevator():
    from friTap.android import MagiskADB

    android = _android()
    elevated = MagiskADB._elevator(None, android._with_pidfile("tcpdump -w x \"not port 1\""))
    # device sh -> su -c <arg> -> sh -c <script>
    (su, dash_c, inner), = [shlex.split(elevated)]
    assert (su, dash_c) == ("su", "-c")
    assert shlex.split(inner)[:2] == ["sh", "-c"]
    assert shlex.split(inner)[2].startswith('echo $$ > "')


# -------------------------------------------------------------- stop

def test_stop_signals_only_the_recorded_pid():
    android = _android({
        "cat \"/data/local/tmp/_cap.1-abcdef.pcap.pid\"": "4242\n",
        "cat /proc/4242/comm": ["tcpdump_arm64_a\n", ""],
    })
    process = MagicMock()

    android.stop_tcpdump_gracefully(process, grace_seconds=0)

    kills = [c for c in _shell_commands(android) if c.startswith("kill")]
    assert kills == ["kill -INT 4242"]
    android.get_pids.assert_not_called()   # no name-based lookup
    process.terminate.assert_called_once()
    android.logger.warning.assert_not_called()


def test_stop_escalates_to_sigkill_for_the_recorded_pid():
    android = _android({
        "cat \"/data/local/tmp/_cap.1-abcdef.pcap.pid\"": "4242",
        "cat /proc/4242/comm": ["tcpdump\n", "tcpdump\n", ""],
    })

    android.stop_tcpdump_gracefully(None, grace_seconds=0)

    kills = [c for c in _shell_commands(android) if c.startswith("kill")]
    assert kills == ["kill -INT 4242", "kill -KILL 4242"]


def test_recycled_pid_is_treated_as_gone():
    android = _android({
        "cat \"/data/local/tmp/_cap.1-abcdef.pcap.pid\"": "4242",
        "cat /proc/4242/comm": "com.example.app\n",
    })

    android.stop_tcpdump_gracefully(None, grace_seconds=0)

    assert not [c for c in _shell_commands(android) if c.startswith("kill")]


def test_unknown_pid_falls_back_to_name_based_kill_with_warning():
    android = _android({"cat \"/data/local/tmp/": ""})   # empty pidfile
    android.get_pids.side_effect = [[111, 222], []]

    android.stop_tcpdump_gracefully(None, grace_seconds=0)

    kills = [c for c in _shell_commands(android) if c.startswith("kill")]
    assert kills == ["kill -INT 111 222"]
    assert "unknown" in android.logger.warning.call_args_list[0][0][0]


def test_unreadable_pidfile_falls_back_too():
    android = _android({"cat \"/data/local/tmp/": TimeoutError("adb")})
    android.get_pids.side_effect = [[]]

    android.stop_tcpdump_gracefully(None, grace_seconds=0)

    android.get_pids.assert_called_once()


def test_stop_twice_is_harmless():
    android = _android({
        "cat \"/data/local/tmp/_cap.1-abcdef.pcap.pid\"": "4242",
        "cat /proc/4242/comm": ["tcpdump", ""],
    })

    android.stop_tcpdump_gracefully(None, grace_seconds=0)
    android.stop_tcpdump_gracefully(None, grace_seconds=0)

    kills = [c for c in _shell_commands(android) if c.startswith("kill")]
    assert kills == ["kill -INT 4242"]


# ------------------------------------------------------ pull and remove

def test_pull_writes_the_unique_device_file_to_the_local_temp_path():
    android = _android()
    android.is_Android = True
    android.adb.run.return_value = SimpleNamespace(returncode=0, stdout="", stderr="1 file pulled")

    assert android.pull_pcap_from_device("/tmp/out", local_path="/tmp/out/_cap.pcap") \
        == "/tmp/out/_cap.pcap"
    android.adb.run.assert_called_once_with(
        "pull", "/data/local/tmp/_cap.1-abcdef.pcap", "/tmp/out/_cap.pcap", timeout=30)


def test_remove_deletes_the_unique_file_and_its_pidfile():
    android = _android()

    android.remove_device_capture()

    assert _shell_commands(android) == [
        'rm -f "/data/local/tmp/_cap.1-abcdef.pcap" '
        '"/data/local/tmp/_cap.1-abcdef.pcap.pid"']


# ------------------------------------------------------------------ TUI

def test_tui_result_stats_find_the_temp_capture_via_the_helper(tmp_path, monkeypatch):
    import pytest
    pytest.importorskip("textual")
    import friTap.pcap
    from tests.unit.test_tui_decrypt_to_flow import _make_controller

    out_dir = tmp_path / "out"
    out_dir.mkdir()
    (out_dir / "_cap.pcap").write_bytes(b"\x00" * 2048)
    calls = []
    real = friTap.pcap.temp_capture_path
    monkeypatch.setattr(friTap.pcap, "temp_capture_path",
                        lambda p: calls.append(p) or real(p))
    controller, _screen, _pushed, state = _make_controller()
    state.keylog_path = ""
    state.pcap_path = str(out_dir / "cap.pcap")

    stats = controller._gather_result_stats()

    assert calls == [str(out_dir / "cap.pcap")]
    assert "PCAP" in stats
