"""A failed or timed-out pull of the device full capture must not lose it (D6).

Live regressions this pins:
* ``[-] error pulling pcap ...`` was followed by deleting the device file, so the
  capture was gone for good; the file is now kept and the exact recovery
  ``adb pull`` command is logged;
* ``adb pull`` had a fixed 30 s timeout, too short for a large capture on a slow
  device; it now scales with the device file size, bounded by a cap.
"""

from __future__ import annotations

import subprocess
import threading
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from friTap.android import Android
from tests.unit._adb_pull_helpers import pull_timeout, reply_to_pull
from friTap.pcap import PCAP

DEVICE_FILE = "/data/local/tmp/_cap.1-abcdef.pcap"


def _android(stat_reply="", stat_rc=0, device_id="emulator-5562"):
    android = Android.__new__(Android)
    android.logger = MagicMock()
    android.device_id = device_id
    android.pcap_name = "_cap.1-abcdef.pcap"
    android.__dict__["is_Android"] = True
    android.__dict__["adb"] = MagicMock()

    def shell(cmd, **_kwargs):
        if cmd.startswith("stat -c %s"):
            if isinstance(stat_reply, Exception):
                raise stat_reply
            return SimpleNamespace(stdout=stat_reply, stderr="", returncode=stat_rc)
        return SimpleNamespace(stdout="", stderr="", returncode=0)

    android.adb.shell.side_effect = shell
    return android


def _pull_timeout(android):
    return pull_timeout(android)


def _shell_commands(android):
    return [c.args[0] for c in android.adb.shell.call_args_list]


# ------------------------------------------------------- timeout scaling

@pytest.mark.parametrize("size, expected", [
    (0, 30),
    (10 * 1024 * 1024, 50),
    (100 * 1024 * 1024, 230),
    (10 * 1024 * 1024 * 1024, 600),  # capped
    (None, 120),                      # size unknown
])
def test_pull_timeout_scales_with_size_and_is_capped(size, expected):
    assert Android.pull_timeout_for(size) == expected


def test_pull_uses_the_device_file_size_for_its_timeout(tmp_path):
    local = tmp_path / "_cap.pcap"
    local.write_bytes(b"x" * 10)
    android = _android(stat_reply=f"{100 * 1024 * 1024}\n")
    reply_to_pull(android)

    android.pull_pcap_from_device(str(tmp_path), local_path=str(local))

    assert f'stat -c %s "{DEVICE_FILE}"' in _shell_commands(android)
    assert _pull_timeout(android) == 230


@pytest.mark.parametrize("stat_reply, stat_rc", [
    ("stat: No such file or directory", 1),
    ("", 0),
    (subprocess.TimeoutExpired("adb", 10), 0),
])
def test_size_query_failure_falls_back_to_the_unknown_size_timeout(stat_reply, stat_rc):
    android = _android(stat_reply=stat_reply, stat_rc=stat_rc)
    reply_to_pull(android)

    assert android.pull_pcap_from_device("/tmp/out", local_path="/tmp/out/_cap.pcap") \
        == "/tmp/out/_cap.pcap"
    assert _pull_timeout(android) == Android.PULL_UNKNOWN_SIZE_TIMEOUT


# ---------------------------------------------------- failed / short pull

def test_timed_out_pull_returns_none_and_logs_the_timeout():
    android = _android(stat_reply="2048")
    reply_to_pull(android, raises=subprocess.TimeoutExpired("adb", 30))

    assert android.pull_pcap_from_device("/tmp/out", local_path="/tmp/out/_cap.pcap") is None
    message = android.logger.error.call_args[0][0]
    assert "timed out after 30 s" in message and DEVICE_FILE in message


def test_pull_shorter_than_the_device_file_counts_as_failed(tmp_path):
    local = tmp_path / "_cap.pcap"
    local.write_bytes(b"x" * 100)
    android = _android(stat_reply="5000")
    reply_to_pull(android)

    assert android.pull_pcap_from_device(str(tmp_path), local_path=str(local)) is None


def test_complete_pull_of_a_known_size_succeeds(tmp_path):
    local = tmp_path / "_cap.pcap"
    local.write_bytes(b"x" * 5000)
    android = _android(stat_reply="5000")
    reply_to_pull(android)

    assert android.pull_pcap_from_device(str(tmp_path), local_path=str(local)) == str(local)


# ----------------------------------------------------- keep + recovery line

def test_keep_for_recovery_keeps_the_pcap_and_logs_the_exact_pull_command():
    android = _android()

    android.keep_device_capture_for_recovery("/tmp/my out/_cap.pcap")

    assert _shell_commands(android) == [f'rm -f "{DEVICE_FILE}.pid"']
    message = android.logger.error.call_args[0][0]
    assert f"kept at {DEVICE_FILE}" in message
    assert message.endswith(
        f"recover it with: adb -s emulator-5562 pull {DEVICE_FILE} '/tmp/my out/_cap.pcap'")


def test_recovery_command_without_a_serial_has_no_dash_s():
    android = _android(device_id=None)
    assert android.recovery_pull_command("/tmp/_c.pcap") == f"adb pull {DEVICE_FILE} /tmp/_c.pcap"


def _pcap_with_real_android(android, output):
    pcap = object.__new__(PCAP)
    pcap.pcap_file_name = output
    pcap.is_Mobile = True
    pcap.owner_capture = False
    pcap.logger = MagicMock()
    pcap._device_capture_lock = threading.RLock()
    pcap.android_Instance = android
    pcap.full_capture_thread = MagicMock(android_capture_process=MagicMock())
    android.stop_tcpdump_gracefully = MagicMock()
    return pcap


def test_failed_pull_in_teardown_keeps_the_device_file(tmp_path):
    android = _android(stat_reply="2048")
    reply_to_pull(android, returncode=1, stderr="adb: error")
    pcap = _pcap_with_real_android(android, str(tmp_path / "cap.pcap"))

    assert pcap.stop_device_capture() is None

    commands = _shell_commands(android)
    assert not any(DEVICE_FILE + '"' in c and c.startswith("rm") for c in commands)
    assert f'rm -f "{DEVICE_FILE}.pid"' in commands
    recovery = android.logger.error.call_args[0][0]
    assert f"pull {DEVICE_FILE} {tmp_path / '_cap.pcap'}" in recovery


def test_successful_pull_in_teardown_still_deletes_the_device_file(tmp_path):
    android = _android(stat_reply="4")
    reply_to_pull(android)
    (tmp_path / "_cap.pcap").write_bytes(b"abcd")
    pcap = _pcap_with_real_android(android, str(tmp_path / "cap.pcap"))

    assert pcap.stop_device_capture() == str(tmp_path / "_cap.pcap")
    assert f'rm -f "{DEVICE_FILE}" "{DEVICE_FILE}.pid"' in _shell_commands(android)
