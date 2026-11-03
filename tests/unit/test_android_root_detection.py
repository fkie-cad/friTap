"""Tri-state Android root detection (friTap/android.py).

Live regression: while Frida attached to Chrome, `adb shell su 0 id -u` took
~1.01 s, the old 1 s probe timed out, ADB.find() silently fell through to the
plain transport and friTap concluded "unrooted" -- full capture (-f) was
dropped. A timeout must never be read as "not rooted": the probe now uses a
realistic timeout with one retry and reports ROOTED / NOT_ROOTED / UNKNOWN.
"""

from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, patch

import pytest

from friTap.android import ADB, MagiskADB, RootADB, RootState, SuADB
from tests.unit._log_helpers import attach_log_capture

PLAIN_UID = "id -u"
SU_UID = "su 0 id -u"
MAGISK_UID = "su -c 'id -u'"
SU_LOOKUP = "command -v su"


class FakeAdbShell:
    """Scripted `subprocess.run` for `adb shell <cmd>`.

    ``script`` maps a shell command to a list of outcomes consumed in order
    (the last one repeats): a string is stdout with returncode 0, an int is a
    bare returncode, ``TIMEOUT`` raises ``subprocess.TimeoutExpired``.
    """

    TIMEOUT = object()

    def __init__(self, script):
        self.script = {cmd: list(outcomes) for cmd, outcomes in script.items()}
        self.calls = []

    def __call__(self, argv, **kwargs):
        cmd = argv[argv.index("shell") + 1]
        self.calls.append((cmd, kwargs.get("timeout")))
        outcomes = self.script.get(cmd, [127])
        outcome = outcomes.pop(0) if len(outcomes) > 1 else outcomes[0]
        if outcome is self.TIMEOUT:
            raise subprocess.TimeoutExpired(argv, kwargs.get("timeout"))
        if isinstance(outcome, int):
            return MagicMock(returncode=outcome, stdout="", stderr="not found")
        return MagicMock(returncode=0, stdout=outcome, stderr="")

    def count(self, cmd):
        return sum(1 for called, _ in self.calls if called == cmd)


TIMEOUT = FakeAdbShell.TIMEOUT


@pytest.fixture
def session_log():
    logger, capture = attach_log_capture("friTap")
    yield capture
    logger.removeHandler(capture)


def _find(script):
    shell = FakeAdbShell(script)
    with patch("subprocess.run", side_effect=shell):
        adb = ADB.find(device_id="emulator-5556")
    return adb, shell


def test_su_timing_out_once_then_answering_is_rooted():
    adb, shell = _find({PLAIN_UID: ["2000\n"], SU_UID: [TIMEOUT, "0\n"]})

    assert type(adb) is SuADB
    assert adb.root_state is RootState.ROOTED
    assert adb.is_rooted is True
    assert shell.count(SU_UID) == 2


def test_su_timing_out_twice_with_su_present_assumes_root(session_log):
    adb, shell = _find({PLAIN_UID: ["2000\n"], SU_UID: [TIMEOUT],
                        MAGISK_UID: [1], SU_LOOKUP: ["/system/xbin/su\n"]})

    assert type(adb) is SuADB, "proceed with the su-based path"
    assert adb.root_state is RootState.UNKNOWN
    assert adb.is_rooted is True
    assert shell.count(SU_UID) == ADB.ROOT_PROBE_ATTEMPTS
    assert "assumes root" in session_log.text


def test_su_timing_out_twice_without_su_is_unknown_not_unrooted(session_log):
    adb, _shell = _find({PLAIN_UID: ["2000\n"], SU_UID: [TIMEOUT],
                         MAGISK_UID: [TIMEOUT], SU_LOOKUP: [1]})

    assert type(adb) is ADB
    assert adb.root_state is RootState.UNKNOWN
    assert adb.is_rooted is False
    assert "Could not determine whether the device is rooted" in session_log.text


def test_uid_zero_is_rooted():
    adb, _shell = _find({PLAIN_UID: ["0\n"]})

    assert type(adb) is RootADB
    assert adb.root_state is RootState.ROOTED


def test_non_zero_uid_everywhere_is_not_rooted():
    adb, shell = _find({PLAIN_UID: ["2000\n"], SU_UID: [127], MAGISK_UID: [127]})

    assert type(adb) is ADB
    assert adb.root_state is RootState.NOT_ROOTED
    assert adb.is_rooted is False
    assert shell.count(SU_LOOKUP) == 0, "a definite answer needs no su lookup"


def test_probe_uses_realistic_timeout():
    _adb, shell = _find({PLAIN_UID: ["0\n"]})

    assert shell.calls[0] == (PLAIN_UID, ADB.ROOT_PROBE_TIMEOUT)
    assert ADB.ROOT_PROBE_TIMEOUT >= 5


def test_slow_plain_probe_is_rechecked_not_guessed():
    # Only the plain `id -u` timed out; every su variant answered "no root".
    adb, _shell = _find({PLAIN_UID: [TIMEOUT, TIMEOUT, "2000\n"],
                         SU_UID: [127], MAGISK_UID: [127]})

    assert type(adb) is ADB
    assert adb.root_state is RootState.NOT_ROOTED


def test_unresponsive_adb_still_reports_no_adb():
    from friTap.fritap_utility import Failure

    with pytest.raises(Failure):
        _find({PLAIN_UID: [TIMEOUT], SU_UID: [127], MAGISK_UID: [127]})


def test_probe_uid_returns_none_after_repeated_timeouts():
    shell = FakeAdbShell({PLAIN_UID: [TIMEOUT]})
    with patch("subprocess.run", side_effect=shell):
        assert ADB().probe_uid() is None
    assert shell.count(PLAIN_UID) == ADB.ROOT_PROBE_ATTEMPTS


def test_probe_uid_raises_value_error_on_non_numeric_answer():
    shell = FakeAdbShell({SU_UID: [127]})
    with patch("subprocess.run", side_effect=shell), pytest.raises(ValueError):
        SuADB().probe_uid()


def test_only_su_elevators_are_marked_as_su():
    assert SuADB.uses_su and MagiskADB.uses_su
    assert not RootADB.uses_su and not ADB.uses_su


def test_android_root_state_falls_back_to_is_rooted():
    from friTap.android import Android

    android = Android(device_id="emulator-5556")
    android.__dict__["adb"] = SuADB(device_id="emulator-5556")  # untagged
    assert android.root_state is RootState.ROOTED


@pytest.mark.parametrize("state, expected", [
    (RootState.UNKNOWN, "could not determine whether the device is rooted"),
    (RootState.NOT_ROOTED, "requires a rooted device"),
])
def test_full_capture_explains_why_root_is_unavailable(state, expected):
    from friTap.pcap import PCAP

    pcap = object.__new__(PCAP)
    pcap.logger = MagicMock()
    pcap.android_Instance = MagicMock(root_state=state)

    pcap._log_root_unavailable()

    assert expected in pcap.logger.error.call_args[0][0]
