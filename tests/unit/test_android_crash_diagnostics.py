#!/usr/bin/env python3
"""Unit tests for the Android crash-diagnostic device I/O.

``Android.get_crash_logcat`` / ``Android.get_latest_tombstone`` own the
device-side shell knowledge (crash log buffer, tombstone layout) that the
crash-attribution path delegates to, so any handler (legacy or a future modern
one) can reuse them without embedding raw adb commands. They run on an
already-dead process as best-effort forensics and must therefore never raise;
they return empty results when the artifact is unavailable.

Exercised with a fake ADB following the ``__new__``-construction pattern used by
``test_crash_attribution.py`` — no device required.
"""

import logging

from friTap.android import Android


class _Result:
    def __init__(self, stdout="", returncode=0):
        self.stdout = stdout
        self.returncode = returncode


class FakeADB:
    """Replays canned stdout keyed by a command substring; records every call."""

    def __init__(self, responses=None, raises=False):
        self._responses = responses or {}
        self._raises = raises
        self.calls = []

    def shell(self, cmd, timeout=None, **kwargs):
        self.calls.append(cmd)
        if self._raises:
            raise RuntimeError("adb offline")
        for needle, out in self._responses.items():
            if needle in cmd:
                return _Result(stdout=out)
        return _Result(stdout="")


def _android(adb):
    """A bare Android bound to *adb*, bypassing the ``adb`` cached_property
    (which would otherwise call ADB.find() and need a real device)."""
    obj = Android.__new__(Android)
    obj.logger = logging.getLogger("test.android.crash")
    obj.__dict__["adb"] = adb  # cached_property is non-data → instance dict wins
    return obj


class TestGetCrashLogcat:
    def test_returns_crash_buffer(self):
        adb = FakeADB({"logcat -b crash": "F/libc: Fatal signal 6 (SIGABRT)"})
        andy = _android(adb)
        assert "SIGABRT" in andy.get_crash_logcat()
        assert any("logcat -b crash -d" in c for c in adb.calls)

    def test_empty_when_no_output(self):
        assert _android(FakeADB()).get_crash_logcat() == ""

    def test_never_raises(self):
        assert _android(FakeADB(raises=True)).get_crash_logcat() == ""


class TestGetLatestTombstone:
    _LISTING = "/data/tombstones/tombstone_02\n/data/tombstones/tombstone_01\n"

    def test_returns_newest_matching_pid(self):
        adb = FakeADB({
            "ls -t": self._LISTING,
            "cat": "signal 11 (SIGSEGV)\npid: 1234, cmdline: com.android.chrome",
        })
        path, text = _android(adb).get_latest_tombstone(pid=1234)
        assert path == "/data/tombstones/tombstone_02"
        assert "SIGSEGV" in text

    def test_matches_on_cmdline_hint_when_pid_absent(self):
        adb = FakeADB({
            "ls -t": self._LISTING,
            "cat": "signal 6 (SIGABRT)\npid: 9999, cmdline: com.android.chrome",
        })
        # With no pid supplied, a cmdline-only match is accepted.
        path, text = _android(adb).get_latest_tombstone(cmdline_hint="com.android.chrome")
        assert path == "/data/tombstones/tombstone_02"
        assert "SIGABRT" in text

    def test_requires_all_supplied_identifiers(self):
        # Both pid and cmdline are given → both must appear (AND semantics),
        # matching the original guard. Here the pid does not appear.
        adb = FakeADB({
            "ls -t": self._LISTING,
            "cat": "signal 6 (SIGABRT)\npid: 9999, cmdline: com.android.chrome",
        })
        assert _android(adb).get_latest_tombstone(pid=1234, cmdline_hint="com.android.chrome") == (None, "")

    def test_rejects_unrelated_tombstone(self):
        adb = FakeADB({
            "ls -t": self._LISTING,
            "cat": "signal 6 (SIGABRT)\npid: 9999, cmdline: com.other.app",
        })
        assert _android(adb).get_latest_tombstone(pid=1234, cmdline_hint="com.android.chrome") == (None, "")

    def test_no_tombstones(self):
        adb = FakeADB({"ls -t": ""})
        assert _android(adb).get_latest_tombstone(pid=1234) == (None, "")

    def test_no_filters_returns_newest(self):
        adb = FakeADB({"ls -t": self._LISTING, "cat": "signal 4 (SIGILL)"})
        path, text = _android(adb).get_latest_tombstone()
        assert path == "/data/tombstones/tombstone_02"
        assert "SIGILL" in text

    def test_never_raises(self):
        assert _android(FakeADB(raises=True)).get_latest_tombstone(pid=1234) == (None, "")
