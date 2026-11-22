#!/usr/bin/env python3
"""Unit tests for the Android crash-evidence sources beyond tombstone/logcat.

Gecko (Firefox) and Crashpad (Chromium) apps write their OWN minidumps into
app-private storage and often leave no tombstone, and the system records Java
crashes / ANRs in the ``events`` buffer (``am_crash`` / ``am_anr``). Without
these a dead Firefox was reported as "no crash evidence; possibly
killed/force-stopped". Covered here:

* the pure parsers (``stat`` listing, events-buffer payloads),
* the app-private directory list (Gecko + Crashpad) and its shell command,
* root / no-root behaviour of the adb I/O (subprocess mocked, no device),
* headline selection and priority, end to end through ``_report_target_crash``.
"""

import logging
import subprocess
import time
import types

import pytest

from friTap.android import ADB, Android, MagiskADB, SuADB
from friTap.legacy.ssl_logger_core import SSL_Logger

PKG = "org.mozilla.firefox"
GECKO_DUMP = f"/data/data/{PKG}/files/mozilla/abc.default/minidumps/1f2e.dmp"
PENDING_DUMP = f"/data/data/{PKG}/files/mozilla/Crash Reports/pending/9a8b.dmp"


def _stamp(epoch):
    """Year-less threadtime logcat stamp in host-local time."""
    return time.strftime("%m-%d %H:%M:%S.000", time.localtime(epoch))


def _host_offset(epoch):
    return time.localtime(epoch).tm_gmtoff


# --------------------------------------------------------------------------
# App-private minidump directories + listing command
# --------------------------------------------------------------------------

class TestMinidumpDirs:
    def test_gecko_and_crashpad_dirs(self):
        dirs = Android.app_minidump_dirs(PKG)
        base = f"/data/data/{PKG}"
        assert f"{base}/files/mozilla/*/minidumps" in dirs
        assert f"{base}/files/mozilla/Crash Reports/pending" in dirs
        for crashpad in ("files/crashpad", "cache/Crashpad"):
            for sub in ("", "/pending", "/completed", "/new"):
                assert f"{base}/{crashpad}{sub}" in dirs

    @pytest.mark.parametrize("bad", ["", None, "1234", "firefox", "a.b; rm -rf /"])
    def test_rejects_non_package_names(self, bad):
        assert Android.app_minidump_dirs(bad) == []

    def test_command_keeps_glob_and_space(self):
        cmd = Android.minidump_listing_command(Android.app_minidump_dirs(PKG))
        assert cmd.startswith("sh -c '") and cmd.endswith("'")
        assert f'"/data/data/{PKG}/files/mozilla/"*"/minidumps"' in cmd
        assert f'"/data/data/{PKG}/files/mozilla/Crash Reports/pending"' in cmd
        assert 'stat -c "%Y %n"' in cmd
        assert cmd.count("'") == 2  # no inner single quotes: elevators can wrap it


# --------------------------------------------------------------------------
# Pure parsers
# --------------------------------------------------------------------------

class TestNewMinidumpsFromStat:
    def test_keeps_new_dumps_newest_first_with_spaces(self):
        out = "\n".join([
            f"1000 {GECKO_DUMP}",
            f"2000 {PENDING_DUMP}",
            "500 /data/data/x/files/crashpad/completed/old.dmp",
            "garbage line",
            "1500 /data/data/x/files/not-a-dump.txt",
        ])
        assert SSL_Logger._new_minidumps_from_stat(out, 900) == [PENDING_DUMP, GECKO_DUMP]

    def test_nothing_without_cutoff_or_output(self):
        assert SSL_Logger._new_minidumps_from_stat(f"1000 {GECKO_DUMP}", None) == []
        assert SSL_Logger._new_minidumps_from_stat("", 0) == []

    def test_minidump_since_prefers_device_clock(self):
        obj = SSL_Logger.__new__(SSL_Logger)
        obj._session_start_time = 10_000.0
        assert obj._minidump_since(12_345.0) == 12_345.0
        assert obj._minidump_since(None) == 10_000.0 - SSL_Logger.MINIDUMP_FALLBACK_CLOCK_TOLERANCE
        obj._session_start_time = None
        assert obj._minidump_since(None) is None


class TestAmEventRecords:
    def _buf(self, now):
        old, new = _stamp(now - 3600), _stamp(now)
        return "\n".join([
            f"{old}  1000  1500 I am_crash: [0,4242,{PKG},12345,java.lang.Old,stale,Foo.java,1,0]",
            f"{new}  1000  1500 I am_crash: [0,7777,com.other.app,0,java.lang.X,boom,X.java,3,0]",
            f"{new}  1000  1500 I am_crash: [0,4242,{PKG},12345,Native crash,Segmentation fault, at x,unknown,0,0]",
            f"{new}  1000  1500 I am_anr: [0,4243,{PKG}:tab0,0,Input dispatching timed out, waited 5s]",
            f"{new}  1000  1500 I am_proc_died: [0,4242,{PKG},0,0]",
        ])

    def test_pid_match_and_time_filter(self):
        now = time.time()
        records = SSL_Logger._am_event_records_for(
            self._buf(now), PKG, 4242, now - 60, _host_offset(now), now)
        assert records == [("am_crash", "Native crash: Segmentation fault, at x")]

    def test_package_match_without_pid_includes_subprocesses(self):
        now = time.time()
        records = SSL_Logger._am_event_records_for(
            self._buf(now), PKG, None, now - 60, _host_offset(now), now)
        assert ("ANR", "Input dispatching timed out, waited 5s") in records
        assert all("com.other" not in d for _, d in records)

    def test_without_time_info_only_identity_filters(self):
        records = SSL_Logger._am_event_records_for(self._buf(time.time()), PKG, 4242, None)
        assert [lbl for lbl, _ in records] == ["am_crash", "am_crash"]

    def test_malformed_payloads_are_ignored(self):
        assert SSL_Logger._parse_am_event_payload("crash", "0,notapid,x,0,y") is None
        assert SSL_Logger._parse_am_event_payload("anr", "0,1") is None
        assert SSL_Logger._am_event_records_for("", PKG, 1, None) == []


class TestSelectCrashEvidence:
    def test_priority_tombstone_minidump_crash_anr(self):
        anr, crash = ("ANR", "timed out"), ("am_crash", "boom")
        select = SSL_Logger._select_crash_evidence
        assert select("/data/tombstones/tombstone_03", [GECKO_DUMP], [anr, crash]) == \
            ("tombstone", "/data/tombstones/tombstone_03")
        assert select(None, [PENDING_DUMP, GECKO_DUMP], [anr, crash]) == ("minidump", PENDING_DUMP)
        assert select(None, [], [anr, crash]) == ("am_crash", "boom")
        assert select(None, [], [anr]) == ("ANR", "timed out")
        assert select(None, [], []) is None


# --------------------------------------------------------------------------
# adb I/O: root / no-root (subprocess mocked)
# --------------------------------------------------------------------------

def _android_on(adb):
    obj = Android.__new__(Android)
    obj.logger = logging.getLogger("test.android.evidence")
    obj.__dict__["adb"] = adb
    return obj


class _Recorder:
    def __init__(self, stdout="", raises=None):
        self.calls, self._stdout, self._raises = [], stdout, raises

    def __call__(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        if self._raises:
            raise self._raises
        return subprocess.CompletedProcess(argv, 0, stdout=self._stdout, stderr="")


class TestListAppMinidumps:
    @pytest.mark.parametrize("adb_cls,prefix", [(MagiskADB, "su -c '"), (SuADB, "su 0 sh -c")])
    def test_rooted_runs_elevated_with_timeout(self, monkeypatch, adb_cls, prefix):
        run = _Recorder(stdout=f"1000 {PENDING_DUMP}\n")
        monkeypatch.setattr("friTap.android.subprocess.run", run)
        out = _android_on(adb_cls(device_id="SERIAL1")).list_app_minidumps(PKG)
        assert PENDING_DUMP in out
        (argv, kwargs), = run.calls
        assert argv[:4] == ["adb", "-s", "SERIAL1", "shell"]
        assert argv[4].startswith(prefix) and "Crash Reports/pending" in argv[4]
        assert kwargs["timeout"] == 15

    def test_unrooted_never_touches_app_storage(self, monkeypatch):
        run = _Recorder(stdout="should not be read")
        monkeypatch.setattr("friTap.android.subprocess.run", run)
        assert _android_on(ADB(device_id="SERIAL1")).list_app_minidumps(PKG) == ""
        assert run.calls == []

    def test_timeout_never_raises(self, monkeypatch):
        run = _Recorder(raises=subprocess.TimeoutExpired("adb", 15))
        monkeypatch.setattr("friTap.android.subprocess.run", run)
        assert _android_on(MagiskADB(device_id="S")).list_app_minidumps(PKG) == ""

    def test_invalid_package_skips_adb(self, monkeypatch):
        run = _Recorder()
        monkeypatch.setattr("friTap.android.subprocess.run", run)
        assert _android_on(MagiskADB(device_id="S")).list_app_minidumps("1234") == ""
        assert run.calls == []


class TestGetEventsLogcat:
    def test_reads_events_buffer_without_root(self, monkeypatch):
        run = _Recorder(stdout="I am_anr: [0,1,x.y,0,r]")
        monkeypatch.setattr("friTap.android.subprocess.run", run)
        assert "am_anr" in _android_on(ADB(device_id="S")).get_events_logcat()
        (argv, kwargs), = run.calls
        assert argv[-1] == "logcat -b events -d" and kwargs["timeout"] == 20

    def test_never_raises(self, monkeypatch):
        monkeypatch.setattr("friTap.android.subprocess.run",
                            _Recorder(raises=subprocess.TimeoutExpired("adb", 20)))
        assert _android_on(ADB(device_id="S")).get_events_logcat() == ""


# --------------------------------------------------------------------------
# Headline selection, unit + end to end
# --------------------------------------------------------------------------

class TestCrashHeadline:
    def test_minidump_without_decoded_cause(self):
        h = SSL_Logger._crash_headline(None, None, True, False, None, "",
                                       evidence=("minidump", PENDING_DUMP))
        assert h == f"Target process crashed (minidump: {PENDING_DUMP})"

    def test_anr_headline(self):
        h = SSL_Logger._crash_headline(None, None, True, False, None, "agent-init: complete",
                                       evidence=("ANR", "Input dispatching timed out"))
        assert h.startswith("Target process terminated — not responding "
                            "(ANR: Input dispatching timed out)")

    def test_signal_keeps_cause_and_appends_evidence(self):
        h = SSL_Logger._crash_headline("SIGSEGV", None, True, False, None, "",
                                       evidence=("tombstone", "/data/tombstones/tombstone_01"))
        assert h == ("Target process terminated unexpectedly — SIGSEGV "
                     "(tombstone: /data/tombstones/tombstone_01)")

    def test_evidence_overrides_no_evidence_and_clean_exit(self):
        ev = ("minidump", GECKO_DUMP)
        assert "no crash evidence" not in SSL_Logger._crash_headline(
            None, None, False, False, None, "", evidence=ev)
        assert "exited" not in SSL_Logger._crash_headline(
            None, None, False, True, None, "agent-init: complete", evidence=ev)

    def test_unchanged_without_evidence(self):
        assert SSL_Logger._crash_headline(None, None, False, False, None, "") == (
            "Target process terminated (no crash evidence; possibly killed/force-stopped)")


class _FakeAndroid:
    def __init__(self, rooted=True, minidumps="", events="", tombstone=(None, "")):
        self._rooted, self._minidumps, self._events = rooted, minidumps, events
        self._tombstone = tombstone
        self.minidump_calls = 0

    def adb_check_root(self):
        return self._rooted

    def get_crash_logcat(self):
        return ""

    def get_device_clock(self):
        now = time.time()
        return int(now), _host_offset(now)

    def get_latest_tombstone(self, pid, hint):
        return self._tombstone

    def list_app_minidumps(self, package):
        self.minidump_calls += 1
        return self._minidumps if package == PKG else ""

    def get_events_logcat(self):
        return self._events


@pytest.fixture
def _no_debug_log(monkeypatch):
    monkeypatch.setattr("friTap.fritap_utility.open_debug_log", lambda *a, **k: None)
    monkeypatch.setattr("friTap.fritap_utility.attach_file_handlers", lambda *a, **k: None)
    monkeypatch.setattr("friTap.fritap_utility.get_debug_log_writer", lambda *a, **k: None)


def _firefox_logger(andy, spawn=False, crumb="agent-init: complete",
                    target=PKG, resolved_name=None):
    obj = SSL_Logger.__new__(SSL_Logger)
    obj.logger = logging.getLogger("test.android.evidence")
    obj.resolved_process_name = resolved_name
    obj._config = types.SimpleNamespace(
        target=target, target_argv=None,
        device=types.SimpleNamespace(spawn=spawn, device_id="SERIAL1"))
    obj.pid = 4242
    obj._exit_status = 0
    obj._crash_reported = False
    obj._last_hook_breadcrumb = crumb
    obj._anti_tamper_seen = ""
    obj._android_target_cached = True
    obj._session_start_time = time.time() - 30
    obj.pcap_obj = types.SimpleNamespace(android_Instance=andy)
    obj.events = []
    obj._event_bus = types.SimpleNamespace(emit=obj.events.append)
    return obj


@pytest.mark.usefixtures("_no_debug_log")
class TestReportTargetCrashEndToEnd:
    def test_firefox_minidump_is_reported(self):
        now = int(time.time())
        andy = _FakeAndroid(minidumps=f"{now - 3600} {GECKO_DUMP}\n{now} {PENDING_DUMP}\n")
        obj = _firefox_logger(andy)
        obj._report_target_crash("process-terminated", None)
        assert obj._termination_headline == (
            f"Target process crashed (minidump: {PENDING_DUMP}) "
            "(last agent stage: agent-init: complete)")
        assert [e.error for e in obj.events] == ["Target process crashed"]

    def test_anr_reported_without_root_and_minidumps_skipped(self):
        now = time.time()
        events = f"{_stamp(now)}  1000  1500 I am_anr: [0,4242,{PKG},0,Input dispatching timed out]"
        andy = _FakeAndroid(rooted=False, minidumps=f"{int(now)} {PENDING_DUMP}", events=events)
        obj = _firefox_logger(andy)
        obj._report_target_crash("process-terminated", None)
        assert "(ANR: Input dispatching timed out)" in obj._termination_headline
        assert andy.minidump_calls == 0

    def test_tombstone_beats_minidump(self):
        now = int(time.time())
        tomb = ("/data/tombstones/tombstone_07",
                f"pid: 4242, tid: 4242, name: x  >>> {PKG} <<<\nsignal 11 (SIGSEGV)")
        andy = _FakeAndroid(minidumps=f"{now} {PENDING_DUMP}", tombstone=tomb)
        obj = _firefox_logger(andy)
        obj._report_target_crash("process-terminated", None)
        assert obj._termination_headline.endswith("(tombstone: /data/tombstones/tombstone_07)")
        assert "SIGSEGV" in obj._termination_headline

    def test_stale_dumps_keep_no_crash_evidence_headline(self):
        andy = _FakeAndroid(minidumps=f"{int(time.time()) - 86400} {PENDING_DUMP}")
        obj = _firefox_logger(andy, spawn=True, crumb="ssl-read: libssl.so")
        obj._report_target_crash("process-terminated", None)
        assert obj._termination_headline.startswith(
            "Target process terminated (no crash evidence; possibly killed/force-stopped)")
        assert obj.events == []


@pytest.mark.usefixtures("_no_debug_log")
class TestPidAttachUsesResolvedPackage:
    """Attach by PID: ``target_app`` is "4242", the package comes from the
    process name resolved after attach (measured on the Pixel 5: the classifier
    never listed Firefox's minidumps because it searched package "4242")."""

    def test_minidump_found_via_resolved_process_name(self):
        now = int(time.time())
        andy = _FakeAndroid(minidumps=f"{now} {PENDING_DUMP}\n")
        obj = _firefox_logger(andy, target="4242", resolved_name=PKG)
        obj._report_target_crash("process-terminated", None)
        assert f"(minidump: {PENDING_DUMP})" in obj._termination_headline
        assert andy.minidump_calls == 1

    @pytest.mark.parametrize("target,resolved,expected", [
        (PKG, None, PKG),
        ("4242", PKG, PKG),
        ("4242", f"{PKG}:tab0", PKG),
        ("4242", None, "4242"),
        ("", None, ""),
    ])
    def test_crash_target_package(self, target, resolved, expected):
        obj = SSL_Logger.__new__(SSL_Logger)
        obj.resolved_process_name = resolved
        assert obj._crash_target_package(target) == expected
