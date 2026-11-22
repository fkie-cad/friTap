#!/usr/bin/env python3
"""Unit tests for local macOS crash attribution.

Covers :mod:`friTap.macos_crash` (finding the ReportCrash ``.ips`` for a pid in
a DiagnosticReports directory, with a bounded poll) and its wiring into
``SSL_Logger`` (``_enrich_crash_log_macos`` and the crash headline). Uses tmp
directories only — never the real ``~/Library/Logs/DiagnosticReports``.
"""

import json
import logging
import os
import types

import pytest

from friTap import macos_crash
from friTap.legacy.ssl_logger_core import SSL_Logger
from friTap.macos_crash import (
    describe_local_crash_cause,
    find_local_crash_report,
    wait_for_local_crash_report,
)

SESSION_START = 1_800_000_000.0  # 2027-01-15 08:00:00 UTC


def _stamp(epoch):
    """An .ips-style timestamp string (UTC) for *epoch*."""
    import datetime
    dt = datetime.datetime.fromtimestamp(epoch, tz=datetime.timezone.utc)
    return dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-4] + " +0000"


def _write_ips(directory, name, pid, epoch, signal="SIGSEGV",
               exc_type="EXC_BAD_ACCESS", subtype="KERN_INVALID_ADDRESS at 0x0"):
    header = {"app_name": "python3.11", "timestamp": _stamp(epoch), "bug_type": "309",
              "name": "python3.11"}
    body = {"pid": pid, "procName": "python3.11", "captureTime": _stamp(epoch),
            "exception": {"type": exc_type, "signal": signal, "subtype": subtype},
            "termination": {"namespace": "SIGNAL", "code": 11,
                            "indicator": "Segmentation fault: 11"}}
    path = os.path.join(str(directory), name)
    with open(path, "w") as handle:
        handle.write(json.dumps(header) + "\n" + json.dumps(body, indent=2))
    os.utime(path, (epoch, epoch))
    return path


# ---------------------------------------------------------------------------
# friTap.macos_crash
# ---------------------------------------------------------------------------
class TestFindLocalCrashReport:
    def test_finds_report_by_pid(self, tmp_path):
        path = _write_ips(tmp_path, "python3.11-a.ips", 4242, SESSION_START + 10)
        _write_ips(tmp_path, "python3.11-b.ips", 999, SESSION_START + 20)
        report = find_local_crash_report(4242, SESSION_START, [str(tmp_path)])
        assert report is not None
        assert report.path == path
        assert report.pid == 4242

    def test_ignores_report_older_than_session(self, tmp_path):
        _write_ips(tmp_path, "python3.11-old.ips", 4242, SESSION_START - 3600)
        assert find_local_crash_report(4242, SESSION_START, [str(tmp_path)]) is None

    def test_newest_matching_report_wins(self, tmp_path):
        _write_ips(tmp_path, "x-1.ips", 4242, SESSION_START + 5)
        newest = _write_ips(tmp_path, "x-2.ips", 4242, SESSION_START + 50)
        report = find_local_crash_report(4242, SESSION_START, [str(tmp_path)])
        assert report.path == newest

    def test_ignores_non_report_files_and_missing_dirs(self, tmp_path):
        (tmp_path / "notes.txt").write_text('{"pid": 4242}')
        missing = str(tmp_path / "does-not-exist")
        assert find_local_crash_report(4242, None, [str(tmp_path), missing]) is None

    def test_no_pid_returns_none(self, tmp_path):
        _write_ips(tmp_path, "x.ips", 4242, SESSION_START + 5)
        assert find_local_crash_report(None, None, [str(tmp_path)]) is None

    def test_malformed_report_does_not_raise(self, tmp_path):
        (tmp_path / "broken.ips").write_text("{not json")
        assert find_local_crash_report(4242, None, [str(tmp_path)]) is None


class TestWaitForLocalCrashReport:
    def test_picks_up_report_written_after_first_poll(self, tmp_path):
        """ReportCrash writes asynchronously: the report appears mid-wait."""
        def sleep(_seconds):
            _write_ips(tmp_path, "late.ips", 4242, SESSION_START + 5)

        report = wait_for_local_crash_report(
            4242, SESSION_START, [str(tmp_path)], timeout=3.0, sleep=sleep)
        assert report is not None and report.pid == 4242

    def test_gives_up_after_timeout(self, tmp_path):
        now = [0.0]
        sleeps = []

        def sleep(seconds):
            sleeps.append(seconds)
            now[0] += seconds

        report = wait_for_local_crash_report(
            4242, SESSION_START, [str(tmp_path)], timeout=1.0, interval=0.25,
            sleep=sleep, clock=lambda: now[0])
        assert report is None
        assert sum(sleeps) == pytest.approx(1.0)


class TestDescribeLocalCrashCause:
    def test_combines_signal_and_exception(self, tmp_path):
        path = _write_ips(tmp_path, "x.ips", 4242, SESSION_START + 5)
        report = find_local_crash_report(4242, None, [str(tmp_path)])
        assert report.path == path
        assert describe_local_crash_cause(report) == (
            "SIGSEGV (EXC_BAD_ACCESS)", "KERN_INVALID_ADDRESS at 0x0")

    def test_none_report(self):
        assert describe_local_crash_cause(None) == (None, None)


def test_diagnostic_report_dirs_includes_sudo_user(monkeypatch):
    monkeypatch.setenv("SUDO_USER", "someone")
    dirs = macos_crash.diagnostic_report_dirs()
    assert macos_crash.SYSTEM_DIAGNOSTIC_REPORTS in dirs
    assert any("someone" in d for d in dirs)
    assert len(dirs) == len(set(dirs))


# ---------------------------------------------------------------------------
# SSL_Logger wiring
# ---------------------------------------------------------------------------
class FakeBackend:
    def __init__(self, os_id):
        self.os_id = os_id

    def query_system_parameters(self, device):
        return {"os": {"id": self.os_id}, "access": "full"}


def _make_logger(os_id="macos", device_type="local", pid=4242):
    obj = SSL_Logger.__new__(SSL_Logger)
    obj.logger = logging.getLogger("test.macos.crash")
    obj.device = types.SimpleNamespace(type=device_type)
    obj._backend = FakeBackend(os_id)
    obj._session_start_time = SESSION_START
    obj.pid = pid
    return obj


@pytest.fixture
def report_dir(tmp_path, monkeypatch):
    """Point the lookup at a tmp dir and make the bounded wait instant."""
    real_wait = macos_crash.wait_for_local_crash_report

    def fake_wait(pid, newer_than=None, **_kwargs):
        return real_wait(pid, newer_than, [str(tmp_path)], timeout=0.0)

    monkeypatch.setattr(macos_crash, "wait_for_local_crash_report", fake_wait)
    return tmp_path


class TestEnrichCrashLogMacos:
    def test_local_macos_report_yields_cause(self, report_dir):
        _write_ips(report_dir, "python3.11-x.ips", 4242, SESSION_START + 5)
        obj = _make_logger()
        assert obj._enrich_crash_log_macos(None, None) == (
            "SIGSEGV (EXC_BAD_ACCESS)", "KERN_INVALID_ADDRESS at 0x0")
        assert obj._macos_crash_report.pid == 4242

    def test_writes_report_to_debug_log(self, report_dir):
        path = _write_ips(report_dir, "python3.11-x.ips", 4242, SESSION_START + 5)

        class Writer:
            text = ""

            def write(self, chunk):
                self.text += chunk

        writer = Writer()
        _make_logger()._enrich_crash_log_macos(None, writer)
        assert f"macOS crash report {path}" in writer.text

    @pytest.mark.parametrize("os_id,device_type", [
        ("ios", "usb"), ("android", "usb"), ("macos", "remote"), ("linux", "local")])
    def test_skipped_off_local_macos(self, report_dir, os_id, device_type):
        _write_ips(report_dir, "python3.11-x.ips", 4242, SESSION_START + 5)
        obj = _make_logger(os_id=os_id, device_type=device_type)
        assert obj._enrich_crash_log_macos(None, None) == (None, None)

    def test_no_report_for_pid(self, report_dir):
        _write_ips(report_dir, "python3.11-x.ips", 1, SESSION_START + 5)
        assert _make_logger()._enrich_crash_log_macos(None, None) == (None, None)


class TestCrashHeadlineReportPath:
    def test_headline_names_signal_and_report(self):
        headline = SSL_Logger._crash_headline(
            "SIGSEGV (EXC_BAD_ACCESS)", "KERN_INVALID_ADDRESS at 0x0",
            True, False, None, "", report_path="/x/python3.11.ips")
        assert headline == (
            "Target process terminated unexpectedly — SIGSEGV (EXC_BAD_ACCESS): "
            "KERN_INVALID_ADDRESS at 0x0 (crash report: /x/python3.11.ips)")

    def test_headline_unchanged_without_report(self):
        headline = SSL_Logger._crash_headline(None, None, False, False, None, "")
        assert headline.startswith("Target process terminated (no crash evidence")


class TestReportTargetCrashMacos:
    """End to end through ``_report_target_crash``: a local macOS target that
    died with no frida Crash object (e.g. just after the graceful detach)."""

    @pytest.fixture(autouse=True)
    def _no_debug_log(self, monkeypatch):
        monkeypatch.setattr("friTap.fritap_utility.open_debug_log", lambda *a, **k: None)
        monkeypatch.setattr("friTap.fritap_utility.attach_file_handlers", lambda *a, **k: None)
        monkeypatch.setattr("friTap.fritap_utility.get_debug_log_writer", lambda *a, **k: None)

    def _logger(self):
        obj = _make_logger()
        obj._crash_reported = False
        obj._last_hook_breadcrumb = "agent-init: complete"
        obj._anti_tamper_seen = ""
        obj._android_target_cached = False
        obj._config = types.SimpleNamespace(
            target="python3.11", target_argv=None,
            device=types.SimpleNamespace(spawn=False, device_id=None))
        obj.pcap_obj = None
        obj._event_bus = types.SimpleNamespace(emit=lambda *a, **k: None)
        return obj

    def test_headline_reports_crash_from_ips(self, report_dir):
        path = _write_ips(report_dir, "python3.11-x.ips", 4242, SESSION_START + 5)
        obj = self._logger()
        obj._report_target_crash("process-terminated", None)
        assert obj._termination_headline == (
            "Target process terminated unexpectedly — SIGSEGV (EXC_BAD_ACCESS): "
            f"KERN_INVALID_ADDRESS at 0x0 (crash report: {path})")

    def test_without_report_headline_is_unchanged(self, report_dir):
        obj = self._logger()
        obj._report_target_crash("process-terminated", None)
        assert "no crash detected" in obj._termination_headline
