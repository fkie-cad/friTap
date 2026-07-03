#!/usr/bin/env python3
"""Unit tests for honest crash attribution + full crash-report capture.

A native abort in the target's own code during friTap-instrumented startup
(e.g. Chrome's ART CheckJNI abort — SIGABRT, "JNI DETECTED ERROR ... java_class
== null") must be reported by its REAL cause, NOT misattributed to Google PairIP
/ anti-tamper. The last-hook breadcrumb is only a weak hint (it may have been set
on a different thread than the one that crashed).

These tests exercise ``SSL_Logger._report_target_crash`` / ``_parse_crash_cause``
without constructing the whole logger (which needs a device/session), following
the pattern in ``test_hook_breadcrumb.py``.
"""

import logging
import types

import pytest

from friTap.legacy.ssl_logger_core import SSL_Logger


class FakeCrash:
    """Mimics frida's ``_frida.Crash`` (only the fields friTap reads)."""

    def __init__(self, report="", summary="", pid=1234):
        self.report = report
        self.summary = summary
        self.pid = pid
        self.parameters = {}


def _make_logger(anti_tamper="", crumb="", spawn=True):
    """A bare SSL_Logger with only what the crash path touches.

    ``_android_target_cached=False`` makes the Android tombstone/logcat
    enrichment a no-op (no device needed).
    """
    obj = SSL_Logger.__new__(SSL_Logger)
    obj.logger = logging.getLogger("test.crash")
    obj.logger.setLevel(logging.DEBUG)
    obj._crash_reported = False
    obj._last_hook_breadcrumb = crumb
    obj._anti_tamper_seen = anti_tamper
    # spawn / target_app / target_argv / device_id are read-only properties
    # backed by the config; provide the minimal nested config they read.
    obj._config = types.SimpleNamespace(
        target="com.android.chrome",
        target_argv=None,
        device=types.SimpleNamespace(spawn=spawn, device_id="TESTSERIAL"),
    )
    obj._android_target_cached = False
    obj.pcap_obj = None
    obj.pid = 1234
    obj._event_bus = types.SimpleNamespace(emit=lambda *a, **k: None)
    return obj


@pytest.fixture(autouse=True)
def _no_debug_log(monkeypatch):
    """Neutralize the on-demand debug-log arming so tests write no files."""
    monkeypatch.setattr("friTap.fritap_utility.open_debug_log", lambda *a, **k: None)
    monkeypatch.setattr("friTap.fritap_utility.attach_file_handlers", lambda *a, **k: None)
    monkeypatch.setattr("friTap.fritap_utility.get_debug_log_writer", lambda *a, **k: None)


CHROME_JNI_CRASH = FakeCrash(
    report=(
        "signal 6 (SIGABRT), code -1 (SI_QUEUE)\n"
        "Abort message: 'JNI DETECTED ERROR IN APPLICATION: java_class == null\n"
        "    in call to GetStaticMethodID\n"
        "    from void J.N.VZ(int, boolean)'\n"
    ),
    summary="Process crashed: SIGABRT",
)


def test_chrome_jni_abort_not_blamed_on_pairip(caplog):
    obj = _make_logger(anti_tamper="", crumb="pattern-scan: libmonochrome_64.so")
    with caplog.at_level(logging.ERROR):
        obj._report_target_crash("process-terminated", CHROME_JNI_CRASH)
    text = caplog.text

    # Real cause surfaced.
    assert "SIGABRT" in text
    assert "JNI DETECTED ERROR" in text
    # NOT misattributed to anti-tamper for a normal app.
    assert "PairIP" not in text
    assert "libpairipcore" not in text
    # The stale breadcrumb is demoted, not asserted as the crash site.
    assert "may" in text and "different thread" in text
    # Headline no longer claims it crashed inside an instrumented hook.
    assert "crashed inside an instrumented hook" not in text


def test_confirmed_anti_tamper_still_reports_pairip(caplog):
    obj = _make_logger(anti_tamper="Google PairIP (libpairipcore.so)")
    with caplog.at_level(logging.ERROR):
        obj._report_target_crash("process-terminated", FakeCrash())
    text = caplog.text
    assert "Anti-tamper protection was detected" in text
    assert "libpairipcore.so" in text


def test_no_crash_object_falls_back_to_breadcrumb(caplog):
    obj = _make_logger(anti_tamper="", crumb="pattern-scan: libssl.so")
    with caplog.at_level(logging.ERROR):
        obj._report_target_crash("process-terminated", None)
    text = caplog.text
    # Without a crash report we keep the (lower-confidence) hook hypothesis...
    assert "crashed inside an instrumented hook" in text
    assert "pattern-scan: libssl.so" in text
    # ...but still never invent a PairIP claim without evidence.
    assert "PairIP" not in text


class TestParseCrashCause:
    def test_extracts_signal_and_jni_abort(self):
        obj = SSL_Logger.__new__(SSL_Logger)
        sig, abort = obj._parse_crash_cause(CHROME_JNI_CRASH.report, CHROME_JNI_CRASH.summary)
        assert sig == "SIGABRT"
        assert abort is not None
        assert "JNI DETECTED ERROR IN APPLICATION: java_class == null" in abort
        # Collapsed to a single line.
        assert "\n" not in abort

    def test_extracts_sigsegv_without_abort(self):
        obj = SSL_Logger.__new__(SSL_Logger)
        sig, abort = obj._parse_crash_cause("signal 11 (SIGSEGV), fault addr 0x0", None)
        assert sig == "SIGSEGV"
        assert abort is None

    def test_empty_returns_none(self):
        obj = SSL_Logger.__new__(SSL_Logger)
        assert obj._parse_crash_cause(None, None) == (None, None)
        assert obj._parse_crash_cause("", "") == (None, None)
