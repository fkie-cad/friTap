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


def test_no_crash_object_reports_plain_termination(caplog):
    # A bare 'process-terminated' (external kill -9, system ANR kill) carries no
    # crash evidence: the breadcrumb alone must not blame an instrumented hook.
    obj = _make_logger(anti_tamper="", crumb="pattern-scan: libssl.so")
    with caplog.at_level(logging.WARNING):
        obj._report_target_crash("process-terminated", None)
    text = caplog.text
    assert "terminated (killed or exited)" in text
    assert "pattern-scan: libssl.so" in text
    assert "crashed inside an instrumented hook" not in text
    assert "PairIP" not in text


def test_clean_attach_exit_not_reported_as_hook_crash(caplog):
    # Attach mode, agent fully initialised ("agent-init: complete"), no frida crash
    # object: a short-lived target that simply finished (e.g. a download script).
    # Must NOT be blamed on an instrumented hook, and must emit no crash noise.
    obj = _make_logger(anti_tamper="", crumb="agent-init: complete", spawn=False)
    with caplog.at_level(logging.INFO):
        obj._report_target_crash("process-terminated", None)
    text = caplog.text
    assert "Target process exited" in text
    assert "no crash detected" in text
    assert "crashed inside an instrumented hook" not in text
    assert "Full crash report" not in text
    assert "PairIP" not in text


def test_spawn_exit_with_empty_crumb_is_not_a_clean_exit(caplog):
    # Empty breadcrumb (target went away before init finished) in spawn mode is
    # not a clean exit, but without crash evidence it is not blamed on a hook.
    obj = _make_logger(anti_tamper="", crumb="", spawn=True)
    with caplog.at_level(logging.WARNING):
        obj._report_target_crash("process-terminated", None)
    assert "terminated (killed or exited)" in caplog.text
    assert "Target process exited" not in caplog.text
    assert "crashed inside an instrumented hook" not in caplog.text


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


# ---------------------------------------------------------------------------
# Evidence-gated hook blame: an external kill -9 / ANR kill (bare
# 'process-terminated', no crash) is not a hook crash.
# ---------------------------------------------------------------------------
def _capture_events(obj):
    events = []
    obj._event_bus = types.SimpleNamespace(emit=events.append)
    return events


def test_external_kill_in_attach_mode_is_plain_termination(caplog):
    obj = _make_logger(crumb="ssl-read: libssl.so", spawn=False)
    events = _capture_events(obj)
    with caplog.at_level(logging.DEBUG):
        obj._report_target_crash("process-terminated", None)
    text = caplog.text
    assert "Target process terminated (killed or exited)" in text
    assert "crashed inside an instrumented hook" not in text
    assert "PairIP" not in text
    assert all(r.levelno < logging.ERROR for r in caplog.records)
    assert [e.error for e in events] == ["Target process terminated"]


def test_android_spawn_kill_without_crash_does_not_guess_pairip(caplog):
    obj = _make_logger(crumb="pattern-scan: libssl.so", spawn=True)
    obj._android_target_cached = True
    obj._enrich_crash_log_android = lambda crash, writer: (None, None)
    with caplog.at_level(logging.DEBUG):
        obj._report_target_crash("process-terminated", None)
    assert "PairIP" not in caplog.text
    assert "crashed inside an instrumented hook" not in caplog.text
    assert "WITHOUT -s" in caplog.text


def test_native_stack_in_instrumented_module_blames_hook(caplog):
    crash = FakeCrash(report=(
        "backtrace:\n"
        "  #00 pc 0001234  /data/local/tmp/re.frida.server/frida-agent-64.so\n"
        "  #01 pc 0005678  /system/lib64/libssl.so (SSL_read+12)\n"))
    obj = _make_logger(crumb="ssl-read: libssl.so")
    events = _capture_events(obj)
    with caplog.at_level(logging.ERROR):
        obj._report_target_crash("process-terminated", crash)
    text = caplog.text
    assert "crashed inside an instrumented hook" in text
    assert "native stack in frida-agent" in text
    assert [e.error for e in events] == ["Target process crashed"]


def test_detected_library_on_stack_is_named_with_real_cause(caplog):
    crash = FakeCrash(
        report="signal 11 (SIGSEGV)\n  #00 pc 0001 /apex/lib64/libboringssl.so\n",
        summary="Process crashed: SIGSEGV")
    obj = _make_logger(crumb="")
    obj._detected_libraries = {"/apex/lib64/libboringssl.so"}
    with caplog.at_level(logging.ERROR):
        obj._report_target_crash("process-terminated", crash)
    assert "SIGSEGV" in caplog.text
    assert "native stack in instrumented module libboringssl.so" in caplog.text


def test_crash_without_instrumented_module_is_not_a_hook_crash(caplog):
    crash = FakeCrash(report="  #00 pc 0001 /system/lib64/libart.so\n")
    obj = _make_logger(crumb="ssl-read: libssl.so", spawn=False)
    with caplog.at_level(logging.ERROR):
        obj._report_target_crash("process-terminated", crash)
    assert "native crash (cause not decoded)" in caplog.text
    assert "crashed inside an instrumented hook" not in caplog.text


def test_crash_report_makes_no_frida_calls():
    # Runs on the fritap-detach thread: no device / script / backend access.
    obj = _make_logger(crumb="ssl-read: libssl.so", spawn=False)
    for attr in ("device", "script", "_backend", "process"):
        assert not hasattr(obj, attr)
    obj._report_target_crash("process-terminated", None)
    obj._report_target_crash("process-terminated", FakeCrash(report="frida-agent"))
