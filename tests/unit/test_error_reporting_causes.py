#!/usr/bin/env python3

"""Error reporting found in end-to-end testing: the ``-j -`` envelope for
pre-stream failures, specific causes in the stream, normal exits that are not
errors, crash evidence scoped to this run, and clean frida error messages.
Frida/devices are never touched."""

from __future__ import annotations

import io
import json
import logging
import time
import types

import frida
import pytest

import friTap.friTap as fritap_cli
from friTap.backends import (
    BackendError,
    BackendInvalidArgumentError,
    BackendNotRunningError,
)
from friTap.backends.frida_backend import _wrap_frida_errors
from friTap.events import EventBus
from friTap.exit_codes import EXIT_RUNTIME_ERROR
from friTap.fritap_utility import Failure
from friTap.legacy.session_manager import SessionManager
from friTap.legacy.ssl_logger_core import SSL_Logger
from friTap.output import stdout_stream
from friTap.output.jsonl_stdout_handler import JsonlStdoutHandler


@pytest.fixture
def claimed_stream():
    """A claimed '-j -' stream backed by a StringIO (no fd juggling)."""
    stdout_stream._reset_for_tests()
    buffer = io.StringIO()
    stdout_stream._stream = buffer
    yield buffer
    stdout_stream._reset_for_tests()


def _records(buffer):
    return [json.loads(line) for line in buffer.getvalue().splitlines()]


# --------------------------------------------------------------------------
# 1. Pre-stream failures still get the full envelope
# --------------------------------------------------------------------------

def test_finish_unclosed_stream_writes_full_envelope(claimed_stream):
    stdout_stream.note_runtime_error("StartupError", "refused", "use -s --x")
    assert stdout_stream.finish_unclosed_stream(EXIT_RUNTIME_ERROR) is True
    records = _records(claimed_stream)
    assert [r["type"] for r in records] == ["stream_start", "error", "stream_end"]
    assert records[1]["message"] == "refused" and records[1]["hint"] == "use -s --x"
    assert records[1]["exit_code"] == records[2]["exit_code"] == EXIT_RUNTIME_ERROR


def test_finish_unclosed_stream_is_noop_without_claim():
    stdout_stream._reset_for_tests()
    assert stdout_stream.finish_unclosed_stream(EXIT_RUNTIME_ERROR) is False


def test_finish_after_normal_close_writes_nothing(claimed_stream):
    handler = JsonlStdoutHandler()
    handler.setup(EventBus())
    handler.close()
    before = claimed_stream.getvalue()
    assert stdout_stream.finish_unclosed_stream(EXIT_RUNTIME_ERROR) is False
    assert claimed_stream.getvalue() == before
    assert [r["type"] for r in _records(claimed_stream)] == ["stream_start", "stream_end"]


def test_finish_on_opened_stream_only_adds_closing_records(claimed_stream):
    handler = JsonlStdoutHandler()
    handler.setup(EventBus())
    stdout_stream.finish_unclosed_stream(EXIT_RUNTIME_ERROR)
    handler.close()  # must not write a second stream_end
    assert [r["type"] for r in _records(claimed_stream)] == [
        "stream_start", "error", "stream_end"]


def test_main_gives_early_failure_the_envelope_with_cause_and_hint(
        claimed_stream, monkeypatch):
    info = "/usr/bin/curl is an Apple platform binary.\n  Options:\n  1) re-run with -s"

    def refuse():
        raise Failure(info=info, code=EXIT_RUNTIME_ERROR)

    monkeypatch.setattr(fritap_cli, "cli", refuse)
    monkeypatch.setattr(fritap_cli, "_dispatch_special_mode", lambda argv: None)
    monkeypatch.setattr(fritap_cli.sys, "argv", ["fritap", "-j", "-", "x"])
    with pytest.raises(SystemExit) as exc:
        fritap_cli.main()
    assert exc.value.code == EXIT_RUNTIME_ERROR
    records = _records(claimed_stream)
    assert [r["type"] for r in records] == ["stream_start", "error", "stream_end"]
    assert records[1]["message"] == "/usr/bin/curl is an Apple platform binary."
    assert "re-run with -s" in records[1]["hint"]
    assert records[2]["exit_code"] == EXIT_RUNTIME_ERROR


def test_usage_error_record_is_not_followed_by_an_envelope(claimed_stream, monkeypatch):
    monkeypatch.setattr(fritap_cli.sys, "argv", ["fritap", "-j", "-", "x"])
    fritap_cli._emit_json_stream_usage_error("bad flag")
    fritap_cli._finish_json_stream_on_exit(2, "bad flag")
    assert [r["type"] for r in _records(claimed_stream)] == ["usage_error"]


def test_logger_exit_path_completes_envelope_when_handlers_never_opened(claimed_stream):
    obj = SSL_Logger.__new__(SSL_Logger)
    obj._config = types.SimpleNamespace(output=types.SimpleNamespace(auxiliary_session=False))
    obj._exit_status = EXIT_RUNTIME_ERROR
    obj._finish_json_stream()
    assert [r["type"] for r in _records(claimed_stream)] == [
        "stream_start", "error", "stream_end"]


def test_lsass_helper_session_does_not_end_the_shared_stream(claimed_stream):
    obj = SSL_Logger.__new__(SSL_Logger)
    obj._config = types.SimpleNamespace(output=types.SimpleNamespace(auxiliary_session=True))
    obj._exit_status = EXIT_RUNTIME_ERROR
    obj._finish_json_stream()
    assert claimed_stream.getvalue() == ""


# --------------------------------------------------------------------------
# 2. Specific causes reach the stream
# --------------------------------------------------------------------------

class _FakeBackend:
    name = "frida"

    def __init__(self, error):
        self._error = error

    def get_device(self, **kwargs):
        raise self._error


def _session_with_backend(error):
    logger = types.SimpleNamespace(_backend=_FakeBackend(error), statuses=[])
    logger.set_exit_status = logger.statuses.append
    return SessionManager(logger), logger


@pytest.mark.parametrize("error, expected", [
    (BackendInvalidArgumentError("device not found"), "Device with ID 'bad-device' not found."),
    (BackendNotRunningError("closed"), "server is not running"),
    (RuntimeError("boom"), "Unexpected error while attaching to the device: boom"),
])
def test_device_lookup_failure_notes_specific_cause(claimed_stream, error, expected):
    manager, logger = _session_with_backend(error)
    with pytest.raises(SystemExit) as exc:
        manager._get_device_or_abort(logger, "bad-device", mobile="bad-device")
    assert exc.value.code == EXIT_RUNTIME_ERROR
    assert logger.statuses == [EXIT_RUNTIME_ERROR]
    error_fields = stdout_stream.runtime_error_fields(EXIT_RUNTIME_ERROR)
    assert expected in error_fields["message"]
    assert "see stderr" not in error_fields["message"]


def _bare_logger(spawn=True):
    obj = SSL_Logger.__new__(SSL_Logger)
    obj.logger = logging.getLogger("test.errors")
    obj._config = types.SimpleNamespace(
        target="com.google.android.calendar", target_argv=None,
        device=types.SimpleNamespace(spawn=spawn, device_id="emulator-5556"))
    obj.pid = 4242
    obj._exit_status = 0
    return obj


def test_death_before_capture_notes_specific_reason(claimed_stream):
    obj = _bare_logger()
    obj._termination_headline = ("Target process terminated (no crash evidence; "
                                 "possibly killed/force-stopped)")
    obj._report_death_before_capture("detached: process-terminated")
    assert obj._exit_status == EXIT_RUNTIME_ERROR
    error = stdout_stream.runtime_error_fields(EXIT_RUNTIME_ERROR)
    assert error["error_type"] == "TargetDetachedBeforeCapture"
    assert "went away before the capture started" in error["message"]
    assert "possibly killed/force-stopped" in error["message"]
    assert "force-stopped by the system" in error["hint"]


# --------------------------------------------------------------------------
# 3. A normal exit is not an error record; crash evidence still is
# --------------------------------------------------------------------------

@pytest.fixture
def _no_debug_log(monkeypatch):
    monkeypatch.setattr("friTap.fritap_utility.open_debug_log", lambda *a, **k: None)
    monkeypatch.setattr("friTap.fritap_utility.attach_file_handlers", lambda *a, **k: None)
    monkeypatch.setattr("friTap.fritap_utility.get_debug_log_writer", lambda *a, **k: None)


def _crash_logger(spawn):
    obj = _bare_logger(spawn)
    obj._crash_reported = False
    obj._last_hook_breadcrumb = "ssl-read: libssl.so"
    obj._anti_tamper_seen = ""
    obj._android_target_cached = False
    obj.pcap_obj = None
    obj.events = []
    obj._event_bus = types.SimpleNamespace(emit=obj.events.append)
    return obj


@pytest.mark.usefixtures("_no_debug_log")
@pytest.mark.parametrize("spawn", [True, False])
def test_plain_termination_emits_no_error_event(spawn):
    obj = _crash_logger(spawn)
    obj._report_target_crash("process-terminated", None)
    assert obj.events == []


@pytest.mark.usefixtures("_no_debug_log")
def test_crash_evidence_still_emits_fatal_error_event():
    obj = _crash_logger(True)
    crash = types.SimpleNamespace(report="signal 11 (SIGSEGV)", summary="", pid=4242)
    obj._report_target_crash("process-terminated", crash)
    assert [e.error for e in obj.events] == ["Target process crashed"]
    assert obj.events[0].severity == "fatal"


# --------------------------------------------------------------------------
# 4. Crash cause only from THIS process and THIS session
# --------------------------------------------------------------------------

def _stamp(epoch, utc_offset=None):
    """A year-less logcat stamp: host-local, or wall clock at *utc_offset*."""
    if utc_offset is None:
        return time.strftime("%m-%d %H:%M:%S.000", time.localtime(epoch))
    return time.strftime("%m-%d %H:%M:%S.000", time.gmtime(epoch + utc_offset))


def _host_offset(epoch):
    return time.localtime(epoch).tm_gmtoff


def _crash_buffer(now):
    old = _stamp(now - 3600)
    recent = _stamp(now)
    return "\n".join([
        "--------- beginning of crash",
        f"{old}  1111  1111 F libc    : Fatal signal 11 (SIGSEGV), code 1 in tid 1111, pid 1111 (other)",
        f"{old}  2222  2222 F DEBUG   : pid: 1111, tid: 1111, name: other  >>> other <<<",
        f"{recent}  3333  3333 F libc    : Fatal signal 6 (SIGABRT) in tid 3333, pid 3333 (third)",
    ])


def test_crash_buffer_ignores_other_pids_and_old_entries():
    now = time.time()
    buf = _crash_buffer(now)
    offset = _host_offset(now)  # _crash_buffer stamps in host-local time
    assert SSL_Logger._crash_buffer_lines_for(buf, 4242, now - 60, offset) == ""
    # pid 1111's own lines are dropped too: an hour older than the session.
    assert SSL_Logger._crash_buffer_lines_for(buf, 1111, now - 60, offset) == ""
    # Without the device's offset only the pid filter applies.
    assert "SIGSEGV" in SSL_Logger._crash_buffer_lines_for(buf, 1111, now - 60)


def test_crash_buffer_keeps_own_lines_and_crash_dump_report():
    now = time.time()
    stamp = _stamp(now)
    buf = "\n".join([
        f"{stamp}  4242  4250 F libc    : Fatal signal 6 (SIGABRT), code -1 in tid 4250, pid 4242 (app)",
        f"{stamp}  5000  5000 F DEBUG   : pid: 4242, tid: 4250, name: app  >>> app <<<",
        f"{stamp}  5000  5000 F DEBUG   : Abort message: 'boom'",
        f"{stamp}  3333  3333 F libc    : Fatal signal 11 (SIGSEGV) pid 3333 (third)",
    ])
    kept = SSL_Logger._crash_buffer_lines_for(buf, 4242, now - 60, _host_offset(now))
    assert "SIGABRT" in kept and "Abort message" in kept and "SIGSEGV" not in kept
    assert SSL_Logger._crash_buffer_lines_for(buf, None, None) == ""


def test_tombstone_older_than_session_is_ignored():
    now = time.time()
    old = time.strftime("%Y-%m-%d %H:%M:%S.123456789%z", time.localtime(now - 3600))
    fresh = time.strftime("%Y-%m-%d %H:%M:%S.1%z", time.localtime(now))
    assert SSL_Logger._tombstone_predates(f"Timestamp: {old}\npid: 1", now - 60)
    assert not SSL_Logger._tombstone_predates(f"Timestamp: {fresh}\npid: 1", now - 60)
    assert not SSL_Logger._tombstone_predates("no timestamp", now - 60)


# Device and host timezones differ: device timestamps are read in the
# device's own timezone and compared on the device's own timeline.
_UTC, _UTC_PLUS_2 = 0, 2 * 3600


@pytest.mark.parametrize("device_offset, host_offset", [
    (_UTC, _UTC_PLUS_2), (_UTC_PLUS_2, _UTC)], ids=["device_utc-host_utc+2", "device_utc+2-host_utc"])
def test_crash_buffer_uses_the_device_timezone(monkeypatch, device_offset, host_offset):
    monkeypatch.setenv("TZ", "UTC" if host_offset == 0 else "Etc/GMT-2")
    time.tzset()
    try:
        now = time.time()
        fresh = _stamp(now, device_offset)
        old = _stamp(now - 3 * 3600, device_offset)
        buf = "\n".join([
            f"{old}  4242  4242 F libc    : Fatal signal 11 (SIGSEGV) pid 4242 (app)",
            f"{fresh}  4242  4250 F libc    : Fatal signal 6 (SIGABRT) pid 4242 (app)",
        ])
        kept = SSL_Logger._crash_buffer_lines_for(buf, 4242, now - 60, device_offset, now)
    finally:
        monkeypatch.delenv("TZ")
        time.tzset()
    assert "SIGABRT" in kept, "a real crash line was dropped by a timezone mismatch"
    assert "SIGSEGV" not in kept


@pytest.mark.parametrize("device_offset, host_tz", [
    (_UTC, "Etc/GMT-2"), (_UTC_PLUS_2, "UTC")], ids=["device_utc-host_utc+2", "device_utc+2-host_utc"])
def test_offsetless_tombstone_uses_the_device_timezone(monkeypatch, device_offset, host_tz):
    monkeypatch.setenv("TZ", host_tz)
    time.tzset()
    try:
        now = time.time()
        fmt = "%Y-%m-%d %H:%M:%S.123"
        fresh = time.strftime(fmt, time.gmtime(now + device_offset))
        old = time.strftime(fmt, time.gmtime(now - 3 * 3600 + device_offset))
        assert not SSL_Logger._tombstone_predates(
            f"Timestamp: {fresh}\npid: 1", now - 60, device_offset)
        assert SSL_Logger._tombstone_predates(f"Timestamp: {old}\npid: 1", now - 60, device_offset)
        # Unknown device timezone: an offset-less timestamp is never filtered.
        assert not SSL_Logger._tombstone_predates(f"Timestamp: {old}\npid: 1", now - 60)
    finally:
        monkeypatch.delenv("TZ")
        time.tzset()


def test_session_start_is_shifted_onto_the_device_clock():
    obj = SSL_Logger.__new__(SSL_Logger)
    obj._session_start_time = 1_000_000.0
    tolerance = SSL_Logger.CRASH_EVIDENCE_CLOCK_TOLERANCE
    # The device clock runs 300 s ahead of the host.
    assert obj._crash_evidence_since((2_000_300.0, 2_000_000.0)) == 1_000_300.0 - tolerance
    assert obj._crash_evidence_since(None) is None


def test_device_clock_unreadable_falls_back_to_the_pid_filter():
    class _NoClock:
        def get_device_clock(self):
            return None
    assert SSL_Logger._read_device_clock(_NoClock()) == (None, None)
    assert SSL_Logger._read_device_clock(object()) == (None, None)


class _FakeAndroid:
    def __init__(self, crash_buf, tombstone=(None, "")):
        self._crash_buf = crash_buf
        self._tombstone = tombstone

    def adb_check_root(self):
        return True

    def get_crash_logcat(self):
        return self._crash_buf

    def get_device_clock(self):
        now = time.time()
        return int(now), _host_offset(now)  # _crash_buffer stamps host-local

    def get_latest_tombstone(self, pid, hint):
        return self._tombstone


@pytest.mark.usefixtures("_no_debug_log")
def test_force_stop_with_stale_sigsegv_reports_no_crash_evidence(caplog):
    now = time.time()
    obj = _crash_logger(True)
    obj._session_start_time = now - 30
    obj._android_target_cached = True
    obj.pcap_obj = types.SimpleNamespace(android_Instance=_FakeAndroid(_crash_buffer(now)))
    with caplog.at_level(logging.DEBUG):
        obj._report_target_crash("process-terminated", None)
    assert "SIGSEGV" not in caplog.text
    assert "no crash evidence; possibly killed/force-stopped" in caplog.text
    assert obj.events == []


# --------------------------------------------------------------------------
# 5. Ordinary frida errors keep a clean message
# --------------------------------------------------------------------------

class _Spawner:
    def __init__(self, error):
        self._error = error

    @_wrap_frida_errors
    def spawn_raw(self, device, target):
        raise self._error


def test_executable_not_found_is_not_an_internal_error():
    with pytest.raises(BackendError) as exc:
        _Spawner(frida.ExecutableNotFoundError(
            "unable to find executable at '/nonexistent'")).spawn_raw(None, "/nonexistent")
    err = exc.value
    assert str(err) == "unable to find executable at '/nonexistent'"
    assert err.category == "frida_executable_not_found"
    assert fritap_cli._unexpected_error_line(err) == (
        "ExecutableNotFoundError: unable to find executable at '/nonexistent'")


def test_real_bug_keeps_internal_error_prefix():
    with pytest.raises(BackendError) as exc:
        _Spawner(KeyError("x")).spawn_raw(None, "t")
    assert str(exc.value).startswith("Internal error in _Spawner.spawn_raw")
    assert exc.value.category == "backend_bug"
    assert fritap_cli._unexpected_error_line(exc.value).startswith("Unknown error:")


# --------------------------------------------------------------------------
# LSASS helper of a -f run: no plaintext hooks, other sessions unchanged
# --------------------------------------------------------------------------

def test_plaintext_hooks_follow_outputs_unless_disabled():
    from friTap.config import FriTapConfig
    config = FriTapConfig.from_legacy_params(app="x", json_output="-")
    assert SSL_Logger(config=config)._plaintext_hooks_needed() is True
    config.output.plaintext_hooks_disabled = True
    assert SSL_Logger(config=config)._plaintext_hooks_needed() is False
