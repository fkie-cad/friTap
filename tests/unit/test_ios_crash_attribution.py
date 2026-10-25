#!/usr/bin/env python3
"""Unit tests for iOS crash attribution inside ``SSL_Logger``.

``friTap.ios`` owns the device plumbing (see ``test_ios_crash_reports.py``);
this file covers the *wiring*: how ``SSL_Logger`` learns that the target is iOS
(``_query_os_id`` / ``_is_ios_target``), how it pulls and parses the ReportCrash
``.ips`` (``_enrich_crash_log_ios`` / ``_parse_crash_cause_ios``), and the
iOS-specific guidance it prints (``_ios_crash_guidance``) — including the
regression guard that hoisting the guidance gate out of ``self.spawn`` left the
Android, Wine and anti-tamper branches untouched (fkie-cad/friTap#65: that
reporter was *attaching*, and attach-mode crashes got no guidance at all).

Device-free by construction, following ``test_crash_attribution.py``: the logger
is built with ``SSL_Logger.__new__`` and only the attributes the crash path
touches, and every frida/libimobiledevice interaction is faked.
"""

import logging
import types

import pytest

from friTap.legacy.ssl_logger_core import (
    IOS_CRASH_REPORT_CLOCK_TOLERANCE,
    UNKNOWN_TARGET_OS,
    SSL_Logger,
)


class FakeCrash:
    """Mimics frida's ``_frida.Crash`` (only the fields friTap reads)."""

    def __init__(self, report="", summary="", pid=1234):
        self.report = report
        self.summary = summary
        self.pid = pid
        self.parameters = {}


def _make_logger(os_id="ios", access="full", spawn=True, crumb="",
                 anti_tamper="", target="com.example.MyApp"):
    """A bare SSL_Logger with only what the crash path touches.

    ``os_id``/``access`` drive the faked ``query_system_parameters`` so the
    platform detection can be exercised without a device.
    """
    obj = SSL_Logger.__new__(SSL_Logger)
    obj.logger = logging.getLogger("test.ios.crash")
    obj.logger.setLevel(logging.DEBUG)
    obj._crash_reported = False
    obj._last_hook_breadcrumb = crumb
    obj._anti_tamper_seen = anti_tamper
    obj._config = types.SimpleNamespace(
        target=target,
        target_argv=None,
        device=types.SimpleNamespace(spawn=spawn, device_id="TESTUDID"),
    )
    obj.device = object()
    obj._backend = FakeBackend({"os": {"id": os_id}, "access": access})
    obj._ios_crash_report = None
    obj._ios_crash_verdict = None
    obj._session_start_time = 1_000_000.0
    obj.pcap_obj = None
    obj.pid = 1234
    obj._event_bus = types.SimpleNamespace(emit=lambda *a, **k: None)
    return obj


class FakeBackend:
    """Counts ``query_system_parameters`` calls so caching can be asserted."""

    def __init__(self, params=None, raises=False):
        self.params = params or {}
        self.raises = raises
        self.calls = 0

    def query_system_parameters(self, device):
        self.calls += 1
        if self.raises:
            raise RuntimeError("frida-server unreachable")
        return self.params


class FakeWriter:
    """Minimal stand-in for the debug-log writer."""

    def __init__(self):
        self.text = ""

    def write(self, chunk):
        self.text += chunk

    def flush(self):
        pass


@pytest.fixture(autouse=True)
def _no_debug_log(monkeypatch):
    """Neutralize the on-demand debug-log arming so tests write no files."""
    monkeypatch.setattr("friTap.fritap_utility.open_debug_log", lambda *a, **k: None)
    monkeypatch.setattr("friTap.fritap_utility.attach_file_handlers", lambda *a, **k: None)
    monkeypatch.setattr("friTap.fritap_utility.get_debug_log_writer", lambda *a, **k: None)


# ---------------------------------------------------------------------------
# _query_os_id / _is_ios_target
# ---------------------------------------------------------------------------
class TestQueryOsId:
    def test_parses_os_id_and_access(self):
        obj = _make_logger(os_id="ios", access="jailed")
        result = obj._query_os_id()
        assert result.os_id == "ios"
        assert result.access == "jailed"

    def test_is_cached(self):
        obj = _make_logger(os_id="ios")
        assert obj._query_os_id() == obj._query_os_id()
        assert obj._backend.calls == 1

    def test_backend_error_yields_unknown(self):
        obj = _make_logger()
        obj._backend = FakeBackend(raises=True)
        assert obj._query_os_id() == UNKNOWN_TARGET_OS
        assert obj._query_os_id().os_id == ""

    def test_missing_device_yields_unknown(self):
        obj = _make_logger()
        obj.device = None
        assert obj._query_os_id() == UNKNOWN_TARGET_OS

    def test_does_not_use_the_android_cache_attribute(self):
        """The Android flag answers a different question and is set by callers /
        tests to disable Android enrichment — the OS lookup must not share it."""
        obj = _make_logger(os_id="ios")
        obj._android_target_cached = False
        assert obj._is_ios_target() is True
        assert obj._android_target_cached is False
        assert obj._is_android_target() is False

    @pytest.mark.parametrize("os_id,expected", [
        ("ios", True), ("macos", False), ("android", False), ("", False),
    ])
    def test_is_ios_target(self, os_id, expected):
        assert _make_logger(os_id=os_id)._is_ios_target() is expected


# ---------------------------------------------------------------------------
# _parse_crash_cause_ios
# ---------------------------------------------------------------------------
class TestParseCrashCauseIos:
    def test_prefers_signal_and_termination_reason(self):
        from friTap.ios import IOSCrashReport
        report = IOSCrashReport(
            signal="SIGSEGV", exception_type="EXC_BAD_ACCESS",
            termination_reason="SIGNAL 11 Segmentation fault: 11",
        )
        sig, abort = SSL_Logger._parse_crash_cause_ios(report)
        assert sig == "SIGSEGV"
        assert abort == "SIGNAL 11 Segmentation fault: 11"

    def test_falls_back_to_exception_type_and_asi(self):
        from friTap.ios import IOSCrashReport
        report = IOSCrashReport(exception_type="EXC_CRASH", asi="dyld:\n  bad image")
        sig, abort = SSL_Logger._parse_crash_cause_ios(report)
        assert sig == "EXC_CRASH"
        # Collapsed to a single line so it is usable in the one-line headline.
        assert abort == "dyld: bad image"

    def test_none_report(self):
        assert SSL_Logger._parse_crash_cause_ios(None) == (None, None)

    def test_empty_report(self):
        from friTap.ios import IOSCrashReport
        assert SSL_Logger._parse_crash_cause_ios(IOSCrashReport()) == (None, None)


# ---------------------------------------------------------------------------
# _enrich_crash_log_ios
# ---------------------------------------------------------------------------
def _fake_report(**kwargs):
    from friTap.ios import IOSCrashReport
    defaults = dict(
        path="/tmp/fritap-ios-crash/MyApp-2026-08-03-120000.ips",
        process_name="MyApp", pid=1234, signal="SIGSEGV",
        exception_type="EXC_BAD_ACCESS", exception_subtype="KERN_INVALID_ADDRESS at 0x0",
        termination_reason="SIGNAL 11 Segmentation fault: 11",
        raw="{...raw ips body...}",
    )
    defaults.update(kwargs)
    return IOSCrashReport(**defaults)


class FakeIOS:
    """Stand-in for ``friTap.ios.IOS`` recording how it was called."""

    instances = []

    def __init__(self, device_id=None, report=None, available=True, raises=False):
        self.device_id = device_id
        self._report = report
        self._available = available
        self._raises = raises
        self.calls = []
        FakeIOS.instances.append(self)

    def check_idevicecrashreport_availability(self):
        return self._available

    def get_latest_crash_report(self, process_name, pid=None, newer_than=None):
        self.calls.append((process_name, pid, newer_than))
        if self._raises:
            raise RuntimeError("idevicecrashreport exploded")
        return self._report

    def describe_crash(self, report):
        from friTap.ios import decode_terminator
        return report.summary, decode_terminator(report)


def _install_fake_ios(monkeypatch, **kwargs):
    """Patch ``friTap.ios.IOS`` (imported lazily inside the crash path)."""
    FakeIOS.instances = []
    monkeypatch.setattr("friTap.ios.IOS", lambda device_id=None: FakeIOS(
        device_id=device_id, **kwargs))


class TestEnrichCrashLogIos:
    def test_off_ios_is_a_noop_without_constructing_ios(self, monkeypatch):
        def _boom(*a, **k):  # pragma: no cover - must never run
            raise AssertionError("IOS must not be constructed off iOS")
        monkeypatch.setattr("friTap.ios.IOS", _boom)
        obj = _make_logger(os_id="android")
        writer = FakeWriter()
        assert obj._enrich_crash_log_ios(FakeCrash(), writer) == (None, None)
        assert writer.text == ""

    def test_returns_parsed_cause_and_writes_crash_section(self, monkeypatch):
        _install_fake_ios(monkeypatch, report=_fake_report())
        obj = _make_logger()
        writer = FakeWriter()

        sig, abort = obj._enrich_crash_log_ios(FakeCrash(), writer)

        assert sig == "SIGSEGV"
        assert abort == "SIGNAL 11 Segmentation fault: 11"
        assert "iOS crash report /tmp/fritap-ios-crash/MyApp-2026-08-03-120000.ips" in writer.text
        assert "...raw ips body..." in writer.text
        assert "iOS crash summary" in writer.text
        # The decoded verdict is remembered for the guidance block.
        assert obj._ios_crash_report is not None
        assert "EXC_BAD_ACCESS" in obj._ios_crash_verdict.verdict

    def test_passes_process_name_pid_and_newer_than(self, monkeypatch):
        _install_fake_ios(monkeypatch, report=_fake_report())
        obj = _make_logger()
        obj._enrich_crash_log_ios(FakeCrash(pid=4321), None)

        helper = FakeIOS.instances[0]
        assert helper.device_id == "TESTUDID"
        process_name, pid, newer_than = helper.calls[0]
        assert process_name == "com.example.MyApp"
        assert pid == 1234  # self.pid wins over the crash's pid
        # Never attribute an older, unrelated crash to this run.
        assert newer_than == pytest.approx(
            obj._session_start_time - IOS_CRASH_REPORT_CLOCK_TOLERANCE)
        assert newer_than <= obj._session_start_time

    def test_uses_crash_pid_when_logger_has_none(self, monkeypatch):
        _install_fake_ios(monkeypatch, report=_fake_report())
        obj = _make_logger()
        obj.pid = None
        obj._enrich_crash_log_ios(FakeCrash(pid=4321), None)
        assert FakeIOS.instances[0].calls[0][1] == 4321

    def test_missing_libimobiledevice_is_reported_and_skipped(self, monkeypatch):
        _install_fake_ios(monkeypatch, report=_fake_report(), available=False)
        obj = _make_logger()
        writer = FakeWriter()
        assert obj._enrich_crash_log_ios(FakeCrash(), writer) == (None, None)
        assert "idevicecrashreport not available" in writer.text

    def test_no_report_found(self, monkeypatch):
        _install_fake_ios(monkeypatch, report=None)
        obj = _make_logger()
        assert obj._enrich_crash_log_ios(FakeCrash(), FakeWriter()) == (None, None)

    def test_never_raises_when_the_helper_raises(self, monkeypatch):
        _install_fake_ios(monkeypatch, raises=True)
        obj = _make_logger()
        assert obj._enrich_crash_log_ios(FakeCrash(), FakeWriter()) == (None, None)

    def test_never_raises_when_the_writer_raises(self, monkeypatch):
        _install_fake_ios(monkeypatch, report=_fake_report())
        obj = _make_logger()

        class BadWriter:
            def write(self, chunk):
                raise IOError("disk full")

            def flush(self):
                raise IOError("disk full")

        # _write_crash_section swallows writer errors; the cause still comes back.
        assert obj._enrich_crash_log_ios(FakeCrash(), BadWriter()) == (
            "SIGSEGV", "SIGNAL 11 Segmentation fault: 11")


# ---------------------------------------------------------------------------
# _ios_crash_guidance (pure)
# ---------------------------------------------------------------------------
class TestIosCrashGuidance:
    def _lines(self, **kwargs):
        params = dict(breadcrumb="", verdict=None, spawn=True, access="full")
        params.update(kwargs)
        return SSL_Logger._ios_crash_guidance(**params)

    def test_agent_init_breadcrumb_says_no_hook_was_installed(self):
        text = "\n".join(self._lines(breadcrumb="agent-init:begin"))
        assert "died before any hook was installed" in text
        assert "agent-init:begin" in text

    def test_install_phase_breadcrumb_says_while_installing_hooks(self):
        text = "\n".join(self._lines(breadcrumb="install-phase:openssl"))
        assert "died while installing hooks" in text
        assert "install-phase:openssl" in text

    def test_unknown_breadcrumb_is_quoted_verbatim(self):
        text = "\n".join(self._lines(breadcrumb="pattern-scan: libboringssl.dylib"))
        assert "Last agent stage: pattern-scan: libboringssl.dylib." in text
        assert "before any hook was installed" not in text

    def test_missing_breadcrumb_is_stated(self):
        text = "\n".join(self._lines())
        assert "never reported a startup stage" in text

    def test_breadcrumb_verdict_comes_before_the_decoded_reason(self):
        from friTap.ios import IOSCrashVerdict
        lines = self._lines(
            breadcrumb="agent-init:begin",
            verdict=IOSCrashVerdict("watchdog timeout (0x8badf00d)", "attach instead"))
        joined = "\n".join(lines)
        assert joined.index("before any hook was installed") < joined.index("0x8badf00d")

    def test_decoded_reason_and_next_step_appear(self):
        from friTap.ios import IOSCrashVerdict
        text = "\n".join(self._lines(
            verdict=IOSCrashVerdict("killed for memory pressure (jetsam)",
                                    "free memory on the device")))
        assert "killed for memory pressure (jetsam)" in text
        assert "free memory on the device" in text

    def test_missing_report_points_at_libimobiledevice(self):
        text = "\n".join(self._lines(verdict=None))
        assert "libimobiledevice" in text

    @pytest.mark.parametrize("spawn", [True, False])
    def test_all_three_retries_appear_in_both_modes(self, spawn):
        text = "\n".join(self._lines(spawn=spawn))
        assert "-s" in text
        assert "--probe" in text
        assert "--modern" in text

    def test_spawn_and_attach_advice_differ(self):
        assert self._lines(spawn=True) != self._lines(spawn=False)
        assert "WITHOUT -s" in "\n".join(self._lines(spawn=True))
        assert "spawn with -s" in "\n".join(self._lines(spawn=False))

    def test_modern_retry_explains_the_ssl_ctx_offset_ab_test(self):
        text = "\n".join(self._lines())
        assert "SSL_CTX" in text

    def test_jailed_and_full_access_differ(self):
        jailed = "\n".join(self._lines(access="jailed"))
        full = "\n".join(self._lines(access="full"))
        assert jailed != full
        # "jailed" is a Gadget-injected app, NOT "no jailbreak on the device".
        assert "gadget" in jailed.lower()
        assert "frida-server" in full

    def test_unknown_access_adds_no_note(self):
        """An unknown access mode must not invent either claim."""
        text = "\n".join(self._lines(access=""))
        assert "gadget" not in text.lower()
        assert "frida-server" not in text


# ---------------------------------------------------------------------------
# _report_target_crash: iOS branch + regression guard for the hoisted gate
# ---------------------------------------------------------------------------
IOS_SEGV_CRASH = FakeCrash(report="", summary="Process crashed: SIGSEGV")


class TestReportTargetCrashIos:
    def test_attach_mode_ios_crash_gets_guidance(self, caplog, monkeypatch):
        """The friTap#65 reporter was attaching; attach-mode crashes used to get
        no guidance at all because the gate required self.spawn."""
        _install_fake_ios(monkeypatch, report=_fake_report())
        obj = _make_logger(spawn=False, crumb="agent-init:begin")
        with caplog.at_level(logging.ERROR):
            obj._report_target_crash("process-terminated", IOS_SEGV_CRASH)
        text = caplog.text

        assert "iOS target died while friTap was instrumenting it." in text
        assert "died before any hook was installed" in text
        assert "EXC_BAD_ACCESS" in text
        assert "--probe" in text and "--modern" in text
        # And the real cause reached the headline.
        assert "SIGSEGV" in text
        # No Android/Wine guidance leaked into the iOS branch.
        assert "PairIP" not in text
        assert "Wine" not in text

    def test_spawn_mode_ios_crash_gets_guidance(self, caplog, monkeypatch):
        _install_fake_ios(monkeypatch, report=_fake_report())
        obj = _make_logger(spawn=True)
        with caplog.at_level(logging.ERROR):
            obj._report_target_crash("process-terminated", IOS_SEGV_CRASH)
        assert "iOS target died while friTap was instrumenting it." in caplog.text
        assert "WITHOUT -s" in caplog.text

    def test_ios_report_summary_is_surfaced(self, caplog, monkeypatch):
        _install_fake_ios(monkeypatch, report=_fake_report())
        obj = _make_logger()
        with caplog.at_level(logging.ERROR):
            obj._report_target_crash("process-terminated", IOS_SEGV_CRASH)
        assert "iOS crash report: MyApp [1234]" in caplog.text

    def test_ios_without_a_crash_report_still_gets_guidance(self, caplog, monkeypatch):
        _install_fake_ios(monkeypatch, report=None)
        obj = _make_logger(spawn=False)
        with caplog.at_level(logging.ERROR):
            obj._report_target_crash("process-terminated", None)
        assert "iOS target died while friTap was instrumenting it." in caplog.text
        assert "libimobiledevice" in caplog.text

    def test_jailed_target_gets_the_gadget_note(self, caplog, monkeypatch):
        _install_fake_ios(monkeypatch, report=_fake_report())
        obj = _make_logger(access="jailed")
        with caplog.at_level(logging.ERROR):
            obj._report_target_crash("process-terminated", IOS_SEGV_CRASH)
        assert "gadget" in caplog.text.lower()

    def test_other_detach_reasons_get_no_guidance(self, caplog, monkeypatch):
        _install_fake_ios(monkeypatch, report=_fake_report())
        obj = _make_logger()
        with caplog.at_level(logging.ERROR):
            obj._report_target_crash("connection-terminated", IOS_SEGV_CRASH)
        assert "iOS target died while friTap was instrumenting it." not in caplog.text


ANDROID_JNI_CRASH = FakeCrash(
    report=(
        "signal 6 (SIGABRT), code -1 (SI_QUEUE)\n"
        "Abort message: 'JNI DETECTED ERROR IN APPLICATION: java_class == null'\n"
    ),
    summary="Process crashed: SIGABRT",
)


class TestNonIosGuidanceUnchangedByTheHoist:
    """Pin the pre-existing wording: hoisting the gate must not alter any
    non-iOS branch (Android hypothesis, Wine hints, anti-tamper)."""

    def test_android_spawn_guidance_is_verbatim(self, caplog):
        obj = _make_logger(os_id="android", spawn=True)
        obj._android_target_cached = True
        with caplog.at_level(logging.ERROR):
            obj._report_target_crash("process-terminated", None)
        text = caplog.text
        assert ("This may be an anti-tamper protection (e.g. Google PairIP / "
                "libpairipcore.so) self-destructing in response to friTap's hooks "
                "during app startup.") in text
        assert ("  -> Try starting the app first, then ATTACH friTap (run WITHOUT -s). "
                "See fkie-cad/friTap#64.") in text
        assert "iOS" not in text

    def test_android_real_cause_guidance_is_verbatim(self, caplog):
        obj = _make_logger(os_id="android", spawn=True,
                           crumb="pattern-scan: libmonochrome_64.so")
        obj._android_target_cached = False
        with caplog.at_level(logging.ERROR):
            obj._report_target_crash("process-terminated", ANDROID_JNI_CRASH)
        text = caplog.text
        assert "JNI DETECTED ERROR" in text
        assert ("  Note: the last agent hook activity was 'pattern-scan: "
                "libmonochrome_64.so', but it may have run on a different thread "
                "and be unrelated to the crash above.") in text
        assert ("  -> Spawn-time instrumentation can destabilize fragile app startup. "
                "Try starting the app first, then ATTACH friTap (run WITHOUT -s). "
                "See fkie-cad/friTap#64.") in text

    def test_anti_tamper_branch_still_fires(self, caplog):
        obj = _make_logger(os_id="android", spawn=True,
                           anti_tamper="Google PairIP (libpairipcore.so)")
        obj._android_target_cached = False
        with caplog.at_level(logging.ERROR):
            obj._report_target_crash("process-terminated", FakeCrash())
        text = caplog.text
        assert ("Anti-tamper protection was detected in this process "
                "(Google PairIP (libpairipcore.so)). It self-destructs when "
                "friTap's hooks are present during startup.") in text
        assert ("  -> Start the app first, then ATTACH friTap (run WITHOUT -s). "
                "See fkie-cad/friTap#64.") in text

    def test_wine_branch_still_fires(self, caplog, monkeypatch):
        obj = _make_logger(os_id="linux", spawn=True, target="wine my_app.exe")
        obj._android_target_cached = False
        monkeypatch.setattr("os.geteuid", lambda: 1000, raising=False)
        with caplog.at_level(logging.ERROR):
            obj._report_target_crash("process-terminated", None)
        text = caplog.text
        assert "Hint: Wine target terminated unexpectedly." in text
        assert ("  -> Try attach mode: start the app yourself with `wine ...`, "
                "then `fritap -k keys.log your_app.exe`. See "
                "docs/platforms/wine.md.") in text

    def test_wine_root_branch_still_fires(self, caplog, monkeypatch):
        obj = _make_logger(os_id="linux", spawn=True, target="wine my_app.exe")
        obj._android_target_cached = False
        monkeypatch.setattr("os.geteuid", lambda: 0, raising=False)
        with caplog.at_level(logging.ERROR):
            obj._report_target_crash("process-terminated", None)
        assert "friTap is running as root" in caplog.text
        assert "WINEPREFIX=/root/.wine" in caplog.text

    def test_attach_mode_off_ios_keeps_the_previous_silence(self, caplog):
        """Non-iOS attach mode had no guidance before the hoist and must keep
        behaving that way — the hoist only added the iOS branch."""
        obj = _make_logger(os_id="android", spawn=False)
        obj._android_target_cached = False
        with caplog.at_level(logging.ERROR):
            obj._report_target_crash("process-terminated", ANDROID_JNI_CRASH)
        text = caplog.text
        assert "Target process terminated unexpectedly" in text
        assert "PairIP" not in text
        assert "WITHOUT -s" not in text
