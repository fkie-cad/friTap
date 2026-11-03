"""Script-error policy: only fatal (load/init-time) agent errors end the run.

An uncaught exception in a deferred agent callback (Java.perform inside a
setTimeout, an Interceptor hook) does not stop the Frida script. SIGTERMing
the host for it detached friTap while Java hooks were mid-install and crashed
Chrome with SIGSEGV.
"""

import logging
import threading
import types

import pytest

from friTap import error_handler
from friTap.error_handler import RuntimeErrorLimiter, ScriptErrorHandler
from friTap.events import HookBreadcrumbEvent
from friTap.legacy.ssl_logger_core import SSL_Logger
from friTap.plugins import legacy_custom_script
from friTap.plugins.legacy_custom_script import LegacyCustomScriptPlugin

RUNTIME_ERROR = {
    "type": "error",
    "description": "TypeError: cannot read property 'implementation' of undefined",
    "stack": "TypeError: x\n    at hookJava (/agent.js:10)\n    at <anonymous>",
    "fileName": "/agent.js", "lineNumber": 10, "columnNumber": 3,
}


@pytest.fixture(autouse=True)
def _fresh_limiter():
    RuntimeErrorLimiter.reset()
    yield
    RuntimeErrorLimiter.reset()


@pytest.fixture
def kills(monkeypatch):
    calls = []
    monkeypatch.setattr(error_handler.os, "kill", lambda pid, sig: calls.append(sig))
    monkeypatch.setattr(legacy_custom_script.os, "kill", lambda pid, sig: calls.append(sig))
    return calls


def _make_logger():
    obj = SSL_Logger.__new__(SSL_Logger)
    obj.logger = logging.getLogger("test.script_error_policy")
    obj._event_bus = types.SimpleNamespace(emit=lambda e: obj._events.append(e))
    obj._events = []
    obj.session_data = {"errors": []}
    obj._session_data_lock = threading.Lock()
    obj._config = types.SimpleNamespace(
        output=types.SimpleNamespace(json_output="session.json"), debug_output=False)
    obj.running = True
    obj._last_hook_breadcrumb = ""
    obj._agent_init_complete = False
    obj.startup = False
    obj.script = object()
    return obj


def _complete_init(obj):
    obj._on_hook_breadcrumb(HookBreadcrumbEvent(marker="agent-init: complete"))


class TestErrorClassification:
    def test_error_before_init_complete_is_fatal(self):
        obj = _make_logger()
        obj._on_hook_breadcrumb(HookBreadcrumbEvent(marker="agent-init-FAILED: hooks"))
        assert obj._is_fatal_script_error(RUNTIME_ERROR) is True

    def test_error_during_startup_handshake_is_fatal(self):
        obj = _make_logger()
        _complete_init(obj)
        obj.startup = True
        assert obj._is_fatal_script_error(RUNTIME_ERROR) is True

    def test_error_after_init_complete_is_runtime(self):
        obj = _make_logger()
        _complete_init(obj)
        obj._on_hook_breadcrumb(HookBreadcrumbEvent(marker="ssl-read: libssl.so"))
        assert obj._is_fatal_script_error(RUNTIME_ERROR) is False

    def test_explicit_fatal_marker_is_fatal(self):
        obj = _make_logger()
        _complete_init(obj)
        assert obj._is_fatal_script_error(dict(RUNTIME_ERROR, fatal=True)) is True


class TestSslLoggerScriptErrors:
    def test_runtime_error_does_not_sigterm_and_is_logged_once(self, kills, caplog):
        obj = _make_logger()
        _complete_init(obj)
        with caplog.at_level(logging.WARNING):
            for _ in range(5):
                obj.on_fritap_message(None, dict(RUNTIME_ERROR), None)
        assert kills == []
        assert caplog.text.count("Agent runtime error") == 1
        assert caplog.text.count("friTap keeps running") == 1
        assert "at hookJava" in caplog.text  # stack included
        assert len(obj._events) == 1  # ErrorEvent for the logged occurrence only

    def test_session_continues_after_runtime_error(self, kills):
        obj = _make_logger()
        _complete_init(obj)
        obj.on_fritap_message(None, dict(RUNTIME_ERROR), None)
        # Still running, the error is in the JSON session log, and a later
        # (different) error is reported too.
        obj.on_fritap_message(None, dict(RUNTIME_ERROR, description="other"), None)
        assert kills == [] and obj.running is True
        assert [e["type"] for e in obj.session_data["errors"]] == [
            "frida_script_runtime_error"] * 2

    def test_load_time_error_still_sigterms(self, kills, caplog):
        obj = _make_logger()  # no "agent-init: complete" yet
        with caplog.at_level(logging.CRITICAL):
            obj.on_fritap_message(None, dict(RUNTIME_ERROR), None)
        assert len(kills) == 1
        assert "Exiting due to script error." in caplog.text


class TestRateLimit:
    def test_repeat_summarised_after_interval(self, kills, caplog, monkeypatch):
        clock = [1000.0]
        monkeypatch.setattr(error_handler.time, "monotonic", lambda: clock[0])
        log = logging.getLogger("test.rate_limit")
        bus = types.SimpleNamespace(emit=lambda e: None)
        args = (bus, {"errors": []}, threading.Lock(), None, False, log)
        with caplog.at_level(logging.ERROR):
            for _ in range(3):
                ScriptErrorHandler.handle(dict(RUNTIME_ERROR), *args, fatal=False)
            clock[0] += error_handler.RUNTIME_ERROR_LOG_INTERVAL + 1
            ScriptErrorHandler.handle(dict(RUNTIME_ERROR), *args, fatal=False)
        lines = [r.getMessage() for r in caplog.records if "runtime error" in r.getMessage()]
        assert len(lines) == 2
        assert "repeated 2 more time(s)" in lines[1]
        assert kills == []

    def test_distinct_errors_each_logged(self, kills, caplog):
        log = logging.getLogger("test.rate_limit")
        bus = types.SimpleNamespace(emit=lambda e: None)
        with caplog.at_level(logging.ERROR):
            for i in range(3):
                ScriptErrorHandler.handle(dict(RUNTIME_ERROR, description=f"err {i}"),
                                          bus, {"errors": []}, threading.Lock(),
                                          None, False, log, fatal=False)
        assert sum("runtime error" in r.getMessage() for r in caplog.records) == 3

    def test_table_is_bounded(self, monkeypatch):
        monkeypatch.setattr(error_handler, "MAX_TRACKED_RUNTIME_ERRORS", 4)
        for i in range(50):
            RuntimeErrorLimiter.check(("k", i), 0.0)
        assert len(RuntimeErrorLimiter._entries) <= 5

    def test_runtime_error_text_is_sanitised(self, kills, caplog):
        log = logging.getLogger("test.rate_limit")
        bus = types.SimpleNamespace(emit=lambda e: None)
        with caplog.at_level(logging.ERROR):
            ScriptErrorHandler.handle(dict(RUNTIME_ERROR, description="x\x1b]0;t\x07"),
                                      bus, {"errors": []}, threading.Lock(),
                                      None, False, log, fatal=False)
        assert "\x1b" not in caplog.text and "\\x1b" in caplog.text


class TestLegacyCustomScriptPlugin:
    def test_error_during_load_sigterms(self, kills):
        plugin = LegacyCustomScriptPlugin("x.js")
        plugin._loading = True
        plugin.on_script_message(dict(RUNTIME_ERROR), None)
        assert len(kills) == 1

    def test_error_right_after_load_still_counts_as_load_time(self, kills, monkeypatch):
        plugin = LegacyCustomScriptPlugin("x.js")
        monkeypatch.setattr(legacy_custom_script.time, "monotonic", lambda: 100.0)
        plugin._loaded_at = 99.9
        plugin.on_script_message(dict(RUNTIME_ERROR), None)
        assert len(kills) == 1

    def test_runtime_error_after_load_keeps_running(self, kills, monkeypatch, caplog):
        plugin = LegacyCustomScriptPlugin("x.js")
        monkeypatch.setattr(legacy_custom_script.time, "monotonic", lambda: 100.0)
        plugin._loaded_at = 10.0
        with caplog.at_level(logging.ERROR):
            plugin.on_script_message(dict(RUNTIME_ERROR), None)
            plugin.on_script_message(dict(RUNTIME_ERROR), None)
        assert kills == []
        assert caplog.text.count("Custom script runtime error") == 1

    def test_on_instrument_marks_load_window(self, kills):
        plugin = LegacyCustomScriptPlugin("x.js")
        seen = []
        plugin.get_script_source = lambda ctx: ""  # skip creating a script
        original = legacy_custom_script.ScriptPlugin.on_instrument

        def spy(self, ctx):
            seen.append(self._loading)
            return original(self, ctx)

        legacy_custom_script.ScriptPlugin.on_instrument = spy
        try:
            plugin.on_instrument(types.SimpleNamespace(backend_name="frida"))
        finally:
            legacy_custom_script.ScriptPlugin.on_instrument = original
        assert seen == [True]
        assert plugin._loading is False and plugin._loaded_at is not None
