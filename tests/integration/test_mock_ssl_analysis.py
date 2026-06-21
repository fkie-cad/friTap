"""
Mock integration tests for the SSL analysis workflow.

These tests drive the *real* ``SSL_Logger`` API
(``friTap/legacy/ssl_logger_core.py``, re-exported from ``friTap.ssl_logger``),
which is EventBus-based. ``SSL_Logger`` wires a set of modular output handlers
(JSON / keylog / pcap) onto an internal :class:`EventBus` at construction time;
agent messages are turned into events via the message router and consumed by
those handlers. No real Frida device or running process is required to exercise
constructor wiring, output-handler setup, event handling, library detection,
session-data accounting and JSON finalization — that is what these tests cover.

Scenarios that genuinely need a live device/frida-server (attach, spawn,
script load) are exercised at their observable boundary (event emission / state)
rather than by calling non-existent private helpers.

The ``mock_integration`` marker is preserved so ``tests/conftest.py`` keeps
skipping the module on CI machines without Frida installed; on a Frida-present
machine these tests run and pass.
"""

import json
import os
import tempfile

import pytest

from friTap.ssl_logger import SSL_Logger
from friTap.android import Android
from friTap.events import (
    LibraryDetectedEvent,
    SessionEvent,
    DatalogEvent,
    ErrorEvent,
    SESSION_STARTED,
)
from friTap.output.json_handler import JsonOutputHandler
from friTap.output.keylog_handler import KeylogOutputHandler


def _json_handler(logger):
    """Return the JsonOutputHandler wired onto the logger, or None."""
    for handler in logger._output_handlers:
        if isinstance(handler, JsonOutputHandler):
            return handler
    return None


@pytest.mark.mock_integration
class TestMockSSLAnalysisWorkflow:
    """Constructor wiring + EventBus-driven analysis workflow."""

    def test_desktop_ssl_analysis_workflow(self):
        """Desktop logger constructs, wires handlers, and is ready to run."""
        with tempfile.TemporaryDirectory() as tmp:
            json_path = os.path.join(tmp, "test_output.json")
            logger = SSL_Logger("firefox", verbose=True, json_output=json_path)

            # Real constructor wiring (no _attach_to_target/_load_agent exist).
            assert logger.target_app == "firefox"
            assert logger.verbose is True
            assert logger.json_output == json_path
            assert logger.running is True
            # The JSON output handler must have been created and registered.
            assert _json_handler(logger) is not None
            assert logger._handlers_active is True
            # The agent script the logger will load is resolvable.
            assert logger.agent_script == "fritap_agent.js"

    def test_android_ssl_analysis_workflow(self):
        """Android logger reflects mobile config and shares the EventBus path."""
        logger = SSL_Logger("com.example.app", mobile=True, verbose=True)

        assert logger.mobile is True
        assert logger.target_app == "com.example.app"
        # session_info records the mobile flag — observable, real state.
        assert logger.session_data["session_info"]["mobile"] is True
        assert logger.session_data["session_info"]["target_app"] == "com.example.app"
        # An Android helper can be constructed without a device (lazy ADB).
        android = Android()
        assert android is not None

    def test_ssl_library_detection_workflow(self):
        """A LibraryDetectedEvent is tracked on the logger's real state."""
        logger = SSL_Logger("test_app")

        logger._event_bus.emit(LibraryDetectedEvent(library="libssl.so.1.1",
                                                     path="/usr/lib/libssl.so.1.1"))

        # _on_library_detected records every library seen (used for exit hint).
        assert "libssl.so.1.1" in logger._detected_libraries

    def test_ssl_key_extraction_workflow(self):
        """A keylog file is created and key material is written via the handler.

        The keylog handler opens its file lazily on the first matching
        KeylogEvent, so we drive a real TLS CLIENT_RANDOM key line through the
        EventBus and assert it lands on disk.
        """
        from friTap.events import KeylogEvent

        with tempfile.TemporaryDirectory() as tmp:
            key_file = os.path.join(tmp, "keys.log")
            logger = SSL_Logger("test_app", keylog=key_file)

            handler = next(
                (h for h in logger._output_handlers
                 if isinstance(h, KeylogOutputHandler)),
                None,
            )
            assert handler is not None

            client_random = "0123456789abcdef" * 4
            master_secret = "fedcba9876543210" * 8
            logger._event_bus.emit(KeylogEvent(
                protocol="tls",
                key_data=f"CLIENT_RANDOM {client_random} {master_secret}",
            ))

            assert os.path.exists(key_file)
            with open(key_file) as fh:
                contents = fh.read()
            assert client_random in contents

    def test_pcap_capture_workflow(self):
        """Requesting a pcap builds a real PCAP object on the logger."""
        with tempfile.TemporaryDirectory() as tmp:
            pcap_path = os.path.join(tmp, "test_capture.pcap")
            logger = SSL_Logger("test_app", pcap_name=pcap_path)

            assert logger.pcap_obj is not None
            assert logger.pcap_name == pcap_path

    def test_json_output_workflow(self):
        """Session/data/library events flow into JSON output and finalize to disk."""
        with tempfile.TemporaryDirectory() as tmp:
            json_path = os.path.join(tmp, "test_output.json")
            logger = SSL_Logger("test_app", json_output=json_path)

            handler = _json_handler(logger)
            assert handler is not None

            # Drive the real EventBus the way agent messages would.
            logger._event_bus.emit(SessionEvent(
                session_id="session_123",
                event_type=SESSION_STARTED,
                cipher_suite="TLS_AES_256_GCM_SHA384",
                protocol_version="TLS 1.3",
            ))
            logger._event_bus.emit(DatalogEvent(
                src_addr="192.168.1.100", src_port=54321,
                dst_addr="93.184.216.34", dst_port=443,
                data=b"hello",
            ))
            logger._event_bus.emit(LibraryDetectedEvent(library="OpenSSL"))

            # Handler in-memory state reflects the events.
            assert len(handler._data["ssl_sessions"]) == 1
            assert len(handler._data["connections"]) == 1
            assert any(lib["name"] == "OpenSSL"
                       for lib in handler._data["libraries_detected"])
            assert handler._data["statistics"]["total_connections"] == 1
            assert handler._data["statistics"]["total_bytes_captured"] == len(b"hello")

            # Finalize: close() writes the JSON document to disk.
            handler.close()
            assert os.path.exists(json_path)
            with open(json_path) as fh:
                written = json.load(fh)
            assert written["ssl_sessions"][0]["session_id"] == "session_123"
            assert written["connections"][0]["dst_port"] == 443
            assert "statistics" in written


@pytest.mark.mock_integration
class TestMockLibrarySpecificWorkflows:
    """Library-specific detection via real LibraryDetectedEvent routing."""

    @pytest.mark.parametrize("library", [
        "libssl.so.1.1",   # OpenSSL
        "libssl.so",       # BoringSSL
        "libnss3.so",      # NSS
    ])
    def test_library_detection_records_library(self, library):
        """Each TLS library kind is tracked when its detection event fires."""
        logger = SSL_Logger("some_app")
        logger._event_bus.emit(LibraryDetectedEvent(library=library))
        assert library in logger._detected_libraries

    def test_multiple_libraries_detected(self):
        """Several libraries detected in one session are all retained."""
        logger = SSL_Logger("firefox")
        for lib in ("libnss3.so", "libssl3.so", "libplc4.so"):
            logger._event_bus.emit(LibraryDetectedEvent(library=lib))
        assert {"libnss3.so", "libssl3.so", "libplc4.so"} <= logger._detected_libraries

    def test_auto_protocol_switch_on_detection(self):
        """In --protocol auto, a detected library can swap the active handler.

        With the default ``auto`` registry the handler starts as TLS; detecting
        a TLS library keeps it on the TLS handler (real auto_detect behavior).
        """
        logger = SSL_Logger("chrome")
        assert logger.protocol in ("auto", "tls", "all")
        start_handler = logger._protocol_handler
        logger._event_bus.emit(LibraryDetectedEvent(library="libssl.so",
                                                     protocol="tls"))
        # Handler remains valid (TLS for a TLS library); never becomes None.
        assert logger._protocol_handler is not None
        assert logger._protocol_handler.name == start_handler.name


@pytest.mark.mock_integration
class TestMockPlatformSpecificWorkflows:
    """Platform-specific construction. Real attach needs a device, so we assert
    on construction/config rather than calling non-existent attach helpers."""

    def test_android_integration_workflow(self):
        """Android helper constructs and an Android-targeted logger is mobile."""
        android = Android()
        logger = SSL_Logger("com.example.app", mobile=True)
        assert logger.mobile is True
        # Android helper exposes the real ADB-availability check.
        assert hasattr(android, "check_adb_availability")
        assert callable(android.check_adb_availability)

    def test_windows_integration_workflow(self):
        """A .exe target constructs cleanly with default (TLS) protocol."""
        logger = SSL_Logger("application.exe")
        assert logger.target_app == "application.exe"
        assert logger.mobile is False
        assert logger._protocol_handler is not None

    def test_macos_integration_workflow(self):
        """A macOS app-bundle path target constructs cleanly."""
        path = "/Applications/App.app/Contents/MacOS/App"
        logger = SSL_Logger(path)
        assert logger.target_app == path
        assert logger._handlers_active is True


@pytest.mark.mock_integration
class TestMockErrorHandlingWorkflows:
    """Error handling that is observable without a device."""

    def test_missing_app_and_config_raises(self):
        """Constructing with neither app nor config is a hard error."""
        with pytest.raises(ValueError, match="Either 'app' or 'config'"):
            SSL_Logger()

    def test_unknown_protocol_raises(self):
        """Requesting an unregistered protocol fails fast at construction."""
        from friTap.config import FriTapConfig
        config = FriTapConfig.from_legacy_params(
            app="test_app", protocol="definitely_not_a_protocol",
        )
        with pytest.raises((RuntimeError, ValueError),
                           match="protocol"):
            SSL_Logger(config=config)

    def test_error_event_recorded_in_json(self):
        """An ErrorEvent is captured by the JSON handler's error list."""
        with tempfile.TemporaryDirectory() as tmp:
            json_path = os.path.join(tmp, "errs.json")
            logger = SSL_Logger("test_app", json_output=json_path)
            handler = _json_handler(logger)
            assert handler is not None
            logger._event_bus.emit(ErrorEvent(error="boom",
                                              description="something failed"))
            assert any(e["error"] == "boom" for e in handler._data["errors"])

    def test_adb_not_available_workflow(self):
        """Android.check_adb_availability returns False when adb is missing."""
        from unittest.mock import patch
        android = Android()
        with patch("friTap.android.subprocess.run",
                   side_effect=FileNotFoundError("adb not found")):
            assert android.check_adb_availability() is False


@pytest.mark.mock_integration
class TestMockPerformanceWorkflows:
    """Throughput / volume handling through the real EventBus."""

    def test_high_throughput_workflow(self):
        """Many DatalogEvents are all accounted for by the JSON handler."""
        with tempfile.TemporaryDirectory() as tmp:
            json_path = os.path.join(tmp, "tp.json")
            logger = SSL_Logger("high_throughput_app", json_output=json_path)
            handler = _json_handler(logger)
            assert handler is not None

            total_bytes = 0
            for i in range(1000):
                payload = (f"ssl_packet_{i}".encode()) * 100
                total_bytes += len(payload)
                logger._event_bus.emit(DatalogEvent(
                    src_addr="192.168.1.100", src_port=54321 + i,
                    dst_addr="93.184.216.34", dst_port=443,
                    data=payload,
                ))

            assert handler._data["statistics"]["total_connections"] == 1000
            assert handler._data["statistics"]["total_bytes_captured"] == total_bytes

    def test_memory_usage_workflow(self):
        """Many SessionEvents accumulate without loss."""
        with tempfile.TemporaryDirectory() as tmp:
            json_path = os.path.join(tmp, "mem.json")
            logger = SSL_Logger("memory_test_app", json_output=json_path)
            handler = _json_handler(logger)
            assert handler is not None

            for i in range(100):
                logger._event_bus.emit(SessionEvent(
                    session_id=f"session_{i}",
                    event_type=SESSION_STARTED,
                    cipher_suite="TLS_AES_256_GCM_SHA384",
                    protocol_version="TLS 1.3",
                ))

            assert len(handler._data["ssl_sessions"]) == 100
            assert handler._data["statistics"]["total_sessions"] == 100

    def test_concurrent_analysis_workflow(self):
        """Multiple independent loggers each wire their own EventBus + handlers."""
        loggers = [SSL_Logger(f"app_{i}") for i in range(5)]
        assert len(loggers) == 5
        for logger in loggers:
            assert logger.running is True
            # Each logger owns a distinct EventBus (no shared global state).
            assert logger._event_bus is not None
        assert len({id(l._event_bus) for l in loggers}) == 5
