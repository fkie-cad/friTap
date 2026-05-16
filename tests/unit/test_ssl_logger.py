"""
Unit tests for the legacy SSL_Logger class.

History note (2026-05): an earlier version of this file contained ~22 tests
probing private methods (`_get_device`, `_attach_to_process`, `_setup_logging`,
`_format_log_message`, `_load_agent_script`, `_get_android_helper`,
`_add_connection`, `_update_statistics`, `_add_detected_library`,
`_write_json_output`, `finalize_json_output`, ...) that were never part of the
SSL_Logger's actual public surface. Those tests were authored against an
imagined API that did not match the codebase, and were removed in the F1
follow-up to issue #63 (no behavioral coverage was lost — none of them ever
exercised real code paths).

Scope of this file going forward: end-to-end smoke checks of `SSL_Logger`
construction and the JSON-output session-data shape. Deeper integration tests
should target `CoreController` / `Session` directly (see `friTap/core.py`),
not the legacy shim.
"""

from unittest.mock import patch, mock_open

from friTap.ssl_logger import SSL_Logger
from friTap.about import __version__


class TestSSLLoggerInitialization:
    """Pin the bool-flag semantics (target_app, verbose, spawn, mobile,
    json_output) — these properties are what consumers read after construction;
    silently changing them is a behavior break."""

    def test_basic_initialization(self):
        logger = SSL_Logger("test_app")

        assert logger.target_app == "test_app"
        assert logger.verbose is False
        assert logger.spawn is False
        assert logger.json_output is None
        assert logger.running is True

    def test_initialization_with_verbose(self):
        logger = SSL_Logger("test_app", verbose=True)

        assert logger.target_app == "test_app"
        assert logger.verbose is True

    def test_initialization_with_spawn(self):
        logger = SSL_Logger("test_app", spawn=True)

        assert logger.target_app == "test_app"
        assert logger.spawn is True

    @patch('builtins.open', new_callable=mock_open)
    def test_initialization_with_json_output(self, mock_file):
        logger = SSL_Logger("test_app", json_output="output.json")

        mock_file.assert_called_with("output.json", "w")
        assert logger.json_output == "output.json"

    def test_initialization_with_mobile(self):
        logger = SSL_Logger("test_app", mobile=True)

        assert logger.target_app == "test_app"
        assert logger.mobile is True


class TestJSONSessionDataShape:
    """Shape of the JSON session-data dict — pinned because consumers (the
    JSON output writer in `friTap/legacy/ssl_logger_core.py:1170`) depend on
    these top-level keys existing."""

    @patch('builtins.open', new_callable=mock_open)
    def test_top_level_keys(self, mock_file):
        logger = SSL_Logger("test_app", json_output="test.json")

        for key in ("friTap_version", "session_info", "ssl_sessions",
                    "connections", "key_extractions", "errors", "statistics"):
            assert key in logger.session_data, f"missing top-level key: {key}"

        assert logger.session_data["friTap_version"] == __version__
        assert logger.session_data["session_info"]["target_app"] == "test_app"

    @patch('builtins.open', new_callable=mock_open)
    def test_statistics_default_keys(self, mock_file):
        logger = SSL_Logger("test_app", json_output="test.json")

        stats = logger.session_data["statistics"]
        for key in ("total_sessions", "total_connections",
                    "total_bytes_captured", "libraries_detected"):
            assert key in stats, f"missing statistics key: {key}"

        assert stats["total_sessions"] == 0
        assert stats["total_connections"] == 0
        assert stats["total_bytes_captured"] == 0
        assert stats["libraries_detected"] == []


class TestSSLSessionAppend:
    """`add_ssl_session` is the public entry point for the JSON writer to
    record a TLS session. Pinned here because removing it would silently
    drop session data from JSON output."""

    @patch('builtins.open', new_callable=mock_open)
    def test_add_ssl_session_appends(self, mock_file):
        logger = SSL_Logger("test_app", json_output="test.json")

        logger.add_ssl_session({
            "session_id": "session_123",
            "cipher_suite": "TLS_AES_256_GCM_SHA384",
            "protocol_version": "TLSv1.3",
        })

        sessions = logger.session_data["ssl_sessions"]
        assert len(sessions) == 1
        assert sessions[0]["session_id"] == "session_123"
        assert sessions[0]["cipher_suite"] == "TLS_AES_256_GCM_SHA384"
