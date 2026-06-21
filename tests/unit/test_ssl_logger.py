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

from unittest.mock import patch, mock_open, MagicMock

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


class TestAgentBundleResolution:
    """FRITAP_AGENT_BUNDLE override (§C step 6.5) + regression guard for the name
    collision it must NOT reintroduce.

    The resolver method `_resolve_agent_bundle_path` must stay distinct from the
    `_agent_script_path` *instance attribute* (the non-Frida processor bundle
    path, which defaults to None under the Frida backend). If the method is ever
    renamed back to `_agent_script_path`, the None instance attribute shadows it
    and `get_agent_script()` calls None() -> TypeError at spawn time.
    """

    def test_default_bundle_path_is_shipped_bundle(self):
        import os
        from friTap.legacy.ssl_logger_core import here
        logger = SSL_Logger("test_app")
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("FRITAP_AGENT_BUNDLE", None)
            assert logger._resolve_agent_bundle_path() == os.path.join(here, "fritap_agent.js")

    def test_env_override_takes_precedence(self):
        import os
        logger = SSL_Logger("test_app")
        with patch.dict(os.environ, {"FRITAP_AGENT_BUNDLE": "/tmp/full_bundle.js"}):
            assert logger._resolve_agent_bundle_path() == "/tmp/full_bundle.js"

    def test_resolver_not_shadowed_by_instance_attr(self):
        # Reproduces the exact bug condition: under the Frida backend the
        # _agent_script_path instance attribute is None. The resolver must still
        # be callable (i.e. a distinct name).
        logger = SSL_Logger("test_app")
        assert logger._agent_script_path is None
        assert callable(logger._resolve_agent_bundle_path)

    def test_get_agent_script_honors_override(self):
        import os
        logger = SSL_Logger("test_app")
        with patch.dict(os.environ, {"FRITAP_AGENT_BUNDLE": "/tmp/full_bundle.js"}):
            with patch("builtins.open", new_callable=mock_open, read_data="// agent") as mo:
                content = logger.get_agent_script()
        mo.assert_called_with("/tmp/full_bundle.js", encoding="utf-8", newline="\n")
        assert content == "// agent"


class TestAgentBundleEntryPointDiscovery:
    """§C.4: ABI-filtered ``fritap.agent_bundle`` entry-point discovery and the
    full precedence FRITAP_AGENT_BUNDLE > entry point (ABI-matched) > shipped.

    Generic by design — the seam names no protocol; a full/extended build
    registers an entry point so its bundle is auto-selected without the env var.
    """

    @staticmethod
    def _fake_ep(name, abi, path):
        obj = MagicMock()
        obj.AGENT_ABI_VERSION = abi
        obj.agent_bundle_path = lambda: path
        ep = MagicMock()
        ep.name = name
        ep.load.return_value = obj
        return ep

    def test_matching_abi_entry_point_selected(self):
        import os
        from friTap.constants import AGENT_ABI_VERSION
        logger = SSL_Logger("test_app")
        ep = self._fake_ep("full", AGENT_ABI_VERSION, "/tmp/full.js")
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("FRITAP_AGENT_BUNDLE", None)
            with patch("importlib.metadata.entry_points", return_value=[ep]), \
                 patch("os.path.isfile", return_value=True):
                assert logger._resolve_agent_bundle_path() == os.path.abspath("/tmp/full.js")

    def test_mismatched_abi_entry_point_skipped(self):
        import os
        from friTap.constants import AGENT_ABI_VERSION
        from friTap.legacy.ssl_logger_core import here
        logger = SSL_Logger("test_app")
        ep = self._fake_ep("stale", AGENT_ABI_VERSION + 99, "/tmp/stale.js")
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("FRITAP_AGENT_BUNDLE", None)
            with patch("importlib.metadata.entry_points", return_value=[ep]), \
                 patch("os.path.isfile", return_value=True):
                # ABI mismatch -> skipped -> falls through to the shipped bundle.
                assert logger._resolve_agent_bundle_path() == os.path.join(here, "fritap_agent.js")

    def test_missing_file_entry_point_skipped(self):
        import os
        from friTap.constants import AGENT_ABI_VERSION
        from friTap.legacy.ssl_logger_core import here
        logger = SSL_Logger("test_app")
        ep = self._fake_ep("full", AGENT_ABI_VERSION, "/tmp/does_not_exist.js")
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("FRITAP_AGENT_BUNDLE", None)
            with patch("importlib.metadata.entry_points", return_value=[ep]), \
                 patch("os.path.isfile", return_value=False):
                assert logger._resolve_agent_bundle_path() == os.path.join(here, "fritap_agent.js")

    def test_env_override_beats_entry_point(self):
        import os
        from friTap.constants import AGENT_ABI_VERSION
        logger = SSL_Logger("test_app")
        ep = self._fake_ep("full", AGENT_ABI_VERSION, "/tmp/full.js")
        with patch.dict(os.environ, {"FRITAP_AGENT_BUNDLE": "/tmp/explicit.js"}):
            with patch("importlib.metadata.entry_points", return_value=[ep]), \
                 patch("os.path.isfile", return_value=True):
                assert logger._resolve_agent_bundle_path() == "/tmp/explicit.js"


class TestAgentAbiCheck:
    """§C.4: best-effort JS<->Python ABI sanity check — non-fatal, defensive,
    uses only the blocking exports_sync proxy."""

    def _logger_with_script(self, abi_returned=None, has_export=True, raises=False):
        logger = SSL_Logger("test_app")
        script = MagicMock()
        if has_export:
            if raises:
                script.exports_sync.agent_abi_version.side_effect = RuntimeError("script destroyed")
            else:
                script.exports_sync.agent_abi_version.return_value = abi_returned
        else:
            script.exports_sync = None
        logger.script = script
        logger.logger = MagicMock()
        return logger

    def test_matching_abi_no_warning(self):
        from friTap.constants import AGENT_ABI_VERSION
        logger = self._logger_with_script(abi_returned=AGENT_ABI_VERSION)
        logger._check_agent_abi()
        logger.logger.warning.assert_not_called()

    def test_mismatched_abi_warns(self):
        from friTap.constants import AGENT_ABI_VERSION
        logger = self._logger_with_script(abi_returned=AGENT_ABI_VERSION + 1)
        logger._check_agent_abi()
        assert logger.logger.warning.called

    def test_missing_export_tolerated(self):
        logger = self._logger_with_script(has_export=False)
        logger._check_agent_abi()  # must not raise
        logger.logger.warning.assert_not_called()

    def test_rpc_exception_tolerated(self):
        logger = self._logger_with_script(raises=True)
        logger._check_agent_abi()  # must not raise
        logger.logger.warning.assert_not_called()
