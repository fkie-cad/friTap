"""
Unit tests for the Python -> Agent pattern handshake boundary.

The agent's `isPatternReplaced()` gate and `typeof === "string"` boundary
check rely on guarantees about what the host posts in `config_batch`
under the `patterns` key. These tests pin those guarantees so future
changes that would silently disable pattern hooking - or crash the agent
at startup - are caught at CI time.
"""

import json
import logging

import pytest

from friTap.patterns.loader import PatternLoader


# Mirrors the agent-side `PATTERNS_PLACEHOLDER` constant. Duplicated on
# purpose so a rename in the agent (which would change the boundary
# semantics) is caught here instead of silently shipping.
PATTERNS_PLACEHOLDER = "{PATTERNS}"


@pytest.fixture
def fritap_logger():
    return logging.getLogger("friTap")


@pytest.fixture(scope="module")
def default_payload():
    return PatternLoader.load(None, logging.getLogger("friTap"))


class TestPatternLoaderReturnType:

    def test_returns_string_or_none(self, fritap_logger):
        result = PatternLoader.load(None, fritap_logger)
        assert isinstance(result, (str, type(None)))

    def test_default_string_longer_than_agent_placeholder(self, default_payload):
        if default_payload is None:
            pytest.skip("default_patterns.json not present")
        assert len(default_payload) > len(PATTERNS_PLACEHOLDER)

    def test_returned_string_does_not_equal_placeholder(self, default_payload):
        if default_payload is None:
            pytest.skip("default_patterns.json not present")
        assert default_payload != PATTERNS_PLACEHOLDER


class TestDefaultPayloadIntegrity:

    def test_default_json_round_trips(self, default_payload):
        if default_payload is None:
            pytest.skip("default_patterns.json not present")
        parsed = json.loads(default_payload)
        assert isinstance(parsed, dict)

    def test_default_has_real_library_keys(self, default_payload):
        if default_payload is None:
            pytest.skip("default_patterns.json not present")
        parsed = json.loads(default_payload)
        non_meta_keys = [k for k in parsed.keys() if not k.startswith("_")]
        assert len(non_meta_keys) > 0


class TestPatternLoaderDegradation:

    def test_missing_user_file_does_not_raise(self, fritap_logger):
        result = PatternLoader.load(
            "/nonexistent/path/does/not/exist.json", fritap_logger
        )
        assert isinstance(result, (str, type(None)))

    def test_invalid_user_json_does_not_raise(self, fritap_logger, tmp_path):
        bad_file = tmp_path / "bad.json"
        bad_file.write_text("{ this is not valid JSON")
        result = PatternLoader.load(str(bad_file), fritap_logger)
        assert isinstance(result, (str, type(None)))


class TestUserOverrideMerge:

    def test_user_override_merges_into_defaults(
        self, fritap_logger, default_payload, tmp_path
    ):
        if default_payload is None:
            pytest.skip("default_patterns.json not present")
        defaults_parsed = json.loads(default_payload)

        user_file = tmp_path / "user.json"
        # Modern Schema A requires an OS layer: library -> os -> arch -> function.
        user_file.write_text(json.dumps({
            "my_custom_lib": {
                "android": {
                    "x64": {"my_func": ["48 89 E5"]},
                }
            }
        }))

        merged = PatternLoader.load(str(user_file), fritap_logger)
        assert isinstance(merged, str)
        merged_parsed = json.loads(merged)

        assert "my_custom_lib" in merged_parsed
        assert merged_parsed["my_custom_lib"]["android"]["x64"]["my_func"] == ["48 89 E5"]

        for k in defaults_parsed:
            if k.startswith("_"):
                continue
            assert k in merged_parsed


class TestSSLLoggerWireContract:

    def test_pattern_data_is_str_or_none_after_init(self, ssl_logger_factory):
        logger = ssl_logger_factory()
        assert isinstance(logger.pattern_data, (str, type(None)))

    def test_pattern_data_default_is_distinguishable_from_placeholder(
        self, ssl_logger_factory
    ):
        logger = ssl_logger_factory()
        if logger.pattern_data is None:
            pytest.skip("pattern_data is None")
        assert logger.pattern_data != PATTERNS_PLACEHOLDER
        assert len(logger.pattern_data) > len(PATTERNS_PLACEHOLDER)
