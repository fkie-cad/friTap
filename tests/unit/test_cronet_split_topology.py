"""Unit tests for Cronet split-topology suppression.

When friTap is run against modern Chrome on Android, BoringSSL is loaded
from ``stable_cronet_libssl.so`` (APEX) while the higher-level
``libmainlinecronet.<ver>.so`` is the Cronet runtime that merely imports
it.  Pattern-scanning the runtime module is futile (it has no
``ssl_log_secret`` of its own) and burns wall-clock during attach.

These tests pin the pure helpers that drive the suppression so future
edits cannot silently re-enable the redundant scan or, conversely,
over-broaden the suppression to libraries we DO want to hook (legacy
``libcronet.so`` monolithic builds).
"""

from __future__ import annotations

from friTap.protocols.tls_handler import (
    covered_by_sibling,
    strip_covered_modules,
)


def _entry(name: str, library_type: str = "boringssl", **extra) -> dict:
    base = {"name": name, "library_type": library_type}
    base.update(extra)
    return base


class TestCoveredBySibling:

    def test_chrome_141_split_marks_libmainlinecronet(self):
        scan = [
            _entry("libssl.so"),
            _entry("stable_cronet_libssl.so"),
            _entry("libmainlinecronet.141.0.7340.3.so"),
            _entry("libmonochrome_64.so"),
        ]
        covered = covered_by_sibling(scan)
        assert "libmainlinecronet.141.0.7340.3.so" in covered
        cov = covered["libmainlinecronet.141.0.7340.3.so"]
        assert cov["sibling"] == "stable_cronet_libssl.so"
        assert "BoringSSL" in cov["reason"]

    def test_legacy_libcronet_monolith_not_suppressed(self):
        scan = [_entry("libcronet.so", classification="app")]
        assert covered_by_sibling(scan) == {}

    def test_force_scan_overrides_suppression(self):
        scan = [
            _entry("stable_cronet_libssl.so"),
            _entry("libmainlinecronet.141.0.7340.3.so"),
        ]
        covered = covered_by_sibling(
            scan, force_scan_modules=["libmainlinecronet.141.0.7340.3.so"]
        )
        assert covered == {}

    def test_force_scan_prefix_override(self):
        scan = [
            _entry("stable_cronet_libssl.so"),
            _entry("libmainlinecronet.141.0.7340.3.so"),
        ]
        covered = covered_by_sibling(scan, force_scan_modules=["libmainlinecronet*"])
        assert covered == {}

    def test_force_scan_regex_override(self):
        scan = [
            _entry("stable_cronet_libssl.so"),
            _entry("libmainlinecronet.141.0.7340.3.so"),
        ]
        covered = covered_by_sibling(
            scan, force_scan_modules=["re:^libmainlinecronet\\."]
        )
        assert covered == {}

    def test_no_sibling_no_suppression(self):
        scan = [_entry("libmainlinecronet.141.0.7340.3.so")]
        assert covered_by_sibling(scan) == {}

    def test_sibling_with_wrong_library_type_is_untrusted(self):
        scan = [
            _entry("stable_cronet_libssl.so", library_type="unknown"),
            _entry("libmainlinecronet.141.0.7340.3.so"),
        ]
        assert covered_by_sibling(scan) == {}

    def test_future_version_still_matches(self):
        scan = [
            _entry("stable_cronet_libssl.so"),
            _entry("libmainlinecronet.999.0.1.so"),
        ]
        covered = covered_by_sibling(scan)
        assert "libmainlinecronet.999.0.1.so" in covered

    def test_empty_input(self):
        assert covered_by_sibling([]) == {}
        assert covered_by_sibling(None) == {}  # type: ignore[arg-type]

    def test_entries_without_name_or_type_are_skipped(self):
        scan = [
            {"name": "stable_cronet_libssl.so"},  # missing library_type
            _entry("libmainlinecronet.141.0.7340.3.so"),
        ]
        assert covered_by_sibling(scan) == {}


class TestStripCoveredModules:

    @staticmethod
    def _sample_pattern_data() -> dict:
        return {
            "modules": {
                "libmainlinecronet.so": {
                    "android": {"arm64": {"Dump-Keys": {"primary": "3F 23"}}}
                },
                "libmonochrome_64.so": {
                    "android": {"arm64": {"Dump-Keys": {"primary": "AA BB"}}}
                },
                "libcronet.so": {
                    "android": {"arm64": {"Dump-Keys": {"primary": "CC DD"}}}
                },
            }
        }

    def test_strips_versioned_match_by_stem(self):
        pattern_data = self._sample_pattern_data()
        covered = {
            "libmainlinecronet.141.0.7340.3.so": {
                "sibling": "stable_cronet_libssl.so", "reason": "..."
            }
        }
        stripped = strip_covered_modules(pattern_data, covered)
        assert "libmainlinecronet.so" not in stripped["modules"]
        assert "libmonochrome_64.so" in stripped["modules"]
        assert "libcronet.so" in stripped["modules"]

    def test_preserves_entries_with_force_scan_flag(self):
        pattern_data = self._sample_pattern_data()
        pattern_data["modules"]["libmainlinecronet.so"]["_force_scan"] = True
        covered = {
            "libmainlinecronet.141.0.7340.3.so": {
                "sibling": "stable_cronet_libssl.so", "reason": "..."
            }
        }
        stripped = strip_covered_modules(pattern_data, covered)
        assert "libmainlinecronet.so" in stripped["modules"]

    def test_preserves_entries_in_force_scan_list(self):
        pattern_data = self._sample_pattern_data()
        covered = {
            "libmainlinecronet.141.0.7340.3.so": {
                "sibling": "stable_cronet_libssl.so", "reason": "..."
            }
        }
        stripped = strip_covered_modules(
            pattern_data, covered, force_scan_modules=["libmainlinecronet*"]
        )
        assert "libmainlinecronet.so" in stripped["modules"]

    def test_returns_input_when_nothing_covered(self):
        pattern_data = self._sample_pattern_data()
        result = strip_covered_modules(pattern_data, {})
        assert result is pattern_data

    def test_handles_none_pattern_data(self):
        assert strip_covered_modules(None, {"libmainlinecronet.x.so": {}}) is None

    def test_handles_pattern_data_without_modules_key(self):
        data = {"version": 1}
        result = strip_covered_modules(
            data, {"libmainlinecronet.x.so": {"sibling": "", "reason": ""}}
        )
        assert result is data


class TestEndToEndSuppressionFlow:
    """Smoke-test the (covered_by_sibling -> strip_covered_modules) pipeline."""

    def test_chrome_141_scenario_strips_pattern_entry(self):
        scan = [
            _entry("libssl.so"),
            _entry("stable_cronet_libssl.so"),
            _entry("libmainlinecronet.141.0.7340.3.so"),
            _entry("libmonochrome_64.so"),
        ]
        pattern_data = {
            "modules": {
                "libmainlinecronet.so": {"placeholder": True},
                "libmonochrome_64.so": {"placeholder": True},
                "libssl.so": {"placeholder": True},
            }
        }
        covered = covered_by_sibling(scan)
        stripped = strip_covered_modules(pattern_data, covered)
        assert "libmainlinecronet.so" not in stripped["modules"]
        assert "libmonochrome_64.so" in stripped["modules"]
        assert "libssl.so" in stripped["modules"]

    def test_legacy_monolith_scenario_keeps_pattern_entry(self):
        scan = [_entry("libcronet.so")]
        pattern_data = {
            "modules": {
                "libcronet.so": {"placeholder": True},
            }
        }
        covered = covered_by_sibling(scan)
        stripped = strip_covered_modules(pattern_data, covered)
        assert "libcronet.so" in stripped["modules"]
