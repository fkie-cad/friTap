#!/usr/bin/env python3

"""Unit tests for the F3 memory-scan engine resolver.

:func:`select_profiles` maps the user's selected ``--protocol`` set, the target
platform and an optional ``-ms`` override onto the ordered list of profiles to
run; :func:`group_profiles_by_scan_target` splits that list by the process each
scan runs in. Both are pure and device-free.

The synthetic database mirrors the three engines F3 must resolve between:

  * ``boringssl`` — the real shipped profile (protocol ``tls``, platforms
    ``["all"]``, scan_target ``self``). Used as-is rather than faked so the
    resolver's mandatory ``validate_profile`` pass exercises the real strict
    BoringSSL validator instead of a lenient stub.
  * ``schannel`` — synthetic (protocol ``tls``, platforms ``["windows"]``,
    scan_target ``lsass``). Only the minimal ``id`` + ``scan_regions`` shape is
    needed: the schannel validator is scaffolding today.
  * ``rc4`` — synthetic (protocol ``rc4``, platforms ``["all"]``, scan_target
    ``self``).
"""

from __future__ import annotations

import json

import pytest

from friTap.memory_scanning.loader import (
    MemoryScanPatternError,
    group_profiles_by_scan_target,
    load_database,
    normalize_os_name,
    select_profiles,
)


def _synthetic_profile(engine, protocol, platforms, scan_target):
    return {
        "id": f"{engine}-synthetic",
        "engine": engine,
        "protocol": protocol,
        "platforms": platforms,
        "scan_target": scan_target,
        # The minimal shape the schannel/rc4 scaffolding validators require.
        "scan_regions": {"protection": "rw-"},
    }


@pytest.fixture
def db():
    """Central DB: the real boringssl profile plus synthetic schannel + rc4."""
    database = load_database()
    database["profiles"] = list(database["profiles"]) + [
        _synthetic_profile("schannel", "tls", ["windows"], "lsass"),
        _synthetic_profile("rc4", "rc4", ["all"], "self"),
    ]
    return database


def _engines(profiles):
    return {p.get("engine", "boringssl") for p in profiles}


# ---------------------------------------------------------------------------
# select_profiles — protocol/platform truth table
# ---------------------------------------------------------------------------

class TestSelectProfilesTruthTable:
    def test_tls_windows_gets_boringssl_and_schannel(self, db):
        assert _engines(select_profiles(db, {"tls"}, "windows", None)) == {
            "boringssl", "schannel"}

    def test_tls_linux_gets_boringssl_only(self, db):
        assert _engines(select_profiles(db, {"tls"}, "linux", None)) == {"boringssl"}

    def test_rc4_linux_gets_rc4_only(self, db):
        assert _engines(select_profiles(db, {"rc4"}, "linux", None)) == {"rc4"}

    def test_tls_and_rc4_windows_gets_all_three(self, db):
        assert _engines(select_profiles(db, {"tls", "rc4"}, "windows", None)) == {
            "boringssl", "schannel", "rc4"}

    def test_unmatched_protocol_returns_empty(self, db):
        assert select_profiles(db, {"ssh"}, "linux", None) == []


# ---------------------------------------------------------------------------
# select_profiles — targeted -ms override
# ---------------------------------------------------------------------------

class TestSelectProfilesTargeted:
    def test_engine_name_targets_only_that_engine(self, db):
        # Targeted wins over protocol/platform: schannel is returned even though
        # only tls is selected and (its own platform aside) nothing else would.
        selected = select_profiles(db, {"tls"}, "windows", "schannel")
        assert _engines(selected) == {"schannel"}

    def test_engine_name_ignores_platform(self, db):
        # -ms schannel on linux still returns schannel (targeted bypasses the
        # platform filter entirely).
        assert _engines(select_profiles(db, {"tls"}, "linux", "schannel")) == {
            "schannel"}

    def test_profile_id_targets_one_profile(self, db):
        selected = select_profiles(db, {"tls"}, "linux", "rc4-synthetic")
        assert [p["id"] for p in selected] == ["rc4-synthetic"]

    def test_unknown_ms_arg_raises(self, db):
        with pytest.raises(MemoryScanPatternError) as exc:
            select_profiles(db, {"tls"}, "windows", "not-a-real-engine")
        # Message names the valid engines.
        assert "boringssl" in str(exc.value)
        assert "schannel" in str(exc.value)

    def test_file_path_ms_arg_merges_then_selects(self, db, tmp_path):
        # A -ms <file> override merges by id, then the protocol/platform select
        # runs over the merged DB. Here the file overrides the rc4 profile's
        # platforms so it now also matches linux under {rc4}.
        override = {
            "schema": 1,
            "profiles": [
                _synthetic_profile("rc4", "rc4", ["all"], "self"),
            ],
        }
        path = tmp_path / "override.json"
        path.write_text(json.dumps(override))
        selected = select_profiles(db, {"rc4"}, "linux", str(path))
        assert _engines(selected) == {"rc4"}


# ---------------------------------------------------------------------------
# scan_target grouping
# ---------------------------------------------------------------------------

class TestGroupByScanTarget:
    def test_splits_self_and_lsass(self, db):
        profiles = select_profiles(db, {"tls"}, "windows", None)
        grouped = group_profiles_by_scan_target(profiles)
        assert set(grouped) == {"self", "lsass"}
        assert _engines(grouped["self"]) == {"boringssl"}
        assert _engines(grouped["lsass"]) == {"schannel"}

    def test_default_scan_target_is_self(self):
        # A profile without an explicit scan_target groups under "self".
        profiles = [{"id": "x", "scan_regions": {}}]
        assert list(group_profiles_by_scan_target(profiles)) == ["self"]


# ---------------------------------------------------------------------------
# normalize_os_name
# ---------------------------------------------------------------------------

class TestNormalizeOsName:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("windows", "windows"),
            ("win32", "windows"),
            ("darwin", "macos"),
            ("macos", "macos"),
            ("linux", "linux"),
            ("android", "android"),
            ("ios", "ios"),
            ("Windows", "windows"),
        ],
    )
    def test_known_aliases(self, raw, expected):
        assert normalize_os_name(raw) == expected

    def test_none_and_unknown_return_none(self):
        assert normalize_os_name(None) is None
        assert normalize_os_name("plan9") is None
