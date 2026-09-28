#!/usr/bin/env python3

"""Unit tests for the memory-scan pattern loader.

Covers loading + validating the shipped default profile, unknown-id selection,
strict validation rejecting corrupted profiles, and user-file merge appending a
new-id profile.
"""

from __future__ import annotations

import copy
import json

import pytest

from friTap.memory_scanning.loader import (
    MemoryScanPatternError,
    load_database,
    load_memory_scan_profile,
    select_profile,
    validate_profile,
)

_SHIPPED_ID = "boringssl-2025-inplacevector-u8len"


# ---------------------------------------------------------------------------
# Default profile
# ---------------------------------------------------------------------------

class TestDefaultProfile:
    def test_default_loads_validates_and_has_expected_id(self):
        # None user_path + None profile_id -> shipped default, first profile.
        profile = load_memory_scan_profile(None, None)
        assert profile["id"] == _SHIPPED_ID
        # load_memory_scan_profile already validated; validating again is a no-op.
        validate_profile(profile)

    def test_select_by_explicit_id(self):
        database = load_database(None)
        profile = select_profile(database, _SHIPPED_ID)
        assert profile["id"] == _SHIPPED_ID


# ---------------------------------------------------------------------------
# Selection errors
# ---------------------------------------------------------------------------

class TestSelectionErrors:
    def test_unknown_profile_id_raises(self):
        database = load_database(None)
        with pytest.raises(MemoryScanPatternError):
            select_profile(database, "does-not-exist")

    def test_unknown_profile_id_via_one_shot_raises(self):
        with pytest.raises(MemoryScanPatternError):
            load_memory_scan_profile(None, "does-not-exist")


# ---------------------------------------------------------------------------
# Strict validation of corrupted profiles
# ---------------------------------------------------------------------------

class TestValidationRejectsCorruptProfiles:
    def _shipped_profile(self):
        return copy.deepcopy(select_profile(load_database(None), _SHIPPED_ID))

    def test_missing_required_key_raises(self):
        profile = self._shipped_profile()
        del profile["keylog_labels"]
        with pytest.raises(MemoryScanPatternError):
            validate_profile(profile)

    def test_undeclared_emitted_label_raises(self):
        profile = self._shipped_profile()
        # Keep the list non-empty but drop every label a tier actually emits;
        # the first emitted-but-undeclared label must be caught.
        profile["keylog_labels"] = ["CLIENT_RANDOM"]
        with pytest.raises(MemoryScanPatternError):
            validate_profile(profile)


# ---------------------------------------------------------------------------
# User-file merge
# ---------------------------------------------------------------------------

class TestUserFileMerge:
    def test_new_id_profile_is_appended(self, tmp_path):
        # Build a valid user profile by cloning the shipped one under a new id,
        # so it survives strict validation when selected.
        base = copy.deepcopy(select_profile(load_database(None), _SHIPPED_ID))
        base["id"] = "user-custom-profile"
        user_db = {"schema": 1, "profiles": [base]}
        user_path = tmp_path / "user_patterns.json"
        user_path.write_text(json.dumps(user_db))

        database = load_database(str(user_path))
        ids = [p["id"] for p in database["profiles"]]
        # Shipped profile is preserved; the new-id profile is appended.
        assert _SHIPPED_ID in ids
        assert "user-custom-profile" in ids
        assert ids.index(_SHIPPED_ID) < ids.index("user-custom-profile")

        # And the merged-in profile is selectable + valid end to end.
        profile = load_memory_scan_profile(str(user_path), "user-custom-profile")
        assert profile["id"] == "user-custom-profile"

    def test_missing_user_file_raises(self, tmp_path):
        with pytest.raises(MemoryScanPatternError):
            load_database(str(tmp_path / "nope.json"))


class TestIdlessMerge:
    def test_two_idless_user_profiles_both_appended(self):
        # Two id-less user profiles must not collide on a shared ``None`` key;
        # both are appended (regression for the _merge_profiles None-key bug).
        from friTap.memory_scanning.loader import _merge_profiles
        base = [{"id": "shipped"}]
        merged = _merge_profiles(base, [{"note": "first"}, {"note": "second"}])
        assert len(merged) == 3
        assert merged[0]["id"] == "shipped"
        assert {"note": "first"} in merged and {"note": "second"} in merged


# ---------------------------------------------------------------------------
# Engine discriminator (F2 scaffolding)
# ---------------------------------------------------------------------------

class TestEngineDispatch:
    """The engine key defaults to boringssl and dispatches validation.

    F2 makes validate_profile() engine-aware without changing how a boringssl
    profile is validated. These lock in exactly that: absent engine == boringssl,
    an explicit boringssl engine validates identically, and an unknown engine is
    rejected fail-loud.
    """

    def _shipped_profile(self):
        return copy.deepcopy(select_profile(load_database(None), _SHIPPED_ID))

    def test_absent_engine_validates_as_boringssl(self):
        # The shipped default carries engine:"boringssl"; stripping the key must
        # still validate, because absence defaults to boringssl.
        profile = self._shipped_profile()
        profile.pop("engine", None)
        validate_profile(profile)  # must not raise

    def test_explicit_boringssl_engine_validates_identically(self):
        # With the key present and set to boringssl, validation is unchanged.
        profile = self._shipped_profile()
        profile["engine"] = "boringssl"
        validate_profile(profile)  # must not raise

    def test_absent_and_explicit_boringssl_agree(self):
        # Both spellings reach the same validator: neither raises, proving the
        # dispatch does not tighten or loosen the boringssl path.
        absent = self._shipped_profile()
        absent.pop("engine", None)
        explicit = self._shipped_profile()
        explicit["engine"] = "boringssl"
        # A no-op pair: if either diverged, one of these would raise.
        validate_profile(absent)
        validate_profile(explicit)

    def test_unknown_engine_is_rejected(self):
        profile = self._shipped_profile()
        profile["engine"] = "does-not-exist"
        with pytest.raises(MemoryScanPatternError):
            validate_profile(profile)

    def test_select_profile_engine_filter_matches_boringssl(self):
        # The optional engine selector narrows to boringssl profiles; the shipped
        # default is one, so it is still selected.
        database = load_database(None)
        profile = select_profile(database, None, engine="boringssl")
        assert profile["id"] == _SHIPPED_ID

    def test_select_profile_unknown_engine_filter_raises(self):
        # The shipped DB now ships boringssl, rc4 AND schannel profiles (WS3/WS4),
        # so an engine filter only raises for an engine no profile declares. Using
        # a genuinely-absent engine token keeps this testing the "no match" branch.
        database = load_database(None)
        with pytest.raises(MemoryScanPatternError):
            select_profile(database, None, engine="no-such-engine")


# ---------------------------------------------------------------------------
# RC4 param overrides (CLI-injected known-plaintext / ciphertext oracles)
# ---------------------------------------------------------------------------

class TestApplyRc4ParamOverrides:
    """apply_rc4_param_overrides merges CLI oracles into the rc4 profile's params.

    Both a hex value and a plain-text value must land as lowercase hex in
    ``params``, and the merged params must still pass RC4 validation.
    """

    def _rc4_profile(self):
        database = load_database(None)
        return select_profile(database, None, engine="rc4")

    def test_none_overrides_leave_profile_untouched(self):
        from friTap.memory_scanning.loader import apply_rc4_param_overrides
        profile = self._rc4_profile()
        before = copy.deepcopy(profile["params"])
        result = apply_rc4_param_overrides(profile)
        assert result is profile
        assert result["params"] == before

    def test_known_plaintext_as_hex_is_used_as_is(self):
        from friTap.memory_scanning.loader import apply_rc4_param_overrides
        profile = self._rc4_profile()
        # "GET /" as lowercase hex.
        result = apply_rc4_param_overrides(profile, known_plaintext="474554202f")
        assert result["params"]["known_plaintext"] == "474554202f"
        # The merged params still validate.
        validate_profile(result)

    def test_known_plaintext_as_plaintext_is_hex_encoded(self):
        from friTap.memory_scanning.loader import apply_rc4_param_overrides
        profile = self._rc4_profile()
        result = apply_rc4_param_overrides(profile, known_plaintext="GET /")
        assert result["params"]["known_plaintext"] == "GET /".encode("utf-8").hex()
        validate_profile(result)

    def test_ciphertext_sample_plaintext_is_hex_encoded(self):
        from friTap.memory_scanning.loader import apply_rc4_param_overrides
        profile = self._rc4_profile()
        result = apply_rc4_param_overrides(profile, ciphertext_sample="hello")
        assert result["params"]["ciphertext_sample"] == b"hello".hex()
        validate_profile(result)
