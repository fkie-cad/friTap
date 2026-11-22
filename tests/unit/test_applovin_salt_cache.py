"""Tests for the persistent AppLovin salt cache and the keyring lookup order."""

from __future__ import annotations

import json
import os

import pytest

from friTap.parsers.app_ciphers import applovin_salt_cache as sc
from friTap.parsers.app_ciphers.applovin_keyring import AppLovinKeyring
from friTap.parsers.app_ciphers.applovin_mediate import protocol_id_for_salt

SALT = bytes(range(0xA1, 0xA1 + 21)) + bytes(11)
PROTOCOL_ID = protocol_id_for_salt(SALT)
OTHER_SALT = bytes(range(1, 33))


@pytest.fixture
def cache(tmp_path) -> sc.SaltCache:
    return sc.SaltCache(str(tmp_path / "salts.json"))


def test_round_trip(cache):
    assert cache.get(PROTOCOL_ID) is None
    assert cache.put(PROTOCOL_ID, SALT)
    assert cache.get(PROTOCOL_ID.upper()) == SALT
    assert json.loads(open(cache.path).read()) == {PROTOCOL_ID: SALT.hex()}


def test_put_merges_and_leaves_no_temp_files(cache, tmp_path):
    other_id = protocol_id_for_salt(OTHER_SALT)
    cache.put(PROTOCOL_ID, SALT)
    cache.put(other_id, OTHER_SALT)
    assert cache.get(PROTOCOL_ID) == SALT and cache.get(other_id) == OTHER_SALT
    assert not [name for name in os.listdir(tmp_path) if name.endswith(".tmp")]


def test_put_rejects_salt_failing_the_oracle(cache):
    assert not cache.put(PROTOCOL_ID, OTHER_SALT)
    assert not os.path.exists(cache.path)


@pytest.mark.parametrize("content", ["{not json", "[1, 2]", '{"x": 5}', ""])
def test_corrupt_file_reads_empty_and_is_repaired(cache, content):
    with open(cache.path, "w") as handle:
        handle.write(content)
    assert cache.get(PROTOCOL_ID) is None
    assert cache.put(PROTOCOL_ID, SALT)
    assert cache.get(PROTOCOL_ID) == SALT


def test_oracle_mismatch_entry_ignored(cache):
    with open(cache.path, "w") as handle:
        json.dump({PROTOCOL_ID: OTHER_SALT.hex()}, handle)
    assert cache.get(PROTOCOL_ID) is None


def test_non_hex_entry_ignored(cache):
    with open(cache.path, "w") as handle:
        json.dump({PROTOCOL_ID: "zz"}, handle)
    assert cache.get(PROTOCOL_ID) is None


def test_env_disable_and_path_override(tmp_path):
    path = str(tmp_path / "x.json")
    assert sc.default_salt_cache({sc.ENV_NO_CACHE: "1", sc.ENV_CACHE_PATH: path}) is None
    assert sc.default_salt_cache({sc.ENV_NO_CACHE: "0", sc.ENV_CACHE_PATH: path}).path == path


def test_conftest_isolates_default_path():
    assert sc.default_cache_path({}) == os.environ[sc.ENV_CACHE_PATH]


# --------------------------------------------------------------------------
# Keyring order: explicit salts -> cache -> bundle recovery (-> cache write)
# --------------------------------------------------------------------------

class _RecordingKeyring(AppLovinKeyring):
    """Keyring whose bundle recovery is a stub that records its calls."""

    def __init__(self, *args, bundle_salt=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.bundle_calls: list[str] = []
        self._stub_salt = bundle_salt

    def _bundle_recovered_salt(self, protocol_id):
        self.bundle_calls.append(protocol_id)
        return self._stub_salt


def test_cache_hit_avoids_bundle_scan(cache):
    cache.put(PROTOCOL_ID, SALT)
    keyring = _RecordingKeyring(bundle_paths=["/a.apk"], salt_cache=cache, bundle_salt=SALT)
    assert keyring.salt_for(PROTOCOL_ID) == SALT
    assert keyring.bundle_calls == []


def test_bundle_recovery_writes_cache(cache):
    keyring = _RecordingKeyring(bundle_paths=["/a.apk"], salt_cache=cache, bundle_salt=SALT)
    assert keyring.salt_for(PROTOCOL_ID) == SALT
    assert keyring.bundle_calls == [PROTOCOL_ID]
    assert cache.get(PROTOCOL_ID) == SALT


def test_explicit_salt_wins_over_cache_and_bundle(cache, monkeypatch):
    monkeypatch.setattr(cache, "get", lambda _pid: pytest.fail("cache consulted"))
    keyring = _RecordingKeyring(salts=[SALT], salt_cache=cache)
    assert keyring.salt_for(PROTOCOL_ID) == SALT
    assert keyring.bundle_calls == []


def test_ios_capture_without_bundle_uses_cache(cache):
    cache.put(PROTOCOL_ID, SALT)
    assert AppLovinKeyring(salt_cache=cache).salt_for(PROTOCOL_ID) == SALT


def test_from_sources_uses_cache_and_env_disable(tmp_path):
    path = str(tmp_path / "s.json")
    sc.SaltCache(path).put(PROTOCOL_ID, SALT)
    enabled = AppLovinKeyring.from_sources(env={sc.ENV_CACHE_PATH: path})
    assert enabled.salt_for(PROTOCOL_ID) == SALT
    disabled = AppLovinKeyring.from_sources(env={sc.ENV_CACHE_PATH: path, sc.ENV_NO_CACHE: "1"})
    assert disabled.salt_cache is None and disabled.salt_for(PROTOCOL_ID) is None


def test_from_sources_explicit_none_cache():
    assert AppLovinKeyring.from_sources(env={}, salt_cache=None).salt_cache is None
