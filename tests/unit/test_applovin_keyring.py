"""Unit tests for AppLovinKeyring (key/salt selection for the mediate cipher)."""

from __future__ import annotations

import sys
import types

import pytest

from friTap.parsers.app_ciphers import applovin_mediate as am
from friTap.parsers.app_ciphers.applovin_keyring import (
    REASON_NO_SALT,
    REASON_NO_SDK_KEY,
    AppLovinKeyring,
    parse_salt_hex,
    split_csv,
)
from tests.unit.test_applovin_mediate import (
    PAYLOAD_JSON,
    SALT,
    SDK_KEY,
    encrypt_for_testing,
    gz_payload,
)

OTHER_KEY = "Z" * 86
OTHER_SALT = bytes(range(100, 132))
KEYS_MODULE = "friTap.parsers.app_ciphers.applovin_keys"


def _envelope(sdk_key: str = SDK_KEY, salt: bytes = SALT) -> am.MediateEnvelope:
    return am.parse_envelope(encrypt_for_testing(gz_payload(), sdk_key, salt, am.ALL_VARIANTS[0]))


@pytest.fixture
def fake_keys_module(monkeypatch):
    """Replace the bundle-mining module with a recording fake."""
    calls = {"salt": []}
    module = types.ModuleType(KEYS_MODULE)
    module.find_sdk_key_candidates = lambda path: [types.SimpleNamespace(key=SDK_KEY, source="manifest")]

    def recover(path, protocol_id):
        calls["salt"].append((path, protocol_id))
        return SALT if am.protocol_id_for_salt(SALT) == protocol_id else None

    module.recover_salt_from_bundle = recover
    monkeypatch.setitem(sys.modules, KEYS_MODULE, module)
    return calls


def test_split_csv_and_parse_salt_hex():
    assert split_csv(" a, ,b,") == ["a", "b"]
    assert split_csv(None) == []
    assert parse_salt_hex("0x" + SALT.hex().upper()) == SALT
    assert parse_salt_hex("zz") is None


def test_from_sources_merges_explicit_and_env_without_duplicates():
    env = {"FRITAP_APPLOVIN_SDK_KEY": f"{OTHER_KEY},{SDK_KEY}",
           "FRITAP_APPLOVIN_SALT": SALT.hex()}
    keyring = AppLovinKeyring.from_sources(sdk_keys=[SDK_KEY], salts_hex=[SALT.hex()], env=env)
    assert keyring.sdk_keys == [SDK_KEY, OTHER_KEY]
    assert keyring.salts == [SALT]
    assert keyring.bundle_paths == []


def test_from_sources_mines_bundle_keys(fake_keys_module):
    env = {"FRITAP_APPLOVIN_BUNDLE": "/x/app.apk"}
    keyring = AppLovinKeyring.from_sources(bundle_paths=["/y/app.ipa"], env=env)
    assert keyring.bundle_paths == ["/y/app.ipa", "/x/app.apk"]
    assert keyring.sdk_keys == [SDK_KEY]


def test_from_sources_survives_unreadable_bundle(tmp_path):
    keyring = AppLovinKeyring.from_sources(bundle_paths=[str(tmp_path / "missing.apk")], env={})
    assert keyring.sdk_keys == [] and keyring.bundle_paths == [str(tmp_path / "missing.apk")]


def test_salt_for_known_salt():
    keyring = AppLovinKeyring(salts=[OTHER_SALT, SALT])
    assert keyring.salt_for(am.protocol_id_for_salt(SALT).upper()) == SALT


def test_salt_for_recovers_from_bundle_once_and_caches_misses(fake_keys_module):
    keyring = AppLovinKeyring(bundle_paths=["/a.apk"])
    wanted = am.protocol_id_for_salt(SALT)
    unknown = am.protocol_id_for_salt(OTHER_SALT)
    assert keyring.salt_for(wanted) == SALT
    assert keyring.salt_for(wanted) == SALT
    assert keyring.salt_for(unknown) is None
    assert keyring.salt_for(unknown) is None
    assert fake_keys_module["salt"] == [("/a.apk", wanted), ("/a.apk", unknown)]


def test_keys_for_orders_suffix_matches_first():
    keyring = AppLovinKeyring(sdk_keys=[OTHER_KEY, SDK_KEY])
    assert keyring.keys_for(_envelope()) == [SDK_KEY, OTHER_KEY]


def test_try_decrypt_success_with_wrong_key_first():
    keyring = AppLovinKeyring(sdk_keys=[OTHER_KEY, SDK_KEY], salts=[SALT])
    result, reason = keyring.try_decrypt(_envelope())
    assert reason == "" and result is not None and result.json == PAYLOAD_JSON


def test_try_decrypt_tries_non_matching_keys_too():
    # Suffix in the envelope does not match, but the key is still tried.
    raw = encrypt_for_testing(gz_payload(), SDK_KEY, SALT, am.ALL_VARIANTS[0])
    envelope = am.parse_envelope(raw.replace(SDK_KEY[32:].encode(), b"x" * 54))
    result, _ = AppLovinKeyring(sdk_keys=[SDK_KEY], salts=[SALT]).try_decrypt(envelope)
    assert result is not None and result.sdk_key_matches_suffix is False


def test_try_decrypt_reports_missing_key_and_salt():
    assert AppLovinKeyring(salts=[SALT]).try_decrypt(_envelope()) == (None, REASON_NO_SDK_KEY)
    assert AppLovinKeyring(sdk_keys=[SDK_KEY]).try_decrypt(_envelope()) == (None, REASON_NO_SALT)


def test_try_decrypt_wrong_key_returns_decoder_reason():
    result, reason = AppLovinKeyring(sdk_keys=[OTHER_KEY], salts=[SALT]).try_decrypt(_envelope())
    assert result is None and reason == am.REASON_NO_VARIANT


def test_is_empty():
    assert AppLovinKeyring().is_empty
    assert not AppLovinKeyring(bundle_paths=["/a.apk"]).is_empty
