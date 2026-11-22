"""HAR export: decrypted AppLovin mediate payloads as ``_fritap_app_cipher``."""

from __future__ import annotations

import base64

import pytest

from friTap.analysis.export_har import (
    APP_CIPHER_FIELD,
    LazyKeyring,
    flow_to_har_entry,
    tap_to_har,
)
from friTap.parsers.app_ciphers import applovin_mediate as am
from friTap.parsers.app_ciphers.applovin_keyring import (
    REASON_NO_SDK_KEY,
    AppLovinKeyring,
)
from tests.unit._digest_helpers import http_flow, write_tap
from tests.unit.test_applovin_mediate import (
    SALT,
    SDK_KEY,
    encrypt_for_testing,
    gz_payload,
)

PAYLOAD = {"device_info": {"os": "17.4"}, "signal_data": [{"name": "a"}]}
ENV_VARS = ("FRITAP_APPLOVIN_SDK_KEY", "FRITAP_APPLOVIN_SALT", "FRITAP_APPLOVIN_BUNDLE")


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for var in ENV_VARS:
        monkeypatch.delenv(var, raising=False)


def _envelope_body() -> bytes:
    raw = encrypt_for_testing(gz_payload(PAYLOAD), SDK_KEY, SALT, am.ALL_VARIANTS[1])
    return base64.b64encode(raw)


def _mediate_flow(flow_id="m1"):
    return http_flow(flow_id, host="ms4.applovin.com", url="/1.0/mediate",
                     body=_envelope_body(), content_type="application/x-www-form-urlencoded")


def _keyring() -> AppLovinKeyring:
    return AppLovinKeyring(sdk_keys=[SDK_KEY], salts=[SALT])


@pytest.fixture
def tap(tmp_path):
    flows = [_mediate_flow(), http_flow("plain", body=b'{"a": 1}')]
    return write_tap(tmp_path / "applovin.tap", flows)


def _entries_by_url(har):
    return {e["request"]["url"]: e for e in har["log"]["entries"]}


def test_decrypted_payload_added_with_bodies(tap):
    entries = _entries_by_url(tap_to_har(str(tap), include_bodies=True, keyring=_keyring()))
    field = entries["https://ms4.applovin.com/1.0/mediate"][APP_CIPHER_FIELD]
    assert field["cipher"] == "applovin_mediate" and field["decrypted"] is True
    assert field["json"] == PAYLOAD and field["timestamp_ms"] == 1_747_000_000_123
    assert field["variant"] == "little/counter_plus_block"
    assert field["protocol_id"] == am.protocol_id_for_salt(SALT)
    assert APP_CIPHER_FIELD not in entries["https://api.example.com/v1/users/42"]


def test_no_field_without_bodies(tap):
    har = tap_to_har(str(tap), include_bodies=False, keyring=_keyring())
    assert all(APP_CIPHER_FIELD not in e for e in har["log"]["entries"])


def test_failure_reason_reported(tap):
    keyring = AppLovinKeyring(sdk_keys=[], salts=[SALT])
    entries = _entries_by_url(tap_to_har(str(tap), include_bodies=True, keyring=keyring))
    field = entries["https://ms4.applovin.com/1.0/mediate"][APP_CIPHER_FIELD]
    assert field == {"cipher": "applovin_mediate", "protocol_id": am.protocol_id_for_salt(SALT),
                     "decrypted": False, "reason": REASON_NO_SDK_KEY}


def test_default_keyring_from_env(tap, monkeypatch):
    monkeypatch.setenv("FRITAP_APPLOVIN_SDK_KEY", SDK_KEY)
    monkeypatch.setenv("FRITAP_APPLOVIN_SALT", SALT.hex())
    entries = _entries_by_url(tap_to_har(str(tap), include_bodies=True))
    assert entries["https://ms4.applovin.com/1.0/mediate"][APP_CIPHER_FIELD]["json"] == PAYLOAD


def test_lazy_keyring_not_built_without_envelope(monkeypatch):
    def _boom(*_a, **_k):
        raise AssertionError("keyring must not be built")

    monkeypatch.setattr(AppLovinKeyring, "from_sources", classmethod(_boom))
    lazy = LazyKeyring()
    entry = flow_to_har_entry(http_flow("plain", body=b'{"a": 1}'), True, lazy)
    assert entry is not None and APP_CIPHER_FIELD not in entry
    assert lazy._keyring is None


def test_lazy_keyring_returns_explicit_keyring():
    keyring = _keyring()
    assert LazyKeyring(keyring).get() is keyring


def test_flow_to_har_entry_backward_compatible():
    entry = flow_to_har_entry(_mediate_flow())
    assert entry is not None and APP_CIPHER_FIELD not in entry
