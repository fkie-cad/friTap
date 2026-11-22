"""Unit tests for AppLovinMediateAnalyzer and its CLI / registry wiring."""

from __future__ import annotations

import base64
import json
from urllib.parse import quote

import pytest

from friTap.analysis import Severity
from friTap.analysis.applovin_mediate import (
    TITLE_DECRYPTED,
    TITLE_NOT_DECRYPTED,
    AppLovinMediateAnalyzer,
    has_envelope_hint,
    is_mediate_target,
    summarize_payload,
)
from friTap.analysis.registry import resolve_analyzers
from friTap.commands.analyze import _build_parser
from friTap.parsers.app_ciphers import applovin_mediate as am
from friTap.parsers.app_ciphers.applovin_keyring import (
    REASON_NO_SALT,
    REASON_NO_SDK_KEY,
    AppLovinKeyring,
)
from tests.unit.test_applovin_mediate import (
    SALT,
    SDK_KEY,
    encrypt_for_testing,
    gz_payload,
)
from tests.unit.test_privacy_analyzer import _make_http_flow

IDFA = "6D92078A-8246-4BA4-AE5B-76104861E7DC"
PAYLOAD = {
    "device_info": {"idfa": IDFA, "os": "17.4", "locale": "de_DE", "tz_offset": 1.0,
                    "bt_ms_2": 1747000000000, "kb": "de"},
    "app_info": {"revision": "13.0.0", "tm": 1},
    "signal_data": [{"name": "a"}, {"name": "b"}, {"name": "c"}],
}
MEDIATE_HOST = "ms4.applovin.com"


def _b64_envelope(payload=PAYLOAD) -> str:
    raw = encrypt_for_testing(gz_payload(payload), SDK_KEY, SALT, am.ALL_VARIANTS[1])
    return base64.b64encode(raw).decode()


def _mediate_flow(body: bytes = b"", *, url: str = "/1.0/mediate", host: str = MEDIATE_HOST):
    return _make_http_flow(body, host=host, url=url, content_type="application/x-www-form-urlencoded")


def _analyzer(**kw) -> AppLovinMediateAnalyzer:
    keyring = AppLovinKeyring(sdk_keys=kw.pop("sdk_keys", [SDK_KEY]), salts=kw.pop("salts", [SALT]))
    return AppLovinMediateAnalyzer(keyring=keyring, **kw)


def _single(findings):
    assert len(findings) == 1
    return findings[0]


def test_target_and_hint_helpers():
    assert is_mediate_target("ms4.applovin.com", "/1.0/mediate")
    assert not is_mediate_target("ms4.applovin.com", "/1.0/event")
    assert not is_mediate_target("example.com", "/1.0/mediate")
    assert has_envelope_hint(_b64_envelope().encode(), "")
    assert has_envelope_hint(b"", "a=1&p=" + quote(_b64_envelope(), safe=""))
    assert not has_envelope_hint(b'{"hello": "world"}' * 10, "q=1")


def test_success_from_raw_body():
    finding = _single(_analyzer(reveal_pii=True).analyze_flow(_mediate_flow(_b64_envelope().encode())))
    assert finding.title == TITLE_DECRYPTED and finding.severity == Severity.LOW
    ev = finding.evidence
    assert ev["timestamp_ms"] == 1_747_000_000_123 and ev["timestamp_utc"].startswith("2025-05-11")
    assert ev["variant"] == "little/counter_plus_block"
    assert json.loads(ev["decrypted_json"]) == PAYLOAD
    assert ev["summary"] == {"idfa": IDFA, "os": "17.4", "locale": "de_DE", "tz_offset": 1.0,
                             "bt_ms_2": 1747000000000, "kb": "de", "revision": "13.0.0",
                             "tm": 1, "signal_data_adapters": 3}
    assert ev["redacted"] is False and finding.category == "pii"


def test_identifiers_masked_by_default():
    finding = _single(_analyzer().analyze_flow(_mediate_flow(_b64_envelope().encode())))
    ev = finding.evidence
    assert IDFA not in ev["decrypted_json"] and IDFA not in json.dumps(ev["summary"])
    assert ev["summary"]["idfa"] == "6D92****"
    assert ev["redacted"] is True and IDFA not in finding.description


def test_success_from_query_p_param():
    url = "/1.0/mediate?v=1&p=" + quote(_b64_envelope(), safe="")
    finding = _single(_analyzer().analyze_flow(_mediate_flow(b"", url=url)))
    assert finding.title == TITLE_DECRYPTED


def test_success_from_form_body_on_other_host():
    body = ("p=" + quote(_b64_envelope(), safe="")).encode()
    finding = _single(_analyzer().analyze_flow(_mediate_flow(body, host="cdn.example.net", url="/x")))
    assert finding.title == TITLE_DECRYPTED


def test_missing_key_reports_reason_and_protocol_id():
    finding = _single(_analyzer(sdk_keys=[]).analyze_flow(_mediate_flow(_b64_envelope().encode())))
    assert finding.title == TITLE_NOT_DECRYPTED and finding.severity == Severity.INFO
    assert finding.evidence["reason"] == REASON_NO_SDK_KEY
    assert finding.evidence["protocol_id"] == am.protocol_id_for_salt(SALT)
    assert am.protocol_id_for_salt(SALT) in finding.description


def test_missing_salt_reports_reason():
    finding = _single(_analyzer(salts=[]).analyze_flow(_mediate_flow(_b64_envelope().encode())))
    assert finding.evidence["reason"] == REASON_NO_SALT


def test_unrelated_flows_produce_nothing():
    analyzer = _analyzer()
    assert analyzer.analyze_flow(_make_http_flow(b'{"a": 1}', content_type="application/json")) == []
    assert analyzer.analyze_flow(_mediate_flow(b"not-base64!!")) == []


def test_keyring_built_lazily_from_env(monkeypatch):
    monkeypatch.setenv("FRITAP_APPLOVIN_SDK_KEY", SDK_KEY)
    monkeypatch.setenv("FRITAP_APPLOVIN_SALT", SALT.hex())
    analyzer = AppLovinMediateAnalyzer()
    assert analyzer._keyring is None
    assert analyzer.analyze_flow(_make_http_flow(b"{}", content_type="application/json")) == []
    assert analyzer._keyring is None  # no envelope seen -> no keyring work
    finding = _single(analyzer.analyze_flow(_mediate_flow(_b64_envelope().encode())))
    assert finding.title == TITLE_DECRYPTED


def test_summary_without_notable_fields():
    assert summarize_payload({"x": {"y": 1}}) == {}


def test_registry_passes_cli_key_material(monkeypatch):
    for var in ("FRITAP_APPLOVIN_SDK_KEY", "FRITAP_APPLOVIN_SALT", "FRITAP_APPLOVIN_BUNDLE"):
        monkeypatch.delenv(var, raising=False)
    (analyzer,) = resolve_analyzers("applovin_mediate", applovin_sdk_keys=[SDK_KEY],
                                    applovin_salts=[SALT.hex()], reveal_pii=True)
    finding = _single(analyzer.analyze_flow(_mediate_flow(_b64_envelope().encode())))
    assert finding.title == TITLE_DECRYPTED and finding.evidence["redacted"] is False


def test_cli_flags_are_repeatable():
    args = _build_parser().parse_args([
        "x.tap", "--applovin-sdk-key", "k1", "--applovin-sdk-key", "k2",
        "--applovin-salt", "00ff", "--app-bundle", "a.apk", "--app-bundle", "b.ipa",
    ])
    assert args.applovin_sdk_keys == ["k1", "k2"]
    assert args.applovin_salts == ["00ff"]
    assert args.app_bundles == ["a.apk", "b.ipa"]


def test_cli_flags_default_to_none():
    args = _build_parser().parse_args(["x.tap"])
    assert args.applovin_sdk_keys is None and args.app_bundles is None


@pytest.mark.parametrize("spec", [None, "all"])
def test_runs_by_default(spec, monkeypatch):
    monkeypatch.setattr("friTap.analysis.registry._DISCOVERED", {})
    monkeypatch.setattr("friTap.analysis.registry._DISCOVERY_DONE", True)
    assert "applovin_mediate" in {a.name for a in resolve_analyzers(spec)}
