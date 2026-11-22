"""App-cipher decoder registry + the AppLovin mediate decoder + TUI section."""

from __future__ import annotations

import base64
import json
from urllib.parse import quote

import pytest

from friTap.parsers.app_ciphers import applovin_mediate as am
from friTap.parsers.app_ciphers import registry as reg
from friTap.parsers.app_ciphers.applovin_decoder import (
    REASON_NO_ENVELOPE,
    TITLE,
    AppLovinMediateDecoder,
    is_mediate_target,
)
from friTap.parsers.app_ciphers.applovin_keyring import (
    REASON_NO_SDK_KEY,
    AppLovinKeyring,
)
from friTap.parsers.app_ciphers.registry import (
    AppCipherDecoder,
    AppCipherRegistry,
    DecodedView,
    split_request_target,
)
from tests.unit.test_applovin_mediate import (
    SALT,
    SDK_KEY,
    encrypt_for_testing,
    gz_payload,
)

HOST = "ms4.applovin.com"
MEDIATE_URL = "/1.0/mediate"
HOSTILE_PAYLOAD = {"model": "[bold]evil[/]", "signal_data": [{"a": 1}]}


def _envelope_b64(payload=HOSTILE_PAYLOAD) -> str:
    raw = encrypt_for_testing(gz_payload(payload), SDK_KEY, SALT, am.ALL_VARIANTS[0])
    return base64.b64encode(raw).decode()


def _keyed_decoder() -> AppLovinMediateDecoder:
    return AppLovinMediateDecoder(lambda: AppLovinKeyring(sdk_keys=[SDK_KEY], salts=[SALT]))


def _empty_decoder() -> AppLovinMediateDecoder:
    return AppLovinMediateDecoder(lambda: AppLovinKeyring.from_sources(env={}))


class _CountingDecoder:
    title = "Counting"

    def __init__(self, match: bool, view=None, boom: bool = False):
        self.match, self.view, self.boom = match, view, boom
        self.decoded_bodies: list[bytes] = []

    def matches(self, host, path, query, body):
        return self.match

    def decode(self, host, path, query, body):
        if self.boom:
            raise RuntimeError("bad wire data")
        self.decoded_bodies.append(body)
        return self.view


# ── registry ────────────────────────────────────────────────────

def test_split_request_target_handles_origin_and_absolute_forms():
    assert split_request_target("MS4.AppLovin.com:443", "/1.0/mediate?p=x") == (
        HOST, "/1.0/mediate", "p=x")
    assert split_request_target("", "https://ms4.applovin.com/1.0/mediate?a=1") == (
        HOST, "/1.0/mediate", "a=1")
    assert split_request_target("", "") == ("", "", "")


def test_registry_skips_non_matching_decoders_without_decoding():
    decoder = _CountingDecoder(match=False)
    registry = AppCipherRegistry()
    registry.register(decoder)
    assert registry.decode_request("example.com", "/", b"body") == []
    assert decoder.decoded_bodies == []


def test_registry_decompresses_body_for_matched_decoders():
    import gzip
    decoder = _CountingDecoder(match=True, view=DecodedView(title="t", ok=True, text="x"))
    registry = AppCipherRegistry()
    registry.register(decoder)
    views = registry.decode_request("h", "/", gzip.compress(b"plain"), "gzip")
    assert [v.text for v in views] == ["x"]
    assert decoder.decoded_bodies == [b"plain"]


def test_registry_turns_decoder_crash_into_reason_view():
    registry = AppCipherRegistry()
    registry.register(_CountingDecoder(match=True, boom=True))
    (view,) = registry.decode_request("h", "/", b"")
    assert not view.ok and view.title == "Counting"
    assert "RuntimeError: bad wire data" in view.reason


def test_default_registry_is_cached_and_contains_applovin(monkeypatch):
    monkeypatch.setattr(reg, "_DEFAULT_REGISTRY", None)
    first = reg.default_registry()
    assert first is reg.default_registry()
    assert any(isinstance(d, AppLovinMediateDecoder) for d in first.decoders)
    assert all(isinstance(d, AppCipherDecoder) for d in first.decoders)


# ── AppLovin decoder ────────────────────────────────────────────

@pytest.mark.parametrize("host,path,expected", [
    (HOST, "/1.0/mediate", True),
    ("ms.applovin.com", "/1.0/mediate_debug", True),
    (HOST, "/2.0/ad", False),
    ("example.com", "/1.0/mediate", False),
])
def test_is_mediate_target(host, path, expected):
    assert is_mediate_target(host, path) is expected


def test_decoder_decrypts_raw_body_to_pretty_json():
    view = _keyed_decoder().decode(HOST, MEDIATE_URL, "", _envelope_b64().encode())
    assert view.ok and view.title == TITLE and view.reason == ""
    assert json.loads(view.text) == HOSTILE_PAYLOAD
    assert "\n  " in view.text  # indented
    assert any(n.startswith("variant: little/") for n in view.notes)
    assert any(n.startswith("timestamp: 2025-") for n in view.notes)


def test_decoder_reads_p_from_query():
    query = "p=" + quote(_envelope_b64(), safe="")
    view = _keyed_decoder().decode(HOST, MEDIATE_URL, query, b"")
    assert view.ok and json.loads(view.text) == HOSTILE_PAYLOAD


def test_decoder_reports_missing_key_material_with_env_hint():
    view = _empty_decoder().decode(HOST, MEDIATE_URL, "", _envelope_b64().encode())
    assert not view.ok and view.reason == REASON_NO_SDK_KEY
    assert "FRITAP_APPLOVIN_SDK_KEY" in view.reason
    assert not any("FRITAP_APPLOVIN_SDK_KEY" in n for n in view.notes)  # no duplicate hint
    assert any(n == f"protocol_id: {am.protocol_id_for_salt(SALT)}" for n in view.notes)


def test_decoder_reports_missing_envelope():
    view = _keyed_decoder().decode(HOST, MEDIATE_URL, "", b"{}")
    assert not view.ok and view.reason == REASON_NO_ENVELOPE


def test_decoder_builds_keyring_once():
    calls = []

    def factory():
        calls.append(1)
        return AppLovinKeyring(sdk_keys=[SDK_KEY], salts=[SALT])

    decoder = AppLovinMediateDecoder(factory)
    body = _envelope_b64().encode()
    decoder.decode(HOST, MEDIATE_URL, "", body)
    decoder.decode(HOST, MEDIATE_URL, "", body)
    assert calls == [1]


def test_decoder_matches_without_building_keyring():
    decoder = AppLovinMediateDecoder(lambda: pytest.fail("keyring built on match"))
    assert decoder.matches(HOST, MEDIATE_URL, "", b"")
    assert not decoder.matches("example.com", "/", "", b"")


# ── TUI flow detail section ─────────────────────────────────────

def _install_registry(monkeypatch, decoder) -> None:
    registry = AppCipherRegistry()
    registry.register(decoder)
    monkeypatch.setattr(reg, "_DEFAULT_REGISTRY", registry)


def _mediate_flow(url: str = MEDIATE_URL, body: bytes = b"", host: str = HOST):
    from friTap.flow.models import Flow
    from friTap.parsers.base import ParseResult

    flow = Flow(flow_id="al1", src_addr="10.0.0.1", src_port=1,
                dst_addr="10.0.0.2", dst_port=443)
    flow.request = ParseResult(protocol="HTTP/1.1", method="POST", url=url, host=host,
                               headers={"Host": host}, body=body)
    return flow


def _request_text(flow) -> str:
    pytest.importorskip("textual")
    from tests.unit._tui_flow_helpers import make_flow_detail_widget

    widget = make_flow_detail_widget()
    widget._update_request(flow)
    return "\n".join(widget._request_log.lines)


def test_flow_detail_shows_decrypted_applovin_section(monkeypatch):
    _install_registry(monkeypatch, _keyed_decoder())
    text = _request_text(_mediate_flow(body=_envelope_b64().encode()))
    assert f"--- {TITLE} ---" in text
    assert '"model": "[bold]evil[/]"' in text  # literal, not eaten as markup
    assert '"signal_data": [' in text


def test_flow_detail_shows_reason_when_key_material_missing(monkeypatch):
    _install_registry(monkeypatch, _empty_decoder())
    query = "?p=" + quote(_envelope_b64(), safe="")
    text = _request_text(_mediate_flow(url=MEDIATE_URL + query))
    assert f"--- {TITLE} ---" in text
    assert f"Not decrypted: {REASON_NO_SDK_KEY}" in " ".join(text.split())  # renderer wraps lines


def test_flow_detail_has_no_section_for_other_hosts(monkeypatch):
    decoder = AppLovinMediateDecoder(lambda: pytest.fail("keyring built for non-AppLovin flow"))
    _install_registry(monkeypatch, decoder)
    text = _request_text(_mediate_flow(host="example.com", body=b"hello"))
    assert TITLE not in text
