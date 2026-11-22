"""Unit tests for the AppLovin MAX /1.0/mediate app-layer cipher decoder."""

from __future__ import annotations

import base64
import gzip
import json
from urllib.parse import quote

import pytest

from friTap.parsers.app_ciphers import applovin_mediate as am

SALT = bytes(range(1, 22)) + bytes(11)          # 21 meaningful bytes + 11 zeros
SDK_KEY = ("abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-_" * 2)[:86]
TIMESTAMP_MS = 1_747_000_000_123
PAYLOAD_JSON = {"device_info": {"model": "Pixel 5"}, "signal_data": [{"a": 1}]}


def encrypt_for_testing(plaintext: bytes, sdk_key: str, salt: bytes,
                        variant: am.CipherVariant, counter: int = TIMESTAMP_MS) -> bytes:
    """Build the base64-decoded envelope the way the SDK is described to."""
    dk = am.derive_key(salt, sdk_key)
    masked = (counter ^ am.counter_mask(dk, variant)).to_bytes(8, "little")
    body = am.apply_keystream(plaintext, counter, dk, variant)
    head = f"2:{am.protocol_id_for_salt(salt)}:{sdk_key[32:]}:".encode("ascii")
    return head + masked + body


def gz_payload(obj=PAYLOAD_JSON) -> bytes:
    return gzip.compress(json.dumps(obj).encode())


def envelope_for(variant=am.ALL_VARIANTS[0], plaintext=None, **kw) -> am.MediateEnvelope:
    raw = encrypt_for_testing(plaintext or gz_payload(), SDK_KEY, SALT, variant, **kw)
    return am.parse_envelope(raw)


def test_fixtures_have_documented_shapes():
    assert len(SDK_KEY) == 86 and len(SDK_KEY[32:]) == 54 and len(SALT) == 32


@pytest.mark.parametrize("variant", am.ALL_VARIANTS, ids=repr)
def test_round_trip_every_variant(variant):
    result = am.decrypt(envelope_for(variant), SDK_KEY, SALT)
    assert result is not None
    assert result.variant == variant
    assert result.timestamp_ms == TIMESTAMP_MS
    assert result.json == PAYLOAD_JSON
    assert result.sdk_key_matches_suffix is True


def test_variant_axes_are_distinct():
    dk = am.derive_key(SALT, SDK_KEY)
    streams = {am.apply_keystream(bytes(40), TIMESTAMP_MS, dk, v) for v in am.ALL_VARIANTS}
    masks = {am.counter_mask(dk, v) for v in am.ALL_VARIANTS}
    assert len(am.ALL_VARIANTS) == 4 and len(streams) == 2 and len(masks) == 2


def test_keystream_byte_matches_apply_keystream():
    dk = am.derive_key(SALT, SDK_KEY)
    for variant in am.ALL_VARIANTS:
        stream = am.apply_keystream(bytes(20), 42, dk, variant)
        assert stream == bytes(am.keystream_byte(42, i, dk, variant) for i in range(20))


def test_non_json_gzip_plaintext_returns_bytes_and_none_json():
    result = am.decrypt(envelope_for(plaintext=gzip.compress(b"\x00not json")), SDK_KEY, SALT)
    assert result is not None and result.plaintext == b"\x00not json" and result.json is None


def test_mix64_known_values():
    assert am.mix64(0) == 0
    x = 1
    x = ((x ^ (x >> 33)) * 0xC2B2AE3D27D4EB4F) % 2**64
    x = ((x ^ (x >> 29)) * 0x85EBCA77C2B2AE63) % 2**64
    assert am.mix64(1) == x ^ (x >> 32)
    assert 0 <= am.mix64(2**64 - 1) < 2**64


def test_derive_key_uses_only_first_32_key_chars():
    assert am.derive_key(SALT, SDK_KEY) == am.derive_key(SALT, SDK_KEY[:32] + "X" * 54)
    assert len(am.derive_key(SALT, SDK_KEY)) == 32


def test_protocol_id_is_sha1_hex():
    assert am.protocol_id_for_salt(b"") == "da39a3ee5e6b4b0d3255bfef95601890afd80709"


# -- envelope parsing ------------------------------------------------------

def test_parse_envelope_splits_only_first_three_colons():
    raw = b"2:" + b"a" * 40 + b":suffix:" + b"\x01:\x02::"
    env = am.parse_envelope(raw)
    assert (env.version, env.protocol_id, env.sdk_key_suffix) == ("2", "a" * 40, "suffix")
    assert env.ciphertext == b"\x01:\x02::"


@pytest.mark.parametrize("raw", [b"", b"2:abc:def:x", b"2:" + b"a" * 40, b"hello world"])
def test_parse_envelope_rejects_malformed(raw):
    with pytest.raises(ValueError):
        am.parse_envelope(raw)


# -- payload extraction ----------------------------------------------------

RAW_ENVELOPE = encrypt_for_testing(gz_payload(), SDK_KEY, SALT, am.ALL_VARIANTS[0])
B64_STD = base64.b64encode(RAW_ENVELOPE).decode()


def test_extract_from_raw_base64_body():
    assert am.extract_envelope_payload(B64_STD.encode(), None) == RAW_ENVELOPE


def test_extract_from_urlsafe_body_without_padding():
    urlsafe = base64.urlsafe_b64encode(RAW_ENVELOPE).decode().rstrip("=")
    assert am.extract_envelope_payload(urlsafe.encode(), None) == RAW_ENVELOPE


def test_extract_from_url_query_param():
    query = f"v=1&p={quote(B64_STD, safe='')}"
    assert am.extract_envelope_payload(b"", query) == RAW_ENVELOPE


def test_extract_from_query_with_unescaped_plus():
    assert am.extract_envelope_payload(b"", "?p=" + B64_STD) == RAW_ENVELOPE


def test_extract_from_form_body():
    body = f"x=y&p={quote(B64_STD, safe='')}".encode()
    assert am.extract_envelope_payload(body, None) == RAW_ENVELOPE


@pytest.mark.parametrize("body,query", [
    (b"", None), (b"\xff\xfe binary", None), (b"not base64 !!", "q=1"),
    (base64.b64encode(b"just some text").decode().encode(), None),
])
def test_extract_returns_none_for_non_envelopes(body, query):
    assert am.extract_envelope_payload(body, query) is None


# -- failure modes ---------------------------------------------------------

def test_wrong_key_returns_none():
    wrong_key = "Z" * 32 + SDK_KEY[32:]
    result, reason = am.decrypt_with_reason(envelope_for(), wrong_key, SALT)
    assert result is None and reason == am.REASON_NO_VARIANT
    assert am.decrypt(envelope_for(), wrong_key, SALT) is None


def test_wrong_salt_reports_protocol_id_mismatch():
    other_salt = bytes(range(2, 23)) + bytes(11)
    result, reason = am.decrypt_with_reason(envelope_for(), SDK_KEY, other_salt)
    assert result is None and reason == am.REASON_PROTOCOL_ID_MISMATCH


def test_non_gzip_plaintext_returns_none():
    env = envelope_for(plaintext=json.dumps(PAYLOAD_JSON).encode())
    assert am.decrypt_with_reason(env, SDK_KEY, SALT) == (None, am.REASON_NO_VARIANT)


def test_gzip_magic_but_corrupt_stream_returns_none():
    env = envelope_for(plaintext=b"\x1f\x8b\x08" + b"\x00" * 30)
    assert am.decrypt(env, SDK_KEY, SALT) is None


@pytest.mark.parametrize("length", [0, 1, 7])
def test_truncated_ciphertext(length):
    env = am.MediateEnvelope("2", am.protocol_id_for_salt(SALT), SDK_KEY[32:], b"\x00" * length)
    assert am.decrypt_with_reason(env, SDK_KEY, SALT) == (None, am.REASON_TRUNCATED)


def test_suffix_mismatch_is_surfaced_not_fatal():
    key_with_other_suffix = SDK_KEY[:32] + "Q" * 54
    result = am.decrypt(envelope_for(), key_with_other_suffix, SALT)
    assert result is not None and result.sdk_key_matches_suffix is False


@pytest.mark.parametrize("host, path, expected", [
    ("ms4.applovin.com", "/1.0/mediate", True),
    ("applovin.com", "/1.0/mediate?x=1", True),
    ("ms4.applovin.com", "/1.0/event", False),
    ("example.com", "/1.0/mediate", False),
    ("ms4.applovin.com:443", "/1.0/mediate", False),  # caller strips the port
    ("MS4.APPLOVIN.COM", "/1.0/mediate", False),       # caller lower-cases
])
def test_is_mediate_request(host, path, expected):
    assert am.is_mediate_request(host, path) is expected


def test_is_mediate_target_aliases_share_the_predicate():
    from friTap.analysis import applovin_mediate as analysis_mod
    from friTap.parsers.app_ciphers import applovin_decoder

    assert analysis_mod.is_mediate_target is am.is_mediate_request
    assert applovin_decoder.is_mediate_target is am.is_mediate_request
