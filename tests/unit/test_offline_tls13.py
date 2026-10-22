"""Unit tests for the protocol-neutral TLS 1.3 package ``friTap.offline.tls``.

Covers the new import paths plus a few behaviour checks: the RFC 8448 key
schedule vector, an AEAD round trip through ``try_decrypt`` /
``inner_content_type``, record splitting (incl. an incomplete tail), the
``_prepared_cipher`` memo, handshake-anchored and mid-stream stream decryption,
and that the legacy ``rc4.crypto`` / ``tls_midstream.crypto`` shims re-export
the very same objects.
"""
from __future__ import annotations

import pytest

from friTap.offline.tls import backend, records, stream, tls13

SUITE = "TLS_AES_128_GCM_SHA256"
SECRET_HEX = "11" * 32
HDR = bytes.fromhex("1703030000")

# RFC 8448 sec 3: client handshake traffic secret -> write key / iv.
CHTS = "b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21"
CHTS_KEY = "dbfaa693d1762c5b666af5d950258d01"
CHTS_IV = "5bd3c71b836e0b76bb73265f"

needs_backend = pytest.mark.skipif(
    not backend.backend_available(), reason="cryptography not installed"
)


def _record(seq: int, inner: bytes, secret_hex: str = SECRET_HEX):
    """Encrypt ``inner`` as one TLS 1.3 application_data record at ``seq``."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    key, iv = tls13.derive_key_iv(bytes.fromhex(secret_hex), SUITE)
    hdr = b"\x17\x03\x03" + (len(inner) + 16).to_bytes(2, "big")
    return 0x17, hdr, AESGCM(key).encrypt(tls13.record_nonce(iv, seq), inner, hdr)


# --- tls13 ----------------------------------------------------------------- #

@needs_backend
def test_derive_key_iv_matches_rfc8448():
    key, iv = tls13.derive_key_iv(bytes.fromhex(CHTS), SUITE)
    assert (key.hex(), iv.hex()) == (CHTS_KEY, CHTS_IV)


@needs_backend
def test_try_decrypt_round_trip_and_inner_type():
    _, hdr, frag = _record(3, b"payload\x17\x00\x00")
    pt = tls13.try_decrypt(bytes.fromhex(SECRET_HEX), SUITE, 3, hdr, frag)
    assert pt == b"payload\x17\x00\x00"
    assert tls13.inner_content_type(pt) == 0x17
    assert tls13.try_decrypt(bytes.fromhex(SECRET_HEX), SUITE, 4, hdr, frag) is None


def test_inner_content_type_all_zero_is_none():
    assert tls13.inner_content_type(b"\x00\x00") is None


@needs_backend
def test_prepared_cipher_is_memoized():
    tls13._prepared_cipher.cache_clear()
    secret = bytes.fromhex(SECRET_HEX)
    first = tls13._prepared_cipher(secret, SUITE)
    assert tls13._prepared_cipher(secret, SUITE) is first
    info = tls13._prepared_cipher.cache_info()
    assert (info.hits, info.misses, info.maxsize) == (1, 1, 128)


def test_suite_tables_agree():
    assert set(tls13.SUITE_BY_ID.values()) == set(tls13.SUITES)


# --- records --------------------------------------------------------------- #

def test_parse_records_drops_incomplete_tail():
    data = bytes.fromhex("1603030003aabbcc" "1703030002dead" "17030300ff00")
    recs = records.parse_records(data)
    assert [(c, h.hex(), f.hex()) for c, h, f in recs] == [
        (0x16, "1603030003", "aabbcc"),
        (0x17, "1703030002", "dead"),
    ]


def test_parse_records_short_header_yields_nothing():
    assert records.parse_records(b"\x17\x03\x03") == []


def test_hello_field_extraction():
    ch = bytes([0x01, 0, 0, 40, 0x03, 0x03]) + bytes(range(32)) + b"\x00\x00"
    assert records.client_random_from_clienthello(ch) == bytes(range(32)).hex()


# --- stream ---------------------------------------------------------------- #

@needs_backend
def test_decrypt_stream_from_seq0():
    recs = [(0x16, HDR, b"x" * 20)] + [_record(i, b"m%d\x17" % i) for i in range(3)]
    assert stream.decrypt_stream(SECRET_HEX, recs, SUITE) == [
        b"m0\x17", b"m1\x17", b"m2\x17"
    ]


@needs_backend
def test_midstream_recovers_unknown_start_seq_and_suite():
    recs = [_record(40 + i, b"m%d\x17" % i) for i in range(2)]
    assert stream.recover_seq(SECRET_HEX, SUITE, recs, max_seq=64) == 40
    assert stream.pick_suite(SECRET_HEX, recs, max_seq=64) == (SUITE, 40)
    assert stream.decrypt_stream_from(SECRET_HEX, SUITE, recs, 40) == [
        b"m0\x17", b"m1\x17"
    ]


# --- legacy shims ---------------------------------------------------------- #

def test_legacy_paths_reexport_same_objects():
    from friTap.offline.rc4 import crypto as rc4_crypto
    from friTap.offline.tls_midstream import crypto as mid_crypto

    assert rc4_crypto.try_decrypt is tls13.try_decrypt
    assert rc4_crypto._prepared_cipher is tls13._prepared_cipher
    assert rc4_crypto.parse_records is records.parse_records
    assert rc4_crypto.decrypt_stream is stream.decrypt_stream
    assert rc4_crypto.backend_available is backend.backend_available
    assert mid_crypto.recover_seq is stream.recover_seq
    assert mid_crypto.DEFAULT_MAX_SEQ == stream.DEFAULT_MAX_SEQ


# --- Phase 4 simplifications ------------------------------------------------ #

@pytest.mark.parametrize("plaintext, expected", [
    (b"hi\x17\x00\x00", b"hi"),
    (b"hi\x17", b"hi"),
    (b"\x17\x00", b""),            # application_data with empty content
    (b"hs\x16\x00", None),         # handshake record
    (b"al\x15", None),             # alert record
    (b"\x00\x00\x00", None),       # all-zero: no content-type byte
    (b"", None),
])
def test_inner_app_content(plaintext, expected):
    assert tls13.inner_app_content(plaintext) == expected


def test_suites_for_secret_filters_by_hash_length():
    assert tls13.suites_for_secret(b"\x00" * 48) == ["TLS_AES_256_GCM_SHA384"]
    assert tls13.suites_for_secret(b"\x00" * 32) == [
        "TLS_AES_128_GCM_SHA256", "TLS_CHACHA20_POLY1305_SHA256"]
    # An odd length matches nothing, so every suite is kept (unchanged behaviour).
    assert tls13.suites_for_secret(b"\x00" * 16) == list(tls13.SUITES)


@needs_backend
def test_prepared_cipher_caches_iv_as_int():
    tls13._prepared_cipher.cache_clear()
    _aead, iv, iv_int = tls13._prepared_cipher(bytes.fromhex(SECRET_HEX), SUITE)
    assert iv_int == int.from_bytes(iv, "big")


def test_app_data_records_filters_decryptable_app_data():
    recs = [(0x17, HDR, b"\x00" * 17), (0x17, HDR, b"\x00" * 16), (0x16, HDR, b"\x00" * 40)]
    assert stream.app_data_records(recs) == recs[:1]
    assert list(stream.iter_app_data_records(recs)) == recs[:1]
