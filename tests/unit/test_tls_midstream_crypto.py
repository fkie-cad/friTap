"""Unit tests for the isolated mid-stream TLS 1.3 record decrypter.

All synthetic: no device, no pcap, no repo-root files. The synthetic records are
built with the same ``cryptography`` AEAD backend the decrypter uses, so a
round-trip proves the whole chain (HKDF-Expand-Label key schedule -> nonce =
iv XOR seq -> AEAD tag -> inner content-type recovery).
"""

import struct

import pytest

from friTap.offline.rc4 import crypto as rc4_crypto
from friTap.offline.tls_midstream import crypto as mid


# RFC 8448 sec 3, TLS_AES_128_GCM_SHA256 client handshake traffic secret and the
# key/iv it must expand to (a HKDF-Expand-Label known-answer vector).
CHTS = "b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21"
CHTS_KEY = "dbfaa693d1762c5b666af5d950258d01"
CHTS_IV = "5bd3c71b836e0b76bb73265f"

ALL_SUITES = [
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
]


# --------------------------------------------------------------------------- #
# Synthetic TLS 1.3 record builder (client-side of the AEAD, for the tests)
# --------------------------------------------------------------------------- #

def _record_header(fragment_len: int) -> bytes:
    """TLS 1.3 outer record header: application_data, legacy version 0x0303, len."""
    return b"\x17\x03\x03" + struct.pack(">H", fragment_len)


def _seal_record(secret_hex: str, suite: str, seq: int, inner: bytes) -> tuple:
    """AEAD-seal one inner plaintext into an (content_type, header5, fragment) rec.

    Inner plaintext = content || inner_content_type(0x17) (no padding here). The
    header length must cover the ciphertext+tag, so we build it after sizing.
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

    key, iv = rc4_crypto.derive_key_iv(bytes.fromhex(secret_hex), suite)
    plaintext = inner + b"\x17"  # inner content-type = application_data
    fragment_len = len(plaintext) + 16  # + AEAD tag
    hdr = _record_header(fragment_len)

    aead = AESGCM(key) if suite != "TLS_CHACHA20_POLY1305_SHA256" else ChaCha20Poly1305(key)
    fragment = aead.encrypt(rc4_crypto.record_nonce(iv, seq), plaintext, hdr)
    return (0x17, hdr, fragment)


def _build_stream(secret_hex: str, suite: str, start_seq: int, messages: list) -> list:
    """Build N consecutive application_data records at start_seq, start_seq+1, ..."""
    return [
        _seal_record(secret_hex, suite, start_seq + i, msg)
        for i, msg in enumerate(messages)
    ]


# --------------------------------------------------------------------------- #
# HKDF-Expand-Label known-answer + round-trip
# --------------------------------------------------------------------------- #

def test_hkdf_expand_label_rfc8448_known_answer():
    """RFC 8448 vector: the imported key schedule expands CHTS to the known key/iv."""
    pytest.importorskip("cryptography")
    key, iv = rc4_crypto.derive_key_iv(bytes.fromhex(CHTS), "TLS_AES_128_GCM_SHA256")
    assert key.hex() == CHTS_KEY
    assert iv.hex() == CHTS_IV


def test_roundtrip_encrypt_then_try_decrypt():
    """A record sealed with the cryptography AEAD decrypts via the shared try_decrypt."""
    pytest.importorskip("cryptography")
    secret = "11" * 32
    suite = "TLS_AES_128_GCM_SHA256"
    _ctype, hdr, frag = _seal_record(secret, suite, 7, b"hello midstream")
    pt = rc4_crypto.try_decrypt(bytes.fromhex(secret), suite, 7, hdr, frag)
    assert pt is not None
    assert rc4_crypto.inner_content_type(pt) == 0x17
    assert pt[:-1] == b"hello midstream"


# --------------------------------------------------------------------------- #
# recover_seq + decrypt_stream_from, for all three suites, mid-stream start S=7
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("suite", ALL_SUITES)
def test_recover_seq_and_decrypt_stream_from(suite):
    pytest.importorskip("cryptography")
    secret = "ab" * 32  # 32-byte secret works for all three (sha256/sha384 both accept)
    start_seq = 7
    messages = [b"first record", b"second record", b"third record", b"fourth"]
    records = _build_stream(secret, suite, start_seq, messages)

    found = mid.recover_seq(secret, suite, records)
    assert found == start_seq

    plaintexts = mid.decrypt_stream_from(secret, suite, records, found)
    assert [p[:-1] for p in plaintexts] == messages


# --------------------------------------------------------------------------- #
# Zero-false-accept: a WRONG secret never yields a sequence number
# --------------------------------------------------------------------------- #

def test_wrong_secret_yields_none():
    pytest.importorskip("cryptography")
    suite = "TLS_AES_128_GCM_SHA256"
    right = "ab" * 32
    wrong = "cd" * 32
    records = _build_stream(right, suite, 7, [b"payload one", b"payload two"])
    # The AEAD tag rejects every seq under the wrong secret across the whole bound.
    assert mid.recover_seq(wrong, suite, records, max_seq=64) is None


def test_start_seq_beyond_bound_yields_none():
    """A start seq past max_seq is not found (bounded oracle)."""
    pytest.importorskip("cryptography")
    suite = "TLS_AES_128_GCM_SHA256"
    secret = "ab" * 32
    records = _build_stream(secret, suite, 100, [b"far out"])
    assert mid.recover_seq(secret, suite, records, max_seq=64) is None
    # But widening the bound finds it.
    assert mid.recover_seq(secret, suite, records, max_seq=128) == 100


# --------------------------------------------------------------------------- #
# pick_suite disambiguates the cipher suite via the tag
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("suite", ALL_SUITES)
def test_pick_suite_selects_correct_suite(suite):
    pytest.importorskip("cryptography")
    secret = "ab" * 32
    start_seq = 7
    records = _build_stream(secret, suite, start_seq, [b"disambiguate me"])
    result = mid.pick_suite(secret, records)
    assert result is not None
    picked_suite, picked_seq = result
    assert picked_suite == suite
    assert picked_seq == start_seq


def test_pick_suite_wrong_secret_returns_none():
    pytest.importorskip("cryptography")
    suite = "TLS_AES_256_GCM_SHA384"
    records = _build_stream("ab" * 32, suite, 7, [b"payload"])
    assert mid.pick_suite("cd" * 32, records) is None
