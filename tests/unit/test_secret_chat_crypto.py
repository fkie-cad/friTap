"""Hermetic golden-vector tests for the Telegram secret-chat (E2E) crypto.

No real traffic: we build valid blobs with the encrypt helper (the inverse of the
decrypt path) and assert the decryptor recovers them, that the direction is
auto-detected via msg_key verification, and that tampering is rejected.
"""

from __future__ import annotations

import hashlib
import os

import pytest

pytest.importorskip("cryptography")  # secret-chat crypto needs an AES backend

from friTap.offline.mtproto import crypto


def _shared_key() -> bytes:
    return os.urandom(crypto.SECRET_CHAT_KEY_LEN)


# --------------------------------------------------------------------------- #
# fingerprint identity
# --------------------------------------------------------------------------- #


def test_fingerprint_is_low64_of_sha1():
    key = _shared_key()
    fp = crypto.compute_secret_chat_fingerprint(key)
    assert fp == hashlib.sha1(key).digest()[-8:]
    assert len(fp) == crypto.E2E_FINGERPRINT_LEN


def test_fingerprint_rejects_wrong_length():
    with pytest.raises(AssertionError):
        crypto.compute_secret_chat_fingerprint(os.urandom(64))


# --------------------------------------------------------------------------- #
# blob round-trip (both directions)
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("sender_is_creator", [True, False])
def test_blob_roundtrip(sender_is_creator):
    key = _shared_key()
    payload = b"\xde\xad\xbe\xef secret chat decrypted message layer"
    blob = crypto.build_secret_chat_blob(
        key, payload, sender_is_creator=sender_is_creator
    )
    # wire header
    assert blob[:8] == crypto.compute_secret_chat_fingerprint(key)
    assert (len(blob) - crypto.E2E_HEADER_LEN) % crypto.AES_BLOCK == 0

    # The decryptor auto-detects the direction; we never tell it which was used.
    plaintext = crypto.decrypt_secret_chat_blob(key, blob)
    assert crypto.parse_secret_chat_plaintext(plaintext) == payload


def test_parse_strips_length_prefix_and_padding():
    key = _shared_key()
    payload = b"x" * 7
    blob = crypto.build_secret_chat_blob(key, payload, sender_is_creator=True)
    plaintext = crypto.decrypt_secret_chat_blob(key, blob)
    # raw plaintext keeps the LE length prefix + >=12 bytes of padding
    assert plaintext[:4] == len(payload).to_bytes(4, "little")
    assert len(plaintext) > 4 + len(payload)
    assert crypto.parse_secret_chat_plaintext(plaintext) == payload


# --------------------------------------------------------------------------- #
# verify=False direction handling (regression: it used to always return x=0)
# --------------------------------------------------------------------------- #


def test_verify_false_requires_explicit_direction():
    key = _shared_key()
    blob = crypto.build_secret_chat_blob(key, b"payload", sender_is_creator=True)
    with pytest.raises(ValueError):
        crypto.decrypt_secret_chat_blob(key, blob, verify=False)


def test_invalid_direction_raises():
    key = _shared_key()
    blob = crypto.build_secret_chat_blob(key, b"payload", sender_is_creator=True)
    with pytest.raises(ValueError):
        crypto.decrypt_secret_chat_blob(key, blob, verify=False, direction="sideways")


@pytest.mark.parametrize("sender_is_creator", [True, False])
def test_verify_false_with_correct_direction_matches_verified(sender_is_creator):
    key = _shared_key()
    payload = b"a secret-chat decrypted message layer payload"
    blob = crypto.build_secret_chat_blob(
        key, payload, sender_is_creator=sender_is_creator
    )
    direction = "write" if sender_is_creator else "read"
    fast = crypto.decrypt_secret_chat_blob(key, blob, verify=False, direction=direction)
    assert crypto.parse_secret_chat_plaintext(fast) == payload
    # The WRONG direction yields different (garbage) plaintext — never the payload.
    wrong = "read" if direction == "write" else "write"
    bad = crypto.decrypt_secret_chat_blob(key, blob, verify=False, direction=wrong)
    assert bad != fast


# --------------------------------------------------------------------------- #
# verification / failure modes
# --------------------------------------------------------------------------- #


def test_wrong_key_fails_verification():
    key = _shared_key()
    blob = crypto.build_secret_chat_blob(key, b"hello", sender_is_creator=True)
    with pytest.raises(crypto.MtprotoCryptoError):
        crypto.decrypt_secret_chat_blob(_shared_key(), blob)


def test_tampered_ciphertext_fails_verification():
    key = _shared_key()
    blob = bytearray(crypto.build_secret_chat_blob(key, b"hello", sender_is_creator=False))
    blob[-1] ^= 0xFF  # flip a ciphertext byte
    with pytest.raises(crypto.MtprotoCryptoError):
        crypto.decrypt_secret_chat_blob(key, bytes(blob))


def test_blob_too_short_raises():
    with pytest.raises(crypto.MtprotoCryptoError):
        crypto.decrypt_secret_chat_blob(_shared_key(), b"\x00" * 10)


def test_unaligned_body_raises():
    with pytest.raises(crypto.MtprotoCryptoError):
        crypto.decrypt_secret_chat_blob(_shared_key(), b"\x00" * (crypto.E2E_HEADER_LEN + 15))


def test_parse_rejects_out_of_bounds_length():
    bad = (10_000).to_bytes(4, "little") + b"short"
    with pytest.raises(crypto.MtprotoCryptoError):
        crypto.parse_secret_chat_plaintext(bad)
