"""Hermetic golden-vector tests for the MTProto 2.0 crypto primitives.

No real traffic: we build valid records with the encrypt helper (the inverse of
the decrypt path) and assert the decryptor recovers them and that msg_key
verification gates correctly. Optional cross-checks against tgcrypto/telethon are
gated with ``importorskip`` so they only run where those libs are present.
"""

from __future__ import annotations

import hashlib
import os

import pytest

pytest.importorskip("cryptography")  # MTProto crypto needs an AES backend

from friTap.offline import mtproto
from friTap.offline.mtproto import crypto


def _auth_key() -> bytes:
    return os.urandom(crypto.AUTH_KEY_LEN)


# --------------------------------------------------------------------------- #
# IGE round-trip
# --------------------------------------------------------------------------- #


def test_ige_roundtrip_recovers_plaintext():
    key = os.urandom(32)
    iv = os.urandom(32)
    pt = os.urandom(64)  # multiple of 16
    ct = crypto.aes_ige_encrypt(key, iv, pt)
    assert ct != pt
    assert crypto.aes_ige_decrypt(key, iv, ct) == pt


def test_ige_rejects_bad_lengths():
    with pytest.raises(crypto.MtprotoCryptoError):
        crypto.aes_ige_decrypt(os.urandom(32), os.urandom(16), os.urandom(16))  # short IV
    with pytest.raises(crypto.MtprotoCryptoError):
        crypto.aes_ige_decrypt(os.urandom(32), os.urandom(32), os.urandom(15))  # unaligned


# --------------------------------------------------------------------------- #
# auth_key_id / KDF identities
# --------------------------------------------------------------------------- #


def test_auth_key_id_is_low64_of_sha1():
    ak = _auth_key()
    assert crypto.compute_auth_key_id(ak) == hashlib.sha1(ak).digest()[-8:]
    assert len(crypto.compute_auth_key_id(ak)) == 8


def test_kdf_direction_offsets_differ():
    ak = _auth_key()
    msg_key = os.urandom(16)
    kw = crypto.derive_aes_key_iv(ak, msg_key, "write")  # x=0
    kr = crypto.derive_aes_key_iv(ak, msg_key, "read")  # x=8
    assert kw != kr
    for key, iv in (kw, kr):
        assert len(key) == 32 and len(iv) == 32


def test_invalid_direction_raises():
    with pytest.raises(crypto.MtprotoCryptoError):
        crypto.derive_aes_key_iv(_auth_key(), os.urandom(16), "sideways")


# --------------------------------------------------------------------------- #
# Full record round-trip + envelope parsing
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("direction", ["write", "read"])
def test_record_roundtrip(direction):
    ak = _auth_key()
    message = b"\xde\xad\xbe\xef hello mtproto, layer 220"
    record = crypto.build_encrypted_record(
        ak, message, direction, msg_id=0x5F00000004, seq_no=7
    )
    # outer header
    assert record[:8] == crypto.compute_auth_key_id(ak)

    rec = crypto.decrypt_record(ak, record, direction, verify=True)
    assert rec.direction == direction
    assert rec.auth_key_id == crypto.compute_auth_key_id(ak)
    assert rec.envelope.message == message
    assert rec.envelope.seq_no == 7
    assert rec.envelope.msg_id == 0x5F00000004
    assert 12 <= len(rec.envelope.padding) <= 1024


def test_msg_key_verification_catches_wrong_key():
    ak = _auth_key()
    record = crypto.build_encrypted_record(ak, b"secret payload", "write")
    wrong = _auth_key()
    with pytest.raises(crypto.MtprotoCryptoError):
        crypto.decrypt_record(wrong, record, "write", verify=True)


def test_record_too_short_raises():
    with pytest.raises(crypto.MtprotoCryptoError):
        crypto.decrypt_record(_auth_key(), b"\x00" * 10, "write")


def test_backend_available_true_with_cryptography():
    assert crypto.backend_available() is True


# --------------------------------------------------------------------------- #
# Optional cross-validation against independent implementations
# --------------------------------------------------------------------------- #


def test_ige_matches_tgcrypto_if_present():
    tgcrypto = pytest.importorskip("tgcrypto")
    key, iv, pt = os.urandom(32), os.urandom(32), os.urandom(48)
    # Our pure-Python path vs tgcrypto's C implementation.
    ours = crypto._xor  # noqa: F841  (touch module to ensure import)
    assert tgcrypto.ige256_decrypt(
        crypto.aes_ige_encrypt(key, iv, pt), key, iv
    ) == pt


def test_dependency_error_is_exported():
    assert issubclass(mtproto.MtprotoDependencyError, mtproto.MtprotoError)
    assert issubclass(mtproto.MtprotoCryptoError, mtproto.MtprotoError)
