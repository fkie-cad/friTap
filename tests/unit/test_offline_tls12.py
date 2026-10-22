"""Unit tests for the TLS 1.2 AEAD peel + PRF (friTap.offline.tls.tls12).

No tshark, no pcap: the PRF is checked against a published test vector, and the
AEAD paths are checked by sealing a synthetic Finished record with the module's
own key schedule and decrypting it back. CBC / unknown suites are not handled by
this module (the oracle falls back to tshark for them).
"""
from __future__ import annotations

import pytest

from friTap.offline.tls import tls12

pytest.importorskip("cryptography")

import hmac as _hmac

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

# RFC 5246-style P_SHA256 test vector (widely published; cross-checked with an
# independent HMAC expansion).
_PRF_SECRET = bytes.fromhex("9bbe436ba940f017b17652849a71db35")
_PRF_SEED = bytes.fromhex("a0ba9f936cda311827a6f796ffd5198c")
_PRF_LABEL = b"test label"
_PRF_EXPECTED = bytes.fromhex(
    "e3f229ba727be17b8d122620557cd453c2aab21d07c3d495329b52d4e61edb5a"
    "6b301791e90d35c9c9a46b4e14baf9af0fa022f7077def17abfd3797c0564bab"
    "4fbc91666e9def9b97fce34f796789baa48082d122ee42c5a72e5a5110fff701"
    "87347b66"
)

AES128GCM = 0xC02F   # ECDHE_RSA_WITH_AES_128_GCM_SHA256
AES256GCM = 0xC030   # ECDHE_RSA_WITH_AES_256_GCM_SHA384
CHACHA20 = 0xCCA8    # ECDHE_RSA_WITH_CHACHA20_POLY1305
AES128_CBC = 0xC027  # ECDHE_RSA_WITH_AES_128_CBC_SHA256 (CBC, now supported)
# CBC suites exercised below: AES-128/SHA1, AES-256/SHA256, AES-256/SHA384.
AES128_CBC_SHA = 0xC013
AES256_CBC_SHA256 = 0x003D
AES256_CBC_SHA384 = 0xC028
# A CBC suite friTap deliberately does NOT decrypt (3DES) → "cannot tell".
TRIPLE_DES_CBC = 0x000A  # TLS_RSA_WITH_3DES_EDE_CBC_SHA

VERSION = b"\x03\x03"
CLIENT_RANDOM = bytes(range(32))
SERVER_RANDOM = bytes(range(32, 64))
MASTER = bytes(range(48))


def test_prf_matches_published_vector():
    out = tls12.prf(_PRF_SECRET, _PRF_LABEL, _PRF_SEED, 100, "sha256")
    assert out == _PRF_EXPECTED


def test_suite_support_gate():
    assert tls12.suite_supported(AES128GCM)
    assert tls12.suite_supported(CHACHA20)
    # CBC suites are not AEAD, but are now supported via the CBC path.
    assert not tls12.suite_supported(AES128_CBC)
    assert tls12.AEAD_SUITES.get(AES128_CBC) is None
    assert tls12.cbc_suite_supported(AES128_CBC)
    assert tls12.cbc_suite_supported(AES256_CBC_SHA384)
    # AES-CBC is covered across key exchanges (the record layer is KX-independent):
    assert tls12.cbc_suite_supported(0xC009)   # ECDHE_ECDSA_AES_128_CBC_SHA
    assert tls12.cbc_suite_supported(0x0033)   # DHE_RSA_AES_128_CBC_SHA
    assert tls12.cbc_suite_supported(0x006B)   # DHE_RSA_AES_256_CBC_SHA256
    assert tls12.cbc_suite_supported(0xC02A)   # ECDH_RSA_AES_256_CBC_SHA384
    assert not tls12.cbc_suite_supported(TRIPLE_DES_CBC)
    assert not tls12.cbc_suite_supported(AES128GCM)


def _seal_finished(master, cipher_suite, *, from_client, seq=0):
    """Seal a synthetic Finished record exactly as decrypt_record expects it."""
    suite = tls12.AEAD_SUITES[cipher_suite]
    ck, sk, civ, siv = tls12.key_block(master, SERVER_RANDOM, CLIENT_RANDOM, suite)
    key, fixed_iv = (ck, civ) if from_client else (sk, siv)
    plaintext = bytes([tls12.FINISHED]) + b"\x00\x00\x0c" + b"\xaa" * 12  # hs Finished
    aad = tls12._aad(seq, tls12.HANDSHAKE, VERSION, len(plaintext))
    if suite.is_chacha:
        nonce = (int.from_bytes(fixed_iv, "big") ^ seq).to_bytes(len(fixed_iv), "big")
        ct = ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)
        return ct
    explicit = seq.to_bytes(8, "big")
    nonce = fixed_iv + explicit
    ct = AESGCM(key).encrypt(nonce, plaintext, aad)
    return explicit + ct


@pytest.mark.parametrize("suite,from_client", [
    (AES128GCM, True), (AES128GCM, False),
    (AES256GCM, True), (CHACHA20, True), (CHACHA20, False),
])
def test_finished_round_trip(suite, from_client):
    frag = _seal_finished(MASTER, suite, from_client=from_client)
    assert tls12.finished_decrypts(
        MASTER, CLIENT_RANDOM, SERVER_RANDOM, suite,
        tls12.HANDSHAKE, VERSION, frag, from_client=from_client)


def test_wrong_master_fails():
    frag = _seal_finished(MASTER, AES128GCM, from_client=True)
    wrong = bytes([(b + 1) & 0xFF for b in MASTER])
    assert not tls12.finished_decrypts(
        wrong, CLIENT_RANDOM, SERVER_RANDOM, AES128GCM,
        tls12.HANDSHAKE, VERSION, frag, from_client=True)


def test_wrong_direction_fails():
    frag = _seal_finished(MASTER, AES128GCM, from_client=True)
    # The server write key cannot authenticate a record sealed with the client key.
    assert not tls12.finished_decrypts(
        MASTER, CLIENT_RANDOM, SERVER_RANDOM, AES128GCM,
        tls12.HANDSHAKE, VERSION, frag, from_client=False)


def test_non_handshake_record_rejected():
    frag = _seal_finished(MASTER, AES128GCM, from_client=True)
    assert not tls12.finished_decrypts(
        MASTER, CLIENT_RANDOM, SERVER_RANDOM, AES128GCM,
        0x17, VERSION, frag, from_client=True)  # application_data content type


def test_unsupported_cbc_suite_unsupported():
    # 3DES-CBC is neither AEAD nor in CBC_SUITES, so the module never decrypts
    # it (the oracle returns None for it and tshark takes over).
    frag = _seal_finished(MASTER, AES128GCM, from_client=True)
    assert not tls12.finished_decrypts(
        MASTER, CLIENT_RANDOM, SERVER_RANDOM, TRIPLE_DES_CBC,
        tls12.HANDSHAKE, VERSION, frag, from_client=True)


def test_unsupported_suite_is_cannot_tell():
    frag = _seal_finished(MASTER, AES128GCM, from_client=True)
    assert tls12.finished_decrypts(
        MASTER, CLIENT_RANDOM, SERVER_RANDOM, TRIPLE_DES_CBC,
        tls12.HANDSHAKE, VERSION, frag, from_client=True) is None


def test_precomputed_key_block_is_used():
    suite = tls12.AEAD_SUITES[AES128GCM]
    keys = tls12.key_block(MASTER, SERVER_RANDOM, CLIENT_RANDOM, suite)
    frag = _seal_finished(MASTER, AES128GCM, from_client=False)
    # The master argument is ignored when the key block is supplied.
    assert tls12.finished_decrypts(
        b"\x00" * 48, CLIENT_RANDOM, SERVER_RANDOM, AES128GCM,
        tls12.HANDSHAKE, VERSION, frag, from_client=False, keys=keys) is True


def test_backend_error_propagates_from_decrypt_record_and_is_none_above(monkeypatch):
    frag = _seal_finished(MASTER, AES128GCM, from_client=True)

    def unsupported(*_a, **_k):
        raise RuntimeError("UnsupportedAlgorithm")

    monkeypatch.setattr(tls12, "_aead", unsupported)
    suite = tls12.AEAD_SUITES[AES128GCM]
    with pytest.raises(RuntimeError):
        tls12.decrypt_record(b"k" * 16, b"i" * 4, suite, 0, tls12.HANDSHAKE,
                             VERSION, frag)
    assert tls12.finished_decrypts(
        MASTER, CLIENT_RANDOM, SERVER_RANDOM, AES128GCM,
        tls12.HANDSHAKE, VERSION, frag, from_client=True) is None


def test_wrong_master_is_a_definite_no():
    frag = _seal_finished(MASTER, AES128GCM, from_client=True)
    wrong = bytes([(b + 1) & 0xFF for b in MASTER])
    assert tls12.finished_decrypts(
        wrong, CLIENT_RANDOM, SERVER_RANDOM, AES128GCM,
        tls12.HANDSHAKE, VERSION, frag, from_client=True) is False


# --------------------------------------------------------------------------- #
# CBC (RFC 5246 MAC-then-encrypt; RFC 7366 Encrypt-then-MAC)
# --------------------------------------------------------------------------- #

_CBC_IV = bytes(range(100, 116))  # deterministic 16-byte explicit IV for tests
_FINISHED_MSG = bytes([tls12.FINISHED]) + b"\x00\x00\x0c" + b"\xaa" * 12


def _tls_pad(data):
    """Append TLS CBC padding so len is a multiple of the AES block size."""
    pad_total = 16 - (len(data) % 16)          # 1..16 bytes, all = pad_total-1
    return data + bytes([pad_total - 1]) * pad_total


def _seal_cbc_finished(master, cipher_suite, *, from_client, uses_etm, seq=0):
    """Seal a synthetic Finished record exactly as _cbc_finished_decrypts expects."""
    suite = tls12.CBC_SUITES[cipher_suite]
    cm, sm, ck, sk = tls12.cbc_key_block(master, SERVER_RANDOM, CLIENT_RANDOM, suite)
    mac_key, key = (cm, ck) if from_client else (sm, sk)

    def encrypt(plaintext):
        enc = Cipher(algorithms.AES(key), modes.CBC(_CBC_IV)).encryptor()
        return enc.update(plaintext) + enc.finalize()

    if uses_etm:
        ct = encrypt(_tls_pad(_FINISHED_MSG))
        covered = _CBC_IV + ct
        mac_input = (seq.to_bytes(8, "big") + bytes([tls12.HANDSHAKE]) + VERSION
                     + len(covered).to_bytes(2, "big") + covered)
        mac = _hmac.new(mac_key, mac_input, suite.mac_hash).digest()
        return covered + mac
    mac_input = (seq.to_bytes(8, "big") + bytes([tls12.HANDSHAKE]) + VERSION
                 + len(_FINISHED_MSG).to_bytes(2, "big") + _FINISHED_MSG)
    mac = _hmac.new(mac_key, mac_input, suite.mac_hash).digest()
    ct = encrypt(_tls_pad(_FINISHED_MSG + mac))
    return _CBC_IV + ct


@pytest.mark.parametrize("suite", [AES128_CBC_SHA, AES256_CBC_SHA256, AES256_CBC_SHA384])
@pytest.mark.parametrize("uses_etm", [False, True])
@pytest.mark.parametrize("from_client", [True, False])
def test_cbc_finished_round_trip(suite, uses_etm, from_client):
    frag = _seal_cbc_finished(MASTER, suite, from_client=from_client, uses_etm=uses_etm)
    assert tls12.finished_decrypts(
        MASTER, CLIENT_RANDOM, SERVER_RANDOM, suite,
        tls12.HANDSHAKE, VERSION, frag,
        from_client=from_client, uses_etm=uses_etm) is True


@pytest.mark.parametrize("uses_etm", [False, True])
def test_cbc_wrong_master_fails(uses_etm):
    frag = _seal_cbc_finished(MASTER, AES128_CBC_SHA, from_client=True, uses_etm=uses_etm)
    wrong = bytes([(b + 1) & 0xFF for b in MASTER])
    assert tls12.finished_decrypts(
        wrong, CLIENT_RANDOM, SERVER_RANDOM, AES128_CBC_SHA,
        tls12.HANDSHAKE, VERSION, frag,
        from_client=True, uses_etm=uses_etm) is False


@pytest.mark.parametrize("uses_etm", [False, True])
def test_cbc_wrong_direction_fails(uses_etm):
    frag = _seal_cbc_finished(MASTER, AES128_CBC_SHA, from_client=True, uses_etm=uses_etm)
    # The server MAC/write key cannot authenticate a record sealed client-side.
    assert tls12.finished_decrypts(
        MASTER, CLIENT_RANDOM, SERVER_RANDOM, AES128_CBC_SHA,
        tls12.HANDSHAKE, VERSION, frag,
        from_client=False, uses_etm=uses_etm) is False


def test_cbc_wrong_framing_fails():
    # A record sealed MtE but checked as EtM (and vice versa) must not validate.
    mte = _seal_cbc_finished(MASTER, AES128_CBC_SHA, from_client=True, uses_etm=False)
    assert tls12.finished_decrypts(
        MASTER, CLIENT_RANDOM, SERVER_RANDOM, AES128_CBC_SHA,
        tls12.HANDSHAKE, VERSION, mte, from_client=True, uses_etm=True) is False
    etm = _seal_cbc_finished(MASTER, AES128_CBC_SHA, from_client=True, uses_etm=True)
    assert tls12.finished_decrypts(
        MASTER, CLIENT_RANDOM, SERVER_RANDOM, AES128_CBC_SHA,
        tls12.HANDSHAKE, VERSION, etm, from_client=True, uses_etm=False) is False


def test_cbc_non_handshake_record_rejected():
    frag = _seal_cbc_finished(MASTER, AES128_CBC_SHA, from_client=True, uses_etm=False)
    assert tls12.finished_decrypts(
        MASTER, CLIENT_RANDOM, SERVER_RANDOM, AES128_CBC_SHA,
        0x17, VERSION, frag, from_client=True, uses_etm=False) is False


def test_cbc_backend_error_is_cannot_tell(monkeypatch):
    frag = _seal_cbc_finished(MASTER, AES128_CBC_SHA, from_client=True, uses_etm=False)

    def boom(*_a, **_k):
        raise RuntimeError("UnsupportedAlgorithm")

    monkeypatch.setattr(tls12, "_aes_cbc_decrypt", boom)
    assert tls12.finished_decrypts(
        MASTER, CLIENT_RANDOM, SERVER_RANDOM, AES128_CBC_SHA,
        tls12.HANDSHAKE, VERSION, frag, from_client=True, uses_etm=False) is None
