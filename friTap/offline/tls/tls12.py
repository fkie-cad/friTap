"""TLS 1.2 AEAD record protection and PRF (RFC 5246).

A small TLS 1.2 peel that answers "does this 48-byte master secret belong to
this connection?" in pure Python. It covers the two AEAD families TLS 1.2 stacks
negotiate in practice — AES-GCM and ChaCha20-Poly1305 — by decrypting the first
record after a side's ChangeCipherSpec (the encrypted ``Finished``) at record
sequence number 0 and checking that the handshake message type is ``finished``
(0x14). The answer is tri-state: ``True`` / ``False``, or ``None`` when this
module cannot tell (unsupported suite, unusable crypto backend).

CBC and any other / unknown suite are intentionally NOT handled here; callers
fall back to another decision path (e.g. tshark) for them.

The ``cryptography`` backend is imported lazily through the :mod:`.tls13` AEAD
factories, so importing this module never requires it.

References: RFC 5246 sec 5 (PRF), sec 6.2.3.3 / RFC 5116 (AEAD records),
RFC 5288 (AES-GCM cipher suites), RFC 7905 (ChaCha20-Poly1305 cipher suites).
"""

from __future__ import annotations

import hmac
from typing import Dict, Optional, Tuple

from .records import CT_CHANGE_CIPHER_SPEC, CT_HANDSHAKE
from .tls13 import _aesgcm, _chacha20, record_nonce

# TLS 1.2 handshake message type ``finished`` (RFC 5246 sec 7.4.9). A master
# that is correct for a connection decrypts that connection's first post-CCS
# record to a plaintext whose first byte is this type.
FINISHED = 0x14

# Record content types, kept under their historical names for importers.
CHANGE_CIPHER_SPEC = CT_CHANGE_CIPHER_SPEC
HANDSHAKE = CT_HANDSHAKE

# Every TLS 1.2 AEAD suite here uses a 16-byte authentication tag.
_TAG_LEN = 16


# Per-suite crypto parameters, keyed by the 2-byte cipher_suite id.
#   hash_name:   PRF hash (and, for GCM, the suite's SHA variant)
#   key_len:     AEAD key length in bytes
#   fixed_iv_len: implicit (salt) nonce bytes derived from the key block
#   record_iv_len: explicit per-record nonce bytes sent on the wire (GCM only)
#   is_chacha:   RFC 7905 nonce construction instead of GCM's salt||explicit
class _Suite:
    __slots__ = ("hash_name", "key_len", "fixed_iv_len", "record_iv_len",
                 "is_chacha")

    def __init__(self, hash_name, key_len, fixed_iv_len, record_iv_len, is_chacha):
        self.hash_name = hash_name
        self.key_len = key_len
        self.fixed_iv_len = fixed_iv_len
        self.record_iv_len = record_iv_len
        self.is_chacha = is_chacha


# AES-GCM suites (RFC 5288 / RFC 5289): 4-byte salt, 8-byte explicit nonce.
# ChaCha20-Poly1305 suites (RFC 7905): 12-byte implicit iv, no explicit nonce.
AEAD_SUITES: Dict[int, _Suite] = {
    # RSA / DH(E) AES-GCM (RFC 5288)
    0x009C: _Suite("sha256", 16, 4, 8, False),   # AES_128_GCM_SHA256
    0x009D: _Suite("sha384", 32, 4, 8, False),   # AES_256_GCM_SHA384
    0x009E: _Suite("sha256", 16, 4, 8, False),   # DHE_RSA_AES_128_GCM_SHA256
    0x009F: _Suite("sha384", 32, 4, 8, False),   # DHE_RSA_AES_256_GCM_SHA384
    # ECDHE AES-GCM (RFC 5289)
    0xC02B: _Suite("sha256", 16, 4, 8, False),   # ECDHE_ECDSA_AES_128_GCM_SHA256
    0xC02C: _Suite("sha384", 32, 4, 8, False),   # ECDHE_ECDSA_AES_256_GCM_SHA384
    0xC02F: _Suite("sha256", 16, 4, 8, False),   # ECDHE_RSA_AES_128_GCM_SHA256
    0xC030: _Suite("sha384", 32, 4, 8, False),   # ECDHE_RSA_AES_256_GCM_SHA384
    # ChaCha20-Poly1305 (RFC 7905)
    0xCCA8: _Suite("sha256", 32, 12, 0, True),   # ECDHE_RSA_CHACHA20_POLY1305
    0xCCA9: _Suite("sha256", 32, 12, 0, True),   # ECDHE_ECDSA_CHACHA20_POLY1305
    0xCCAA: _Suite("sha256", 32, 12, 0, True),   # DHE_RSA_CHACHA20_POLY1305
}


def suite_supported(cipher_suite: int) -> bool:
    """True when :mod:`.tls12` can trial-decrypt this cipher suite (AEAD only)."""
    return cipher_suite in AEAD_SUITES


# --------------------------------------------------------------------------- #
# PRF (RFC 5246 sec 5)
# --------------------------------------------------------------------------- #

def _p_hash(secret: bytes, seed: bytes, length: int, hash_name: str) -> bytes:
    """RFC 5246 sec 5 P_hash: HMAC expansion to ``length`` bytes."""
    out = bytearray()
    a = hmac.new(secret, seed, hash_name).digest()         # A(1)
    while len(out) < length:
        out += hmac.new(secret, a + seed, hash_name).digest()
        a = hmac.new(secret, a, hash_name).digest()        # A(i+1)
    return bytes(out[:length])


def prf(secret: bytes, label: bytes, seed: bytes, length: int,
        hash_name: str) -> bytes:
    """RFC 5246 sec 5 TLS 1.2 PRF = P_<hash>(secret, label || seed)."""
    return _p_hash(secret, label + seed, length, hash_name)


def key_block(master: bytes, server_random: bytes, client_random: bytes,
              suite: _Suite) -> Tuple[bytes, bytes, bytes, bytes]:
    """Derive ``(client_key, server_key, client_iv, server_iv)`` (RFC 5246 sec 6.3).

    AEAD suites have no MAC key, so the key block is just the two write keys and
    the two fixed IVs (the "implicit nonce" / salt), in that order.
    """
    need = 2 * suite.key_len + 2 * suite.fixed_iv_len
    block = prf(master, b"key expansion", server_random + client_random,
                need, suite.hash_name)
    kl, il = suite.key_len, suite.fixed_iv_len
    client_key = block[0:kl]
    server_key = block[kl:2 * kl]
    client_iv = block[2 * kl:2 * kl + il]
    server_iv = block[2 * kl + il:2 * kl + 2 * il]
    return client_key, server_key, client_iv, server_iv


# --------------------------------------------------------------------------- #
# AEAD record protection (RFC 5246 sec 6.2.3.3)
# --------------------------------------------------------------------------- #

def _aead(key: bytes, is_chacha: bool):
    """The AEAD object for *key* (shared factories with :mod:`.tls13`)."""
    return _chacha20(key) if is_chacha else _aesgcm(key)


def _aad(seq: int, content_type: int, version: bytes, plaintext_len: int) -> bytes:
    """TLS 1.2 AEAD additional data: seq(8) || type || version || length(2)."""
    return (seq.to_bytes(8, "big") + bytes([content_type]) + version
            + plaintext_len.to_bytes(2, "big"))


def decrypt_record(key: bytes, fixed_iv: bytes, suite: _Suite, seq: int,
                   content_type: int, version: bytes,
                   fragment: bytes) -> Optional[bytes]:
    """Decrypt one TLS 1.2 AEAD record fragment, or ``None`` on tag failure.

    ``fragment`` is the record's on-the-wire payload (after the 5-byte header).
    For GCM it is ``explicit_nonce(8) || ciphertext || tag(16)`` and the nonce is
    ``salt || explicit_nonce``. For ChaCha20-Poly1305 (RFC 7905) there is no
    explicit nonce; the nonce is the 12-byte fixed IV XORed with the record
    sequence number, and the fragment is ``ciphertext || tag(16)``.

    Only an authentication failure (``InvalidTag``) means "wrong key" and yields
    ``None``; a crypto-backend error (missing ``cryptography``, an algorithm the
    linked OpenSSL does not support) propagates, so callers can tell "no" from
    "cannot tell".
    """
    explicit_len = 0 if suite.is_chacha else suite.record_iv_len
    if len(fragment) < explicit_len + _TAG_LEN:
        return None
    if suite.is_chacha:
        nonce = record_nonce(fixed_iv, seq)
    else:
        nonce = fixed_iv + fragment[:explicit_len]
    ciphertext = fragment[explicit_len:]
    aad = _aad(seq, content_type, version, len(ciphertext) - _TAG_LEN)
    aead = _aead(key, suite.is_chacha)
    from cryptography.exceptions import InvalidTag
    try:
        return aead.decrypt(nonce, ciphertext, aad)
    except InvalidTag:  # the "wrong master" signal
        return None


# --------------------------------------------------------------------------- #
# CBC record protection (RFC 5246 sec 6.2.3.2; Encrypt-then-MAC per RFC 7366)
# --------------------------------------------------------------------------- #

# AES-CBC block size, and the explicit per-record IV length (TLS 1.2).
_AES_BLOCK = 16


class _CbcSuite:
    """Crypto parameters for a TLS 1.2 AES-CBC cipher suite.

    ``prf_hash`` is the PRF hash (SHA-384 for the ``*_SHA384`` suites, SHA-256
    otherwise). ``mac_hash`` / ``mac_len`` are the record HMAC. ``key_len`` is
    the AES key length (16 or 32). TLS 1.2 CBC records carry a 16-byte explicit
    IV, so the key block has no write-IV tail — only MAC keys and write keys.
    """

    __slots__ = ("prf_hash", "mac_hash", "mac_len", "key_len")

    def __init__(self, prf_hash, mac_hash, mac_len, key_len):
        self.prf_hash = prf_hash
        self.mac_hash = mac_hash
        self.mac_len = mac_len
        self.key_len = key_len


# AES-CBC suites this module can trial-decrypt. The record protection depends
# only on the AES key length and the MAC hash, so the key exchange (RSA / DHE /
# ECDHE / static DH-ECDH, and the auth, RSA vs ECDSA/DSS) is irrelevant here —
# the master secret is already known. Every AES-CBC suite maps to one of a few
# parameter tuples. 3DES / Camellia / SEED / IDEA / RC4 and the export ciphers
# are intentionally omitted: an unknown CBC suite falls back to tshark (``None``).
#
# PRF hash is SHA-256 for every TLS 1.2 suite except the ``*_SHA384`` ones.
CBC_SUITES: Dict[int, _CbcSuite] = {
    # --- AES-128-CBC, HMAC-SHA1 (RFC 5246 / RFC 4492) ---
    0x002F: _CbcSuite("sha256", "sha1", 20, 16),    # RSA
    0x0032: _CbcSuite("sha256", "sha1", 20, 16),    # DHE_DSS
    0x0033: _CbcSuite("sha256", "sha1", 20, 16),    # DHE_RSA
    0xC004: _CbcSuite("sha256", "sha1", 20, 16),    # ECDH_ECDSA
    0xC009: _CbcSuite("sha256", "sha1", 20, 16),    # ECDHE_ECDSA
    0xC00E: _CbcSuite("sha256", "sha1", 20, 16),    # ECDH_RSA
    0xC013: _CbcSuite("sha256", "sha1", 20, 16),    # ECDHE_RSA
    # --- AES-256-CBC, HMAC-SHA1 ---
    0x0035: _CbcSuite("sha256", "sha1", 20, 32),    # RSA
    0x0038: _CbcSuite("sha256", "sha1", 20, 32),    # DHE_DSS
    0x0039: _CbcSuite("sha256", "sha1", 20, 32),    # DHE_RSA
    0xC005: _CbcSuite("sha256", "sha1", 20, 32),    # ECDH_ECDSA
    0xC00A: _CbcSuite("sha256", "sha1", 20, 32),    # ECDHE_ECDSA
    0xC00F: _CbcSuite("sha256", "sha1", 20, 32),    # ECDH_RSA
    0xC014: _CbcSuite("sha256", "sha1", 20, 32),    # ECDHE_RSA
    # --- AES-128-CBC, HMAC-SHA256 (PRF SHA-256) ---
    0x003C: _CbcSuite("sha256", "sha256", 32, 16),  # RSA
    0x0040: _CbcSuite("sha256", "sha256", 32, 16),  # DHE_DSS
    0x0067: _CbcSuite("sha256", "sha256", 32, 16),  # DHE_RSA
    0xC023: _CbcSuite("sha256", "sha256", 32, 16),  # ECDHE_ECDSA
    0xC025: _CbcSuite("sha256", "sha256", 32, 16),  # ECDH_ECDSA
    0xC027: _CbcSuite("sha256", "sha256", 32, 16),  # ECDHE_RSA
    0xC029: _CbcSuite("sha256", "sha256", 32, 16),  # ECDH_RSA
    # --- AES-256-CBC, HMAC-SHA256 (PRF SHA-256) ---
    0x003D: _CbcSuite("sha256", "sha256", 32, 32),  # RSA
    0x006A: _CbcSuite("sha256", "sha256", 32, 32),  # DHE_DSS
    0x006B: _CbcSuite("sha256", "sha256", 32, 32),  # DHE_RSA
    # --- AES-256-CBC, HMAC-SHA384 (PRF SHA-384) ---
    0xC024: _CbcSuite("sha384", "sha384", 48, 32),  # ECDHE_ECDSA
    0xC026: _CbcSuite("sha384", "sha384", 48, 32),  # ECDH_ECDSA
    0xC028: _CbcSuite("sha384", "sha384", 48, 32),  # ECDHE_RSA
    0xC02A: _CbcSuite("sha384", "sha384", 48, 32),  # ECDH_RSA
}


def cbc_suite_supported(cipher_suite: int) -> bool:
    """True when :mod:`.tls12` can trial-decrypt this AES-CBC cipher suite."""
    return cipher_suite in CBC_SUITES


def cbc_key_block(master: bytes, server_random: bytes, client_random: bytes,
                  suite: _CbcSuite) -> Tuple[bytes, bytes, bytes, bytes]:
    """Derive ``(client_mac, server_mac, client_key, server_key)`` (RFC 5246 sec 6.3).

    The key block is MAC keys then write keys; TLS 1.2 CBC uses a per-record
    explicit IV, so there is no write-IV tail.
    """
    need = 2 * suite.mac_len + 2 * suite.key_len
    block = prf(master, b"key expansion", server_random + client_random,
                need, suite.prf_hash)
    ml, kl = suite.mac_len, suite.key_len
    client_mac = block[0:ml]
    server_mac = block[ml:2 * ml]
    client_key = block[2 * ml:2 * ml + kl]
    server_key = block[2 * ml + kl:2 * ml + 2 * kl]
    return client_mac, server_mac, client_key, server_key


def _aes_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """Raw AES-CBC decryption (no padding removal)."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    return dec.update(ciphertext) + dec.finalize()


def _strip_tls_padding(block: bytes) -> Optional[bytes]:
    """Strip TLS CBC padding, or ``None`` when it is malformed.

    The last byte is ``padding_length``; the final ``padding_length + 1`` bytes
    must all equal it (RFC 5246 sec 6.2.3.2).
    """
    if not block:
        return None
    pad_len = block[-1]
    total = pad_len + 1
    if total > len(block):
        return None
    if any(b != pad_len for b in block[-total:]):
        return None
    return block[:-total]


def _hmac_ok(mac_key: bytes, mac_hash: str, mac_input: bytes,
             expected: bytes) -> bool:
    """Constant-time check that HMAC(mac_key, mac_input) == expected."""
    actual = hmac.new(mac_key, mac_input, mac_hash).digest()
    return hmac.compare_digest(actual, expected)


def _cbc_finished_decrypts(master: bytes, client_random: bytes,
                           server_random: bytes, suite: _CbcSuite, seq: int,
                           content_type: int, version: bytes, fragment: bytes,
                           *, from_client: bool, uses_etm: bool) -> Optional[bool]:
    """Does ``master`` decrypt this first post-CCS CBC record to a Finished?

    The record HMAC is the authoritative signal: a verifying HMAC means the
    master is correct (forging it is infeasible), a failing one means a wrong
    master. So a framing, padding or MAC failure is a definite ``False``; a
    verified record whose plaintext is a Finished is ``True``; and a verified
    record whose plaintext is *not* a recognizable Finished (e.g. the legacy TLS
    record compression in some captures leaves a DEFLATE stream, not ``0x14``)
    is ``None`` — the master is right, but this peel cannot confirm it, so the
    caller defers to tshark rather than wrongly excluding a valid master. A
    crypto-backend error propagates so :func:`finished_decrypts` reports ``None``.
    """
    cm, sm, ck, sk = cbc_key_block(master, server_random, client_random, suite)
    mac_key, key = (cm, ck) if from_client else (sm, sk)
    if len(fragment) < 2 * _AES_BLOCK + (suite.mac_len if uses_etm else 0):
        return False
    iv = fragment[:_AES_BLOCK]
    if uses_etm:
        # record = IV || AES-CBC(content || padding) || MAC; MAC covers IV||ct.
        ciphertext = fragment[_AES_BLOCK:-suite.mac_len]
        mac = fragment[-suite.mac_len:]
        if not ciphertext or len(ciphertext) % _AES_BLOCK:
            return False
        covered = fragment[:_AES_BLOCK + len(ciphertext)]
        mac_input = (seq.to_bytes(8, "big") + bytes([content_type]) + version
                     + len(covered).to_bytes(2, "big") + covered)
        if not _hmac_ok(mac_key, suite.mac_hash, mac_input, mac):
            return False
        content = _strip_tls_padding(_aes_cbc_decrypt(key, iv, ciphertext))
    else:
        # MAC-then-encrypt: AES-CBC over content || MAC || padding; MAC covers content.
        ciphertext = fragment[_AES_BLOCK:]
        if not ciphertext or len(ciphertext) % _AES_BLOCK:
            return False
        plain = _strip_tls_padding(_aes_cbc_decrypt(key, iv, ciphertext))
        if plain is None or len(plain) < suite.mac_len:
            return False
        content, mac = plain[:-suite.mac_len], plain[-suite.mac_len:]
        mac_input = (seq.to_bytes(8, "big") + bytes([content_type]) + version
                     + len(content).to_bytes(2, "big") + content)
        if not _hmac_ok(mac_key, suite.mac_hash, mac_input, mac):
            return False
    # The HMAC verified, so the master is correct. A plain Finished confirms it;
    # anything else (compression, or an unexpected empty body) is "cannot tell".
    if not content:
        return None
    return True if content[0] == FINISHED else None


def finished_decrypts(master: bytes, client_random: bytes, server_random: bytes,
                      cipher_suite: int, content_type: int, version: bytes,
                      fragment: bytes, *, from_client: bool,
                      keys: Optional[Tuple[bytes, bytes, bytes, bytes]] = None,
                      uses_etm: bool = False,
                      ) -> Optional[bool]:
    """Does ``master`` decrypt this first post-CCS record to a Finished?

    This is the TLS 1.2 analogue of tshark's ``tls.handshake.type==20`` success
    check, for both AEAD and AES-CBC suites. ``from_client`` selects the client
    vs server write key/iv. *keys* is an optional precomputed :func:`key_block`
    result for an AEAD (master, randoms, suite), so a caller testing both
    directions derives it once; it is ignored for CBC (which derives its own
    MAC+write key block). ``uses_etm`` selects Encrypt-then-MAC framing (RFC
    7366) for CBC, and is read from the ServerHello by the caller.

    Returns ``False`` for a non-handshake record or a MAC/tag/padding failure
    (a wrong master); ``True`` when the record authenticates and its plaintext is
    a Finished; and ``None`` (cannot tell) for an unsupported suite, a crypto
    backend error, or a record that authenticates but whose plaintext is not a
    recognizable Finished (e.g. legacy TLS record compression). A master that
    authenticates a record is never reported ``False``, so a correct key is never
    wrongly excluded — the caller defers it to tshark instead.
    """
    aead_suite = AEAD_SUITES.get(cipher_suite)
    cbc_suite = None if aead_suite is not None else CBC_SUITES.get(cipher_suite)
    if aead_suite is None and cbc_suite is None:
        return None
    if content_type != CT_HANDSHAKE:
        return False
    try:
        if cbc_suite is not None:
            return _cbc_finished_decrypts(
                master, client_random, server_random, cbc_suite, 0,
                content_type, version, fragment,
                from_client=from_client, uses_etm=uses_etm)
        if keys is None:
            keys = key_block(master, server_random, client_random, aead_suite)
        ck, sk, civ, siv = keys
        key, fixed_iv = (ck, civ) if from_client else (sk, siv)
        pt = decrypt_record(key, fixed_iv, aead_suite, 0, content_type, version, fragment)
    except Exception:  # noqa: BLE001 - a backend error is "cannot tell", never "no"
        return None
    if pt is None:
        return False                      # tag failed → wrong master
    # Authenticated: a Finished confirms the master; anything else (e.g. legacy
    # record compression) is "cannot tell", so the master is never excluded.
    return True if pt[0] == FINISHED else None


__all__ = [
    "FINISHED",
    "CHANGE_CIPHER_SPEC",
    "HANDSHAKE",
    "AEAD_SUITES",
    "CBC_SUITES",
    "suite_supported",
    "cbc_suite_supported",
    "prf",
    "key_block",
    "cbc_key_block",
    "decrypt_record",
    "finished_decrypts",
]
