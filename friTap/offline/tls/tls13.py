"""TLS 1.3 cipher suites, key schedule and record protection (RFC 8446).

A port of ``research/memory_scan_lsass/tools/tls13_trial_decrypt.py``:
HKDF-Expand-Label key schedule, nonce = iv XOR seq, AAD = record header. It
imports the optional ``cryptography`` backend **lazily**, so importing this
module never requires it (see :func:`friTap.offline.tls.backend.backend_available`).
"""

from __future__ import annotations

import struct
from functools import lru_cache
from typing import Callable, Dict, Optional, Tuple

# Display label of the protocol version, spelled exactly like the label a
# handshake-anchored flow's TLS layer carries (``friTap.offline.tshark``
# ``TLS_VERSION_NAMES["0x0304"]``), so a flow recovered without a handshake
# reads the same. The suite names in :data:`SUITES` likewise match that
# module's cipher-suite display names.
VERSION_LABEL = "TLS 1.3"


# --------------------------------------------------------------------------- #
# TLS 1.3 cipher suites (lazy cryptography backend)
# --------------------------------------------------------------------------- #

def _aesgcm(key: bytes):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    return AESGCM(key)


def _chacha20(key: bytes):
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

    return ChaCha20Poly1305(key)


# name -> (hash_name, key_len, aead_factory). All TLS 1.3 suites use a 12-byte iv.
# The hash is a NAME (resolved lazily) so importing this module never imports
# ``cryptography``; the factory turns a key into an AEAD object on demand.
SUITES: Dict[str, Tuple[str, int, Callable[[bytes], object]]] = {
    "TLS_AES_128_GCM_SHA256":       ("sha256", 16, _aesgcm),
    "TLS_AES_256_GCM_SHA384":       ("sha384", 32, _aesgcm),
    "TLS_CHACHA20_POLY1305_SHA256": ("sha256", 32, _chacha20),
}
SUITE_BY_ID = {
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
}


# Digest size in bytes per hash name; also the TLS 1.3 traffic-secret length.
_HASH_LEN = {"sha256": 32, "sha384": 48}


def _hash_alg(name: str):
    from cryptography.hazmat.primitives import hashes

    return {"sha256": hashes.SHA256, "sha384": hashes.SHA384}[name]()


# Record content_type for application_data (RFC 8446 sec 5.1). Every post-
# handshake TLS 1.3 record on the wire is wrapped as application_data; the
# *inner* content-type (recovered after decryption) reveals the real type.
APPLICATION_DATA = 0x17


# --------------------------------------------------------------------------- #
# Key schedule (RFC 8446 sec 7.1) — HKDF-Expand-Label
# --------------------------------------------------------------------------- #

def hkdf_expand_label(secret: bytes, label: bytes, context: bytes,
                      length: int, hashalg) -> bytes:
    """RFC 8446 HKDF-Expand-Label. ``label`` is the bare label, e.g. ``b"key"``."""
    from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

    full = b"tls13 " + label
    # struct: uint16 length; opaque label<7..255>; opaque context<0..255>
    hkdf_label = struct.pack(">H", length) + bytes([len(full)]) + full \
        + bytes([len(context)]) + context
    return HKDFExpand(algorithm=hashalg, length=length, info=hkdf_label).derive(secret)


def derive_key_iv(secret: bytes, suite: str) -> Tuple[bytes, bytes]:
    """Per RFC 8446 sec 7.3: write_key = HKDF-Expand-Label(S,"key",...) etc."""
    hash_name, key_len, _ = SUITES[suite]
    hashalg = _hash_alg(hash_name)
    key = hkdf_expand_label(secret, b"key", b"", key_len, hashalg)
    iv = hkdf_expand_label(secret, b"iv", b"", 12, hashalg)
    return key, iv


def record_nonce(iv: bytes, seq: int) -> bytes:
    """RFC 8446 sec 5.3: nonce = iv XOR seq (seq right-aligned, big-endian).

    Uses a single big-integer XOR rather than a per-byte Python loop: this is on
    the mid-stream sequence-recovery hot path (millions of calls), and the two
    forms are identical for any ``seq`` that fits in ``len(iv)`` bytes (both raise
    ``OverflowError`` otherwise)."""
    return _xor_nonce(int.from_bytes(iv, "big"), seq, len(iv))


def _xor_nonce(iv_int: int, seq: int, iv_len: int) -> bytes:
    """:func:`record_nonce` with the static iv already converted to an int."""
    return (iv_int ^ seq).to_bytes(iv_len, "big")


def suites_for_secret(secret: bytes):
    """The TLS 1.3 suite names whose hash length matches ``len(secret)``.

    A traffic secret is ``Hash.length`` bytes (RFC 8446 sec 7.1): 48 for the
    SHA-384 suite, 32 for the SHA-256 suites. A suite with another hash derives a
    key that can never authenticate the record, so trying it is wasted work. A
    secret of any other length matches no suite and keeps all of them.
    """
    matching = [name for name, (hash_name, _, _) in SUITES.items()
                if _HASH_LEN[hash_name] == len(secret)]
    return matching or list(SUITES)


@lru_cache(maxsize=128)
def _prepared_cipher(secret: bytes, suite: str) -> Tuple[object, bytes, int]:
    """Return the ``(AEAD object, static iv, iv as int)`` for a ``(secret, suite)``.

    The TLS 1.3 record key + iv are a pure function of the traffic secret and the
    suite (RFC 8446 sec 7.3), and the AEAD object is stateless (the per-record
    nonce is supplied to each ``decrypt`` call), so both are INVARIANT across the
    record sequence number. Deriving them once and memoizing keeps the mid-stream
    starting-sequence brute force
    (:func:`friTap.offline.tls.stream.recover_seq`, up to 100k trials
    per wrong secret/suite) from re-running HKDF and rebuilding the cipher on
    every trial -- previously the dominant cost of the whole mid-stream stage.
    Bounded cache: a run touches only a handful of distinct (secret, suite) pairs.
    The iv is also cached as an int so each trial's nonce is a single XOR.
    """
    _, _, aead_factory = SUITES[suite]
    key, iv = derive_key_iv(secret, suite)
    return aead_factory(key), iv, int.from_bytes(iv, "big")


def try_decrypt(secret: bytes, suite: str, seq: int,
                aad: bytes, ciphertext: bytes) -> Optional[bytes]:
    """Return inner plaintext (incl. content-type + padding) or None on tag failure."""
    aead, iv, iv_int = _prepared_cipher(secret, suite)
    try:
        return aead.decrypt(_xor_nonce(iv_int, seq, len(iv)), ciphertext, aad)
    except Exception:  # noqa: BLE001 - a tag failure is the expected "wrong key" signal
        return None


def inner_content_type(plaintext: bytes) -> Optional[int]:
    """TLS 1.3 inner plaintext = content || type || zeros; strip trailing zeros."""
    i = len(plaintext) - 1
    while i >= 0 and plaintext[i] == 0:
        i -= 1
    return plaintext[i] if i >= 0 else None


def inner_app_content(plaintext: bytes) -> Optional[bytes]:
    """Application_data content of one TLS 1.3 inner plaintext, or ``None``.

    The inner plaintext is ``content || content_type || zeros`` (RFC 8446 sec
    5.2). Returns the bytes before the content-type byte (possibly empty) when
    that type is application_data (0x17), else ``None`` (handshake/alert records,
    or an all-zero plaintext with no type byte).
    """
    stripped = plaintext.rstrip(b"\x00")
    if not stripped or stripped[-1] != APPLICATION_DATA:
        return None
    return stripped[:-1]


def next_traffic_secret(secret: bytes, suite: str) -> bytes:
    """RFC 8446 sec 7.2: the traffic secret after a KeyUpdate.

    ``application_traffic_secret_N+1 = HKDF-Expand-Label(secret_N, "traffic upd",
    "", Hash.length)``.
    """
    hash_name = SUITES[suite][0]
    return hkdf_expand_label(secret, b"traffic upd", b"", _HASH_LEN[hash_name],
                             _hash_alg(hash_name))
