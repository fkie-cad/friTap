"""TLS 1.3 cipher suites, key schedule and record protection (RFC 8446).

HKDF-Expand-Label key schedule, nonce = iv XOR seq, AAD = record header. The
optional ``cryptography`` backend is imported lazily (see
:func:`friTap.offline.tls.backend.backend_available`).
"""

from __future__ import annotations

import struct
from functools import lru_cache
from typing import Callable, Dict, Optional, Tuple

# Must match ``friTap.offline.tshark.TLS_VERSION_NAMES["0x0304"]``; the suite
# names in :data:`SUITES` likewise match that module's cipher-suite names.
VERSION_LABEL = "TLS 1.3"


def _aesgcm(key: bytes):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    return AESGCM(key)


def _chacha20(key: bytes):
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

    return ChaCha20Poly1305(key)


# name -> (hash_name, key_len, aead_factory). All suites use a 12-byte iv.
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


# Outer content_type of every protected record (RFC 8446 sec 5.1).
APPLICATION_DATA = 0x17


def hkdf_expand_label(secret: bytes, label: bytes, context: bytes,
                      length: int, hashalg) -> bytes:
    """RFC 8446 HKDF-Expand-Label; *label* is the bare label, e.g. ``b"key"``."""
    from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

    full = b"tls13 " + label
    # struct: uint16 length; opaque label<7..255>; opaque context<0..255>
    hkdf_label = struct.pack(">H", length) + bytes([len(full)]) + full \
        + bytes([len(context)]) + context
    return HKDFExpand(algorithm=hashalg, length=length, info=hkdf_label).derive(secret)


def derive_key_iv(secret: bytes, suite: str) -> Tuple[bytes, bytes]:
    """``(write_key, iv)`` per RFC 8446 sec 7.3."""
    hash_name, key_len, _ = SUITES[suite]
    hashalg = _hash_alg(hash_name)
    key = hkdf_expand_label(secret, b"key", b"", key_len, hashalg)
    iv = hkdf_expand_label(secret, b"iv", b"", 12, hashalg)
    return key, iv


def record_nonce(iv: bytes, seq: int) -> bytes:
    """RFC 8446 sec 5.3: nonce = iv XOR seq (big-endian, right-aligned).

    One big-integer XOR: this is the seq-recovery hot path. Raises
    ``OverflowError`` if *seq* does not fit in ``len(iv)`` bytes."""
    return _xor_nonce(int.from_bytes(iv, "big"), seq, len(iv))


def _xor_nonce(iv_int: int, seq: int, iv_len: int) -> bytes:
    """:func:`record_nonce` with the static iv already converted to an int."""
    return (iv_int ^ seq).to_bytes(iv_len, "big")


def suites_for_secret(secret: bytes):
    """Suite names whose hash length equals ``len(secret)`` (RFC 8446 sec 7.1).

    Other suites can never authenticate; a secret of any other length keeps all suites.
    """
    matching = [name for name, (hash_name, _, _) in SUITES.items()
                if _HASH_LEN[hash_name] == len(secret)]
    return matching or list(SUITES)


@lru_cache(maxsize=128)
def _prepared_cipher(secret: bytes, suite: str) -> Tuple[object, bytes, int]:
    """``(AEAD object, static iv, iv as int)`` for a ``(secret, suite)``.

    Key and iv depend only on secret and suite and the AEAD is stateless, so
    memoizing keeps the seq brute force (up to 100k trials per wrong secret) from
    re-running HKDF per trial, the dominant mid-stream cost. The iv is cached as
    an int so each nonce is one XOR.
    """
    _, _, aead_factory = SUITES[suite]
    key, iv = derive_key_iv(secret, suite)
    return aead_factory(key), iv, int.from_bytes(iv, "big")


def try_decrypt(secret: bytes, suite: str, seq: int,
                aad: bytes, ciphertext: bytes) -> Optional[bytes]:
    """Inner plaintext (with content-type and padding), or None on tag failure."""
    aead, iv, iv_int = _prepared_cipher(secret, suite)
    try:
        return aead.decrypt(_xor_nonce(iv_int, seq, len(iv)), ciphertext, aad)
    except Exception:  # noqa: BLE001 - a tag failure is the expected "wrong key" signal
        return None


def inner_content_type(plaintext: bytes) -> Optional[int]:
    """Content-type byte of ``content || type || zeros``, or None if all zero."""
    i = len(plaintext) - 1
    while i >= 0 and plaintext[i] == 0:
        i -= 1
    return plaintext[i] if i >= 0 else None


def inner_app_content(plaintext: bytes) -> Optional[bytes]:
    """Content of an application_data inner plaintext (RFC 8446 sec 5.2), else ``None``."""
    stripped = plaintext.rstrip(b"\x00")
    if not stripped or stripped[-1] != APPLICATION_DATA:
        return None
    return stripped[:-1]


def next_traffic_secret(secret: bytes, suite: str) -> bytes:
    """Traffic secret after a KeyUpdate: HKDF-Expand-Label(secret, "traffic upd") (RFC 8446 sec 7.2)."""
    hash_name = SUITES[suite][0]
    return hkdf_expand_label(secret, b"traffic upd", b"", _HASH_LEN[hash_name],
                             _hash_alg(hash_name))
