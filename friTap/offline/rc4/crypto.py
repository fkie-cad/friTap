"""RC4 core (KSA + PRGA) plus re-exports of the TLS 1.3 AEAD peeler.

The RC4 cipher is a port of ``research/memory_scan_lsass/tools/rc4_trial_decrypt.py``
(offline analogue of ``agent/rc4_decrypt.js``). It is pure Python, so standalone
RC4 works without third-party packages. The known-answer test
``RC4("Key","Plaintext") == bbf316e8d940af0ad3`` runs at import.

The TLS 1.3 peeler lives in :mod:`friTap.offline.tls`; its names are re-exported
here because tests use them through this module. The optional ``cryptography``
backend is imported lazily; :func:`backend_available` probes for it.
"""

from __future__ import annotations

from typing import List

# Re-exports of the TLS 1.3 record layer.
from ..tls.backend import backend_available  # noqa: F401
from ..tls.keylog import parse_strict_nss_line
from ..tls.records import (  # noqa: F401
    client_random_from_clienthello,
    parse_records,
)
from ..tls.stream import APPLICATION_DATA, decrypt_stream  # noqa: F401
from ..tls.tls13 import (  # noqa: F401
    SUITE_BY_ID,
    SUITES,
    _aesgcm,
    _chacha20,
    _hash_alg,
    _prepared_cipher,
    derive_key_iv,
    hkdf_expand_label,
    inner_content_type,
    record_nonce,
    try_decrypt,
)

# TLS 1.3 inner plaintext = content || content_type || zeros (RFC 8446 sec 5.2).
INNER_APPLICATION_DATA = APPLICATION_DATA


def rc4_ksa(key: bytes) -> List[int]:
    """Key-scheduling: build the 256-byte S-box permutation from the key."""
    if not key:
        raise ValueError("RC4 key must be non-empty")
    s = list(range(256))
    j = 0
    klen = len(key)
    for i in range(256):
        j = (j + s[i] + key[i % klen]) & 0xFF
        s[i], s[j] = s[j], s[i]
    return s


def rc4_prga(sbox: List[int], data: bytes) -> bytes:
    """PRGA from i=j=0 over a copy of the S-box, so a scanned box is not mutated."""
    s = sbox[:]
    out = bytearray(len(data))
    i = j = 0
    for n, b in enumerate(data):
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        out[n] = b ^ s[(s[i] + s[j]) & 0xFF]
    return bytes(out)


def rc4(key: bytes, data: bytes) -> bytes:
    """RC4 keystream XOR (symmetric: the same call encrypts and decrypts)."""
    return rc4_prga(rc4_ksa(key), data)


# Known-answer test shared with agent/rc4_decrypt.js (selfTest) and tls13_rc4_target.ps1.
_KAT_KEY, _KAT_PT, _KAT_CT = b"Key", b"Plaintext", bytes.fromhex("bbf316e8d940af0ad3")
if rc4(_KAT_KEY, _KAT_PT) != _KAT_CT:  # pragma: no cover - a build-time invariant
    raise RuntimeError("RC4 known-answer test failed; the implementation is broken")


def secrets_from_keylog(text: str) -> List[str]:
    """Extract candidate traffic secrets from any NSS-style keylog text."""
    out = []
    for line in text.splitlines():
        entry = parse_strict_nss_line(line, allow_unknown_client_random=True)
        if entry is not None:
            out.append(entry.secret)
    return out
