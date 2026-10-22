"""RC4 core + TLS 1.3 AEAD peeler for the offline RC4 decryptor.

Two independent crypto layers live here, both ports of the research tools:

  * The **RC4 stream cipher** (KSA + PRGA) — a byte-for-byte port of
    ``research/memory_scan_lsass/tools/rc4_trial_decrypt.py`` (which is itself the
    offline analogue of ``agent/rc4_decrypt.js``). RC4 is symmetric, so the same
    routine encrypts and decrypts. The shared known-answer test
    ``RC4("Key","Plaintext") == bbf316e8d940af0ad3`` is asserted at import so a
    broken RC4 fails loudly rather than mis-decrypting silently. This layer is
    PURE PYTHON and needs no third-party dependency — standalone RC4-over-TCP
    works on a ``--no-deps`` install.

  * The **TLS 1.3 AEAD peeler** — now lives in the protocol-neutral
    :mod:`friTap.offline.tls` package and is RE-EXPORTED here so every existing
    ``friTap.offline.rc4.crypto`` import keeps working. Used for the pure-Python
    nested RC4-in-TLS path (and its tests) when a raw TLS traffic secret is
    supplied instead of driving tshark. It imports the optional ``cryptography``
    backend **lazily**, so importing this module never requires it;
    :func:`backend_available` probes for it.
"""

from __future__ import annotations

from typing import List

# Re-exports: the TLS 1.3 record layer moved to friTap.offline.tls (shims only).
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


# --------------------------------------------------------------------------- #
# RC4 core (same KSA/PRGA as agent/rc4_decrypt.js and rc4_trial_decrypt.py).
# --------------------------------------------------------------------------- #

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
    """PRGA over a COPY of the S-box (so a scanned box is not mutated), from i=j=0."""
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


# Known-answer test, shared with agent/rc4_decrypt.js (selfTest), the research
# tool, and tls13_rc4_target.ps1 ($katExp). Running it at import makes a broken
# RC4 fail loudly rather than mis-decrypt silently.
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
