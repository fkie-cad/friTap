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

  * The **TLS 1.3 AEAD peeler** — a port of
    ``research/memory_scan_lsass/tools/tls13_trial_decrypt.py`` (RFC 8446
    HKDF-Expand-Label key schedule, nonce = iv XOR seq, AAD = record header).
    Used for the pure-Python nested RC4-in-TLS path (and its tests) when a raw
    TLS traffic secret is supplied instead of driving tshark. It imports the
    optional ``cryptography`` backend **lazily**, so importing this module never
    requires it; :func:`backend_available` probes for it.
"""

from __future__ import annotations

import struct
from typing import Callable, Dict, List, Optional, Tuple

# TLS 1.3 inner plaintext = content || content_type || zeros (RFC 8446 sec 5.2).
INNER_APPLICATION_DATA = 0x17


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


# --------------------------------------------------------------------------- #
# TLS 1.3 cipher suites (lazy cryptography backend)
# --------------------------------------------------------------------------- #

def backend_available() -> bool:
    """Return True if the optional ``cryptography`` AEAD backend is importable."""
    try:
        import cryptography.hazmat.primitives.ciphers.aead  # noqa: F401
        import cryptography.hazmat.primitives.kdf.hkdf  # noqa: F401

        return True
    except Exception:  # noqa: BLE001 - any import failure means "unavailable"
        return False


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


def _hash_alg(name: str):
    from cryptography.hazmat.primitives import hashes

    return {"sha256": hashes.SHA256, "sha384": hashes.SHA384}[name]()


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
    """RFC 8446 sec 5.3: nonce = iv XOR seq (seq right-aligned, big-endian)."""
    seqb = seq.to_bytes(len(iv), "big")
    return bytes(a ^ b for a, b in zip(iv, seqb))


def try_decrypt(secret: bytes, suite: str, seq: int,
                aad: bytes, ciphertext: bytes) -> Optional[bytes]:
    """Return inner plaintext (incl. content-type + padding) or None on tag failure."""
    _, _, aead_factory = SUITES[suite]
    key, iv = derive_key_iv(secret, suite)
    aead = aead_factory(key)
    try:
        return aead.decrypt(record_nonce(iv, seq), ciphertext, aad)
    except Exception:  # noqa: BLE001 - a tag failure is the expected "wrong key" signal
        return None


def inner_content_type(plaintext: bytes) -> Optional[int]:
    """TLS 1.3 inner plaintext = content || type || zeros; strip trailing zeros."""
    i = len(plaintext) - 1
    while i >= 0 and plaintext[i] == 0:
        i -= 1
    return plaintext[i] if i >= 0 else None


# --------------------------------------------------------------------------- #
# pcap -> per-stream TLS records (pure parsing; unit-testable via parse_records)
# --------------------------------------------------------------------------- #

def parse_records(stream: bytes) -> List[Tuple[int, bytes, bytes]]:
    """Split a reassembled TLS byte stream into (content_type, header5, fragment)."""
    out, i, n = [], 0, len(stream)
    while i + 5 <= n:
        ctype = stream[i]
        length = int.from_bytes(stream[i + 3:i + 5], "big")
        if i + 5 + length > n:
            break
        out.append((ctype, stream[i:i + 5], stream[i + 5:i + 5 + length]))
        i += 5 + length
    return out


def client_random_from_clienthello(frag: bytes) -> Optional[str]:
    """ClientHello handshake fragment -> 32-byte random (hex), or None."""
    if len(frag) >= 38 and frag[0] == 0x01:
        return frag[6:38].hex()
    return None


def cipher_suite_from_serverhello(frag: bytes) -> Optional[int]:
    """ServerHello handshake fragment -> negotiated cipher_suite id, or None."""
    if len(frag) < 39 or frag[0] != 0x02:
        return None
    off = 6 + 32               # ht+len+ver + random
    if off >= len(frag):
        return None
    sid_len = frag[off]; off += 1 + sid_len
    if off + 2 > len(frag):
        return None
    return int.from_bytes(frag[off:off + 2], "big")


def confirm_secret(secret_hex: str, records: List[Tuple[int, bytes, bytes]],
                   suites: List[str], max_seq: int = 4):
    """Try ``secret`` against the application_data records in one direction.

    Returns (suite, seq, plaintext, ctype) for the first record that decrypts,
    else None.
    """
    secret = bytes.fromhex(secret_hex)
    for ctype, hdr, frag in records:
        if ctype != 0x17 or len(frag) < 17:  # need >= 1 byte + 16-byte tag
            continue
        for suite in suites:
            for seq in range(max_seq + 1):
                pt = try_decrypt(secret, suite, seq, hdr, frag)
                if pt is not None:
                    ct = inner_content_type(pt)
                    if ct in (0x16, 0x17, 0x15):  # handshake / app / alert
                        return suite, seq, pt, ct
    return None


def decrypt_stream(secret_hex: str, records, suite: str) -> List[bytes]:
    """Decrypt consecutive app-data records once the seq-0 anchor is found."""
    secret = bytes.fromhex(secret_hex)
    out, seq, started = [], 0, False
    for ctype, hdr, frag in records:
        if ctype != 0x17 or len(frag) < 17:
            continue
        if not started:
            pt = try_decrypt(secret, suite, 0, hdr, frag)
            if pt is None:
                continue           # still in handshake records
            started, seq = True, 1
            out.append(pt)
        else:
            pt = try_decrypt(secret, suite, seq, hdr, frag)
            seq += 1
            if pt is not None:
                out.append(pt)
    return out


def secrets_from_keylog(text: str) -> List[str]:
    """Extract candidate traffic secrets from any NSS-style keylog text."""
    out = []
    for line in text.splitlines():
        p = line.split()
        if len(p) == 3 and not line.startswith("#") and len(p[2]) in (64, 96):
            out.append(p[2].lower())
    return out
