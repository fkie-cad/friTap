"""Mid-stream TLS 1.3 record decryption from a raw traffic secret.

Unlike :mod:`friTap.offline.rc4.crypto` (whose ``confirm_secret`` /
``decrypt_stream`` assume the capture began at the handshake, so the first
application_data record carries record sequence number 0), this module targets a
capture that started **mid-flow**: the ClientHello/ServerHello were never seen,
the negotiated cipher suite is unknown, and the record sequence number of the
first captured application_data record is some unknown ``S > 0``.

The recovery relies on the AEAD authentication tag as a zero-false-accept
oracle. TLS 1.3 uses ``nonce = static_iv XOR seq`` (RFC 8446 sec 5.3), so a
wrong ``seq`` produces a wrong nonce and the 16-byte GCM/Poly1305 tag fails to
verify with overwhelming probability (~2^-128 per trial). We therefore brute
force the small unknown starting ``seq`` (and, when unknown, the three TLS 1.3
suites) against the first application_data record and accept only a decryption
whose inner content-type is a legal TLS 1.3 value.

All cryptographic primitives are IMPORTED READ-ONLY from
:mod:`friTap.offline.rc4.crypto`; nothing here mutates or re-implements them.
"""

from __future__ import annotations

from typing import List, Optional, Tuple

from ..rc4.crypto import (
    SUITES,
    inner_content_type,
    try_decrypt,
)

# Record content_type for application_data (RFC 8446 sec 5.1). Every post-
# handshake TLS 1.3 record on the wire is wrapped as application_data; the
# *inner* content-type (recovered after decryption) reveals the real type.
APPLICATION_DATA = 0x17

# Minimum encrypted fragment length: >= 1 inner byte + the 16-byte AEAD tag.
MIN_AEAD_FRAGMENT_LEN = 17

# Legal inner content-types for a genuine decryption: handshake (0x16, e.g. a
# post-handshake NewSessionTicket / KeyUpdate), application_data (0x17), alert
# (0x15). Anything else means the tag matched by chance (never observed) or the
# record is not what we think it is.
_VALID_INNER_TYPES = (0x16, 0x17, 0x15)

# Default upper bound for the unknown starting sequence number search. A capture
# that began shortly after the handshake has a small S; 64 covers realistic
# mid-stream starts while keeping the brute force trivial.
DEFAULT_MAX_SEQ = 64


def _app_data_records(
    records: List[Tuple[int, bytes, bytes]]
) -> List[Tuple[int, bytes, bytes]]:
    """Filter a parsed record list down to decryptable application_data records."""
    return [
        rec for rec in records
        if rec[0] == APPLICATION_DATA and len(rec[2]) >= MIN_AEAD_FRAGMENT_LEN
    ]


def recover_seq(
    secret_hex: str,
    suite: str,
    records: List[Tuple[int, bytes, bytes]],
    max_seq: int = DEFAULT_MAX_SEQ,
) -> Optional[int]:
    """Recover the unknown starting record sequence number, or ``None``.

    Brute forces ``seq`` in ``0..max_seq`` against the first application_data
    record (the AEAD tag makes wrong guesses fail), returning the ``seq`` at
    which it first decrypts to a legal inner content-type. Early-exits on the
    first success.
    """
    secret = bytes.fromhex(secret_hex)
    for _ctype, hdr, frag in _app_data_records(records):
        for seq in range(max_seq + 1):
            plaintext = try_decrypt(secret, suite, seq, hdr, frag)
            if plaintext is not None and inner_content_type(plaintext) in _VALID_INNER_TYPES:
                return seq
        # The first application_data record did not decrypt for any seq in range:
        # a correct secret/suite would have matched it, so this secret is wrong.
        return None
    return None


def decrypt_stream_from(
    secret_hex: str,
    suite: str,
    records: List[Tuple[int, bytes, bytes]],
    start_seq: int,
) -> List[bytes]:
    """Decrypt consecutive application_data records starting at ``start_seq``.

    Mirrors :func:`friTap.offline.rc4.crypto.decrypt_stream` but seeds the
    sequence counter with the recovered mid-stream ``start_seq`` instead of
    anchoring on seq 0. The counter advances by one per application_data record
    (each such record consumes one record sequence number on this direction's
    traffic keys). Successful inner plaintexts are appended in order.
    """
    secret = bytes.fromhex(secret_hex)
    out: List[bytes] = []
    seq = start_seq
    for _ctype, hdr, frag in _app_data_records(records):
        plaintext = try_decrypt(secret, suite, seq, hdr, frag)
        seq += 1
        if plaintext is not None:
            out.append(plaintext)
    return out


def pick_suite(
    secret_hex: str,
    records: List[Tuple[int, bytes, bytes]],
    suites: Optional[List[str]] = None,
) -> Optional[Tuple[str, int]]:
    """Brute force the cipher suite AND starting seq when the suite is unknown.

    With no ServerHello in a mid-stream capture the negotiated suite is unknown,
    so this tries each candidate suite (the AEAD tag disambiguates) and returns
    ``(suite, start_seq)`` for the first that recovers a sequence number, else
    ``None``.
    """
    for suite in (suites if suites is not None else list(SUITES)):
        seq = recover_seq(secret_hex, suite, records)
        if seq is not None:
            return suite, seq
    return None
