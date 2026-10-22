"""Decrypt one direction's TLS 1.3 application_data records from a traffic secret.

Two entry points, sharing the :mod:`.tls13` primitives:

  * **Handshake-anchored** (:func:`decrypt_stream`):
    the capture began at the handshake, so the first application_data record
    carries record sequence number 0.

  * **Mid-stream** (:func:`recover_seq`, :func:`decrypt_stream_from`,
    :func:`pick_suite`): the capture started **mid-flow** — the
    ClientHello/ServerHello were never seen, the negotiated cipher suite is
    unknown, and the record sequence number of the first captured
    application_data record is some unknown ``S > 0``.

The mid-stream recovery relies on the AEAD authentication tag as a
zero-false-accept oracle. TLS 1.3 uses ``nonce = static_iv XOR seq`` (RFC 8446
sec 5.3), so a wrong ``seq`` produces a wrong nonce and the 16-byte
GCM/Poly1305 tag fails to verify with overwhelming probability (~2^-128 per
trial). We therefore brute force the small unknown starting ``seq`` (and, when
unknown, the three TLS 1.3 suites) against the first application_data record and
accept only a decryption whose inner content-type is a legal TLS 1.3 value.
"""

from __future__ import annotations

from itertools import islice
from typing import Iterator, List, NamedTuple, Optional, Tuple

from .tls13 import (  # noqa: F401 - APPLICATION_DATA is re-exported
    APPLICATION_DATA,
    SUITES,
    inner_content_type,
    suites_for_secret,
    try_decrypt,
)

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
# The starting record sequence is unknown in a mid-stream capture: it equals the
# number of application_data records the connection already sent before capture
# began. A freshly-established connection sits near 0, but a connection that has
# been alive for a while (the common attach-to-running-Signal case) can be far
# higher, so the search must reach well past a handful. The AEAD tag is a
# zero-false-accept oracle (a wrong seq never authenticates), so raising this only
# widens what binds; the only cost is up to max_seq AEAD tag checks on the FIRST
# record per wrong (secret, suite, direction) trial — microseconds each. Override
# per call for pathological captures with very many bundles×streams.
# The mid-stream stage searches ``0..max_seq`` window by window (see
# :data:`SEQ_LADDER`), so a wrong stream usually costs only the first rung.
DEFAULT_MAX_SEQ = 100000

# How many leading application_data records a mid-stream binding may try. The
# first captured record can legitimately fail (corrupt/partial, or still under a
# previous key), so binding falls back to the next few. Each extra record costs
# one more ``max_seq`` sweep for a WRONG secret, but no extra key derivation
# (the AEAD is memoized per (secret, suite)), so the bound stays small.
DEFAULT_BIND_RECORDS = 4

# Rungs of the iterative-deepening seq search (see :func:`seq_windows`). Most
# mid-stream captures start within a few dozen records of the handshake, so the
# first rung binds the right stream after a handful of AEAD trials while a WRONG
# stream costs only ``rung + 1`` trials per record instead of ``max_seq + 1``.
SEQ_LADDER = (64, 4096)


class SeqBinding(NamedTuple):
    """Where a mid-stream secret bound: the suite, the application_data record
    index (into the direction's app-data records) and that record's seq."""

    suite: str
    record_index: int
    seq: int


def decrypt_stream(secret_hex: str, records, suite: str) -> List[bytes]:
    """Decrypt consecutive app-data records once the seq-0 anchor is found."""
    secret = bytes.fromhex(secret_hex)
    out, seq, started = [], 0, False
    for _ctype, hdr, frag in iter_app_data_records(records):
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


def iter_app_data_records(
    records: List[Tuple[int, bytes, bytes]]
) -> Iterator[Tuple[int, bytes, bytes]]:
    """Lazily yield the decryptable application_data records of a record list."""
    return (
        rec for rec in records
        if rec[0] == APPLICATION_DATA and len(rec[2]) >= MIN_AEAD_FRAGMENT_LEN
    )


def app_data_records(
    records: List[Tuple[int, bytes, bytes]]
) -> List[Tuple[int, bytes, bytes]]:
    """Filter a parsed record list down to decryptable application_data records."""
    return list(iter_app_data_records(records))


def seq_windows(max_seq: int) -> Iterator[Tuple[int, int]]:
    """Split ``0..max_seq`` into disjoint inclusive ``(lo, hi)`` seq windows.

    Windows follow :data:`SEQ_LADDER` in increasing order, e.g. ``(0, 64)``,
    ``(65, 4096)``, ``(4097, max_seq)``, clipped to ``max_seq``: a ``max_seq`` at
    or below the first rung yields the single window ``(0, max_seq)``. Searching
    the windows in order visits every seq exactly once, smallest first.
    """
    low = 0
    for rung in SEQ_LADDER:
        if rung >= max_seq:
            break
        yield low, rung
        low = rung + 1
    yield low, max_seq


def _record_seq(secret: bytes, suite: str, hdr: bytes, frag: bytes,
                max_seq: int, min_seq: int = 0) -> Optional[int]:
    """The ``seq`` in ``min_seq..max_seq`` at which one record authenticates, or ``None``."""
    for seq in range(min_seq, max_seq + 1):
        plaintext = try_decrypt(secret, suite, seq, hdr, frag)
        if plaintext is not None and inner_content_type(plaintext) in _VALID_INNER_TYPES:
            return seq
    return None


def recover_binding(
    secret_hex: str,
    suite: str,
    records: List[Tuple[int, bytes, bytes]],
    max_seq: int = DEFAULT_MAX_SEQ,
    max_records: int = DEFAULT_BIND_RECORDS,
    first_record: int = 0,
    min_seq: int = 0,
) -> Optional[Tuple[int, int]]:
    """Find ``(record_index, seq)`` of the first of the leading records that binds.

    Brute forces ``seq`` in ``0..max_seq`` against each of the first
    ``max_records`` application_data records in turn (the AEAD tag makes wrong
    guesses fail) and returns the first record that decrypts to a legal inner
    content-type, with its index among the app-data records. A record that fails
    (corrupt, partial, or under another key) is skipped rather than condemning
    the whole direction. ``first_record`` skips the leading app-data records a
    caller already tried; the returned index still counts from the first one.
    ``min_seq`` > 0 restricts the search to ``min_seq..max_seq`` (one window of
    an iterative-deepening search whose lower seqs were already tried).
    """
    secret = bytes.fromhex(secret_hex)
    window = islice(iter_app_data_records(records), first_record, max_records)
    for index, (_ctype, hdr, frag) in enumerate(window, start=first_record):
        seq = _record_seq(secret, suite, hdr, frag, max_seq, min_seq)
        if seq is not None:
            return index, seq
    return None


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
    first success. Stays first-record-only because the returned ``seq`` seeds
    record 0 in :func:`decrypt_stream_from`; use :func:`recover_binding` to
    tolerate a failing first record.
    """
    found = recover_binding(secret_hex, suite, records, max_seq, max_records=1)
    return None if found is None else found[1]


def decrypt_stream_from(
    secret_hex: str,
    suite: str,
    records: List[Tuple[int, bytes, bytes]],
    start_seq: int,
    start_index: int = 0,
) -> List[bytes]:
    """Decrypt consecutive application_data records starting at ``start_seq``.

    Mirrors :func:`decrypt_stream` but seeds the
    sequence counter with the recovered mid-stream ``start_seq`` instead of
    anchoring on seq 0. The counter advances by one per application_data record
    (each such record consumes one record sequence number on this direction's
    traffic keys). Successful inner plaintexts are appended in order.
    ``start_index`` skips that many leading application_data records (those
    before a :class:`SeqBinding` point), so ``start_seq`` applies to the record
    at that index.
    """
    secret = bytes.fromhex(secret_hex)
    out: List[bytes] = []
    seq = start_seq
    for _ctype, hdr, frag in islice(iter_app_data_records(records), start_index, None):
        plaintext = try_decrypt(secret, suite, seq, hdr, frag)
        seq += 1
        if plaintext is not None:
            out.append(plaintext)
    return out


def pick_suite(
    secret_hex: str,
    records: List[Tuple[int, bytes, bytes]],
    suites: Optional[List[str]] = None,
    max_seq: int = DEFAULT_MAX_SEQ,
) -> Optional[Tuple[str, int]]:
    """Brute force the cipher suite AND starting seq when the suite is unknown.

    With no ServerHello in a mid-stream capture the negotiated suite is unknown,
    so this tries each candidate suite (the AEAD tag disambiguates) and returns
    ``(suite, start_seq)`` for the first that recovers a sequence number, else
    ``None``. ``max_seq`` bounds the starting-sequence search (see
    :data:`DEFAULT_MAX_SEQ`).
    """
    for suite in (suites if suites is not None else list(SUITES)):
        seq = recover_seq(secret_hex, suite, records, max_seq=max_seq)
        if seq is not None:
            return suite, seq
    return None


def pick_binding(
    secret_hex: str,
    records: List[Tuple[int, bytes, bytes]],
    suites: Optional[List[str]] = None,
    max_seq: int = DEFAULT_MAX_SEQ,
    max_records: int = DEFAULT_BIND_RECORDS,
    first_record: int = 0,
    min_seq: int = 0,
) -> Optional[SeqBinding]:
    """Brute force the suite, binding record and its seq for a mid-stream direction.

    Like :func:`pick_suite`, but tolerant of failing leading records: each
    candidate suite is tried against the app-data records from ``first_record``
    up to ``max_records`` (see :func:`recover_binding`). Returns the first
    :class:`SeqBinding`, else ``None``. With no explicit ``suites``, only the
    suites whose hash length matches the secret are tried (see
    :func:`~friTap.offline.tls.tls13.suites_for_secret`); the others can never
    authenticate, so the result is unchanged. ``min_seq`` bounds the seq search
    from below (see :func:`recover_binding`).
    """
    if suites is None:
        suites = suites_for_secret(bytes.fromhex(secret_hex))
    for suite in suites:
        found = recover_binding(secret_hex, suite, records, max_seq, max_records,
                                first_record, min_seq)
        if found is not None:
            return SeqBinding(suite, found[0], found[1])
    return None
