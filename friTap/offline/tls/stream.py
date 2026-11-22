"""Decrypt one direction's TLS 1.3 application_data records from a traffic secret.

Handshake-anchored (:func:`decrypt_stream`): the first application_data record
has sequence number 0. Mid-stream (:func:`recover_seq`, :func:`pick_suite`, ...):
the suite and the first record's seq ``S > 0`` are unknown and brute forced.

The AEAD tag is a zero-false-accept oracle: ``nonce = static_iv XOR seq`` (RFC
8446 sec 5.3), so a wrong seq fails the tag (~2^-128 false accept per trial) and
only a decryption with a legal inner content-type is accepted.
"""

from __future__ import annotations

from itertools import islice
from typing import Iterator, List, NamedTuple, Optional, Tuple

from .tls13 import (  # noqa: F401 - APPLICATION_DATA is re-exported for rc4/crypto
    APPLICATION_DATA,
    SUITES,
    inner_content_type,
    suites_for_secret,
    try_decrypt,
)

# Minimum encrypted fragment length: >= 1 inner byte + the 16-byte AEAD tag.
MIN_AEAD_FRAGMENT_LEN = 17

# Legal inner content-types: handshake (0x16), application_data (0x17), alert (0x15).
_VALID_INNER_TYPES = (0x16, 0x17, 0x15)

# Upper bound for the unknown starting seq (records sent before capture began).
# A wrong seq never authenticates, so raising it only costs up to max_seq tag
# checks per wrong (secret, suite, direction) trial; the search runs window by
# window (:data:`SEQ_LADDER`), so a wrong stream usually costs only the first rung.
DEFAULT_MAX_SEQ = 100000

# Leading application_data records a mid-stream binding may try (the first can be
# corrupt or under a previous key). Each extra one costs another ``max_seq`` sweep
# for a wrong secret, so the bound stays small.
DEFAULT_BIND_RECORDS = 4

# Rungs of the iterative-deepening seq search (:func:`seq_windows`). Most captures
# start within a few dozen records of the handshake, so a wrong stream costs
# ``rung + 1`` trials per record instead of ``max_seq + 1``.
SEQ_LADDER = (64, 4096)


class SeqBinding(NamedTuple):
    """Where a mid-stream secret bound: suite, app-data record index and its seq."""

    suite: str
    record_index: int
    seq: int


class TrialBudget:
    """Cap on AEAD trial decryptions shared by every seq search of one run.

    Secrets may come from an untrusted file, so brute force work is bounded.
    Once a :meth:`grant` is cut short the budget is :attr:`exhausted` and later
    searches get zero trials.
    """

    def __init__(self, limit: int):
        self.limit = limit
        self.remaining = limit
        self.exhausted = False

    def grant(self, wanted: int) -> int:
        """Up to *wanted* trials; fewer (marking the budget exhausted) when short."""
        granted = max(0, min(wanted, self.remaining))
        if granted < wanted:
            self.exhausted = True
        return granted

    def spend(self, used: int) -> None:
        """Account for *used* trials of an earlier :meth:`grant`."""
        self.remaining -= used

    @property
    def used(self) -> int:
        """Trials spent so far."""
        return self.limit - self.remaining


def decrypt_stream(secret_hex: str, records, suite: str) -> List[bytes]:
    """Decrypt consecutive app-data records from the first one that opens at seq 0."""
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
    """Split ``0..max_seq`` into disjoint inclusive windows along :data:`SEQ_LADDER`.

    E.g. ``(0, 64)``, ``(65, 4096)``, ``(4097, max_seq)``; visits every seq once.
    """
    low = 0
    for rung in SEQ_LADDER:
        if rung >= max_seq:
            break
        yield low, rung
        low = rung + 1
    yield low, max_seq


def _record_seq(secret: bytes, suite: str, hdr: bytes, frag: bytes,
                max_seq: int, min_seq: int = 0,
                budget: Optional[TrialBudget] = None) -> Optional[int]:
    """The seq in ``min_seq..max_seq`` at which a record authenticates, or ``None``.

    With a *budget*, only the seqs it grants are tried (lowest first).
    """
    wanted = max(0, max_seq - min_seq + 1)
    granted = wanted if budget is None else budget.grant(wanted)
    for seq in range(min_seq, min_seq + granted):
        plaintext = try_decrypt(secret, suite, seq, hdr, frag)
        if plaintext is not None and inner_content_type(plaintext) in _VALID_INNER_TYPES:
            _spend(budget, seq - min_seq + 1)
            return seq
    _spend(budget, granted)
    return None


def _spend(budget: Optional[TrialBudget], used: int) -> None:
    """Spend from *budget* if there is one."""
    if budget is not None:
        budget.spend(used)


def recover_binding(
    secret_hex: str,
    suite: str,
    records: List[Tuple[int, bytes, bytes]],
    max_seq: int = DEFAULT_MAX_SEQ,
    max_records: int = DEFAULT_BIND_RECORDS,
    first_record: int = 0,
    min_seq: int = 0,
    budget: Optional[TrialBudget] = None,
) -> Optional[Tuple[int, int]]:
    """Find ``(record_index, seq)`` of the first leading app-data record that binds.

    Tries ``min_seq..max_seq`` against app-data records ``first_record`` to
    ``max_records``; a failing record is skipped, not fatal. The index counts from
    the first app-data record. *budget* caps the trials and stops the search once
    exhausted.
    """
    secret = bytes.fromhex(secret_hex)
    window = islice(iter_app_data_records(records), first_record, max_records)
    for index, (_ctype, hdr, frag) in enumerate(window, start=first_record):
        if budget is not None and budget.exhausted:
            return None
        seq = _record_seq(secret, suite, hdr, frag, max_seq, min_seq, budget)
        if seq is not None:
            return index, seq
    return None


def recover_seq(
    secret_hex: str,
    suite: str,
    records: List[Tuple[int, bytes, bytes]],
    max_seq: int = DEFAULT_MAX_SEQ,
) -> Optional[int]:
    """Recover the seq of the first application_data record, or ``None``.

    First-record-only; use :func:`recover_binding` to tolerate a failing first record.
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
    """Decrypt consecutive app-data records with the counter starting at ``start_seq``.

    ``start_index`` skips leading app-data records, so ``start_seq`` applies to that record.
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
    """Brute force the suite and starting seq; returns ``(suite, start_seq)`` or ``None``."""
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
    budget: Optional[TrialBudget] = None,
) -> Optional[SeqBinding]:
    """Brute force suite, binding record and seq for a mid-stream direction.

    Like :func:`pick_suite` but tolerant of failing leading records. Without
    ``suites``, only suites whose hash length matches the secret are tried (the
    others can never authenticate). Returns a :class:`SeqBinding` or ``None``.
    """
    if suites is None:
        suites = suites_for_secret(bytes.fromhex(secret_hex))
    for suite in suites:
        found = recover_binding(secret_hex, suite, records, max_seq, max_records,
                                first_record, min_seq, budget)
        if found is not None:
            return SeqBinding(suite, found[0], found[1])
    return None
