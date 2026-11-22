"""Structured salt candidates for the AppLovin SHA-1 oracle.

``applovin_keys.recover_salt`` already finds a salt stored as contiguous raw
bytes, hex or base64.  This module adds candidate *sources* for salts stored
differently, so recovery keeps working without per-app hints:

1. dex ``fill-array-data`` payloads of any element width (``int[]`` salts);
2. dex inline ``const*``/``aput*`` array literals (d8/R8 small arrays);
3. XOR de-obfuscation over those arrays: pairwise XOR of equal-length
   arrays, single-byte XOR keys, repeating keys taken from other arrays or
   printable strings; plus single-byte XOR windows over the raw blob,
   located by their tell-tale ``k * 11`` tail (the zero tail XOR k).

Limitation: Mach-O arm64 code that builds arrays instruction by instruction
is not decoded; contiguous ``__const`` data is covered by the raw scan.

Candidates are 21 or 32 bytes long.  All work is bounded by the caps below
and reported through :class:`SaltCandidateStats`.  Pure stdlib, I/O-free.
"""

from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import dataclass
from itertools import combinations
from typing import Iterable, Iterator

from friTap.parsers.app_ciphers.applovin_keys import (
    SALT_LENGTH,
    SALT_MEANINGFUL_LENGTH,
    SALT_ZERO_TAIL,
)
from friTap.parsers.app_ciphers.dex_arrays import iter_dex_arrays

logger = logging.getLogger(__name__)

TARGET_LENGTHS = (SALT_MEANINGFUL_LENGTH, SALT_LENGTH)

MAX_ARRAYS = 5000
MAX_PAIRWISE_XORS = 500_000
MAX_REPEATING_KEY_XORS = 300_000
MAX_KEY_STRINGS = 20_000
MAX_TAIL_WINDOWS_PER_RUN = 32
MAX_TAIL_WINDOWS = 200_000

_PRINTABLE_RE = re.compile(rb"[\x20-\x7e]{4,64}")
_PROTOCOL_ID_RE = re.compile(r"^[0-9a-fA-F]{40}$")
_REPEATED_TAIL_RE = re.compile(rb"([\x01-\xff])\1{10,}", re.DOTALL)


@dataclass
class SaltCandidateStats:
    """Counters for one ``iter_salt_candidates`` / ``check_candidates`` run."""

    arrays_found: int = 0
    target_arrays: int = 0
    key_strings: int = 0
    candidates_yielded: int = 0
    candidates_tried: int = 0


# --------------------------------------------------------------------------
# XOR transforms
# --------------------------------------------------------------------------

def _xor(data: bytes, key: bytes) -> bytes:
    """``data[i] ^ key[i % len(key)]`` (key repeats)."""
    repeated = (key * (len(data) // len(key) + 1))[:len(data)]
    return (int.from_bytes(data, "big") ^ int.from_bytes(repeated, "big")).to_bytes(len(data), "big")


def _single_byte_xors(array: bytes) -> Iterator[bytes]:
    """32-byte arrays: XOR with their repeated tail byte; 21-byte: all keys."""
    if len(array) == SALT_LENGTH:
        k = array[-1]
        if k and array[SALT_MEANINGFUL_LENGTH:] == bytes([k]) * len(SALT_ZERO_TAIL):
            yield _xor(array, bytes([k]))
    elif len(array) == SALT_MEANINGFUL_LENGTH:
        for k in range(1, 256):
            yield _xor(array, bytes([k]))


def _pairwise_xors(targets: list[bytes]) -> Iterator[bytes]:
    budget = MAX_PAIRWISE_XORS
    for length in TARGET_LENGTHS:
        same = [t for t in targets if len(t) == length]
        for a, b in combinations(same, 2):
            if budget <= 0:
                logger.debug("pairwise XOR budget exhausted")
                return
            budget -= 1
            yield _xor(a, b)


def _repeating_key_xors(targets: list[bytes], keys: list[bytes]) -> Iterator[bytes]:
    if not targets:
        return
    usable = keys[:max(1, MAX_REPEATING_KEY_XORS // len(targets))]
    if len(usable) < len(keys):
        logger.debug("repeating-key XOR capped at %d of %d keys", len(usable), len(keys))
    for key in usable:
        for target in targets:
            if key != target:
                yield _xor(target, key)


def iter_tail_xor_windows(blob: bytes) -> Iterator[bytes]:
    """Raw 32-byte windows ending in ``k * 11`` (k != 0), XORed with k.

    One regex pass finds every run of >= 11 equal non-zero bytes; each run
    yields a window for every tail position inside it (the salt's own last
    bytes may extend the run), capped per run and in total.
    """
    tail_len, emitted = len(SALT_ZERO_TAIL), 0
    for run in _REPEATED_TAIL_RE.finditer(blob, SALT_MEANINGFUL_LENGTH):
        key = run.group()[:1]
        last_tail = min(run.end() - tail_len, run.start() + MAX_TAIL_WINDOWS_PER_RUN - 1)
        for pos in range(run.start(), last_tail + 1):
            start = pos - SALT_MEANINGFUL_LENGTH
            if start < 0:
                continue
            yield _xor(blob[start:pos + tail_len], key)
            emitted += 1
        if emitted >= MAX_TAIL_WINDOWS:
            logger.debug("tail-XOR window cap %d reached", MAX_TAIL_WINDOWS)
            return


# --------------------------------------------------------------------------
# Source collection
# --------------------------------------------------------------------------

def _collect_arrays(blob: bytes) -> list[bytes]:
    unique: dict[bytes, None] = {}
    for array in iter_dex_arrays(blob):
        unique.setdefault(array, None)
        if len(unique) >= MAX_ARRAYS:
            logger.debug("structured array cap %d reached", MAX_ARRAYS)
            break
    return list(unique)


def _collect_key_strings(blob: bytes) -> list[bytes]:
    unique: dict[bytes, None] = {}
    for match in _PRINTABLE_RE.finditer(blob):
        unique.setdefault(match.group(), None)
        if len(unique) >= MAX_KEY_STRINGS:
            break
    return list(unique)


def iter_salt_candidates(
    name: str, blob: bytes, stats: SaltCandidateStats | None = None
) -> Iterator[bytes]:
    """21/32-byte salt candidates from structured sources in *blob*.

    *name* is the member name (used for logging only).  Cheapest and most
    likely sources come first.  The raw sliding window is NOT repeated here.
    """
    stats = stats if stats is not None else SaltCandidateStats()
    blob = bytes(blob)
    arrays = _collect_arrays(blob)
    targets = [a for a in arrays if len(a) in TARGET_LENGTHS]
    stats.arrays_found, stats.target_arrays = len(arrays), len(targets)
    # Key strings only matter as XOR keys for salt-sized arrays.
    keys = arrays + (_collect_key_strings(blob) if targets else [])
    stats.key_strings = len(keys) - len(arrays)
    logger.debug("%s: %d structured arrays (%d salt-sized), %d key strings",
                 name, len(arrays), len(targets), stats.key_strings)

    for candidate in _iter_all(blob, arrays, targets, keys):
        stats.candidates_yielded += 1
        yield candidate


def _iter_all(blob: bytes, arrays: list[bytes], targets: list[bytes], keys: list[bytes]) -> Iterator[bytes]:
    yield from targets
    for array in arrays:  # a longer array may start with the salt
        if len(array) > SALT_LENGTH:
            yield array[:SALT_LENGTH]
    for target in targets:
        yield from _single_byte_xors(target)
    yield from _pairwise_xors(targets)
    yield from iter_tail_xor_windows(blob)
    yield from _repeating_key_xors(targets, keys)


# --------------------------------------------------------------------------
# Oracle
# --------------------------------------------------------------------------

def _target_digest(protocol_id: str | bytes) -> bytes:
    if isinstance(protocol_id, bytes) and len(protocol_id) == 20:
        return protocol_id
    text = protocol_id.decode("ascii") if isinstance(protocol_id, bytes) else protocol_id
    text = text.strip()
    if not _PROTOCOL_ID_RE.match(text):
        raise ValueError(f"protocol_id must be 40 hex chars, got {protocol_id!r}")
    return bytes.fromhex(text)


def _salt_forms(candidate: bytes) -> Iterator[bytes]:
    """A candidate as-is (if 32) and its first 21 bytes plus the zero tail."""
    if len(candidate) == SALT_LENGTH:
        yield candidate
    if len(candidate) >= SALT_MEANINGFUL_LENGTH:
        padded = candidate[:SALT_MEANINGFUL_LENGTH] + SALT_ZERO_TAIL
        if padded != candidate:
            yield padded


def check_candidates(
    cands: Iterable[bytes],
    protocol_id: str | bytes,
    stats: SaltCandidateStats | None = None,
) -> bytes | None:
    """The 32-byte salt among *cands* whose SHA-1 is *protocol_id*, else None."""
    target = _target_digest(protocol_id)
    sha1 = hashlib.sha1
    tried = 0
    try:
        for candidate in cands:
            for salt in _salt_forms(candidate):
                tried += 1
                if sha1(salt).digest() == target:
                    return salt
        return None
    finally:
        if stats is not None:
            stats.candidates_tried += tried
