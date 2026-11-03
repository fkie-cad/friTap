"""Bounded reads for length-prefixed binary formats read from untrusted files.

CPython's ``BufferedReader.read(n)`` / ``FileIO.read(n)`` allocate ``n`` bytes
*before* reading, so ``f.read(length)`` with a crafted 32-bit length field is a
4 GiB allocation attempt even when the file holds a few hundred bytes. Readers
of third-party files (``.tap`` captures, pcap / pcapng, memory dumps) check a
length against the bytes actually left in the file and a per-record-type
maximum *before* using it.

Stdlib-only leaf: imports nothing from friTap.
"""

from __future__ import annotations

import io
import os
import stat
from typing import BinaryIO, Optional, Type

#: Read size used when the bytes left in a stream cannot be known up front
#: (pipes, decompressors): the result then only grows as data actually arrives.
_CHUNK_SIZE = 1 << 20


class BoundsError(ValueError):
    """A length field is negative, exceeds its record type's maximum, or runs past EOF.

    A :class:`ValueError`, so readers that already treat ``ValueError`` as
    "malformed input" keep handling it unchanged.
    """


def remaining_bytes(f: BinaryIO) -> Optional[int]:
    """Bytes between the current position of *f* and EOF, or ``None`` when unknown.

    Only a regular file opened through :class:`io.FileIO` (optionally buffered)
    reports a trustworthy size. Wrappers such as ``gzip.GzipFile`` forward
    ``fileno()`` to the *compressed* file, so their size is never trusted.
    """
    raw = getattr(f, "raw", f)
    if not isinstance(raw, io.FileIO):
        return None
    try:
        status = os.fstat(raw.fileno())
        if not stat.S_ISREG(status.st_mode):
            return None
        return max(0, status.st_size - f.tell())
    except (OSError, ValueError):
        return None


def check_length(
    n: int,
    what: str,
    limit: int,
    remaining: Optional[int] = None,
    error: Type[ValueError] = BoundsError,
) -> None:
    """Raise *error* unless ``0 <= n <= limit`` and *n* fits in *remaining* bytes."""
    if n < 0:
        raise error(f"{what}: negative length {n}")
    if n > limit:
        raise error(f"{what}: length {n} exceeds the {limit}-byte maximum")
    if remaining is not None and n > remaining:
        raise error(
            f"{what}: length {n} runs past the end of the file ({remaining} bytes left)"
        )


def read_bounded(
    f: BinaryIO,
    n: int,
    what: str,
    limit: int,
    error: Type[ValueError] = BoundsError,
) -> bytes:
    """Read exactly *n* bytes of *what* from *f*, validating *n* before allocating.

    *n* must be non-negative, at most *limit* and (when the file size is known)
    at most the bytes left in the file. For streams of unknown size the read is
    done in chunks, so a short stream never costs an *n*-byte allocation.
    Raises *error* (a :class:`ValueError`) on an implausible or truncated read.
    """
    remaining = remaining_bytes(f)
    check_length(n, what, limit, remaining, error)
    data = f.read(n) if remaining is not None else _read_chunked(f, n)
    if len(data) < n:
        raise error(f"{what}: truncated, got {len(data)} of {n} bytes")
    return data


def _read_chunked(f: BinaryIO, n: int) -> bytes:
    """Up to *n* bytes from *f*, read in bounded chunks until EOF."""
    chunks = []
    left = n
    while left > 0:
        chunk = f.read(min(left, _CHUNK_SIZE))
        if not chunk:
            break
        chunks.append(chunk)
        left -= len(chunk)
    return b"".join(chunks)
