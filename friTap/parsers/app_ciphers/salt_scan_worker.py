"""Subprocess worker for the parallel AppLovin salt sliding-window scan.

Run as ``python -m friTap.parsers.app_ciphers.salt_scan_worker PADDED_BLOB_PATH
TARGET_HEX`` by :mod:`friTap.parsers.app_ciphers.salt_scan_pool`.  Being a
fresh interpreter (not a ``multiprocessing`` child) it never re-imports the
caller's ``__main__``, so scripts calling the salt recovery need no main guard.

The worker mmaps the padded blob read-only, then reads ``<start> <count>``
chunk assignments from stdin (one per line, until EOF).  For each it scans
window offsets ``[start, start + count)`` -- touching only those bytes plus
the 20-byte window overlap -- and prints one line on stdout::

    <start> <hit_offset>   # the lowest matching window in that chunk
    <start> -              # no match in that chunk

It exits 0 at stdin EOF.
"""

from __future__ import annotations

import mmap
import sys
from typing import IO, Sequence

from friTap.parsers.app_ciphers.applovin_keys import SALT_MEANINGFUL_LENGTH, _scan_window_range

WINDOW_OVERLAP = SALT_MEANINGFUL_LENGTH - 1
NO_HIT = "-"


def scan_chunk(view, start: int, count: int, target: bytes) -> str:
    """The report line for one chunk of *view* (the padded blob)."""
    hit = _scan_window_range(view[start:start + count + WINDOW_OVERLAP], start, count, target)
    return f"{start} {NO_HIT if hit is None else hit}"


def serve(view, target: bytes, assignments: IO[str], reports: IO[str]) -> None:
    """Answer every ``<start> <count>`` assignment line until EOF."""
    for line in assignments:
        start, count = (int(field) for field in line.split())
        print(scan_chunk(view, start, count, target), file=reports, flush=True)


def main(argv: Sequence[str] | None = None) -> int:
    path, target_hex = list(sys.argv[1:] if argv is None else argv)
    with open(path, "rb") as handle, mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as view:
        serve(view, bytes.fromhex(target_hex), sys.stdin, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
