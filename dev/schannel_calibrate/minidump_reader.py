#!/usr/bin/env python3
"""Read a Windows minidump (.dmp) as VA-space memory, offline.

WHY THIS EXISTS
  tools/schannel_dump.py produces a MiniDumpWithFullMemory .dmp of lsass (read-only,
  no hooking). To answer "where does the TLS 1.3 client_random / secret live relative
  to the SChannel structs", we must search that dump in *virtual-address* space and
  report the delta from a hit to the nearest struct magic tag ('BDDD','3lss','YKSM'…).
  The older tools/schannel_autocalibrate.py `analyze` mode only understood a FLAT
  dump and reported absolute file offsets, leaving the operator to compare by hand.

  This parser turns a .dmp into (va, size, file_offset) ranges and offers VA search,
  so a hit's address is a real lsass address and can be compared to a tag's address.

  Nothing here touches lsass; it is pure offline post-processing of a file.

FORMAT
  A full-memory minidump stores its memory in a Memory64ListStream (type 16): a header
  of NumberOfMemoryRanges + BaseRva, followed by (StartOfMemoryRange, DataSize) pairs;
  the raw bytes for every range are concatenated starting at BaseRva, in list order.
  Older/partial dumps use MemoryListStream (type 5) with per-range RVAs. We parse both.
"""
from __future__ import annotations

import struct
from bisect import bisect_right
from pathlib import Path
from typing import Iterable, Iterator, NamedTuple

MINIDUMP_SIGNATURE = 0x504D444D  # 'MDMP'
# MINIDUMP_STREAM_TYPE values (dbghelp): MemoryListStream=5, Memory64ListStream=9.
# (16 is MemoryInfoListStream — region metadata, NOT contents; do not use it here.)
STREAM_MEMORY_LIST = 5
STREAM_MEMORY64_LIST = 9


class Range(NamedTuple):
    va: int          # StartOfMemoryRange (virtual address in the dumped process)
    size: int        # bytes of this range present in the dump
    file_off: int    # byte offset of this range's data within the .dmp file


class MiniDump:
    """A parsed minidump: its memory ranges plus VA-space read/search helpers."""

    def __init__(self, data: bytes):
        self.data = data
        self.ranges: list[Range] = _parse_ranges(data)
        # Sorted VA starts for O(log n) va -> range lookup.
        self._starts = [r.va for r in self.ranges]

    @classmethod
    def from_path(cls, path: str | Path) -> "MiniDump":
        return cls(Path(path).read_bytes())

    # -- reading -----------------------------------------------------------
    def read_range(self, r: Range) -> bytes:
        return self.data[r.file_off:r.file_off + r.size]

    def iter_ranges(self) -> Iterator[tuple[int, bytes]]:
        for r in self.ranges:
            yield r.va, self.read_range(r)

    def range_for_va(self, va: int) -> Range | None:
        i = bisect_right(self._starts, va) - 1
        if i < 0:
            return None
        r = self.ranges[i]
        return r if r.va <= va < r.va + r.size else None

    def read_va(self, va: int, n: int) -> bytes | None:
        r = self.range_for_va(va)
        if r is None:
            return None
        start = r.file_off + (va - r.va)
        end = start + n
        if end > r.file_off + r.size:
            return None
        return self.data[start:end]

    # -- searching ---------------------------------------------------------
    def search(self, needle: bytes) -> list[int]:
        """Every virtual address at which `needle` occurs across all ranges."""
        out: list[int] = []
        for va, buf in self.iter_ranges():
            start = 0
            while True:
                idx = buf.find(needle, start)
                if idx == -1:
                    break
                out.append(va + idx)
                start = idx + 1
        return out

    def total_bytes(self) -> int:
        return sum(r.size for r in self.ranges)


def _parse_ranges(data: bytes) -> list[Range]:
    if len(data) < 32 or struct.unpack_from("<I", data, 0)[0] != MINIDUMP_SIGNATURE:
        raise ValueError("not a minidump (bad MDMP signature); is this a flat dump?")
    # MINIDUMP_HEADER: Signature(u32) Version(u32) NumberOfStreams(u32)
    #                  StreamDirectoryRva(u32) ...
    n_streams, dir_rva = struct.unpack_from("<II", data, 8)
    streams: dict[int, tuple[int, int]] = {}  # type -> (data_size, rva)
    for i in range(n_streams):
        off = dir_rva + i * 12
        stype, dsize, rva = struct.unpack_from("<III", data, off)
        streams.setdefault(stype, (dsize, rva))

    if STREAM_MEMORY64_LIST in streams:
        return _parse_memory64(data, streams[STREAM_MEMORY64_LIST][1])
    if STREAM_MEMORY_LIST in streams:
        return _parse_memory32(data, streams[STREAM_MEMORY_LIST][1])
    raise ValueError("minidump has no memory stream (need MiniDumpWithFullMemory)")


def _parse_memory64(data: bytes, rva: int) -> list[Range]:
    # MINIDUMP_MEMORY64_LIST: NumberOfMemoryRanges(u64) BaseRva(u64)
    #                         MINIDUMP_MEMORY_DESCRIPTOR64[ ] { StartOfMemoryRange(u64) DataSize(u64) }
    count, base_rva = struct.unpack_from("<QQ", data, rva)
    ranges: list[Range] = []
    file_off = base_rva
    entry = rva + 16
    for _ in range(count):
        start, size = struct.unpack_from("<QQ", data, entry)
        entry += 16
        ranges.append(Range(va=start, size=size, file_off=file_off))
        file_off += size
    return ranges


def _parse_memory32(data: bytes, rva: int) -> list[Range]:
    # MINIDUMP_MEMORY_LIST: NumberOfMemoryRanges(u32)
    #   MINIDUMP_MEMORY_DESCRIPTOR[ ] { StartOfMemoryRange(u64) DataSize(u32) Rva(u32) }
    (count,) = struct.unpack_from("<I", data, rva)
    ranges: list[Range] = []
    entry = rva + 4
    for _ in range(count):
        start, size, r = struct.unpack_from("<QII", data, entry)
        entry += 16
        ranges.append(Range(va=start, size=size, file_off=r))
    return ranges


# --------------------------------------------------------------------------- #
# Pure tag-locality helpers (unit-testable without a dump)
# --------------------------------------------------------------------------- #

def nearest_preceding(sorted_positions: list[int], va: int) -> int | None:
    """Largest position <= va, or None. `sorted_positions` must be sorted."""
    i = bisect_right(sorted_positions, va) - 1
    return sorted_positions[i] if i >= 0 else None


def tag_positions(dump: MiniDump, tag: bytes) -> list[int]:
    """Sorted VAs of a magic tag, both byte orders folded together."""
    hits = set(dump.search(tag))
    rev = tag[::-1]
    if rev != tag:
        hits |= set(dump.search(rev))
    return sorted(hits)


def nearest_tag(tag_index: dict[str, list[int]], va: int) -> tuple[str, int] | None:
    """Nearest preceding tag to `va`: returns (tag, delta) with delta = va - tag_va.

    `tag_index` maps a tag name to its sorted VA positions (e.g. from tag_positions).
    The nearest *preceding* tag is chosen because a struct's magic sits at its base
    and its fields follow, so a secret's address is base+delta with delta >= 0.
    """
    best: tuple[str, int] | None = None
    for name, positions in tag_index.items():
        p = nearest_preceding(positions, va)
        if p is None:
            continue
        delta = va - p
        if best is None or delta < best[1]:
            best = (name, delta)
    return best
