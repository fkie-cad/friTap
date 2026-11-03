"""Pre-validate pcap / pcapng record lengths before scapy reads a capture.

scapy's readers trust the on-disk lengths: ``RawPcapReader`` calls
``f.read(caplen)`` and ``RawPcapNgReader`` ``f.read(blocklen - 12)`` straight
from the record header, and CPython pre-allocates the requested size. A
third-party capture (shared trace, malware-sandbox output) with a 4 GiB length
field therefore costs a 4 GiB allocation attempt. :func:`validate_capture_file`
walks the record / block headers with ``seek`` -- never reading a payload -- and
rejects lengths that are nonsensical, exceed their record type's maximum or run
past the end of the file, so a capture reaches scapy only once every length is
sane. :func:`capture_read_guard` turns what still escapes scapy
(``MemoryError``, ``struct.error``) into the same :class:`CaptureFormatError`.

The final record may be cut short (a capture interrupted mid-write) when its
length is within the standard packet bound: scapy then reads only what is there
with a bounded allocation, exactly as before.

Leaf module: the stdlib plus :mod:`friTap.binary_bounds`.
"""

from __future__ import annotations

import gzip
import os
import struct
import zlib
from contextlib import contextmanager
from functools import lru_cache
from typing import BinaryIO, Iterator, Optional

from friTap.binary_bounds import BoundsError, check_length

#: Largest packet Wireshark accepts for ordinary link types
#: (``WTAP_MAX_PACKET_SIZE_STANDARD``); also the default tcpdump/dumpcap snaplen.
MAX_STANDARD_PACKET = 262144
#: Ceiling for one pcapng block, and for a pcap record whatever its snaplen says.
MAX_RECORD_BYTES = 64 * 1024 * 1024
#: A final record running past EOF is tolerated up to this length (truncated tail).
TRUNCATED_TAIL_MAX = MAX_STANDARD_PACKET

_GZIP_MAGIC = b"\x1f\x8b"
_PCAP_MAGIC_TO_ENDIAN = {
    b"\xa1\xb2\xc3\xd4": ">", b"\xd4\xc3\xb2\xa1": "<",  # microsecond
    b"\xa1\xb2\x3c\x4d": ">", b"\x4d\x3c\xb2\xa1": "<",  # nanosecond
}
_PCAP_GLOBAL_HEADER_REST = 20   # global header bytes after the 4-byte magic
_PCAP_RECORD_HEADER = 16        # ts_sec, ts_frac, caplen, wirelen
_PCAP_SNAPLEN_OFFSET = 12       # within the 20 bytes after the magic
_PCAP_CAPLEN_OFFSET = 8         # within the record header
_PCAPNG_SHB_MAGIC = b"\x0a\x0d\x0d\x0a"
_PCAPNG_BYTE_ORDER = {b"\x1a\x2b\x3c\x4d": "big", b"\x4d\x3c\x2b\x1a": "little"}
_PCAPNG_BLOCK_HEADER = 8        # block type + block total length
_PCAPNG_MIN_BLOCK = 12          # type + leading length + trailing length
_PCAPNG_MIN_SHB = 28            # + byte-order magic, versions, section length


class CaptureFormatError(BoundsError):
    """A pcap / pcapng capture whose record lengths cannot be trusted.

    A ``ValueError`` (via :class:`~friTap.binary_bounds.BoundsError`).
    """


def validate_capture_file(path: str) -> None:
    """Raise :class:`CaptureFormatError` unless every record length in *path* is sane.

    Classic pcap (both byte orders, us/ns), pcapng and gzip-compressed variants
    of both are walked header by header; anything else is left for scapy to
    reject. A file that validated is remembered by (path, size, mtime), so the
    several readers of one conversion walk it once.
    """
    status = os.stat(path)
    _validate_once(os.path.realpath(path), status.st_size, status.st_mtime_ns)


@contextmanager
def capture_read_guard(path: str) -> Iterator[None]:
    """Re-raise a ``MemoryError`` / ``struct.error`` from scapy as CaptureFormatError."""
    try:
        yield
    except (MemoryError, struct.error) as exc:
        raise CaptureFormatError(
            f"{path}: malformed capture ({type(exc).__name__}: {exc})"
        ) from exc


@lru_cache(maxsize=64)
def _validate_once(path: str, size: int, _mtime_ns: int) -> None:
    """Walk *path* once per (path, size, mtime); a failure is not cached."""
    with open(path, "rb") as raw:
        if raw.read(2) != _GZIP_MAGIC:
            raw.seek(0)
            _walk_capture(raw, size, path)
            return
        raw.seek(0)
        with gzip.GzipFile(fileobj=raw) as unpacked:
            _walk_gzip_capture(unpacked, path)


def _walk_gzip_capture(f: BinaryIO, path: str) -> None:
    """Walk a gzip-compressed capture; its decompressed size is unknown up front."""
    try:
        _walk_capture(f, None, path)
    except EOFError:
        pass  # truncated gzip stream: scapy ends its read there as well
    except (OSError, zlib.error) as exc:
        raise CaptureFormatError(f"{path}: corrupt gzip stream ({exc})") from exc


def _walk_capture(f: BinaryIO, size: Optional[int], path: str) -> None:
    """Dispatch on the magic; *size* is ``None`` when the length is unknown."""
    magic = f.read(4)
    if magic in _PCAP_MAGIC_TO_ENDIAN:
        _walk_pcap(f, size, _PCAP_MAGIC_TO_ENDIAN[magic], path)
    elif magic == _PCAPNG_SHB_MAGIC:
        f.seek(0)
        _walk_pcapng(f, size, path)


def _walk_pcap(f: BinaryIO, size: Optional[int], endian: str, path: str) -> None:
    """Check every record's ``caplen`` against the snaplen-derived maximum and EOF."""
    header = f.read(_PCAP_GLOBAL_HEADER_REST)
    if len(header) < _PCAP_GLOBAL_HEADER_REST:
        return  # scapy rejects the short global header itself
    (snaplen,) = struct.unpack_from(endian + "I", header, _PCAP_SNAPLEN_OFFSET)
    limit = min(max(snaplen, MAX_STANDARD_PACKET), MAX_RECORD_BYTES)
    while True:
        start = f.tell()
        record = f.read(_PCAP_RECORD_HEADER)
        if len(record) < _PCAP_RECORD_HEADER:
            return
        (caplen,) = struct.unpack_from(endian + "I", record, _PCAP_CAPLEN_OFFSET)
        what = f"{path}: pcap record at offset {start}"
        check_length(caplen, what, limit, error=CaptureFormatError)
        if not _skip_to(f, start + _PCAP_RECORD_HEADER + caplen, size):
            _check_truncated_tail(caplen, what, size, start)
            return


def _walk_pcapng(f: BinaryIO, size: Optional[int], path: str) -> None:
    """Check every block's total length (minimum, alignment, maximum, EOF)."""
    endian = "little"
    while True:
        start = f.tell()
        header = f.read(_PCAPNG_BLOCK_HEADER)
        if len(header) < _PCAPNG_BLOCK_HEADER:
            return
        is_shb = header[:4] == _PCAPNG_SHB_MAGIC
        if is_shb:
            endian = _PCAPNG_BYTE_ORDER.get(f.read(4))
            if endian is None:
                return  # unknown byte order: scapy stops (or rejects) here too
        block_len = int.from_bytes(header[4:8], endian)
        what = f"{path}: pcapng block at offset {start}"
        _check_pcapng_block_length(block_len, is_shb, what)
        if not _skip_to(f, start + block_len, size):
            _check_truncated_tail(block_len, what, size, start)
            return


def _check_pcapng_block_length(block_len: int, is_shb: bool, what: str) -> None:
    """Reject a block total length the pcapng spec rules out, or one above the cap."""
    minimum = _PCAPNG_MIN_SHB if is_shb else _PCAPNG_MIN_BLOCK
    if block_len < minimum:
        raise CaptureFormatError(f"{what}: block length {block_len} is below {minimum}")
    if block_len % 4:
        raise CaptureFormatError(f"{what}: block length {block_len} is not a multiple of 4")
    check_length(block_len, what, MAX_RECORD_BYTES, error=CaptureFormatError)


def _skip_to(f: BinaryIO, end: int, size: Optional[int]) -> bool:
    """Seek to *end*; False when the record runs past EOF (nothing is read for a file)."""
    if size is not None:
        if end > size:
            return False
        f.seek(end)
        return True
    return f.seek(end) >= end  # a decompressor stops at EOF and reports where


def _check_truncated_tail(length: int, what: str, size: Optional[int], start: int) -> None:
    """A final record past EOF is a cut-short capture only if its length is plausible."""
    if length <= TRUNCATED_TAIL_MAX:
        return
    left = "an unknown number of" if size is None else str(max(0, size - start))
    raise CaptureFormatError(
        f"{what}: length {length} runs past the end of the file ({left} bytes left)"
    )
