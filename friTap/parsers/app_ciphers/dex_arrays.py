"""Heuristic extraction of small constant arrays from Dalvik bytecode.

Pure, I/O-free scanners over a whole ``classes*.dex`` blob.  They do not
parse the dex structure (no code_item walking); they scan for the two ways
d8/R8 materialise a constant array literal and tolerate arbitrary garbage.

Instruction formats relied on (source.android.com/docs/core/runtime/dalvik-bytecode,
all little-endian, one code unit = 2 bytes, low byte = opcode):

* ``fill-array-data-payload``: ushort ident 0x0300, ushort element_width,
  uint size, then ``size * element_width`` data bytes.
* ``const/4 vA, #+B``      0x12, fmt 11n: byte1 = (B << 4) | A, B signed nibble.
* ``const/16 vAA, #+BBBB`` 0x13, fmt 21s: byte1 = AA, unit2 = signed int16.
* ``const vAA, #+BBBBBBBB`` 0x14, fmt 31i: byte1 = AA, units 2-3 = int32.
* ``aput{,-byte,-char,-short} vAA, vBB, vCC`` 0x4b/0x4f/0x50/0x51, fmt 23x:
  byte1 = AA (value), byte2 = BB (array), byte3 = CC (index).
* ``new-array vA, vB, type@CCCC`` 0x23, fmt 22c: byte1 = (B << 4) | A.

Every array is reduced to bytes by taking each element's low byte, which
also matches Java's ``(byte) intValue`` narrowing, so salts declared as
``int[]``/``short[]``/``char[]`` come out identical to ``byte[]`` ones.
"""

from __future__ import annotations

import re
import struct
from typing import Iterator

MIN_ARRAY_LENGTH = 16
MAX_ARRAY_LENGTH = 64

_PAYLOAD_IDENT = b"\x00\x03"
_VALID_WIDTHS = (1, 2, 4, 8)

_OP_CONST4, _OP_CONST16, _OP_CONST = 0x12, 0x13, 0x14
_OP_NEW_ARRAY = 0x23
_APUT_OPS = frozenset((0x4B, 0x4F, 0x50, 0x51))
# Opcodes that are skipped without touching tracked state: code-unit length.
_NEUTRAL_OPS = {
    0x00: 1,  # nop
    0x0C: 1,  # move-result-object
    0x0E: 1,  # return-void
    0x1A: 2,  # const-string
    0x22: 2,  # new-instance
    0x62: 2,  # sget-object
    0x69: 2,  # sput-object
    0x6E: 3, 0x6F: 3, 0x70: 3, 0x71: 3, 0x72: 3,  # invoke-*
}
_MAX_CONSECUTIVE_MISSES = 4
# Inline decode only runs on regions holding at least this many aput opcodes
# within _CLUSTER_GAP bytes of each other (a 16-element literal needs 16).
_CLUSTER_GAP = 24
_CLUSTER_MARGIN = 16
_APUT_BYTE_RE = re.compile(rb"[\x4b\x4f\x50\x51]")


def _low_bytes(values: list[int]) -> bytes:
    return bytes(v & 0xFF for v in values)


def _fits_in_byte(value: int) -> bool:
    return -128 <= value <= 255


def _decode_payload(blob: bytes, pos: int) -> list[int] | None:
    """Element values of a fill-array-data payload at *pos*, or None."""
    if pos + 8 > len(blob):
        return None
    width, size = struct.unpack_from("<HI", blob, pos + 2)
    if width not in _VALID_WIDTHS or not MIN_ARRAY_LENGTH <= size <= MAX_ARRAY_LENGTH:
        return None
    end = pos + 8 + width * size
    if end > len(blob):
        return None
    fmt = {1: "B", 2: "h", 4: "i", 8: "q"}[width]
    return list(struct.unpack_from(f"<{size}{fmt}", blob, pos + 8))


def iter_fill_array_payloads(blob: bytes) -> Iterator[bytes]:
    """Byte arrays (16..64 long) from every plausible fill-array-data payload.

    Wider elements must hold byte-range values (-128..255): that is what a
    salt declared as ``int[]`` looks like and it rejects most random hits.
    """
    pos = blob.find(_PAYLOAD_IDENT)
    while pos != -1:
        if pos % 2 == 0:
            values = _decode_payload(blob, pos)
            if values is not None and all(_fits_in_byte(v) for v in values):
                yield _low_bytes(values)
        pos = blob.find(_PAYLOAD_IDENT, pos + 1)


# --------------------------------------------------------------------------
# Inline const/aput sequences
# --------------------------------------------------------------------------

def _contiguous_array(slots: dict[int, int]) -> bytes | None:
    n = len(slots)
    if not MIN_ARRAY_LENGTH <= n <= MAX_ARRAY_LENGTH:
        return None
    if any(i not in slots for i in range(n)):
        return None
    return bytes(slots[i] & 0xFF for i in range(n))


class _InlineArrayDecoder:
    """Tiny register machine over a code-unit stream (see module docstring)."""

    def __init__(self) -> None:
        self.registers: dict[int, int] = {}
        self.arrays: dict[int, dict[int, int]] = {}
        self.found: list[bytes] = []
        self.misses = 0

    def flush_array(self, reg: int) -> None:
        slots = self.arrays.pop(reg, None)
        array = _contiguous_array(slots) if slots else None
        if array is not None:
            self.found.append(array)

    def reset(self) -> None:
        for reg in list(self.arrays):
            self.flush_array(reg)
        self.registers.clear()

    def set_register(self, reg: int, value: int) -> None:
        self.flush_array(reg)  # an array register overwritten by a constant
        self.registers[reg] = value

    def aput(self, value_reg: int, array_reg: int, index_reg: int) -> None:
        value = self.registers.get(value_reg)
        index = self.registers.get(index_reg)
        if value is None or index is None or not 0 <= index < MAX_ARRAY_LENGTH:
            return
        self.arrays.setdefault(array_reg, {})[index] = value

    def step(self, code: bytes, pos: int) -> int:
        """Decode one instruction at *pos*; return its length in bytes."""
        op, b1 = code[pos], code[pos + 1]
        units = self._execute(op, b1, code, pos)
        if units:
            self.misses = 0
            return units * 2
        self.misses += 1
        if self.misses >= _MAX_CONSECUTIVE_MISSES:
            self.reset()
        return 2

    def _execute(self, op: int, b1: int, code: bytes, pos: int) -> int:
        if op == _OP_CONST4:
            nibble = b1 >> 4
            self.set_register(b1 & 0x0F, nibble - 16 if nibble > 7 else nibble)
            return 1
        if op == _OP_CONST16 and pos + 4 <= len(code):
            self.set_register(b1, struct.unpack_from("<h", code, pos + 2)[0])
            return 2
        if op == _OP_CONST and pos + 6 <= len(code):
            self.set_register(b1, struct.unpack_from("<i", code, pos + 2)[0])
            return 3
        if op in _APUT_OPS and pos + 4 <= len(code):
            self.aput(b1, code[pos + 2], code[pos + 3])
            return 2
        if op == _OP_NEW_ARRAY:
            self.flush_array(b1 & 0x0F)
            self.registers.pop(b1 & 0x0F, None)
            return 2
        return _NEUTRAL_OPS.get(op, 0)


def _aput_clusters(blob: bytes) -> Iterator[tuple[int, int]]:
    """(start, end) byte ranges dense in aput opcodes at even offsets."""
    start = last = -1
    count = 0
    for match in _APUT_BYTE_RE.finditer(blob):
        pos = match.start()
        if pos % 2:
            continue
        if last >= 0 and pos - last <= _CLUSTER_GAP:
            count += 1
        else:
            if count >= MIN_ARRAY_LENGTH:
                yield start, last
            start, count = pos, 1
        last = pos
    if count >= MIN_ARRAY_LENGTH:
        yield start, last


def _decode_region(blob: bytes, start: int, end: int) -> list[bytes]:
    decoder = _InlineArrayDecoder()
    pos = max(0, start - _CLUSTER_MARGIN * 2)
    pos -= pos % 2
    stop = min(len(blob) - 1, end + _CLUSTER_MARGIN)
    while pos < stop:
        pos += decoder.step(blob, pos)
    decoder.reset()
    return decoder.found


def iter_inline_arrays(blob: bytes) -> Iterator[bytes]:
    """Byte arrays (16..64 long) built by ``const*`` + ``aput*`` sequences.

    Only regions with >= 16 nearby aput opcodes are decoded, which keeps a
    whole-dex scan fast; arrays need contiguous indices 0..n-1.
    """
    for start, end in _aput_clusters(blob):
        yield from _decode_region(blob, start, end)


def iter_dex_arrays(blob: bytes) -> Iterator[bytes]:
    """All structured arrays: fill-array-data payloads, then inline literals."""
    yield from iter_fill_array_payloads(blob)
    yield from iter_inline_arrays(blob)
