"""Tests for friTap.parsers.app_ciphers.salt_candidates and dex_arrays."""

from __future__ import annotations

import hashlib
import random
import struct

import pytest

from friTap.parsers.app_ciphers import dex_arrays as dx
from friTap.parsers.app_ciphers import salt_candidates as sc

SALT21 = bytes([0x11, 0xF4, 0x80, 0x7F, 0x05] + list(range(0x90, 0x90 + 16)))
SALT32 = SALT21 + bytes(11)
PROTOCOL_ID = hashlib.sha1(SALT32).hexdigest()
FILLER = b"\x0e\x00" * 8  # return-void code units


# --------------------------------------------------------------------------
# Hand-assembled Dalvik helpers
# --------------------------------------------------------------------------

def fill_array_payload(values: list[int], width: int) -> bytes:
    fmt = {1: "b", 2: "h", 4: "i", 8: "q"}[width]
    if width == 1:
        values = [v - 256 if v > 127 else v for v in values]
    body = struct.pack(f"<{len(values)}{fmt}", *values)
    payload = b"\x00\x03" + struct.pack("<HI", width, len(values)) + body
    return payload + b"\x00" * (len(payload) % 2)


def const4(reg: int, value: int) -> bytes:
    return bytes([0x12, ((value & 0xF) << 4) | reg])


def const16(reg: int, value: int) -> bytes:
    return bytes([0x13, reg]) + struct.pack("<h", value)


def const32(reg: int, value: int) -> bytes:
    return bytes([0x14, reg]) + struct.pack("<i", value)


def aput(op: int, value_reg: int, array_reg: int, index_reg: int) -> bytes:
    return bytes([op, value_reg, array_reg, index_reg])


def load(reg: int, value: int) -> bytes:
    if -8 <= value <= 7:
        return const4(reg, value)
    return const16(reg, value)


def inline_array(values: bytes, op: int = 0x4F, signed: bool = True) -> bytes:
    """new-array v0 ... then d8-style const index/value + aput per element."""
    code = bytes([0x23, 0x10, 0x01, 0x00])  # new-array v0, v1, type@1
    for index, byte in enumerate(values):
        value = byte - 256 if signed and byte > 127 else byte
        code += load(1, index) + load(2, value) + aput(op, 2, 0, 1)
    return code + bytes([0x69, 0x00, 0x02, 0x00])  # sput-object v0


def oracle(blob: bytes) -> bytes | None:
    return sc.check_candidates(sc.iter_salt_candidates("test.dex", blob), PROTOCOL_ID)


# --------------------------------------------------------------------------
# dex_arrays
# --------------------------------------------------------------------------

def test_fill_array_width1():
    blob = FILLER + fill_array_payload([b - 256 if b > 127 else b for b in SALT21], 1)
    assert SALT21 in list(dx.iter_fill_array_payloads(blob))


def test_fill_array_width4_int_salt():
    values = [b - 256 if b > 127 else b for b in SALT32]
    blob = FILLER + fill_array_payload(values, 4) + FILLER
    assert SALT32 in list(dx.iter_fill_array_payloads(blob))


def test_fill_array_rejects_out_of_byte_range_and_truncation():
    wide = fill_array_payload([1000] * 20, 4)
    truncated = fill_array_payload(list(range(20)), 4)[:-8]
    assert list(dx.iter_fill_array_payloads(wide)) == []
    assert list(dx.iter_fill_array_payloads(truncated)) == []


@pytest.mark.parametrize("op", [0x4F, 0x4B, 0x50, 0x51])
def test_inline_aput_sequence(op):
    blob = FILLER + inline_array(SALT21, op=op) + FILLER
    assert SALT21 in list(dx.iter_inline_arrays(blob))


def test_inline_const32_values_and_negative_bytes():
    code = b""
    for index, byte in enumerate(SALT32):
        code += const4(3, 0) if index == 0 else const16(3, index)
        code += const32(4, byte - 256 if byte > 127 else byte) + aput(0x4F, 4, 0, 3)
    assert SALT32 in list(dx.iter_inline_arrays(FILLER + code + FILLER))


def test_inline_gap_in_indices_is_rejected():
    values = bytes(range(1, 21))
    code = b"".join(load(1, i) + load(2, v) + aput(0x4F, 2, 0, 1)
                    for i, v in enumerate(values) if i != 7)
    assert list(dx.iter_inline_arrays(code)) == []


def test_two_inline_arrays_in_different_registers():
    other = bytes(range(0x40, 0x40 + 21))
    code = b""
    for index in range(21):
        code += load(1, index) + load(2, SALT21[index] - 256 if SALT21[index] > 127 else SALT21[index])
        code += aput(0x4F, 2, 0, 1) + load(3, other[index]) + aput(0x4F, 3, 5, 1)
    assert {SALT21, other} <= set(dx.iter_inline_arrays(code))


def test_garbage_does_not_crash():
    rng = random.Random(1234)
    for _ in range(20):
        blob = bytes(rng.getrandbits(8) for _ in range(rng.randint(0, 4000)))
        list(dx.iter_dex_arrays(blob))


# --------------------------------------------------------------------------
# salt_candidates: sources + XOR transforms through the oracle
# --------------------------------------------------------------------------

def test_oracle_pads_21_byte_candidate():
    assert sc.check_candidates([SALT21], PROTOCOL_ID) == SALT32
    assert sc.check_candidates([SALT32], PROTOCOL_ID.upper()) == SALT32
    assert sc.check_candidates([b"\x00" * 21], PROTOCOL_ID) is None


def test_oracle_rejects_bad_protocol_id():
    with pytest.raises(ValueError):
        sc.check_candidates([SALT21], "nothex")


def test_oracle_counts_tries():
    stats = sc.SaltCandidateStats()
    sc.check_candidates([b"\x01" * 32, b"\x02" * 21], PROTOCOL_ID, stats)
    assert stats.candidates_tried == 3


def test_recovers_inline_byte_salt():
    assert oracle(FILLER + inline_array(SALT21) + FILLER) == SALT32


def test_recovers_int_array_salt():
    values = [b - 256 if b > 127 else b for b in SALT21]
    assert oracle(FILLER + fill_array_payload(values, 4)) == SALT32


def test_two_array_xor():
    mask = bytes(random.Random(7).getrandbits(8) for _ in range(21))
    obf = bytes(a ^ b for a, b in zip(SALT21, mask))
    blob = FILLER + inline_array(obf) + FILLER + fill_array_payload(list(mask), 1)
    assert oracle(blob) == SALT32


def test_single_byte_xor_21_array():
    obf = bytes(b ^ 0x5A for b in SALT21)
    assert oracle(FILLER + inline_array(obf) + FILLER) == SALT32


def test_single_byte_xor_32_array_with_tail():
    obf = bytes(b ^ 0xC3 for b in SALT32)
    assert oracle(FILLER + fill_array_payload(list(obf), 1)) == SALT32


def test_single_byte_xor_raw_window_with_tail():
    obf = bytes(b ^ 0x37 for b in SALT32)
    blob = b"random-prefix-" * 50 + obf + b"-suffix" * 50
    assert oracle(blob) == SALT32


def test_repeating_ascii_key_xor():
    key = b"AppLovinK3y!"
    obf = bytes(b ^ key[i % len(key)] for i, b in enumerate(SALT32))
    blob = FILLER + fill_array_payload(list(obf), 1) + b"\x0cAppLovinK3y!\x00" + FILLER
    assert oracle(blob) == SALT32


def test_random_garbage_has_no_false_positive():
    rng = random.Random(99)
    blob = bytes(rng.getrandbits(8) for _ in range(200_000))
    stats = sc.SaltCandidateStats()
    found = sc.check_candidates(sc.iter_salt_candidates("rand", blob, stats), PROTOCOL_ID, stats)
    assert found is None
    assert stats.candidates_tried == stats.candidates_yielded or stats.candidates_tried > 0


def test_stats_populated():
    stats = sc.SaltCandidateStats()
    list(sc.iter_salt_candidates("x", FILLER + inline_array(SALT21) + b"somekeystring", stats))
    assert stats.arrays_found == 1
    assert stats.target_arrays == 1
    assert stats.key_strings >= 1
    assert stats.candidates_yielded > 256
