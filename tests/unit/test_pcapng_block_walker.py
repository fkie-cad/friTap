"""``iter_pcapng_blocks`` against the pcapng spec (draft-ietf-opsawg-pcapng).

Each Section Header Block sets the byte order of its own section; a block's
total length is at least 12 (28 for an SHB), a multiple of 4 and repeated at
the end of the block. The walker stops, without yielding, at anything else.
"""

from __future__ import annotations

import io
import struct

import pytest

from friTap.offline.net.capture_validation import iter_pcapng_blocks
from friTap.offline.tshark import capture_has_dsb

SHB, IDB, EPB, DSB = 0x0A0D0D0A, 0x00000001, 0x00000006, 0x0000000A


def _block(block_type: int, body: bytes, endian: str = "<", total=None, trailer=None) -> bytes:
    total = 12 + len(body) if total is None else total
    trailer = total if trailer is None else trailer
    return struct.pack(endian + "II", block_type, total) + body + struct.pack(endian + "I", trailer)


def _shb(endian: str = "<", major: int = 1) -> bytes:
    return _block(SHB, struct.pack(endian + "IHHq", 0x1A2B3C4D, major, 0, -1), endian)


def _types(data: bytes) -> list[int]:
    return [block_type for block_type, _, _ in iter_pcapng_blocks(io.BytesIO(data))]


@pytest.mark.parametrize("endian", ["<", ">"])
def test_walks_a_well_formed_section(endian):
    data = _shb(endian) + _block(IDB, b"\0" * 8, endian) + _block(EPB, b"\0" * 20, endian)
    blocks = list(iter_pcapng_blocks(io.BytesIO(data)))
    assert blocks == [(SHB, 0, 28), (IDB, 28, 20), (EPB, 48, 32)]


def test_each_section_header_sets_its_own_byte_order():
    data = _shb("<") + _block(IDB, b"\0" * 8, "<") + _shb(">") + _block(EPB, b"\0" * 20, ">")
    assert _types(data) == [SHB, IDB, SHB, EPB]


def test_later_section_with_unknown_byte_order_ends_the_walk():
    bad_shb = struct.pack("<II", SHB, 28) + b"XXXX" + b"\0" * 16
    assert _types(_shb() + bad_shb + _block(EPB, b"\0" * 20)) == [SHB]


def test_unknown_major_version_ends_the_walk():
    assert _types(_shb(major=2) + _block(EPB, b"\0" * 20)) == []


@pytest.mark.parametrize("data", [
    b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00" + b"\0" * 40,  # classic pcap global header
    _block(IDB, b"\0" * 8) + _block(EPB, b"\0" * 20),  # pcapng body without an SHB
])
def test_stream_not_starting_with_a_section_header_yields_nothing(data):
    assert _types(data) == []


def test_section_header_shorter_than_28_bytes_ends_the_walk():
    short_shb = _block(SHB, struct.pack("<IHH", 0x1A2B3C4D, 1, 0) + b"\0" * 4)  # 24 bytes
    assert _types(short_shb + _block(EPB, b"\0" * 20)) == []


@pytest.mark.parametrize("total", [8, 22])  # below the minimum / not a multiple of 4
def test_bad_block_length_ends_the_walk_before_that_block(total):
    data = _shb() + _block(EPB, b"\0" * 20, total=total) + _block(EPB, b"\0" * 20)
    assert _types(data) == [SHB]


def test_trailing_length_mismatch_ends_the_walk_before_that_block():
    data = _shb() + _block(EPB, b"\0" * 20, trailer=36) + _block(EPB, b"\0" * 20)
    assert _types(data) == [SHB]


def test_final_block_cut_short_is_yielded_and_ends_the_walk():
    data = _shb() + _block(EPB, b"\0" * 20)[:16]
    assert _types(data) == [SHB, EPB]


def test_walk_starts_at_the_current_position():
    f = io.BytesIO(b"\0" * 4 + _shb() + _block(EPB, b"\0" * 20))
    f.seek(4)
    assert list(iter_pcapng_blocks(f)) == [(SHB, 4, 28), (EPB, 32, 32)]


# capture_has_dsb on the shared walker (spec-correct, fails closed).

def _write(tmp_path, data: bytes) -> str:
    path = tmp_path / "capture.pcapng"
    path.write_bytes(data)
    return str(path)


def test_dsb_in_a_later_big_endian_section_is_found(tmp_path):
    data = _shb("<") + _shb(">") + _block(DSB, b"\0" * 8, ">")
    assert capture_has_dsb(_write(tmp_path, data)) is True


def test_dsb_header_with_length_below_minimum_is_not_a_dsb(tmp_path):
    # Was True: the old walker checked the type before the length.
    assert capture_has_dsb(_write(tmp_path, _shb() + struct.pack("<II", DSB, 8))) is False


def test_truncated_final_dsb_still_counts(tmp_path):
    data = _shb() + _block(DSB, b"\0" * 8)[:12]
    assert capture_has_dsb(_write(tmp_path, data)) is True
