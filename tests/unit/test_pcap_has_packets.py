"""Edge cases of the session-end empty-pcap check (``_pcap_has_packets``).

The check decides whether the results modal reports "no traffic" and whether
the decrypt offer is shown. It fails open: only a confidently empty capture
returns False.
"""

from __future__ import annotations

import struct

import pytest

pytest.importorskip("textual")

from friTap.tui import capture_controller, capture_results  # noqa: E402
from friTap.tui.capture_results import _pcap_has_packets  # noqa: E402

PCAPNG_SHB_TYPE = 0x0A0D0D0A
PCAPNG_IDB_TYPE = 0x00000001
PCAPNG_EPB_TYPE = 0x00000006
PCAPNG_SPB_TYPE = 0x00000003


def _block(block_type: int, body: bytes, endian: str = "<") -> bytes:
    total = 12 + len(body)
    return struct.pack(endian + "II", block_type, total) + body + struct.pack(endian + "I", total)


def _shb(endian: str = "<") -> bytes:
    return _block(PCAPNG_SHB_TYPE, struct.pack(endian + "IHHq", 0x1A2B3C4D, 1, 0, -1), endian)


def _pcap_global_header(magic: bytes) -> bytes:
    return magic + b"\x00" * 20


def _write(tmp_path, data: bytes) -> str:
    path = tmp_path / "capture.bin"
    path.write_bytes(data)
    return str(path)


def test_helpers_are_reexported_from_capture_controller():
    assert capture_controller._pcap_has_packets is capture_results._pcap_has_packets
    assert capture_controller._pcapng_has_packets is capture_results._pcapng_has_packets


@pytest.mark.parametrize("data", [b"", b"\x0a\x0d\x0d"])
def test_short_file_is_empty(tmp_path, data):
    assert _pcap_has_packets(_write(tmp_path, data)) is False


def test_missing_file_fails_open(tmp_path):
    assert _pcap_has_packets(str(tmp_path / "missing.pcap")) is True


def test_unknown_magic_fails_open(tmp_path):
    assert _pcap_has_packets(_write(tmp_path, b"NOPE" + b"\x00" * 40)) is True


@pytest.mark.parametrize("magic", [
    b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x4d\x3c\xb2\xa1",
])
def test_classic_pcap_header_only_is_empty(tmp_path, magic):
    assert _pcap_has_packets(_write(tmp_path, _pcap_global_header(magic))) is False


@pytest.mark.parametrize("magic", [b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1"])
def test_classic_pcap_with_a_record_header_has_packets(tmp_path, magic):
    data = _pcap_global_header(magic) + b"\x00" * 16
    assert _pcap_has_packets(_write(tmp_path, data)) is True


def test_classic_pcap_with_a_truncated_record_header_is_empty(tmp_path):
    data = _pcap_global_header(b"\xd4\xc3\xb2\xa1") + b"\x00" * 15
    assert _pcap_has_packets(_write(tmp_path, data)) is False


@pytest.mark.parametrize("endian", ["<", ">"])
def test_pcapng_header_and_interface_only_is_empty(tmp_path, endian):
    data = _shb(endian) + _block(PCAPNG_IDB_TYPE, b"\x00" * 8, endian)
    assert _pcap_has_packets(_write(tmp_path, data)) is False


@pytest.mark.parametrize("endian", ["<", ">"])
@pytest.mark.parametrize("packet_type", [PCAPNG_EPB_TYPE, PCAPNG_SPB_TYPE, 0x00000002])
def test_pcapng_packet_block_has_packets(tmp_path, endian, packet_type):
    data = (_shb(endian) + _block(PCAPNG_IDB_TYPE, b"\x00" * 8, endian)
            + _block(packet_type, b"\x00" * 20, endian))
    assert _pcap_has_packets(_write(tmp_path, data)) is True


def test_pcapng_shorter_than_shb_prefix_is_empty(tmp_path):
    assert _pcap_has_packets(_write(tmp_path, _shb()[:11])) is False


def test_pcapng_unknown_byte_order_fails_open(tmp_path):
    data = struct.pack("<II", PCAPNG_SHB_TYPE, 28) + b"XXXX" + b"\x00" * 16
    assert _pcap_has_packets(_write(tmp_path, data)) is True


def test_pcapng_block_length_below_minimum_stops_the_walk(tmp_path):
    bad_header = struct.pack("<II", PCAPNG_IDB_TYPE, 8)
    data = _shb() + bad_header + _block(PCAPNG_EPB_TYPE, b"\x00" * 20)
    assert _pcap_has_packets(_write(tmp_path, data)) is False


def test_pcapng_packet_block_with_length_below_minimum_is_not_counted(tmp_path):
    data = _shb() + struct.pack("<II", PCAPNG_EPB_TYPE, 8)
    assert _pcap_has_packets(_write(tmp_path, data)) is False


def test_pcapng_truncated_packet_block_still_counts(tmp_path):
    data = _shb() + _block(PCAPNG_EPB_TYPE, b"\x00" * 20)[:10]
    assert _pcap_has_packets(_write(tmp_path, data)) is True


def test_pcapng_block_running_past_eof_ends_the_walk(tmp_path):
    data = _shb() + struct.pack("<II", PCAPNG_IDB_TYPE, 4096) + b"\x00" * 8
    assert _pcap_has_packets(_write(tmp_path, data)) is False


# Behaviour on the shared pcapng walker (iter_pcapng_blocks), per the pcapng spec.

def test_pcapng_packet_in_a_later_section_with_other_byte_order_has_packets(tmp_path):
    # Was False: the old walker kept the first section's byte order for the whole file.
    data = (_shb("<") + _block(PCAPNG_IDB_TYPE, b"\x00" * 8)
            + _shb(">") + _block(PCAPNG_EPB_TYPE, b"\x00" * 20, ">"))
    assert _pcap_has_packets(_write(tmp_path, data)) is True


def test_pcapng_later_section_with_unknown_byte_order_ends_the_walk(tmp_path):
    # Was True: only the first SHB's byte order was checked; a later bad SHB is not a section.
    bad_shb = struct.pack("<II", PCAPNG_SHB_TYPE, 28) + b"XXXX" + b"\x00" * 16
    data = _shb() + bad_shb + _block(PCAPNG_EPB_TYPE, b"\x00" * 20)
    assert _pcap_has_packets(_write(tmp_path, data)) is False


def test_pcapng_packet_block_with_mismatched_trailing_length_is_not_counted(tmp_path):
    epb = _block(PCAPNG_EPB_TYPE, b"\x00" * 20)
    data = _shb() + epb[:-4] + struct.pack("<I", 36)
    assert _pcap_has_packets(_write(tmp_path, data)) is False
