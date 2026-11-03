"""Binary readers of third-party files must not trust their length fields.

``.tap`` captures, pcap / pcapng traces and minidumps can come from third
parties (shared captures, malware sandboxes). CPython's ``read(n)`` allocates
``n`` bytes up front, so a crafted 4 GiB length used to mean a 4 GiB
allocation attempt (scapy reaches a 4 GiB tracemalloc peak on such a pcap).
Every crafted file below must end in a clean format error -- or, where the
format defines graceful recovery, a clean partial read -- with a tracemalloc
peak far below the claimed size. Valid files still load unchanged.
"""

from __future__ import annotations

import gzip
import io
import logging
import struct
import tracemalloc
from contextlib import contextmanager
from pathlib import Path

import pytest

pytest.importorskip("scapy.all")

import scapy.all  # noqa: E402,F401 - load layers before any tracemalloc window
from scapy.layers.inet import IP, TCP  # noqa: E402
from scapy.layers.l2 import Ether  # noqa: E402
from scapy.utils import wrpcap, wrpcapng  # noqa: E402

from friTap.binary_bounds import (  # noqa: E402
    BoundsError,
    check_length,
    read_bounded,
    remaining_bytes,
)
from friTap.flow import tap_reader as tap_reader_module  # noqa: E402
from friTap.flow.models import Flow, FlowChunk, FlowState  # noqa: E402
from friTap.flow.tap_format import (  # noqa: E402
    _RECORD_ENVELOPE,
    FLAG_HAS_INDEX,
    REC_FLOW,
    REC_FLOW_INDEX,
    REC_META,
    SYNC_MARKER,
    TapMeta,
    encode_flow,
    encode_flow_index,
    encode_footer,
    encode_header,
    encode_meta,
    encode_record,
)
from friTap.flow.tap_reader import TapReader  # noqa: E402
from friTap.offline.net import pcap_fast, tcp_reassembly  # noqa: E402
from friTap.offline.net.capture_validation import (  # noqa: E402
    MAX_RECORD_BYTES,
    CaptureFormatError,
    capture_read_guard,
    validate_capture_file,
)
from friTap.offline.rc4.memreader import (  # noqa: E402
    FlatDump,
    MiniDump,
    MiniDumpFormatError,
    load_dump,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
MIB = 1024 * 1024
PEAK_LIMIT = 16 * MIB
HUGE = 0xFFFFFFFF          # a 4 GiB u32 length
HUGE_ALIGNED = 0xFFFFFFFC  # 4 GiB, multiple of 4 (pcapng)


@contextmanager
def peak_below(limit: int = PEAK_LIMIT):
    """Assert the traced allocation peak inside the block stays below *limit*."""
    tracemalloc.start()
    try:
        yield
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert peak < limit, f"allocation peak {peak} bytes >= {limit}"


def _write(path: Path, data: bytes) -> str:
    path.write_bytes(data)
    return str(path)


# --------------------------------------------------------------------------- #
# friTap.binary_bounds
# --------------------------------------------------------------------------- #

def test_check_length_rejects_negative_length():
    with pytest.raises(BoundsError, match="negative length"):
        check_length(-1, "record", limit=100)


def test_check_length_rejects_length_above_limit():
    with pytest.raises(BoundsError, match="exceeds the 100-byte maximum"):
        check_length(101, "record", limit=100)


def test_bounds_error_is_a_value_error():
    assert issubclass(BoundsError, ValueError)


def test_read_bounded_rejects_length_past_eof_without_allocating(tmp_path):
    path = _write(tmp_path / "small.bin", b"x" * 100)
    with open(path, "rb") as f, peak_below():
        with pytest.raises(BoundsError, match="runs past the end of the file"):
            read_bounded(f, HUGE, "record", limit=1 << 40)


def test_read_bounded_reads_exact_bytes(tmp_path):
    path = _write(tmp_path / "data.bin", b"abcdef")
    with open(path, "rb") as f:
        f.seek(2)
        assert read_bounded(f, 3, "record", limit=10) == b"cde"


def test_read_bounded_on_unknown_size_stream_reads_in_chunks():
    stream = io.BytesIO(b"y" * 1000)  # no file size: bounded chunked read
    with peak_below():
        with pytest.raises(BoundsError, match="truncated, got 1000"):
            read_bounded(stream, HUGE, "record", limit=1 << 40)


def test_remaining_bytes_ignores_compressed_wrapper(tmp_path):
    path = tmp_path / "data.gz"
    with gzip.open(path, "wb") as f:
        f.write(b"z" * 10000)
    with gzip.open(path, "rb") as f:
        assert remaining_bytes(f) is None  # fstat would report the compressed size
    with open(path, "rb") as f:
        assert remaining_bytes(f) == path.stat().st_size


# --------------------------------------------------------------------------- #
# .tap reader
# --------------------------------------------------------------------------- #

def _flow(flow_id: str = "flow-1") -> Flow:
    flow = Flow(
        flow_id=flow_id, connection_id="c1",
        src_addr="10.0.0.2", src_port=51000, dst_addr="93.184.216.34", dst_port=443,
        state=FlowState.COMPLETE, started=1000.0, ended=1001.0,
    )
    flow.chunks.append(FlowChunk(
        data=b"GET / HTTP/1.1\r\n\r\n", direction="write",
        timestamp=1000.0, function="SSL_write",
    ))
    return flow


def _bogus_envelope(rec_type: int, payload_len: int) -> bytes:
    return _RECORD_ENVELOPE.pack(SYNC_MARKER, rec_type, 0, 0, payload_len, 0)


def _meta_record() -> bytes:
    return encode_record(REC_META, encode_meta(TapMeta()))


def test_tap_meta_with_4gib_length_opens_without_allocating(tmp_path):
    path = _write(tmp_path / "meta.tap",
                  encode_header() + _bogus_envelope(REC_META, HUGE) + b"\0" * 64)
    with peak_below():
        reader = TapReader(path)
        reader.open()
    assert reader.flow_count == 0
    reader.close()


def test_tap_scan_keeps_flows_before_a_4gib_record(tmp_path):
    data = (encode_header() + _meta_record() + encode_record(REC_FLOW, encode_flow(_flow()))
            + _bogus_envelope(REC_FLOW, HUGE) + b"\0" * 64)
    path = _write(tmp_path / "huge.tap", data)
    with peak_below(), TapReader(path) as reader:
        assert reader.flow_count == 1
        assert reader.read_flow("flow-1").flow_id == "flow-1"


def test_tap_record_length_past_eof_ends_scan(tmp_path):
    data = (encode_header() + _meta_record() + encode_record(REC_FLOW, encode_flow(_flow()))
            + _bogus_envelope(REC_FLOW, 5000) + b"\0" * 100)
    path = _write(tmp_path / "past_eof.tap", data)
    with TapReader(path) as reader:
        assert reader.flow_count == 1


def test_tap_index_record_with_4gib_length_falls_back_to_scan(tmp_path):
    body = encode_header(flags=FLAG_HAS_INDEX) + _meta_record()
    flow_offset = len(body)
    body += encode_record(REC_FLOW, encode_flow(_flow()))
    index_offset = len(body)
    body += _bogus_envelope(REC_FLOW_INDEX, HUGE)
    path = _write(tmp_path / "index.tap", body + encode_footer(index_offset))
    with peak_below(), TapReader(path) as reader:
        assert reader.flow_count == 1
        assert reader._flow_offsets["flow-1"] == flow_offset


def test_tap_valid_index_still_used(tmp_path):
    body = encode_header(flags=FLAG_HAS_INDEX) + _meta_record()
    flow_offset = len(body)
    body += encode_record(REC_FLOW, encode_flow(_flow()))
    index_offset = len(body)
    body += encode_record(REC_FLOW_INDEX, encode_flow_index(
        [{"flow_id": "flow-1", "offset": flow_offset}]))
    path = _write(tmp_path / "ok.tap", body + encode_footer(index_offset))
    with TapReader(path) as reader:
        assert reader.flow_count == 1
        assert len(reader.read_flow("flow-1").chunks) == 1


def test_tap_read_payload_raises_format_error(tmp_path):
    path = _write(tmp_path / "plain.tap", encode_header() + _meta_record())
    with TapReader(path) as reader, peak_below():
        with pytest.raises(ValueError, match="tap record payload"):
            reader._read_payload(HUGE)


def test_tap_payload_above_cap_is_not_read(tmp_path, monkeypatch):
    data = encode_header() + _meta_record() + encode_record(REC_FLOW, encode_flow(_flow()))
    path = _write(tmp_path / "cap.tap", data)
    monkeypatch.setattr(tap_reader_module, "MAX_RECORD_PAYLOAD", 16)
    with TapReader(path) as reader:
        assert reader.flow_count == 0  # FLOW payload > cap: treated as corrupt


@pytest.mark.parametrize("name, flows, chunks", [
    ("captures1.tap", 2, 8),
    ("1capture.tap", 40, 40),
])
def test_repo_tap_captures_still_load(name, flows, chunks):
    path = REPO_ROOT / name
    if not path.exists():
        pytest.skip(f"{name} not present")
    with TapReader(str(path)) as reader:
        assert len(reader.read_flow_summaries()) == flows
        loaded = reader.read_all_flows()
    assert len(loaded) == flows
    assert sum(len(f.chunks) for f in loaded) == chunks


# --------------------------------------------------------------------------- #
# pcap / pcapng pre-validation (scapy call sites)
# --------------------------------------------------------------------------- #

def _pcap_header(snaplen: int = 65535, linktype: int = 1) -> bytes:
    return struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, snaplen, linktype)


def _pcap_record(caplen: int, data: bytes = b"") -> bytes:
    return struct.pack("<IIII", 1, 0, caplen, caplen) + data


def _pcapng_block(block_type: int, body: bytes, total_len: int | None = None) -> bytes:
    length = 12 + len(body) if total_len is None else total_len
    return struct.pack("<II", block_type, length) + body + struct.pack("<I", length)


def _pcapng_head() -> bytes:
    shb = _pcapng_block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    idb = _pcapng_block(1, struct.pack("<HHI", 1, 0, 65535))
    return shb + idb


def _tcp_packet(payload: bytes = b"hello"):
    return (Ether() / IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=40000, dport=443, seq=1000, flags="PA") / payload)


def test_pcap_4gib_caplen_is_rejected(tmp_path):
    path = _write(tmp_path / "huge.pcap", _pcap_header() + _pcap_record(HUGE, b"x" * 100))
    with peak_below():
        with pytest.raises(CaptureFormatError, match="offset 24.*maximum"):
            validate_capture_file(path)
    assert issubclass(CaptureFormatError, ValueError)


def test_pcap_fast_reader_rejects_4gib_caplen_without_allocating(tmp_path):
    path = _write(tmp_path / "huge.pcap", _pcap_header() + _pcap_record(HUGE, b"x" * 100))
    with peak_below():
        with pytest.raises(CaptureFormatError):
            list(pcap_fast.iter_tcp_segments(path, fallback=lambda pkt: None))
        with pytest.raises(CaptureFormatError):
            pcap_fast.first_packet_time(path)
        assert pcap_fast.capture_may_carry_udp(path) is True  # degrades, never raises


def test_legacy_scapy_parser_rejects_4gib_caplen(tmp_path):
    path = _write(tmp_path / "huge.pcap", _pcap_header() + _pcap_record(HUGE, b"x" * 100))
    with peak_below():
        with pytest.raises(CaptureFormatError):
            tcp_reassembly.parse_pcap_scapy(path)


def test_pcap_caplen_past_eof_is_rejected(tmp_path):
    caplen = 1 * MIB  # within a 2 MiB snaplen, but far past the end of the file
    path = _write(tmp_path / "past.pcap",
                  _pcap_header(snaplen=2 * MIB) + _pcap_record(caplen, b"x" * 100))
    with pytest.raises(CaptureFormatError, match="runs past the end of the file"):
        validate_capture_file(path)


def test_pcap_huge_snaplen_does_not_lift_the_hard_cap(tmp_path):
    path = _write(tmp_path / "snap.pcap",
                  _pcap_header(snaplen=HUGE) + _pcap_record(MAX_RECORD_BYTES + 4, b"x"))
    with pytest.raises(CaptureFormatError, match="maximum"):
        validate_capture_file(path)


def test_pcap_truncated_final_record_is_tolerated(tmp_path):
    """A capture cut short mid-packet still loads (scapy reads what is there)."""
    good = tmp_path / "good.pcap"
    wrpcap(str(good), [_tcp_packet()])
    path = _write(tmp_path / "cut.pcap", good.read_bytes() + _pcap_record(1500, b"x" * 40))
    validate_capture_file(path)
    segments = list(pcap_fast.iter_tcp_segments(path, fallback=lambda pkt: None))
    assert [s[6] for s in segments] == [b"hello"]


def test_gzip_pcap_with_4gib_caplen_is_rejected(tmp_path):
    path = tmp_path / "huge.pcap.gz"
    with gzip.open(path, "wb") as f:
        f.write(_pcap_header() + _pcap_record(HUGE, b"x" * 100))
    with peak_below():
        with pytest.raises(CaptureFormatError, match="maximum"):
            validate_capture_file(str(path))


def test_gzip_pcap_valid_capture_passes(tmp_path):
    plain = tmp_path / "plain.pcap"
    wrpcap(str(plain), [_tcp_packet(), _tcp_packet(b"world")])
    path = tmp_path / "plain.pcap.gz"
    with gzip.open(path, "wb") as f:
        f.write(plain.read_bytes())
    validate_capture_file(str(path))
    segments = list(pcap_fast.iter_tcp_segments(str(path), fallback=lambda pkt: None))
    assert [s[6] for s in segments] == [b"hello", b"world"]


@pytest.mark.parametrize("total_len, message", [
    (HUGE_ALIGNED, "maximum"),
    (8, "below 12"),
    (30, "not a multiple of 4"),
    (1 * MIB, "runs past the end of the file"),
])
def test_pcapng_bad_block_length_is_rejected(tmp_path, total_len, message):
    data = _pcapng_head() + _pcapng_block(6, b"\0" * 40, total_len=total_len)
    path = _write(tmp_path / "bad.pcapng", data)
    with peak_below():
        with pytest.raises(CaptureFormatError, match=message):
            validate_capture_file(path)


def test_pcapng_shb_length_below_28_is_rejected(tmp_path):
    shb = _pcapng_block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1), total_len=24)
    path = _write(tmp_path / "shb.pcapng", shb)
    with pytest.raises(CaptureFormatError, match="below 28"):
        validate_capture_file(path)


def test_pcap_fast_reader_rejects_4gib_pcapng_block_without_allocating(tmp_path):
    data = _pcapng_head() + _pcapng_block(6, b"\0" * 40, total_len=HUGE_ALIGNED)
    path = _write(tmp_path / "huge.pcapng", data)
    with peak_below():
        with pytest.raises(CaptureFormatError):
            list(pcap_fast.iter_tcp_segments(path, fallback=lambda pkt: None))


@pytest.mark.parametrize("writer, suffix", [(wrpcap, "pcap"), (wrpcapng, "pcapng")])
def test_valid_captures_still_parse(tmp_path, writer, suffix):
    path = str(tmp_path / f"valid.{suffix}")
    writer(path, [_tcp_packet(), _tcp_packet(b"world")])
    validate_capture_file(path)
    fast = list(pcap_fast.iter_tcp_segments(path, fallback=lambda pkt: None))
    legacy = list(tcp_reassembly._iter_scapy_segments(path))
    assert [s[6] for s in fast] == [b"hello", b"world"]
    assert [s[:7] for s in fast] == [s[:7] for s in legacy]


def test_non_capture_files_are_left_to_scapy(tmp_path):
    validate_capture_file(_write(tmp_path / "notes.txt", b"not a capture at all"))
    validate_capture_file(_write(tmp_path / "empty.pcap", b""))


@pytest.mark.parametrize("error", [MemoryError("boom"), struct.error("short buffer")])
def test_capture_read_guard_converts_reader_errors(error):
    with pytest.raises(CaptureFormatError, match="malformed capture") as excinfo:
        with capture_read_guard("trace.pcap"):
            raise error
    assert excinfo.value.__cause__ is error


# --------------------------------------------------------------------------- #
# Minidump (offline RC4 memory source)
# --------------------------------------------------------------------------- #

_MDMP_HEADER = struct.Struct("<IIIIIIQ")  # 32 bytes
_DIR_RVA = 32


def _minidump64(ranges: list[tuple[int, bytes]], *, n_streams: int = 1,
                dir_rva: int = _DIR_RVA, count: int | None = None,
                list_rva: int | None = None) -> bytes:
    """A MiniDumpWithFullMemory image: header, one directory entry, Memory64List."""
    list_rva = _DIR_RVA + 12 if list_rva is None else list_rva
    count = len(ranges) if count is None else count
    descriptors = b"".join(struct.pack("<QQ", va, len(data)) for va, data in ranges)
    base_rva = _DIR_RVA + 12 + 16 + len(descriptors)
    mem_list = struct.pack("<QQ", count, base_rva) + descriptors
    header = _MDMP_HEADER.pack(0x504D444D, 0xA793, n_streams, dir_rva, 0, 0, 0)
    directory = struct.pack("<III", 9, len(mem_list), list_rva)
    return header + directory + mem_list + b"".join(data for _va, data in ranges)


def _minidump32(ranges: list[tuple[int, bytes]], *, count: int | None = None) -> bytes:
    """A dump with a 32-bit MemoryListStream (per-range RVAs)."""
    count = len(ranges) if count is None else count
    list_rva = _DIR_RVA + 12
    data_rva = list_rva + 4 + 16 * len(ranges)
    descriptors, blobs = b"", b""
    for va, data in ranges:
        descriptors += struct.pack("<QII", va, len(data), data_rva + len(blobs))
        blobs += data
    mem_list = struct.pack("<I", count) + descriptors
    header = _MDMP_HEADER.pack(0x504D444D, 0xA793, 1, _DIR_RVA, 0, 0, 0)
    directory = struct.pack("<III", 5, len(mem_list), list_rva)
    return header + directory + mem_list + blobs


def test_valid_memory64_dump_parses():
    dump = MiniDump(_minidump64([(0x1000, b"A" * 16), (0x5000, b"B" * 8)]))
    assert [va for va, _ in dump.iter_ranges()] == [0x1000, 0x5000]
    assert dump.total_bytes() == 24
    assert dump.read_va(0x5002, 4) == b"BBBB"


def test_valid_memory32_dump_parses():
    dump = MiniDump(_minidump32([(0x2000, b"key-material"), (0x9000, b"zz")]))
    assert list(dump.iter_ranges()) == [(0x2000, b"key-material"), (0x9000, b"zz")]


@pytest.mark.parametrize("data", [
    pytest.param(_minidump64([(0x1000, b"A" * 16)], n_streams=HUGE), id="stream-count-4g"),
    pytest.param(_minidump64([(0x1000, b"A" * 16)], dir_rva=HUGE), id="directory-rva-past-eof"),
    pytest.param(_minidump64([(0x1000, b"A" * 16)], count=(1 << 64) - 1), id="range64-count"),
    pytest.param(_minidump64([(0x1000, b"A" * 16)], list_rva=HUGE), id="memory-list-rva"),
    pytest.param(_minidump32([(0x1000, b"A" * 16)], count=HUGE), id="range32-count"),
])
def test_crafted_minidump_counts_raise_format_error(data):
    with peak_below():
        with pytest.raises(MiniDumpFormatError, match="runs past the end"):
            MiniDump(data)
    assert issubclass(MiniDumpFormatError, ValueError)


def test_minidump_range_data_past_eof_is_clipped():
    data = bytearray(_minidump64([(0x1000, b"A" * 16)]))
    struct.pack_into("<Q", data, _DIR_RVA + 12 + 16 + 8, HUGE)  # DataSize = 4 GiB
    dump = MiniDump(bytes(data))
    assert dump.total_bytes() == 16
    assert dump.read_va(0x1000, 16) == b"A" * 16
    assert dump.read_va(0x1000, 17) is None


def test_truncated_minidumps_never_leak_struct_error():
    valid = _minidump64([(0x1000, b"A" * 64), (0x8000, b"B" * 64)])
    for cut in range(32, len(valid)):
        try:
            MiniDump(valid[:cut])
        except ValueError:
            pass  # MiniDumpFormatError or "no memory stream": both clean


def test_load_dump_reports_malformed_minidump_and_scans_it_flat(tmp_path, caplog):
    data = _minidump64([(0x1000, b"A" * 16)], count=(1 << 64) - 1)
    path = _write(tmp_path / "bad.dmp", data)
    with caplog.at_level(logging.WARNING, logger="friTap.offline.rc4.memreader"):
        reader = load_dump(path)
    assert isinstance(reader, FlatDump)
    assert reader.total_bytes() == len(data)
    assert "malformed minidump" in caplog.text


def test_load_dump_keeps_flat_fallback_for_non_minidumps(tmp_path):
    path = _write(tmp_path / "flat.bin", b"\x00" * 64)
    assert isinstance(load_dump(path), FlatDump)
