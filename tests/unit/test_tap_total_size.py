"""Optional FLOW meta ``total_size``: written only when non-zero, read by the
summary fast path, and records without it summarize exactly as before."""

from __future__ import annotations

import dataclasses
import json
import struct
from pathlib import Path

import pytest

from friTap.flow.models import Flow, FlowChunk
from friTap.flow.tap_format import decode_flow, decode_flow_summary, encode_flow
from friTap.flow.tap_reader import TapReader
from friTap.flow.tap_writer import TapWriter

REPO_ROOT = Path(__file__).resolve().parents[2]
OLD_TAPS = [REPO_ROOT / "demo" / "tst.tap", REPO_ROOT / "captures1.tap"]


def _flow(*sizes: int, flow_id: str = "f1") -> Flow:
    flow = Flow(flow_id=flow_id, started=1.0)
    flow.chunks = [
        FlowChunk(data=bytes([i]) * size, direction="read", timestamp=float(i))
        for i, size in enumerate(sizes)
    ]
    return flow


def _meta(payload: bytes) -> dict:
    (meta_len,) = struct.unpack("<I", payload[:4])
    return json.loads(payload[4:4 + meta_len])


def _with_meta(payload: bytes, meta: dict) -> bytes:
    (meta_len,) = struct.unpack("<I", payload[:4])
    meta_bytes = json.dumps(meta, separators=(",", ":")).encode()
    return struct.pack("<I", len(meta_bytes)) + meta_bytes + payload[4 + meta_len:]


def _without_total_size(payload: bytes) -> bytes:
    meta = _meta(payload)
    meta.pop("total_size", None)
    return _with_meta(payload, meta)


def test_encode_writes_sum_of_chunk_lengths():
    assert _meta(encode_flow(_flow(3, 5, 7)))["total_size"] == 15


def test_deduplicated_chunks_still_count_each_chunk():
    flow = Flow(flow_id="dup")
    flow.chunks = [FlowChunk(data=b"same", direction="read", timestamp=1.0),
                   FlowChunk(data=b"same", direction="write", timestamp=2.0)]
    assert _meta(encode_flow(flow))["total_size"] == 8


@pytest.mark.parametrize("sizes", [(), (0,), (0, 0)])
def test_encode_omits_key_when_zero(sizes):
    payload = encode_flow(_flow(*sizes))
    assert "total_size" not in _meta(payload)
    assert b"total_size" not in payload


def test_summary_reads_stored_value():
    payload = encode_flow(_flow(4, 4))
    meta = _meta(payload)
    meta["total_size"] = 99
    assert decode_flow_summary(_with_meta(payload, meta)).total_size == 99


def test_summary_without_key_sums_chunks():
    payload = _without_total_size(encode_flow(_flow(2, 9)))
    assert decode_flow_summary(payload).total_size == 11


@pytest.mark.parametrize("bad", [-1, True, "12", 1.5, None, [3]])
def test_invalid_stored_value_falls_back_to_chunk_sum(bad):
    payload = encode_flow(_flow(2, 9))
    meta = _meta(payload)
    meta["total_size"] = bad
    assert decode_flow_summary(_with_meta(payload, meta)).total_size == 11


def test_summary_identical_with_and_without_key():
    flow = _flow(5, 1, 30)
    payload = encode_flow(flow)
    with_key = decode_flow_summary(payload, file_offset=7)
    without_key = decode_flow_summary(_without_total_size(payload), file_offset=7)
    assert dataclasses.asdict(with_key) == dataclasses.asdict(without_key)


def test_full_decode_ignores_the_key():
    payload = encode_flow(_flow(5, 1))
    assert (decode_flow(payload).to_dict(include_bodies=True)
            == decode_flow(_without_total_size(payload)).to_dict(include_bodies=True))


def test_tap_written_without_key_reads_identically(tmp_path, monkeypatch):
    import friTap.flow.tap_writer as tap_writer_mod

    flows = [_flow(3, 4, flow_id="a"), _flow(10, flow_id="b"), _flow(flow_id="c")]
    new_path, old_path = tmp_path / "new.tap", tmp_path / "old.tap"
    for path, encode in ((new_path, encode_flow),
                         (old_path, lambda f: _without_total_size(encode_flow(f)))):
        monkeypatch.setattr(tap_writer_mod, "encode_flow", encode)
        writer = TapWriter()
        writer.open(str(path), target="t", capture_start=1.0)
        for flow in flows:
            writer.write_flow(flow)
        writer.close()
    assert b"total_size" in new_path.read_bytes()
    assert b"total_size" not in old_path.read_bytes()

    def summaries(path):
        with TapReader(str(path)) as reader:
            return [s.to_dict() for s in reader.read_flow_summaries()]

    assert summaries(new_path) == summaries(old_path)
    assert [s["total_bytes"] for s in summaries(new_path)] == [7, 10, 0]


@pytest.mark.parametrize("path", OLD_TAPS, ids=lambda p: p.name)
def test_existing_tap_files_summarize_the_same_through_either_path(path):
    if not path.exists():
        pytest.skip(f"{path} not present")
    with TapReader(str(path)) as reader:
        summaries = reader.read_flow_summaries()
        assert summaries
        for summary in summaries:
            payload = reader._read_record_payload_at(summary.file_offset)
            meta = _meta(payload)
            assert "total_size" not in meta
            assert summary.total_size == sum(cm.get("blob_len", 0) for cm in meta["chunks"])
            meta["total_size"] = summary.total_size
            original = decode_flow_summary(payload, summary.file_offset)
            stored = decode_flow_summary(_with_meta(payload, meta), summary.file_offset)
            assert dataclasses.asdict(stored) == dataclasses.asdict(original)
