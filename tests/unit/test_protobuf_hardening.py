"""Hardening tests for protobuf/gRPC decoding of attacker-controlled input.

Covers the nesting-depth fallback, the per-decode field cap, the gRPC frame
cap and shared inflate budget, and the analyzer's input/format/evidence caps.
"""

from __future__ import annotations

import gzip
import struct
import time
from types import SimpleNamespace

from friTap.analysis import protobuf_analyzer as pa
from friTap.analysis.protobuf_analyzer import ProtobufAnalyzer
from friTap.parsers.decompress import MAX_INFLATE
from friTap.parsers.protobuf import (
    decode_protobuf_view,
    decode_raw,
    decode_raw_lenient,
    extract_grpc_messages,
    format_message,
    is_likely_protobuf,
    split_grpc_frames_lenient,
)
from friTap.parsers.protobuf.grpc import (
    GRPC_FRAME_LIMIT_NOTE,
    MAX_GRPC_FRAMES_PER_BODY,
    MAX_GRPC_INFLATE_PER_BODY,
    InflateBudget,
    decompress_grpc_payload,
    strip_grpc_frame_with_end,
)
from friTap.parsers.protobuf.wire import (
    FIELD_LIMIT_NOTE,
    MAX_FIELDS_PER_DECODE,
    format_message_bounded,
)


def _varint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _nested(levels: int, leaf: bytes = b"\x08\x01") -> bytes:
    """*levels* nested field-1 sub-messages around *leaf*."""
    data = leaf
    for _ in range(levels):
        data = b"\x0a" + _varint(len(data)) + data
    return data


def _grpc_frame(payload: bytes, compressed: bool = False) -> bytes:
    return bytes([1 if compressed else 0]) + struct.pack(">I", len(payload)) + payload


def _depth(msg) -> int:
    depth = 0
    while msg.fields and msg.fields[0].sub_message is not None:
        msg = msg.fields[0].sub_message
        depth += 1
    return depth


# ── depth limit ──────────────────────────────────────────────────


def test_depth_limit_keeps_deepest_field_as_raw_bytes():
    data = _nested(40)
    msg = decode_raw(data, max_depth=16)  # must not raise
    assert _depth(msg) == 15
    node = msg
    for _ in range(15):
        node = node.fields[0].sub_message
    deepest = node.fields[0]
    assert deepest.sub_message is None
    assert deepest.length_delimited == _nested(40 - 16)


def test_depth_limit_small_max_depth_does_not_raise():
    msg = decode_raw(_nested(5), max_depth=3)
    assert _depth(msg) == 2
    assert format_message(msg)  # still formattable


def test_lenient_depth_limit_reports_no_error():
    msg, error = decode_raw_lenient(_nested(40))
    assert error == "" and len(msg.fields) == 1


def test_is_likely_protobuf_accepts_valid_deep_message():
    # Deeper than is_likely_protobuf's internal depth of 4.
    assert is_likely_protobuf(_nested(10, leaf=b"\x08\x96\x01\x10\x02"))


# ── field cap ────────────────────────────────────────────────────


def test_field_cap_bounds_decode_of_many_tiny_fields():
    data = b"\x08\x01" * 50_000
    start = time.monotonic()
    msg = decode_raw(data)
    assert time.monotonic() - start < 5
    assert len(msg.fields) == MAX_FIELDS_PER_DECODE
    assert msg.truncated


def test_field_cap_lenient_returns_note():
    msg, error = decode_raw_lenient(b"\x08\x01" * 50_000)
    assert len(msg.fields) == MAX_FIELDS_PER_DECODE
    assert msg.truncated and error == FIELD_LIMIT_NOTE


def test_field_cap_counts_nested_fields():
    inner = b"\x08\x01" * 20_000
    msg = decode_raw(b"\x0a" + _varint(len(inner)) + inner)
    # Budget ran out inside the sub-message attempt -> kept as raw bytes.
    assert len(msg.fields) == 1
    assert msg.fields[0].sub_message is None
    assert msg.fields[0].length_delimited == inner


def test_small_message_not_truncated():
    msg = decode_raw(b"\x08\x96\x01\x12\x03abc")
    assert not msg.truncated and len(msg.fields) == 2


# ── gRPC frame cap ───────────────────────────────────────────────


def test_grpc_frame_cap_lenient():
    body = _grpc_frame(b"\x08\x01") * 5000
    frames, error = split_grpc_frames_lenient(body)
    assert len(frames) == MAX_GRPC_FRAMES_PER_BODY
    assert error == GRPC_FRAME_LIMIT_NOTE


def test_grpc_frame_cap_strict_does_not_raise():
    body = _grpc_frame(b"\x08\x01") * 5000
    assert len(strip_grpc_frame_with_end(body)) == MAX_GRPC_FRAMES_PER_BODY
    assert len(extract_grpc_messages(body, "application/grpc")) == MAX_GRPC_FRAMES_PER_BODY


def test_grpc_frame_cap_not_hit_exactly_at_limit():
    body = _grpc_frame(b"\x08\x01") * MAX_GRPC_FRAMES_PER_BODY
    frames, error = split_grpc_frames_lenient(body)
    assert len(frames) == MAX_GRPC_FRAMES_PER_BODY and error == ""


def test_grpc_view_frame_cap():
    body = _grpc_frame(b"\x08\x01") * 5000
    view = decode_protobuf_view(body, content_type="application/grpc")
    assert len(view.messages) == MAX_GRPC_FRAMES_PER_BODY
    assert GRPC_FRAME_LIMIT_NOTE in view.notes


# ── inflate budget ───────────────────────────────────────────────


def test_inflate_budget_limits_total_output():
    budget = InflateBudget(limit=1000)
    data, note = decompress_grpc_payload(gzip.compress(b"\0" * 600), "gzip", budget)
    assert data == b"\0" * 600 and note == ""
    data, note = decompress_grpc_payload(gzip.compress(b"\0" * 600), "gzip", budget)
    assert data is None and "decompression failed" in note
    data, note = decompress_grpc_payload(gzip.compress(b"\0"), "gzip", budget)
    assert data is None and "budget" in note


def test_inflate_budget_unsupported_encoding_is_free():
    budget = InflateBudget(limit=1000)
    decompress_grpc_payload(b"xx", "snappy", budget)
    assert budget.remaining == 1000


def test_inflate_without_budget_unchanged():
    assert decompress_grpc_payload(gzip.compress(b"abc"), "gzip") == (b"abc", "")


def test_gzip_bomb_frames_limited_by_body_budget():
    bomb = gzip.compress(b"\0" * MAX_INFLATE)  # exactly the per-message cap
    body = _grpc_frame(bomb, compressed=True) * 10
    view = decode_protobuf_view(body, content_type="application/grpc",
                                grpc_encoding="gzip")
    inflated = sum(1 for m in view.messages if "budget" not in m.error)
    allowed = MAX_GRPC_INFLATE_PER_BODY // MAX_INFLATE
    assert len(view.messages) == 10
    assert inflated == allowed
    assert all("budget" in m.error for m in view.messages[allowed:])


# ── analyzer caps ────────────────────────────────────────────────


def _report(data: bytes, **kwargs) -> list:
    findings: list = []
    flow = SimpleNamespace(flow_id="f1")
    ProtobufAnalyzer()._decode_and_report(
        data, "response", "application/x-protobuf", flow, findings, **kwargs,
    )
    return findings


def _decoded_evidence(findings: list) -> dict:
    return next(f.evidence for f in findings if f.evidence["type"] == "protobuf_decoded")


def test_analyzer_input_cap(monkeypatch):
    seen: list[int] = []
    real = pa.decode_raw_lenient
    monkeypatch.setattr(pa, "decode_raw_lenient",
                        lambda d, *a, **k: (seen.append(len(d)), real(d, *a, **k))[1])
    data = (b"\x12\x08" + b"abcdefgh") * 50_000  # 500 KB of string fields
    evidence = _decoded_evidence(_report(data))
    assert seen == [pa.MAX_ANALYSIS_INPUT]
    assert evidence["truncated"] is True
    assert evidence["size"] == len(data)


def test_analyzer_evidence_field_cap_and_format_cap():
    data = b"\x08\x01" * 5000
    evidence = _decoded_evidence(_report(data))
    assert len(evidence["fields"]) == pa.MAX_EVIDENCE_FIELDS
    assert evidence["fields_total"] == 5000
    assert len(evidence["formatted"]) <= pa.MAX_FORMATTED_CHARS


def test_analyzer_small_message_untruncated():
    evidence = _decoded_evidence(_report(b"\x08\x96\x01"))
    assert evidence["formatted"] == "1: 150"
    assert evidence["truncated"] is False


def test_analyzer_budgets_grpc_messages():
    messages = [b"\x08\x01" * 100_000] * 5  # 200 KB each
    budgeted = pa._budgeted_messages(messages)
    assert sum(limit for _, limit in budgeted) == pa.MAX_ANALYSIS_INPUT
    assert len(budgeted) == 2
    many = pa._budgeted_messages([b"\x08\x01"] * 5000)
    assert len(many) == MAX_GRPC_FRAMES_PER_BODY


def test_format_message_bounded_stops_early():
    msg = decode_raw(b"\x08\x01" * 5000)
    text = format_message_bounded(msg, 100)
    assert len(text) == 100
    assert format_message(msg).startswith(text)


def test_format_message_bounded_short_message_identical():
    msg = decode_raw(_nested(3, leaf=b"\x08\x96\x01\x12\x03abc"))
    assert format_message_bounded(msg, 10_000) == format_message(msg)
