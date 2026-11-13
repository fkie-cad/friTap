"""REC_REQUEST_CONTEXT in the .tap format: round trip, bounds, cap, header flag,
and unchanged existing reader paths."""

from __future__ import annotations

import json
import logging
import struct

import pytest

from friTap.analysis import Finding, Severity
from friTap.caller_stack_shapes import (
    REQUEST_CONTEXT_FRAME_LIMIT,
    REQUEST_CONTEXT_URL_LIMIT,
)
from friTap.flow import tap_writer as tap_writer_module
from friTap.flow.tap_format import (
    _HEADER_STRUCT,
    FLAG_HAS_FINDINGS,
    FLAG_HAS_INDEX,
    FLAG_HAS_REQUEST_CONTEXTS,
    MAX_REQUEST_CONTEXT_FLOW_IDS,
    MAX_REQUEST_CONTEXT_REDIRECTS,
    REC_FINDING,
    REC_FLOW,
    REC_FLOW_INDEX,
    REC_KEYLOG,
    REC_META,
    REC_REQUEST_CONTEXT,
    decode_request_context,
    encode_record,
    encode_request_context,
    sanitize_request_context,
)
from friTap.flow.tap_reader import TapReader
from friTap.flow.tap_writer import TapWriter
from tests.unit._digest_helpers import KEYLOG_LINE, http_flow

FULL_CONTEXT = {
    "req_id": "okhttp-42",
    "stack_kind": "okhttp",
    "url": "https://api.example.com/v1/items?q=1",
    "method": "POST",
    "frames": ["com.example.Api.fetch(Api.java:12)", "okhttp3.RealCall.execute"],
    "thread": "OkHttp Dispatcher",
    "t_start": 1700000000.25,
    "t_end": 1700000001.5,
    "status": 200,
    "protocol": "h2",
    "cached": False,
    "error": "",
    "webview_id": "wv-1",
    "main_frame": True,
    "redirects": ["https://example.com/a", "https://example.com/b"],
    "originator": {"sdk": "OkHttp", "vendor": "Square", "category": "network"},
    "confidence": "high",
    "source": "java-request",
    "matched_flow_ids": ["10.0.0.1:443-10.0.0.2:5555:0"],
    "bucket": "cache",
}


# ---------------------------------------------------------------------------
# Format: encode / decode / sanitize
# ---------------------------------------------------------------------------

def test_record_type_is_new_and_distinct():
    assert REC_REQUEST_CONTEXT == 0x05
    assert REC_REQUEST_CONTEXT not in {REC_FLOW, REC_KEYLOG, REC_META, REC_FINDING, REC_FLOW_INDEX}
    assert FLAG_HAS_REQUEST_CONTEXTS not in (FLAG_HAS_INDEX, FLAG_HAS_FINDINGS)


def test_encode_decode_round_trip_keeps_every_valid_field():
    assert decode_request_context(encode_request_context(FULL_CONTEXT)) == FULL_CONTEXT


def test_minimal_context_needs_only_req_id():
    assert decode_request_context(encode_request_context({"req_id": "r1"})) == {"req_id": "r1"}


@pytest.mark.parametrize("value", [
    None, [], "r1", {}, {"req_id": ""}, {"req_id": 5}, {"url": "https://x"},
])
def test_sanitize_requires_req_id(value):
    assert sanitize_request_context(value) is None


def test_encode_without_req_id_raises():
    with pytest.raises(ValueError):
        encode_request_context({"url": "https://x"})


def test_sanitize_drops_unknown_keys_and_wrong_types():
    hostile = {
        "req_id": "r1",
        "evil": "x",
        "url": 123,
        "method": ["GET"],
        "frames": "not-a-list",
        "t_start": True,
        "t_end": float("nan"),
        "status": True,
        "cached": 1,
        "main_frame": "yes",
        "stack_kind": "Not A Slug!",
        "redirects": {"a": 1},
        "matched_flow_ids": None,
        "originator": {"vendor": "nameless"},
        "confidence": "certain",
        "source": "guess",
        "bucket": "elsewhere",
    }
    assert sanitize_request_context(hostile) == {"req_id": "r1"}


@pytest.mark.parametrize("status,kept", [(200, True), (-1, True), (999, True),
                                         (1000, False), (-2, False), (2**70, False)])
def test_status_range(status, kept):
    clean = sanitize_request_context({"req_id": "r", "status": status})
    assert ("status" in clean) is kept


def test_sanitize_bounds_oversized_input():
    hostile = {
        "req_id": "r" * 10_000,
        "url": "https://x/" + "a" * 100_000,
        "method": "M" * 500,
        "thread": "T" * 500,
        "frames": ["f" * 5000] * 1000 + [7, None],
        "redirects": ["https://r/" + "b" * 10_000] * 100,
        "matched_flow_ids": ["id" * 1000] * 1000,
        "originator": {"sdk": "S" * 1000, "vendor": "V", "category": "c", "x": 1},
    }
    clean = sanitize_request_context(hostile)
    assert len(clean["req_id"]) <= 80
    assert len(clean["url"]) == REQUEST_CONTEXT_URL_LIMIT
    assert len(clean["method"]) <= 16
    assert len(clean["thread"]) <= 80
    assert len(clean["frames"]) == REQUEST_CONTEXT_FRAME_LIMIT
    assert all(len(frame) <= 120 for frame in clean["frames"])
    assert len(clean["redirects"]) == MAX_REQUEST_CONTEXT_REDIRECTS
    assert all(len(url) <= REQUEST_CONTEXT_URL_LIMIT for url in clean["redirects"])
    assert len(clean["matched_flow_ids"]) == MAX_REQUEST_CONTEXT_FLOW_IDS
    assert set(clean["originator"]) == {"sdk", "vendor", "category"}
    assert len(clean["originator"]["sdk"]) <= 80


def test_sanitize_escapes_control_characters():
    clean = sanitize_request_context({
        "req_id": "r\x1b[31m", "url": "https://x/\x1b]0;pwn\x07", "frames": ["a\x1bb"],
    })
    for text in (clean["req_id"], clean["url"], clean["frames"][0]):
        assert "\x1b" not in text and "\x07" not in text


def test_sanitize_skips_non_string_list_entries():
    clean = sanitize_request_context({"req_id": "r", "frames": [1, "a", None, "b"]})
    assert clean["frames"] == ["a", "b"]


@pytest.mark.parametrize("payload", [
    b"not json",
    b"[1, 2]",
    b'{"url": "https://x"}',
    b"[" * 100_000 + b"]" * 100_000,
])
def test_decode_rejects_malformed_payloads(payload):
    assert decode_request_context(payload) is None


def test_decode_rebounds_hostile_payload():
    payload = json.dumps({"req_id": "r", "url": "u" * 50_000, "junk": [1] * 10}).encode()
    record = decode_request_context(payload)
    assert record == {"req_id": "r", "url": "u" * REQUEST_CONTEXT_URL_LIMIT}


# ---------------------------------------------------------------------------
# Writer + reader
# ---------------------------------------------------------------------------

def _finding(flow_id: str) -> Finding:
    return Finding(severity=Severity.LOW, title="t", description="d",
                   source="test", flow_id=flow_id, timestamp=1.0)


def _write_tap(path, *, contexts=(), close=True):
    writer = TapWriter()
    writer.open(str(path), target="test")
    writer.write_keylog(KEYLOG_LINE)
    for index, context in enumerate(contexts):
        writer.write_flow(http_flow(f"flow-{index}"))
        writer.write_request_context(context)
    writer.write_flow(http_flow("flow-last"))
    writer.write_findings("flow-last", [_finding("flow-last")])
    if close:
        writer.close()
    else:
        writer.flush()
    return writer


def _header_flags(path) -> int:
    with open(path, "rb") as handle:
        return _HEADER_STRUCT.unpack(handle.read(_HEADER_STRUCT.size))[2]


def _contexts(n):
    return [{"req_id": f"r{i}", "url": f"https://x/{i}"} for i in range(n)]


def test_reader_round_trip_in_file_order(tmp_path):
    tap = tmp_path / "ctx.tap"
    _write_tap(tap, contexts=[FULL_CONTEXT, {"req_id": "r2"}])
    with TapReader(str(tap)) as reader:
        assert list(reader.iter_request_contexts()) == [FULL_CONTEXT, {"req_id": "r2"}]


def test_writer_drops_context_without_req_id(tmp_path):
    tap = tmp_path / "ctx.tap"
    writer = TapWriter()
    writer.open(str(tap))
    assert writer.write_request_context({"url": "https://x"}) is False
    assert writer.write_request_context({"req_id": "ok"}) is True
    writer.close()
    with TapReader(str(tap)) as reader:
        assert list(reader.iter_request_contexts()) == [{"req_id": "ok"}]


def test_write_after_close_is_ignored(tmp_path):
    writer = TapWriter()
    writer.open(str(tmp_path / "ctx.tap"))
    writer.close()
    assert writer.write_request_context({"req_id": "late"}) is False


def test_header_flag_set_only_when_contexts_written(tmp_path):
    with_ctx, without_ctx = tmp_path / "with.tap", tmp_path / "without.tap"
    _write_tap(with_ctx, contexts=_contexts(1))
    _write_tap(without_ctx)
    assert _header_flags(with_ctx) & FLAG_HAS_REQUEST_CONTEXTS
    assert not _header_flags(without_ctx) & FLAG_HAS_REQUEST_CONTEXTS
    assert _header_flags(without_ctx) & FLAG_HAS_FINDINGS  # existing flag untouched


def test_tap_without_contexts_yields_nothing(tmp_path):
    tap = tmp_path / "plain.tap"
    _write_tap(tap)
    with TapReader(str(tap)) as reader:
        assert list(reader.iter_request_contexts()) == []


def test_indexed_file_without_flag_is_not_scanned(tmp_path, monkeypatch):
    tap = tmp_path / "plain.tap"
    _write_tap(tap)
    with TapReader(str(tap)) as reader:
        monkeypatch.setattr(reader, "_iter_records", pytest.fail)
        assert list(reader.iter_request_contexts()) == []


def test_unclosed_file_is_scanned(tmp_path):
    """No footer/header flags (crash): presence is unknown, so the reader scans."""
    tap = tmp_path / "partial.tap"
    writer = _write_tap(tap, contexts=_contexts(2), close=False)
    try:
        assert not _header_flags(tap) & FLAG_HAS_INDEX
        with TapReader(str(tap)) as reader:
            assert [c["req_id"] for c in reader.iter_request_contexts()] == ["r0", "r1"]
    finally:
        writer.close()


def test_crc_mismatched_and_corrupt_records_are_skipped(tmp_path):
    tap = tmp_path / "ctx.tap"
    writer = TapWriter()
    writer.open(str(tap))
    writer.write_request_context({"req_id": "good"})
    good = encode_request_context({"req_id": "bad-crc"})
    record = bytearray(encode_record(REC_REQUEST_CONTEXT, good))
    record[-1] ^= 0xFF  # flip a payload byte: CRC no longer matches
    with writer._lock:
        writer._file.write(bytes(record))
        writer._file.write(encode_record(REC_REQUEST_CONTEXT, b'{"no_req_id": 1}'))
        writer._request_context_count += 2
    writer.close()
    with TapReader(str(tap)) as reader:
        assert list(reader.iter_request_contexts()) == [{"req_id": "good"}]


def test_record_cap_drops_extras_and_warns_once(tmp_path, monkeypatch, caplog):
    monkeypatch.setattr(tap_writer_module, "MAX_REQUEST_CONTEXT_RECORDS", 3)
    tap = tmp_path / "cap.tap"
    writer = TapWriter()
    writer.open(str(tap))
    # caplog cannot see friTap loggers (propagation off): attach directly.
    handler_records: list[logging.LogRecord] = []
    handler = logging.Handler()
    handler.emit = handler_records.append
    tap_writer_module.logger.addHandler(handler)
    try:
        results = [writer.write_request_context(c) for c in _contexts(6)]
    finally:
        tap_writer_module.logger.removeHandler(handler)
    writer.close()

    assert results == [True, True, True, False, False, False]
    cap_logs = [r for r in handler_records if "cap" in r.getMessage()]
    assert len(cap_logs) == 1
    with TapReader(str(tap)) as reader:
        assert [c["req_id"] for c in reader.iter_request_contexts()] == ["r0", "r1", "r2"]


def test_cap_resets_when_writer_reopened(tmp_path, monkeypatch):
    monkeypatch.setattr(tap_writer_module, "MAX_REQUEST_CONTEXT_RECORDS", 1)
    writer = TapWriter()
    for name in ("a.tap", "b.tap"):
        writer.open(str(tmp_path / name))
        assert writer.write_request_context({"req_id": name}) is True
        assert writer.write_request_context({"req_id": "extra"}) is False
        writer.close()


# ---------------------------------------------------------------------------
# Backward compatibility of every existing reader path
# ---------------------------------------------------------------------------

def _reader_view(path):
    """Everything the pre-existing reader API exposes, in comparable form."""
    with TapReader(str(path)) as reader:
        summaries = [(s.flow_id, s.method, s.url, s.finding_count)
                     for s in reader.read_flow_summaries()]
        flows = sorted(reader.read_all_flows(), key=lambda f: f.flow_id)
        return {
            "flow_count": reader.flow_count,
            "summaries": summaries,
            "flows": [(f.flow_id, len(f.chunks), f.request.body if f.request else None)
                      for f in flows],
            "iter_flows": sorted(f.flow_id for _n, _s, f in reader.iter_flows()),
            "findings": [fd.title for fd in reader.read_findings("flow-last")],
            "has_findings": reader.has_findings(),
            "keylogs": [k for k, _ts in reader.iter_keylogs()],
            "meta": reader.meta.fritap_version if reader.meta else None,
        }


def _strip_request_context_records(src, dst):
    """Copy *src* minus its REC_REQUEST_CONTEXT records, via the raw walker.

    Offsets in the FLOW_INDEX would shift, so the copy is read by linear scan
    only (header index flag cleared) -- the baseline for the linear-scan path.
    """
    with TapReader(str(src)) as reader:
        records = [(rec_type, payload) for _o, rec_type, payload, _crc
                   in reader._iter_records(reader._data_start)
                   if rec_type not in (REC_REQUEST_CONTEXT, REC_FLOW_INDEX)]
        header_size = reader._data_start
    with open(src, "rb") as handle:
        header = bytearray(handle.read(header_size))
    struct.pack_into("<H", header, 6, 0)  # flags = 0: no index, linear scan
    with open(dst, "wb") as handle:
        handle.write(bytes(header))
        for rec_type, payload in records:
            handle.write(encode_record(rec_type, payload))


def test_existing_reader_paths_ignore_interleaved_contexts(tmp_path):
    baseline, mixed = tmp_path / "baseline.tap", tmp_path / "mixed.tap"
    contexts = [dict(FULL_CONTEXT, req_id=f"r{i}") for i in range(3)]
    writer = TapWriter()
    writer.open(str(baseline), target="test")
    writer.write_keylog(KEYLOG_LINE)
    for index in range(3):
        writer.write_flow(http_flow(f"flow-{index}"))
    writer.write_flow(http_flow("flow-last"))
    writer.write_findings("flow-last", [_finding("flow-last")])
    writer.close()
    _write_tap(mixed, contexts=contexts)

    view = _reader_view(mixed)
    assert view == _reader_view(baseline)
    assert view["flow_count"] == 4
    assert view["findings"] and view["keylogs"] == [KEYLOG_LINE]


def test_linear_scan_path_ignores_interleaved_contexts(tmp_path):
    """Crash-recovery path (no footer index) walks every record, contexts included."""
    mixed, stripped = tmp_path / "mixed.tap", tmp_path / "stripped.tap"
    _write_tap(mixed, contexts=_contexts(3))
    _strip_request_context_records(mixed, stripped)
    unindexed_mixed = tmp_path / "unindexed_mixed.tap"
    data = bytearray(mixed.read_bytes())
    struct.pack_into("<H", data, 6, 0)  # drop FLAG_HAS_INDEX: forces linear scan
    unindexed_mixed.write_bytes(bytes(data))

    assert _reader_view(unindexed_mixed) == _reader_view(stripped)
    with TapReader(str(unindexed_mixed)) as reader:
        assert [c["req_id"] for c in reader.iter_request_contexts()] == ["r0", "r1", "r2"]


def test_footer_index_offsets_still_resolve_with_contexts(tmp_path):
    tap = tmp_path / "mixed.tap"
    _write_tap(tap, contexts=_contexts(5))
    with TapReader(str(tap)) as reader:
        assert reader.header.flags & FLAG_HAS_INDEX
        for index in range(5):
            assert reader.read_flow(f"flow-{index}").flow_id == f"flow-{index}"
