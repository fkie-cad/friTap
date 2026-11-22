"""Transport stream ids persist in the ``.tap`` format.

Chunk entries carry ``stream_id`` only when set, so id-less records stay
byte-identical and older records decode to ``None``. A single-stream flow also
gets a top-level ``stream_id`` for the summary path; the decoded Flow still
derives its id from the chunk ids.
"""

from __future__ import annotations

import json
import struct

import pytest

from friTap.flow.models import Flow, FlowChunk, FlowState
from friTap.flow.models import FlowSummary as LiveFlowSummary
from friTap.flow.tap_format import (
    FlowSummary as TapFlowSummary,
)
from friTap.flow.tap_format import (
    decode_flow,
    decode_flow_summary,
    encode_flow,
)
from friTap.flow.tap_reader import TapReader
from friTap.flow.tap_writer import TapWriter
from tests.unit._display_filter_helpers import match as _match


def _flow(*stream_ids, flow_id: str = "s-1") -> Flow:
    flow = Flow(flow_id=flow_id, connection_id="c-1", state=FlowState.COMPLETE,
                started=1.0, ended=2.0)
    for index, sid in enumerate(stream_ids):
        flow.chunks.append(FlowChunk(data=b"x%d" % index, direction="write",
                                     timestamp=1.0 + index, function="SSL_write",
                                     stream_id=sid))
    return flow


def _meta(payload: bytes) -> dict:
    (meta_len,) = struct.unpack("<I", payload[:4])
    return json.loads(payload[4:4 + meta_len])


def _rewrite_meta(payload: bytes, meta: dict) -> bytes:
    (meta_len,) = struct.unpack("<I", payload[:4])
    meta_bytes = json.dumps(meta, separators=(",", ":")).encode()
    return struct.pack("<I", len(meta_bytes)) + meta_bytes + payload[4 + meta_len:]


# -- Flow.stream_id -----------------------------------------------------------


def test_flow_stream_id_single_stream():
    assert _flow(4, None, 4).stream_id == 4


def test_flow_stream_id_mixed_streams_is_none():
    assert _flow(4, 8).stream_id is None


def test_flow_stream_id_without_ids_is_none():
    assert _flow(None, None).stream_id is None
    assert Flow().stream_id is None


def test_flow_stream_id_follows_appends_and_replaced_lists():
    flow = _flow(4)
    assert flow.stream_id == 4
    flow.chunks.append(FlowChunk(b"y", "read", 3.0, stream_id=8))
    assert flow.stream_id is None
    flow.chunks = [FlowChunk(b"z", "read", 4.0, stream_id=12)]
    assert flow.stream_id == 12


def test_flow_stream_id_mixed_is_terminal_across_appends():
    flow = _flow(4, 8)
    assert flow.stream_id is None
    flow.chunks.append(FlowChunk(b"y", "read", 3.0, stream_id=4))
    assert flow.stream_id is None


def test_flow_stream_id_scans_only_new_chunks():
    class CountingChunk(FlowChunk):
        reads = 0

        def __getattribute__(self, name):
            if name == "stream_id":
                type(self).reads += 1
            return super().__getattribute__(name)

    flow = Flow()
    flow.chunks.extend(CountingChunk(b"x", "read", 0.0, stream_id=4)
                       for _ in range(3))
    assert flow.stream_id == 4
    assert CountingChunk.reads == 3
    flow.chunks.append(CountingChunk(b"y", "read", 1.0, stream_id=4))
    assert flow.stream_id == 4
    assert CountingChunk.reads == 4


def test_flow_copy_stream_id_tracks_its_own_chunks():
    import copy

    flow = _flow(4, 4)
    assert flow.stream_id == 4
    snapshot = copy.copy(flow)
    flow.chunks.append(FlowChunk(b"y", "read", 3.0, stream_id=8))
    assert flow.stream_id is None
    assert snapshot.stream_id == 4
    snapshot.chunks.append(FlowChunk(b"z", "read", 4.0, stream_id=12))
    assert snapshot.stream_id is None


def test_flow_to_dict_includes_stream_id_only_when_set():
    assert _flow(4).to_dict()["stream_id"] == 4
    assert "stream_id" not in _flow(None).to_dict()
    assert "stream_id" not in _flow(4, 8).to_dict()


# -- Encoding -----------------------------------------------------------------


def test_encode_omits_keys_when_unset():
    meta = _meta(encode_flow(_flow(None, None)))
    assert "stream_id" not in meta
    assert all("stream_id" not in cm for cm in meta["chunks"])


def test_encode_without_ids_is_byte_identical_to_old_layout():
    payload = encode_flow(_flow(None))
    meta = _meta(payload)
    assert list(meta["chunks"][0]) == [
        "direction", "timestamp", "function", "blob_offset", "blob_len"]
    assert b"stream_id" not in payload
    assert _rewrite_meta(payload, meta) == payload


def test_encode_writes_chunk_ids_and_flow_id():
    meta = _meta(encode_flow(_flow(4, None, 4)))
    assert [cm.get("stream_id") for cm in meta["chunks"]] == [4, None, 4]
    assert meta["stream_id"] == 4


def test_encode_mixed_flow_has_chunk_ids_but_no_flow_id():
    meta = _meta(encode_flow(_flow(4, 8)))
    assert [cm["stream_id"] for cm in meta["chunks"]] == [4, 8]
    assert "stream_id" not in meta


# -- Decoding -----------------------------------------------------------------


def test_decode_round_trips_chunk_ids():
    decoded = decode_flow(encode_flow(_flow(4, None, 4)))
    assert [c.stream_id for c in decoded.chunks] == [4, None, 4]
    assert decoded.stream_id == 4


def test_old_meta_decodes_none():
    flow = decode_flow(encode_flow(_flow(None)))
    assert flow.chunks[0].stream_id is None and flow.stream_id is None
    summary = decode_flow_summary(encode_flow(_flow(None)))
    assert summary.stream_id is None


def test_summary_derives_id_from_chunk_ids():
    assert decode_flow_summary(encode_flow(_flow(4, None, 4))).stream_id == 4
    assert decode_flow_summary(encode_flow(_flow(4, 8))).stream_id is None


def test_summary_prefers_top_level_flow_id():
    payload = encode_flow(_flow(4, None, 4))
    meta = _meta(payload)
    meta["stream_id"] = 12
    assert decode_flow_summary(_rewrite_meta(payload, meta)).stream_id == 12


def test_summary_falls_back_to_chunk_ids_without_flow_id():
    payload = encode_flow(_flow(4, None, 4))
    meta = _meta(payload)
    del meta["stream_id"]
    assert decode_flow_summary(_rewrite_meta(payload, meta)).stream_id == 4


def test_decoded_flow_ignores_top_level_flow_id():
    payload = encode_flow(_flow(4, 8))
    meta = _meta(payload)
    meta["stream_id"] = 4
    decoded = decode_flow(_rewrite_meta(payload, meta))
    assert decoded.stream_id is None


def test_tap_file_round_trip(tmp_path):
    path = str(tmp_path / "streams.tap")
    writer = TapWriter()
    writer.open(path, target="test")
    writer.write_flow(_flow(4, None, 4, flow_id="single"))
    writer.write_flow(_flow(4, 8, flow_id="mixed"))
    writer.close()

    with TapReader(path) as reader:
        summaries = {s.flow_id: s for s in reader.read_flow_summaries()}
        single = reader.read_flow("single")
        mixed = reader.read_flow("mixed")

    assert summaries["single"].stream_id == 4
    assert summaries["mixed"].stream_id is None
    assert [c.stream_id for c in single.chunks] == [4, None, 4]
    assert single.stream_id == 4
    assert [c.stream_id for c in mixed.chunks] == [4, 8]
    assert mixed.stream_id is None


# -- Summaries ----------------------------------------------------------------


@pytest.mark.parametrize("summary_cls", [LiveFlowSummary, TapFlowSummary])
def test_summary_to_dict_omits_stream_id_when_none(summary_cls):
    assert "stream_id" not in summary_cls.from_flow(_flow(None)).to_dict()
    assert summary_cls.from_flow(_flow(4)).to_dict()["stream_id"] == 4


def test_summary_to_dict_key_sets_match_with_stream_id():
    flow = _flow(4)
    live = LiveFlowSummary.from_flow(flow).to_dict()
    tap = TapFlowSummary.from_flow(flow).to_dict()
    assert set(live) == set(tap)


def test_from_tap_summary_keeps_stream_id():
    tap_summary = decode_flow_summary(encode_flow(_flow(4)))
    synthetic = Flow(flow_id=tap_summary.flow_id)
    assert LiveFlowSummary.from_tap_summary(tap_summary, synthetic).stream_id == 4


# -- Display filter -----------------------------------------------------------


def test_filter_matches_live_flow_and_summary():
    flow = _flow(4)
    assert _match("stream_id == 4", flow)
    assert not _match("stream_id == 8", flow)
    assert _match("stream_id == 4", LiveFlowSummary.from_flow(flow))
    assert not _match("stream_id == 4", _flow(4, 8))


def test_filter_matches_replayed_summary(tmp_path):
    path = str(tmp_path / "filter.tap")
    writer = TapWriter()
    writer.open(path, target="test")
    writer.write_flow(_flow(4))
    writer.close()
    with TapReader(path) as reader:
        (summary,) = reader.read_flow_summaries()
    assert _match("stream_id == 4", summary)
    assert not _match("stream_id == 8", summary)


def test_layer_signature_sees_stream_id_change():
    from friTap.tui.widgets.flow_list import layer_signature

    flow = _flow(4)
    before = layer_signature(flow)
    flow.chunks.append(FlowChunk(b"y", "read", 3.0, stream_id=8))
    assert layer_signature(flow) != before


# -- HTTP/2 body extraction ---------------------------------------------------


def _h2_frame(ftype: int, flags: int, stream_id: int, payload: bytes) -> bytes:
    return (struct.pack("!I", len(payload))[1:] + bytes([ftype, flags])
            + struct.pack("!I", stream_id) + payload)


def test_h2_body_without_request_uses_flow_stream_id():
    flow = _flow()
    flow.detected_protocol = "HTTP/2"
    wire = _h2_frame(0, 0, 3, b"three") + _h2_frame(0, 1, 5, b"five")
    flow.chunks.append(FlowChunk(wire, "read", 1.0, stream_id=5))
    assert flow._extract_h2_body("read") == b"five"


def test_h2_body_without_any_stream_id_keeps_all_streams():
    flow = _flow()
    wire = _h2_frame(0, 0, 3, b"three") + _h2_frame(0, 1, 5, b"five")
    flow.chunks.append(FlowChunk(wire, "read", 1.0))
    assert flow._extract_h2_body("read") == b"threefive"


# -- HTTP/2 collector attribution ---------------------------------------------


def test_h2_collector_stamps_real_stream_ids():
    pytest.importorskip("hpack")
    from friTap.flow.collector import FlowCollector
    from tests.unit.test_collector_h2_attribution import (
        _connection,
        _feed,
        _flows_by_path,
        _records,
        _tricky_cuts,
    )

    conn = _connection()
    collector = _feed(FlowCollector(), [conn.client],
                      _records(conn.server, _tricky_cuts(conn)))
    flows = _flows_by_path(collector)
    for sid, path in conn.paths.items():
        flow = flows[path]
        assert flow.stream_id == sid, path
        assert {c.stream_id for c in flow.chunks} <= {sid}
        assert decode_flow(encode_flow(flow)).stream_id == sid


def test_flow_stream_id_rescans_chunks_appended_during_a_scan():
    flow = Flow()

    class AppendingChunk(FlowChunk):
        def __getattribute__(self, name):
            if name == "stream_id" and len(flow.chunks) == 1:
                # Another thread appends while this call is scanning.
                flow.chunks.append(FlowChunk(b"y", "read", 1.0, stream_id=8))
            return super().__getattribute__(name)

    flow.chunks.append(AppendingChunk(b"x", "read", 0.0, stream_id=4))
    assert flow.stream_id == 4
    assert flow.stream_id is None
