#!/usr/bin/env python3

"""Orphan-merge / .tap consistency, replay summary status, and capture start.

* Orphan request/response merging skips message-stream transports (MTProto
  cloud, Telegram Secret Chats) but still pairs HTTP halves.
* A flow the collector REMOVES after it was already written leaves no ghost
  in the .tap; a merge target that was already written is re-written.
* ``tap_format.FlowSummary`` carries ``has_request``/``has_response`` (derived
  from the FLOW meta, so old taps decode them), and the flow-list status of a
  replayed message flow renders from them.
* ``_first_packet_time`` reads the capture's first packet time.
"""

from __future__ import annotations

import json

from friTap.flow import display
from friTap.flow.collector import FlowCollector
from friTap.flow.models import Flow, FlowChunk, FlowState
from friTap.flow.tap_format import (
    _META_LEN,
    FlowSummary,
    decode_flow_summary,
    encode_flow,
)
from friTap.flow.tap_reader import TapReader
from friTap.flow.tap_writer import TapWriter
from friTap.parsers.base import ParseResult

_CONN = "conn-1"


def _half_flow(flow_id: str, transport: str, *, request: bool,
               started: float = 1000.0) -> Flow:
    """A request-only (``request=True``) or response-only flow on _CONN."""
    flow = Flow(flow_id=flow_id, connection_id=_CONN, transport=transport,
                dst_addr="149.154.167.41", dst_port=443, started=started)
    parsed = ParseResult(protocol="p", is_complete=True)
    direction = "write" if request else "read"
    flow.chunks.append(FlowChunk(b"x", direction, started))
    if request:
        flow.request = parsed
    else:
        flow.response = parsed
    return flow


def _collector_with(*flows: Flow) -> FlowCollector:
    collector = FlowCollector()
    for flow in flows:
        collector._flows[flow.flow_id] = flow
        collector._flow_index.setdefault(flow.connection_id, []).append(flow.flow_id)
    return collector


# --------------------------------------------------------------------------
# Orphan merge transport scope
# --------------------------------------------------------------------------

def test_mtproto_orphans_are_not_merged():
    pong = _half_flow("f:1", "mtproto", request=False, started=1000.0)
    ack = _half_flow("f:2", "mtproto", request=True, started=1001.0)
    collector = _collector_with(pong, ack)

    removed = collector._merge_remaining_orphans()

    assert removed == []
    assert set(collector._flows) == {"f:1", "f:2"}
    assert ack.response is None and len(ack.chunks) == 1


def test_telegram_e2e_orphans_are_not_merged():
    recv = _half_flow("e:1", "telegram_e2e", request=False)
    sent = _half_flow("e:2", "telegram_e2e", request=True)
    collector = _collector_with(recv, sent)

    assert collector._merge_remaining_orphans() == []


def test_tls_orphans_still_merge():
    resp = _half_flow("t:1", "tls", request=False, started=1000.0)
    req = _half_flow("t:2", "tls", request=True, started=1001.0)
    collector = _collector_with(resp, req)

    removed = collector._merge_remaining_orphans()

    assert [f.flow_id for f in removed] == ["t:1"]
    assert req.response is resp.response
    assert len(req.chunks) == 2


def test_is_orphan_merge_candidate():
    assert FlowCollector._is_orphan_merge_candidate(Flow(transport="tls"))
    assert FlowCollector._is_orphan_merge_candidate(Flow(transport="quic"))
    assert not FlowCollector._is_orphan_merge_candidate(Flow(transport="mtproto"))
    assert not FlowCollector._is_orphan_merge_candidate(
        Flow(transport="telegram_e2e"))


def test_flush_emits_updated_for_already_complete_merge_target():
    resp = _half_flow("t:1", "tls", request=False)
    req = _half_flow("t:2", "tls", request=True)
    req.state = FlowState.COMPLETE
    collector = _collector_with(resp, req)
    events: list[tuple[str, str]] = []
    collector.subscribe(lambda flow, et: events.append((et.value, flow.flow_id)))

    collector.flush(end_at_last_activity=True)

    assert ("removed", "t:1") in events
    assert ("updated", "t:2") in events


# --------------------------------------------------------------------------
# TapWriter: no ghosts, stale records refreshed
# --------------------------------------------------------------------------

def _read_ids(path) -> list[str]:
    reader = TapReader(str(path))
    reader.open()
    try:
        return [s.flow_id for s in reader.read_flow_summaries()]
    finally:
        reader.close()


def test_removed_flow_leaves_no_ghost_in_tap(tmp_path):
    path = tmp_path / "ghost.tap"
    writer = TapWriter()
    writer.open(str(path), capture_start=1000.0)
    resp = _half_flow("t:1", "tls", request=False)
    req = _half_flow("t:2", "tls", request=True)
    writer.on_flow_event(resp, "completed")   # written early, then merged away
    writer.on_flow_event(resp, "removed")
    writer.on_flow_event(req, "completed")
    writer.close()

    assert _read_ids(path) == ["t:2"]


def test_forget_flow_unknown_id_is_noop(tmp_path):
    writer = TapWriter()
    writer.open(str(tmp_path / "x.tap"), capture_start=1000.0)
    writer.forget_flow("missing")
    assert not writer.has_written("missing")
    writer.close()


def test_updated_rewrites_only_already_written_flows(tmp_path):
    path = tmp_path / "upd.tap"
    writer = TapWriter()
    writer.open(str(path), capture_start=1000.0)
    active = _half_flow("t:3", "tls", request=True)
    writer.on_flow_event(active, "updated")          # not written: ignored
    assert not writer.has_written("t:3")

    req = _half_flow("t:2", "tls", request=True)
    writer.on_flow_event(req, "completed")
    req.response = ParseResult(protocol="p", is_complete=True)
    writer.on_flow_event(req, "updated")             # stale: re-written
    writer.close()

    reader = TapReader(str(path))
    reader.open()
    try:
        assert [s.flow_id for s in reader.read_flow_summaries()] == ["t:2"]
        assert reader.read_flow("t:2").response is not None
    finally:
        reader.close()


def test_collector_to_writer_end_to_end_has_no_ghost(tmp_path):
    path = tmp_path / "e2e.tap"
    resp = _half_flow("t:1", "tls", request=False)
    req = _half_flow("t:2", "tls", request=True)
    collector = _collector_with(resp, req)
    writer = TapWriter()
    writer.open(str(path), capture_start=1000.0)
    collector.subscribe(writer.on_flow_event)
    writer.write_flow(resp)                           # completed mid-capture

    collector.flush(end_at_last_activity=True)
    writer.close()

    assert _read_ids(path) == ["t:2"]


# --------------------------------------------------------------------------
# Replay summary: has_request / has_response
# --------------------------------------------------------------------------

def _paired_e2e_flow(with_response: bool = True) -> Flow:
    flow = _half_flow("e:1", "telegram_e2e", request=True)
    if with_response:
        flow.response = ParseResult(protocol="p", is_complete=True)
    flow.state = FlowState.COMPLETE
    return flow


def test_summary_round_trip_has_request_and_response():
    summary = decode_flow_summary(encode_flow(_paired_e2e_flow()))
    assert summary.has_request and summary.has_response
    assert display.message_direction_status(summary) == "sent+recv"


def test_summary_round_trip_request_only():
    summary = decode_flow_summary(encode_flow(_paired_e2e_flow(False)))
    assert summary.has_request and not summary.has_response
    assert display.message_direction_status(summary) == "sent"


def test_old_tap_meta_without_parse_entries_defaults_false():
    meta = json.dumps({"flow_id": "old", "transport": "telegram_e2e"}).encode()
    summary = decode_flow_summary(_META_LEN.pack(len(meta)) + meta)
    assert not summary.has_request and not summary.has_response
    assert display.message_direction_status(summary) == ""


def test_from_flow_sets_has_fields():
    summary = FlowSummary.from_flow(_paired_e2e_flow(False))
    assert summary.has_request and not summary.has_response


def test_has_parsed_side_on_live_flow_and_summary():
    flow = _paired_e2e_flow(False)
    assert display.has_parsed_side(flow, "request")
    assert not display.has_parsed_side(flow, "response")
    assert display.has_parsed_side(FlowSummary(has_response=True), "response")
    assert not display.has_parsed_side(FlowSummary(), "request")


def test_flow_list_status_from_replayed_summary():
    from friTap.tui.widgets.flow_list import FlowListWidget

    status = FlowListWidget._message_transport_status
    e2e = decode_flow_summary(encode_flow(_paired_e2e_flow()))
    assert status(e2e) == "sent+recv"
    cloud_flow = _paired_e2e_flow()
    cloud_flow.transport = "mtproto"
    cloud = decode_flow_summary(encode_flow(cloud_flow))
    assert status(cloud) == "sent+recv"
    # Per-packet rows (T1): a cloud record shows its own direction.
    sent_only = _paired_e2e_flow()
    sent_only.transport = "mtproto"
    sent_only.response = None
    assert status(decode_flow_summary(encode_flow(sent_only))) == "sent"
    recv_only = _paired_e2e_flow()
    recv_only.transport = "mtproto"
    recv_only.request = None
    assert status(decode_flow_summary(encode_flow(recv_only))) == "recv"
    assert status(FlowSummary(transport="mtproto")) == "-"


# --------------------------------------------------------------------------
# Capture start = first pcap packet
# --------------------------------------------------------------------------

def test_first_packet_time_reads_first_record(tmp_path):
    from scapy.layers.inet import IP, TCP
    from scapy.utils import wrpcap

    from friTap.offline.pcap_to_tap import _first_packet_time

    first = IP(dst="1.2.3.4") / TCP(dport=443)
    first.time = 1790358544.95096
    second = IP(dst="1.2.3.4") / TCP(dport=443)
    second.time = 1790358547.984745
    path = tmp_path / "two.pcap"
    wrpcap(str(path), [first, second])

    assert abs(_first_packet_time(str(path)) - 1790358544.95096) < 1e-5


def test_first_packet_time_unreadable_is_zero(tmp_path):
    from friTap.offline.pcap_to_tap import _first_packet_time

    bogus = tmp_path / "bogus.pcap"
    bogus.write_bytes(b"not a pcap")
    assert _first_packet_time(str(bogus)) == 0.0
    assert _first_packet_time(str(tmp_path / "missing.pcap")) == 0.0


def test_convert_lowers_capture_start_to_first_packet(tmp_path, monkeypatch):
    """The header start is the first pcap packet, even with no emitted data."""
    from friTap.offline import pcap_to_tap as p2t

    monkeypatch.setattr(p2t, "find_tshark", lambda *a, **k: "/usr/bin/tshark")
    monkeypatch.setattr(p2t, "tshark_version", lambda path: (4, 6, 0))
    monkeypatch.setattr(p2t, "list_tls_streams", lambda *a, **k: [])
    monkeypatch.setattr(p2t, "stream_packets", lambda cmd: iter(()))
    monkeypatch.setattr(p2t, "_first_packet_time", lambda path: 1234.5)

    pcap = tmp_path / "cap.pcapng"
    pcap.write_bytes(b"\x00")
    keylog = tmp_path / "keys.log"
    keylog.write_text("")
    tap = tmp_path / "cap.tap"
    p2t.convert_pcap_to_tap(str(pcap), keylog_path=str(keylog), tap_path=str(tap))

    reader = TapReader(str(tap))
    reader.open()
    try:
        assert reader.header.capture_start == 1234.5
    finally:
        reader.close()
