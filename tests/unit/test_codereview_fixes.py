#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Focused regression tests for five recently-fixed code-review bugs.

Pure Python — no device/Frida/tshark. Each test pins one fix so a future
refactor that reintroduces the bug fails loudly:

* #2  http2 split-headers: END_STREAM on a HEADERS frame that lacks
      END_HEADERS must survive the CONTINUATION and still finalize the stream.
* #4  collector orphan response ordering: an orphan complete response must
      emit CREATED before COMPLETED for the new flow.
* #5  models read-probe non-mutation: serializing / snapshotting a non-TLS
      flow must NOT attach an empty tls layer (writes still must).
* #6  tap_format finding bytes: encode_finding_record must hex-encode raw and
      oversized bytes instead of raising, and round-trip through decode.
* #1  message_router protocol coercion: protocol="" must coerce to the same
      connection key as protocol="tls" on both the lifecycle and data sites.
"""

from __future__ import annotations

import struct

import pytest

# --- BUG #2 imports (mirror tests/unit/test_http2_hpack.py) -----------------
from friTap.parsers.http2 import Http2Parser, _hpack_available

# --- BUG #4 imports (mirror test_flow_completion_lifecycle / session_meta) --
from friTap.events import DatalogEvent
from friTap.flow.collector import FlowCollector

# --- BUG #5 imports (mirror tests/unit/test_flow_layers.py) -----------------
from friTap.flow.models import Flow, FlowSummary
from friTap.flow.tap_format import (
    encode_flow,
    encode_finding_record,
    decode_finding_record,
)

# --- BUG #1 imports (mirror test_session_metadata_stamping.py) --------------
from friTap.connection_index import resolve_connection_key
from friTap.message_router import MessageRouter
from friTap.events import EventBus, SESSION_STARTED


# ===========================================================================
# BUG #2 — split-headers END_STREAM (friTap/parsers/http2.py)
# ===========================================================================

_HEADERS, _CONTINUATION = 0x01, 0x09
_END_STREAM, _END_HEADERS = 0x01, 0x04

pytestmark_h2 = pytest.mark.skipif(
    not _hpack_available, reason="hpack library not installed"
)


def _frame(ftype: int, flags: int, stream_id: int, payload: bytes) -> bytes:
    """Build a 9-byte-header HTTP/2 frame (copied from test_http2_hpack.py)."""
    return (struct.pack("!I", len(payload))[1:]  # 24-bit length
            + bytes([ftype, flags])
            + struct.pack("!I", stream_id)
            + payload)


def _encoder():
    from hpack import Encoder
    return Encoder()


def _final(results):
    completed = [r for r in results if r.is_complete]
    assert len(completed) == 1, f"expected one completed result, got {results}"
    return completed[0]


@pytestmark_h2
def test_split_headers_preserves_end_stream_across_continuation():
    """#2: HEADERS has END_STREAM but NOT END_HEADERS; the CONTINUATION carries
    the rest with END_HEADERS (CONTINUATION cannot carry END_STREAM). The stream
    must finalize as COMPLETE — the END_STREAM seen on the HEADERS frame must not
    be lost while the block buffers across the CONTINUATION."""
    parser = Http2Parser()
    enc = _encoder()
    block = enc.encode([(":method", "GET"), (":path", "/split"),
                        (":authority", "example.com")])
    half = len(block) // 2

    # HEADERS: END_STREAM set, END_HEADERS NOT set -> nothing completes yet.
    early = parser.feed(_frame(_HEADERS, _END_STREAM, 1, block[:half]), "write")
    assert [r for r in early if r.is_complete] == [], \
        "HEADERS without END_HEADERS must not complete yet"

    # CONTINUATION: END_HEADERS set, no END_STREAM (it cannot carry it).
    result = _final(parser.feed(
        _frame(_CONTINUATION, _END_HEADERS, 1, block[half:]), "write"
    ))
    assert result.is_complete is True, \
        "END_STREAM from the HEADERS frame was lost across the CONTINUATION"
    assert result.method == "GET"
    assert result.url == "/split"
    assert result.error == ""


@pytestmark_h2
def test_split_headers_without_end_stream_stays_incomplete():
    """#2 no-regression teeth: HEADERS WITHOUT END_STREAM continued by a
    CONTINUATION with END_HEADERS (but no END_STREAM) must yield an INCOMPLETE
    result — the headers decode but the stream is not finalized."""
    parser = Http2Parser()
    enc = _encoder()
    block = enc.encode([(":method", "POST"), (":path", "/upload"),
                        (":authority", "example.com")])
    half = len(block) // 2

    early = parser.feed(_frame(_HEADERS, 0x00, 1, block[:half]), "write")
    assert [r for r in early if r.is_complete] == []

    results = parser.feed(
        _frame(_CONTINUATION, _END_HEADERS, 1, block[half:]), "write"
    )
    assert [r for r in results if r.is_complete] == [], \
        "headers without END_STREAM must NOT finalize the stream"


# ===========================================================================
# BUG #4 — orphan complete-response CREATED-before-COMPLETED ordering
# ===========================================================================

_COMPLETE_RESPONSE = (
    b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n"
    b"Content-Type: text/plain\r\n\r\nhello"
)


def _response_only_event(*, timestamp=2000.0):
    """A read (response) DatalogEvent with NO preceding request/active flow."""
    return DatalogEvent(
        data=_COMPLETE_RESPONSE,
        function="SSL_read",
        direction="read",
        src_addr="10.0.0.9",
        src_port=52000,
        dst_addr="93.184.216.34",
        dst_port=443,
        ssl_session_id="orphan-sess",
        timestamp=timestamp,
    )


def test_orphan_complete_response_emits_created_before_completed():
    """#4: a self-contained complete response with no matching request creates a
    new orphan flow. Subscribers (drained FIFO) must see CREATED before
    COMPLETED for that flow_id — never a COMPLETED for a flow whose CREATED has
    not yet been delivered."""
    fc = FlowCollector()
    events: list[tuple[str, str]] = []
    fc.subscribe(lambda flow, et: events.append((et.value, flow.flow_id)))

    fc.on_data(_response_only_event())

    # Locate the orphan flow and the indices of its CREATED / COMPLETED.
    created = [i for i, (et, _) in enumerate(events) if et == "created"]
    completed = [i for i, (et, _) in enumerate(events) if et == "completed"]
    assert created, "no CREATED event emitted for the orphan response flow"
    assert completed, "orphan complete response did not emit COMPLETED"

    flow_id = events[completed[0]][1]
    created_idx = next(i for i, (et, fid) in enumerate(events)
                       if et == "created" and fid == flow_id)
    completed_idx = next(i for i, (et, fid) in enumerate(events)
                         if et == "completed" and fid == flow_id)
    assert created_idx < completed_idx, \
        "COMPLETED was delivered before CREATED for the orphan flow"


# ===========================================================================
# BUG #5 — read-probe non-mutation (friTap/flow/models.py + tap_format.py)
# ===========================================================================

def test_encode_flow_does_not_attach_tls_layer_to_non_tls_flow():
    """#5(a): encoding a non-TLS (quic) flow is a pure read; it must use the
    non-mutating layer() lookup and NOT grow an empty tls layer onto the flow."""
    flow = Flow(flow_id="q1", connection_id="cq1", transport="quic")
    assert flow.layer("tls") is None  # precondition: no tls layer yet

    payload = encode_flow(flow)
    assert isinstance(payload, (bytes, bytearray))
    assert flow.layer("tls") is None, \
        "encode_flow attached an empty tls layer to a non-TLS flow"


def test_flow_summary_does_not_attach_tls_layer_to_non_tls_flow():
    """#5(b): FlowSummary.from_flow is a snapshot (pure read). It must report an
    empty tls_sni for a non-TLS flow WITHOUT materializing a tls layer."""
    flow = Flow(flow_id="q2", connection_id="cq2", transport="quic")
    assert flow.layer("tls") is None

    summary = FlowSummary.from_flow(flow)
    assert summary.tls_sni == ""
    assert flow.layer("tls") is None, \
        "FlowSummary.from_flow attached an empty tls layer to a non-TLS flow"


def test_tls_write_ergonomic_still_materializes_layer():
    """#5(c) sanity: the never-None WRITE path must still work — assigning a
    field via flow.tls materializes and persists the tls layer."""
    flow = Flow(flow_id="t1", connection_id="ct1", transport="quic")
    assert flow.layer("tls") is None

    flow.tls.version = "TLS 1.3"
    assert flow.layer("tls") is not None, "write via flow.tls did not persist"
    assert flow.layer("tls").version == "TLS 1.3"


# ===========================================================================
# BUG #6 — finding evidence bytes (friTap/flow/tap_format.py)
# ===========================================================================

def test_encode_finding_record_hex_encodes_bytes_and_round_trips():
    """#6: a finding whose evidence holds short raw bytes and oversized bytes
    (alongside normal str/int) must encode without raising; bytes become hex
    strings and the record round-trips through decode_finding_record."""
    finding = {
        "severity": "high",
        "title": "binary-token",
        "evidence": {
            "match": b"\x01\x02",        # short raw bytes -> "0102"
            "big": b"A" * 600,           # oversized -> truncated hex
            "label": "token",            # normal str passes through
            "count": 3,                  # normal int passes through
        },
    }

    payload = encode_finding_record("flow-7", [finding])
    assert isinstance(payload, (bytes, bytearray))

    flow_id, findings = decode_finding_record(payload)
    assert flow_id == "flow-7"
    assert len(findings) == 1
    evidence = findings[0]["evidence"]
    assert evidence["match"] == "0102"           # short bytes -> hex string
    assert isinstance(evidence["big"], str)       # oversized -> hex string
    assert evidence["big"].startswith("41")       # b"A" == 0x41
    assert evidence["label"] == "token"
    assert evidence["count"] == 3


# ===========================================================================
# BUG #1 — protocol key coercion (friTap/message_router.py)
# ===========================================================================

SRC_ADDR = "10.0.0.2"
SRC_PORT = 51000
DST_ADDR = "93.184.216.34"
DST_PORT = 443
CR = "cd" * 32  # 64 hex chars


def _empty_protocol_lifecycle_payload(client_random):
    """A connection_lifecycle payload with an EMPTY protocol string."""
    return {
        "contentType": "connection_lifecycle",
        "event": SESSION_STARTED,
        "src_addr": SRC_ADDR,
        "src_port": SRC_PORT,
        "dst_addr": DST_ADDR,
        "dst_port": DST_PORT,
        "ss_family": "AF_INET",
        "client_random": client_random,
        "ssl_session_id": "",
        "protocol": "",  # the coercion under test
    }


def test_empty_protocol_coerces_to_tls_key_contract():
    """#1 (contract): resolve_connection_key with protocol="" must NOT produce a
    ``cr::`` key. The router/collector coerce ``payload.get("protocol") or "tls"``
    so "" must resolve to the SAME key as an explicit "tls"."""
    coerced = resolve_connection_key(
        SRC_ADDR, SRC_PORT, DST_ADDR, DST_PORT,
        session_token="", client_random=CR,
        protocol="" or "tls",
    )
    explicit_tls = resolve_connection_key(
        SRC_ADDR, SRC_PORT, DST_ADDR, DST_PORT,
        session_token="", client_random=CR,
        protocol="tls",
    )
    assert coerced == explicit_tls == f"cr:tls:{CR}"


def test_empty_protocol_lifecycle_matches_data_event_key():
    """#1 (real router + collector): a lifecycle payload with protocol="" routed
    through MessageRouter must emit a connection_id whose prefix matches what
    FlowCollector.on_data builds for a DatalogEvent with protocol="" on the same
    4-tuple/client_random. Both must coerce "" -> "tls"."""
    bus = EventBus()
    collector = FlowCollector(event_bus=bus)
    bus.subscribe(DatalogEvent, collector.on_data)
    from friTap.events import SessionEvent
    bus.subscribe(SessionEvent, collector.on_session_event)
    router = MessageRouter(bus)

    captured = {}
    bus.subscribe(SessionEvent,
                  lambda ev: captured.update(connection_id=ev.connection_id))

    # Lifecycle side: protocol="" -> must coerce to a tls key.
    router.route(_empty_protocol_lifecycle_payload(CR), b"")

    # Data side: a DatalogEvent with protocol="" on the same 4-tuple/client_random.
    data_event = DatalogEvent(
        data=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
        function="SSL_write",
        direction="write",
        src_addr=SRC_ADDR,
        src_port=SRC_PORT,
        dst_addr=DST_ADDR,
        dst_port=DST_PORT,
        client_random=CR,
        protocol="",
        timestamp=3000.0,
    )
    bus.emit(data_event)

    flows = collector.get_flows()
    assert len(flows) == 1
    data_key = flows[0].connection_id
    assert data_key == f"cr:tls:{CR}"
    assert captured["connection_id"] == data_key, \
        "lifecycle and data sites disagreed on the coerced protocol key"


# ===========================================================================
# BUG #8 — per-connection flow index (O(streams x flows) scans -> O(1) lookup)
# ===========================================================================

_IDX_SRC, _IDX_DST = "10.0.0.5", "93.184.216.34"


def _assert_index_mirrors_flows(fc):
    """The per-connection index must EXACTLY mirror _flows grouped by conn_id —
    no missing flow, no stale id, no dangling empty list."""
    expected: dict[str, list[str]] = {}
    for fid, flow in fc._flows.items():
        expected.setdefault(flow.connection_id, []).append(fid)
    assert set(fc._flow_index) == set(expected), \
        f"index conns {set(fc._flow_index)} != flows conns {set(expected)}"
    for cid, ids in expected.items():
        assert sorted(fc._flow_index[cid]) == sorted(ids), \
            f"index[{cid}] {fc._flow_index[cid]} != flows {ids}"
    assert all(ids for ids in fc._flow_index.values()), \
        "index left a dangling empty list (it must be pruned on removal)"


def _meta_session_event(conn_id, *, sni="example.com"):
    """An offline-style metadata-bearing SessionEvent (the only kind that
    reaches the stamp scan — the live path carries no metadata)."""
    from friTap.events import SessionEvent
    return SessionEvent(
        connection_id=conn_id,
        event_type=SESSION_STARTED,
        server_name=sni,
        protocol_version="TLS 1.3",
        alpn="h2",
        cipher_suite="TLS_AES_128_GCM_SHA256",
    )


def test_stamp_reaches_all_flows_on_one_connection():
    """#8: the index-based stamp loop must reach EVERY flow on a connection, not
    just one. Two flows sharing a conn_id must BOTH get metadata stamped — a
    regression where the index missed a flow would leave the second unstamped."""
    fc = FlowCollector()
    f0 = fc.add_synthetic_flow(src_addr=_IDX_SRC, src_port=51000,
                               dst_addr=_IDX_DST, dst_port=443)
    f1 = fc.add_synthetic_flow(src_addr=_IDX_SRC, src_port=51000,
                               dst_addr=_IDX_DST, dst_port=443)
    assert f0.connection_id == f1.connection_id  # same endpoints -> same conn
    assert f0.flow_id.endswith(":0") and f1.flow_id.endswith(":1")

    fc.on_session_event(_meta_session_event(f0.connection_id))

    by_id = {f.flow_id: f for f in fc.get_flows()}
    assert by_id[f0.flow_id].tls.sni == "example.com"
    assert by_id[f1.flow_id].tls.sni == "example.com", \
        "the second flow on the connection was not reached by the stamp loop"
    _assert_index_mirrors_flows(fc)


def test_synthetic_flow_sequence_numbers_via_index():
    """#8: add_synthetic_flow now derives its per-connection sequence from the
    index length (O(1)) instead of an O(n) scan; numbering must be unchanged."""
    fc = FlowCollector()
    a = fc.add_synthetic_flow(src_addr=_IDX_SRC, src_port=51000,
                              dst_addr=_IDX_DST, dst_port=443)
    b = fc.add_synthetic_flow(src_addr=_IDX_SRC, src_port=51000,
                              dst_addr=_IDX_DST, dst_port=443)
    c = fc.add_synthetic_flow(src_addr=_IDX_SRC, src_port=51000,
                              dst_addr=_IDX_DST, dst_port=8443)  # diff endpoint
    assert a.flow_id.endswith(":0")
    assert b.flow_id.endswith(":1")
    assert c.flow_id.endswith(":0")  # different conn -> its own sequence
    _assert_index_mirrors_flows(fc)


def test_flow_index_consistent_across_create_and_orphan_merge():
    """#8: the index must stay a faithful mirror across the data-driven add path
    AND the orphan-merge REMOVE path. Sending a response before its request makes
    a response-only orphan flow; a later request-only flow to the same dst is
    merged at flush(), deleting the response-only flow from _flows — the index
    must drop it too (no stale id, no dangling conn)."""
    fc = FlowCollector()
    # Response first (no request yet) -> a response-only orphan flow is created.
    fc.on_data(DatalogEvent(
        data=b"HTTP/1.1 204 No Content\r\n\r\n", function="SSL_read",
        direction="read", src_addr=_IDX_SRC, src_port=40002,
        dst_addr=_IDX_DST, dst_port=443, timestamp=1000.0))
    # Then a request-only flow to the same destination on a different 4-tuple.
    fc.on_data(DatalogEvent(
        data=b"GET /a HTTP/1.1\r\nHost: h\r\n\r\n", function="SSL_write",
        direction="write", src_addr=_IDX_SRC, src_port=40001,
        dst_addr=_IDX_DST, dst_port=443, timestamp=1000.2))
    _assert_index_mirrors_flows(fc)
    assert len(fc._flows) == 2

    fc.flush()  # orphan merge removes the response-only flow
    assert len(fc._flows) == 1, "orphan merge should have collapsed the two flows"
    _assert_index_mirrors_flows(fc)
