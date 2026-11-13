#!/usr/bin/env python3

"""FlowCollector flags flows born on a synthetic (option 5) tuple and upgrades
them once to the real tuple carried as ``observed_*``; the ``.tap`` format
round-trips the ``endpoints_synthetic`` flag (written only when True)."""

from __future__ import annotations

from friTap.events import DatalogEvent, EventBus
from friTap.flow.collector import FlowCollector
from friTap.flow.models import Flow, FlowChunk, FlowState
from friTap.flow.synthetic_endpoint_upgrade import (
    observed_endpoint_map,
    upgrade_flow_endpoints,
)
from friTap.flow.tap_format import decode_flow, encode_flow

CLIENT_RANDOM = "5a" * 32
SYN_CLIENT = ("198.18.1.2", 50000)
SYN_SERVER = ("198.19.3.4", 443)
REAL_CLIENT = ("10.0.0.2", 41000)
REAL_SERVER = ("93.184.216.34", 443)


def _wire_up():
    bus = EventBus()
    collector = FlowCollector(event_bus=bus)
    bus.subscribe(DatalogEvent, collector.on_data)
    return bus, collector


def _record(direction="write", observed=False, timestamp=1000.0,
            data=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"):
    """A pinned record; a read travels server -> client, as the pinner emits it."""
    src, dst = (SYN_CLIENT, SYN_SERVER) if direction == "write" else (SYN_SERVER, SYN_CLIENT)
    real_src, real_dst = ((REAL_CLIENT, REAL_SERVER) if direction == "write"
                          else (REAL_SERVER, REAL_CLIENT))
    event = DatalogEvent(
        data=data, function="SSL_write" if direction == "write" else "SSL_read",
        direction=direction, src_addr=src[0], src_port=src[1],
        dst_addr=dst[0], dst_port=dst[1], client_random=CLIENT_RANDOM,
        endpoints_synthetic=True, timestamp=timestamp,
    )
    if observed:
        event.observed_src_addr, event.observed_src_port = real_src
        event.observed_dst_addr, event.observed_dst_port = real_dst
        event.observed_ss_family = "AF_INET"
    return event


def _endpoints(flow):
    return ((flow.src_addr, flow.src_port), (flow.dst_addr, flow.dst_port),
            (flow.local_addr, flow.local_port), (flow.remote_addr, flow.remote_port))


def test_flow_from_synthetic_record_is_flagged():
    bus, collector = _wire_up()
    bus.emit(_record())
    flow = collector.get_flows()[0]
    assert flow.endpoints_synthetic is True
    assert _endpoints(flow) == (SYN_CLIENT, SYN_SERVER, SYN_CLIENT, SYN_SERVER)


def test_real_record_flow_is_not_flagged():
    bus, collector = _wire_up()
    event = _record()
    event.endpoints_synthetic = False
    bus.emit(event)
    assert collector.get_flows()[0].endpoints_synthetic is False


def test_observed_read_upgrades_existing_flow_and_keeps_connection_key():
    bus, collector = _wire_up()
    bus.emit(_record())
    conn_id = collector.get_flows()[0].connection_id
    # The real tuple arrives on a read: reversed orientation, same mapping.
    bus.emit(_record(direction="read", observed=True, timestamp=1001.0,
                     data=b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
    flows = collector.get_flows()
    assert all(f.connection_id == conn_id for f in flows)
    assert conn_id.startswith("cr:")
    flow = flows[0]
    assert flow.endpoints_synthetic is False
    assert _endpoints(flow) == (REAL_CLIENT, REAL_SERVER, REAL_CLIENT, REAL_SERVER)


def test_upgrade_happens_once_first_real_tuple_wins():
    bus, collector = _wire_up()
    bus.emit(_record(observed=True))
    later = _record(observed=True, timestamp=1001.0)
    later.observed_src_addr = "10.9.9.9"
    bus.emit(later)
    flows = collector.get_flows()
    assert all((f.src_addr, f.src_port) == REAL_CLIENT for f in flows)
    assert all(not f.endpoints_synthetic for f in flows)


def test_flow_born_after_upgrade_starts_real():
    bus, collector = _wire_up()
    bus.emit(_record(observed=True))
    conn = next(iter(collector._connections.values()))
    newborn = collector._make_flow(conn, _record(timestamp=2000.0))
    assert newborn.endpoints_synthetic is False
    assert (newborn.src_addr, newborn.src_port) == REAL_CLIENT


def test_observed_map_needs_synthetic_flag_and_both_addresses():
    event = _record(observed=True)
    assert observed_endpoint_map(event) == {SYN_CLIENT: REAL_CLIENT, SYN_SERVER: REAL_SERVER}
    event.endpoints_synthetic = False
    assert observed_endpoint_map(event) is None
    assert observed_endpoint_map(_record()) is None


def test_upgrade_skips_flow_the_map_does_not_cover():
    flow = Flow(flow_id="f", connection_id="c", src_addr="198.18.9.9", src_port=1,
                dst_addr="198.19.9.9", dst_port=443, endpoints_synthetic=True)
    assert upgrade_flow_endpoints(flow, {SYN_CLIENT: REAL_CLIENT}) is False
    assert flow.endpoints_synthetic is True


def _tap_flow(synthetic: bool) -> Flow:
    flow = Flow(flow_id="f-1", connection_id="c-1", src_addr=SYN_CLIENT[0],
                src_port=SYN_CLIENT[1], dst_addr=SYN_SERVER[0], dst_port=SYN_SERVER[1],
                state=FlowState.COMPLETE, started=1000.0, ended=1001.0,
                endpoints_synthetic=synthetic)
    flow.chunks.append(FlowChunk(data=b"x" * 16, direction="write", timestamp=1000.0))
    return flow


def test_tap_roundtrip_endpoints_synthetic():
    assert decode_flow(encode_flow(_tap_flow(True))).endpoints_synthetic is True
    assert decode_flow(encode_flow(_tap_flow(False))).endpoints_synthetic is False
    assert b'"endpoints_synthetic"' not in encode_flow(_tap_flow(False))
