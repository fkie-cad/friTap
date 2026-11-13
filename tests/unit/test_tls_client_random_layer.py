"""``TlsLayer.client_random``: the agent-stamped ClientHello random on TLS flows.

The live collector copies a datalog record's ``client_random`` onto the flow's
``tls`` layer (filling an empty value only), including flows of the connection
born before the agent knew it. The field is serialized only when non-empty, so
flows without it keep their pre-existing ``to_dict`` / .tap shape.
"""

from __future__ import annotations

from friTap.events import DatalogEvent, EventBus
from friTap.flow.collector import FlowCollector
from friTap.flow.layers import TlsLayer
from friTap.flow.models import Flow, FlowState
from friTap.flow.tap_format import decode_flow, encode_flow
from friTap.flow.tap_reader import TapReader
from friTap.flow.tap_writer import TapWriter

CLIENT_RANDOM = "5c" * 32

# -- Layer model --------------------------------------------------------------


def test_client_random_round_trips_through_dict():
    layer = TlsLayer.from_dict(TlsLayer(sni="example.com", client_random=CLIENT_RANDOM).to_dict())
    assert layer.client_random == CLIENT_RANDOM
    assert layer.sni == "example.com"


def test_layer_without_client_random_omits_key():
    assert "client_random" not in TlsLayer(sni="example.com").to_dict()


def test_old_dict_without_client_random_loads_empty():
    assert TlsLayer.from_dict({"name": "tls", "sni": "x"}).client_random == ""


def test_client_random_alone_makes_layer_non_empty():
    assert TlsLayer().is_empty()
    assert not TlsLayer(client_random=CLIENT_RANDOM).is_empty()


# -- .tap round-trip ----------------------------------------------------------


def _tls_flow(client_random: str = CLIENT_RANDOM) -> Flow:
    flow = Flow(flow_id="t-1", connection_id=f"cr:tls:{client_random}",
                state=FlowState.COMPLETE)
    flow.tls.client_random = client_random
    return flow


def test_encode_decode_preserves_client_random():
    assert decode_flow(encode_flow(_tls_flow())).tls.client_random == CLIENT_RANDOM


def test_tap_file_round_trip_preserves_client_random(tmp_path):
    path = str(tmp_path / "cr.tap")
    writer = TapWriter()
    writer.open(path, target="test")
    writer.write_flow(_tls_flow())
    writer.close()

    with TapReader(path) as reader:
        (summary,) = reader.read_flow_summaries()
        flow = reader.read_flow(summary.flow_id)
    assert flow.tls.client_random == CLIENT_RANDOM


# -- Live collector -----------------------------------------------------------


def _collector() -> tuple[EventBus, FlowCollector]:
    bus = EventBus()
    collector = FlowCollector(event_bus=bus)
    bus.subscribe(DatalogEvent, collector.on_data)
    return bus, collector


def _record(client_random: str = "", protocol: str = "tls", ts: float = 1000.0) -> DatalogEvent:
    return DatalogEvent(
        data=b"\x00\x01payload", function="SSL_write", direction="write",
        src_addr="10.0.0.2", src_port=52000, dst_addr="142.250.1.1", dst_port=443,
        client_random=client_random, protocol=protocol, timestamp=ts,
    )


def test_collector_stamps_client_random_from_datalog():
    bus, collector = _collector()
    bus.emit(_record(CLIENT_RANDOM))
    (flow,) = collector.get_flows()
    assert flow.tls.client_random == CLIENT_RANDOM


def test_collector_backfills_flow_born_before_client_random():
    bus, collector = _collector()
    bus.emit(_record())
    bus.emit(_record(CLIENT_RANDOM, ts=1000.1))
    (flow,) = collector.get_flows()
    assert flow.tls.client_random == CLIENT_RANDOM


def test_collector_never_overwrites_client_random():
    bus, collector = _collector()
    bus.emit(_record(CLIENT_RANDOM))
    (flow,) = collector.get_flows()
    collector._stamp_client_random(flow, _record("ff" * 32))
    assert flow.tls.client_random == CLIENT_RANDOM


def test_record_without_client_random_attaches_no_tls_field():
    bus, collector = _collector()
    bus.emit(_record())
    (flow,) = collector.get_flows()
    tls = flow.layer("tls")
    assert tls is None or tls.client_random == ""


def test_quic_flow_gets_no_tls_layer_from_client_random():
    bus, collector = _collector()
    bus.emit(_record(CLIENT_RANDOM, protocol="quic"))
    (flow,) = collector.get_flows()
    assert flow.layer("tls") is None
