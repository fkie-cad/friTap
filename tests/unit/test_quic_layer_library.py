"""``QuicLayer.library`` mirrors ``TlsLayer.library`` for live QUIC flows.

The live collector stamps the detected TLS library onto the flow's transport
layer: ``flow.tls`` for TLS flows, ``flow.quic`` for QUIC flows, and nothing
for other transports (attribute access would attach a stray layer). The field
is serialized only when non-empty, so offline QUIC flows keep their old shape.
"""

from __future__ import annotations

import pytest

from friTap.events import DatalogEvent, EventBus, LibraryDetectedEvent
from friTap.filter.layer_fields import extract_filter_attrs
from friTap.flow.collector import FlowCollector
from friTap.flow.layers import QuicLayer
from friTap.flow.models import Flow, FlowState
from friTap.flow.tap_format import decode_flow, encode_flow
from friTap.flow.tap_reader import TapReader
from friTap.flow.tap_writer import TapWriter
from tests.unit._display_filter_helpers import match as _match

# -- Live collector -----------------------------------------------------------


def _collector_with_library(library: str) -> tuple[EventBus, FlowCollector]:
    bus = EventBus()
    collector = FlowCollector(event_bus=bus)
    bus.subscribe(DatalogEvent, collector.on_data)
    bus.subscribe(LibraryDetectedEvent, collector.on_library_detected)
    bus.emit(LibraryDetectedEvent(library=library))
    return bus, collector


def _live_flow(protocol: str, library: str = "BoringSSL") -> Flow:
    bus, collector = _collector_with_library(library)
    bus.emit(DatalogEvent(
        data=b"\x00\x01\x02\x03payload", function="hook", direction="write",
        src_addr="10.0.0.2", src_port=52000, dst_addr="142.250.1.1",
        dst_port=443, protocol=protocol, timestamp=1000.0,
    ))
    (flow,) = collector.get_flows()
    return flow


def test_live_quic_flow_gets_library_on_quic_layer():
    flow = _live_flow("quic", "BoringSSL")
    assert flow.transport == "quic"
    quic = flow.layer("quic")
    assert quic is not None and quic.library == "BoringSSL"
    assert flow.layer("tls") is None
    assert not _match("tls", flow)


def test_live_tls_flow_library_unchanged():
    flow = _live_flow("tls", "OpenSSL")
    tls = flow.layer("tls")
    assert tls is not None and tls.library == "OpenSSL"
    assert flow.layer("quic") is None


@pytest.mark.parametrize("protocol", ["mtproto", "telegram_e2e"])
def test_live_other_transport_gets_neither_layer(protocol):
    flow = _live_flow(protocol)
    assert flow.layer("tls") is None
    assert flow.layer("quic") is None


def test_no_library_event_leaves_quic_library_empty():
    bus = EventBus()
    collector = FlowCollector(event_bus=bus)
    bus.subscribe(DatalogEvent, collector.on_data)
    bus.emit(DatalogEvent(
        data=b"payload", function="hook", direction="write",
        src_addr="10.0.0.2", src_port=52001, dst_addr="142.250.1.1",
        dst_port=443, protocol="quic", timestamp=1000.0,
    ))
    (flow,) = collector.get_flows()
    quic = flow.layer("quic")
    assert quic is None or quic.library == ""


# -- QuicLayer dict round-trip ------------------------------------------------


def test_quic_layer_round_trip_with_library():
    layer = QuicLayer(library="BoringSSL", alpn="h3", version="1")
    d = layer.to_dict()
    assert d["library"] == "BoringSSL"
    restored = QuicLayer.from_dict(d)
    assert restored.library == "BoringSSL"
    assert restored.alpn == "h3" and restored.version == "1"


def test_quic_layer_without_library_omits_key():
    d = QuicLayer(alpn="h3").to_dict()
    assert "library" not in d
    assert QuicLayer.from_dict(d).library == ""


def test_quic_layer_old_dict_without_library_loads():
    old = {"name": "quic", "depth": 0, "version": "1", "sni": "a.example",
           "alpn": "h3", "cipher": "", "scid": "", "dcid": ""}
    assert QuicLayer.from_dict(old).library == ""


def test_library_alone_makes_quic_layer_non_empty():
    assert QuicLayer().is_empty()
    assert not QuicLayer(library="BoringSSL").is_empty()


# -- .tap round-trip ----------------------------------------------------------


def _quic_flow(library: str = "") -> Flow:
    flow = Flow(flow_id="q-1", connection_id="c-q", state=FlowState.COMPLETE)
    flow.transport = "quic"
    flow.quic.alpn = "h3"
    flow.quic.library = library
    return flow


def test_encode_decode_preserves_quic_library():
    decoded = decode_flow(encode_flow(_quic_flow("BoringSSL")))
    assert decoded.quic.library == "BoringSSL"
    assert decoded.layer("tls") is None


def test_encode_decode_without_quic_library():
    decoded = decode_flow(encode_flow(_quic_flow()))
    assert decoded.quic.library == ""
    assert decoded.quic.alpn == "h3"


def test_tap_file_round_trip_preserves_quic_library(tmp_path):
    path = str(tmp_path / "quic.tap")
    writer = TapWriter()
    writer.open(path, target="test")
    writer.write_flow(_quic_flow("BoringSSL"))
    writer.close()

    with TapReader(path) as reader:
        (summary,) = reader.read_flow_summaries()
        flow = reader.read_flow(summary.flow_id)

    assert flow.quic.library == "BoringSSL"
    assert _match('quic.library == "BoringSSL"', summary)
    assert _match('quic.library == "BoringSSL"', flow)


# -- Display filter -----------------------------------------------------------


def test_quic_library_filter_attr():
    attrs = extract_filter_attrs([QuicLayer(library="BoringSSL").to_dict()])
    assert attrs["quic.library"] == ("BoringSSL",)


def test_quic_library_filter_matches_flow():
    flow = _quic_flow("BoringSSL")
    assert _match('quic.library == "BoringSSL"', flow)
    assert not _match('quic.library == "OpenSSL"', flow)
    assert not _match('quic.library == "BoringSSL"', _quic_flow())
