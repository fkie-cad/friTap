"""Collector-level guard: QUIC stream bytes are never labelled HTTP/2/WebSocket."""

from friTap.events import DatalogEvent, EventBus
from friTap.flow.collector import FlowCollector
from tests.unit._h3_helpers import control_stream_bytes

_H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + b"\x00\x00\x00\x04\x00\x00\x00\x00\x00"


def _event(data: bytes, protocol: str, stream_id=2) -> DatalogEvent:
    return DatalogEvent(
        data=data, function="quic_stream", direction="write",
        src_addr="10.0.0.1", src_port=5000,
        dst_addr="93.184.216.34", dst_port=443,
        ssl_session_id=f"{protocol}-conn-1", protocol=protocol,
        transport="udp" if protocol == "quic" else "tcp",
        stream_id=stream_id if protocol == "quic" else None,
    )


def _collect(*events) -> list:
    bus = EventBus()
    collector = FlowCollector(event_bus=bus)
    bus.subscribe(DatalogEvent, collector.on_data)
    for event in events:
        bus.emit(event)
    collector.flush()
    return collector.get_flows()


def _labels(flows) -> set[str]:
    labels = set()
    for flow in flows:
        labels.add(flow.detected_protocol or "")
        for msg in (flow.request, flow.response):
            if msg is not None:
                labels.add(getattr(msg, "protocol", "") or "")
    return labels


def test_quic_control_stream_not_http2_or_websocket():
    flows = _collect(_event(control_stream_bytes(), "quic"))
    labels = _labels(flows)
    assert not any("HTTP/2" in lbl or "WebSocket" in lbl for lbl in labels), labels


def test_tls_h2_preface_still_http2():
    flows = _collect(_event(_H2_PREFACE, "tls"))
    assert any("HTTP/2" in lbl for lbl in _labels(flows))
