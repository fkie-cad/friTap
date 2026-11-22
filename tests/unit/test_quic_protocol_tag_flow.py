"""QUIC records tagged ``quic`` end to end: agent payload -> router -> collector.

The agent tags Chromium QUICHE data and lifecycle records ``quic`` (not
``tls``), so a QuicConnection becomes a ``sid:quic:`` flow with transport
``quic``, its HTTP/3 streams are parsed, and session metadata lands on
``flow.quic``.
"""

from friTap.connection_index import resolve_connection_key
from friTap.events import SESSION_DESTROYED, SESSION_STARTED, DatalogEvent, EventBus, SessionEvent
from friTap.flow.collector import FlowCollector
from friTap.message_router import MessageRouter
from tests.unit.test_collector_quiche_frame_streams import DEVICE, SERVER, _chrome_like_session

QUIC_CONNECTION = "0x72004e7c00"


def _wire_up():
    bus = EventBus()
    collector = FlowCollector(event_bus=bus)
    bus.subscribe(DatalogEvent, collector.on_data)
    bus.subscribe(SessionEvent, collector.on_session_event)
    seen = []
    bus.subscribe(SessionEvent, seen.append)
    return collector, MessageRouter(bus, active_protocol=["tls"]), seen


def _endpoints(direction: str) -> dict:
    src, dst = (DEVICE, SERVER) if direction == "write" else (SERVER, DEVICE)
    return {"src_addr": src[0], "src_port": src[1], "dst_addr": dst[0], "dst_port": dst[1],
            "ss_family": "AF_INET"}


def _datalog_payload(event: DatalogEvent) -> dict:
    return {
        "contentType": "datalog", "protocol": "quic", "function": event.function,
        "direction": event.direction, "ssl_session_id": QUIC_CONNECTION, "transport": "udp",
        "stream_id": event.stream_id, "quic_payload": event.quic_payload,
        "library": event.library, **_endpoints(event.direction),
    }


def _lifecycle_payload(event: str) -> dict:
    return {"contentType": "connection_lifecycle", "event": event, "protocol": "quic",
            "ssl_session_id": QUIC_CONNECTION, **_endpoints("read")}


def _route_session(router: MessageRouter) -> None:
    for event in _chrome_like_session():
        router.route(_datalog_payload(event), event.data)


def _request_flows(collector: FlowCollector) -> list:
    return [f for f in collector.get_flows()
            if f.request is not None and f.request.method in ("GET", "POST")]


def test_quic_tagged_records_become_a_quic_flow_with_http3_parsed():
    collector, router, _ = _wire_up()
    _route_session(router)
    flows = _request_flows(collector)
    assert {f.request.method for f in flows} == {"GET", "POST"}
    for flow in flows:
        assert flow.connection_id == f"sid:quic:{QUIC_CONNECTION}"
        assert flow.transport == "quic"
        assert flow.layer("tls") is None
    get = next(f for f in flows if f.request.method == "GET")
    assert get.response is not None and get.response.status_code == 200


def test_lifecycle_keys_to_the_same_connection_as_the_data():
    collector, router, seen = _wire_up()
    router.route(_lifecycle_payload("created"), b"")
    _route_session(router)
    router.route(_lifecycle_payload(SESSION_DESTROYED), b"")
    assert {e.connection_id for e in seen} == {f"sid:quic:{QUIC_CONNECTION}"}
    assert {e.protocol for e in seen} == {"quic"}
    assert f"sid:quic:{QUIC_CONNECTION}" not in collector._connections


def test_session_metadata_lands_on_the_quic_layer():
    collector, router, _ = _wire_up()
    _route_session(router)
    conn_id = resolve_connection_key(*DEVICE, *SERVER, session_token=QUIC_CONNECTION,
                                     protocol="quic")
    collector.on_session_event(SessionEvent(
        event_type=SESSION_STARTED, connection_id=conn_id, session_id=QUIC_CONNECTION,
        server_name="www.google.com", alpn="h3", cipher_suite="TLS_AES_128_GCM_SHA256",
        quic_version="1", protocol="quic",
        src_addr=DEVICE[0], src_port=DEVICE[1], dst_addr=SERVER[0], dst_port=SERVER[1],
    ))
    for flow in _request_flows(collector):
        assert (flow.quic.sni, flow.quic.alpn, flow.quic.version) == ("www.google.com", "h3", "1")
        assert flow.quic.cipher == "TLS_AES_128_GCM_SHA256"
        assert flow.layer("tls") is None
