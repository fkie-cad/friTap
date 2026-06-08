"""Unit tests for SessionEvent connection-keying + TLS metadata stamping.

Regression coverage for the bug where MessageRouter._emit_lifecycle built a
plain "src:port-dst:port" connection_id while FlowCollector keys flows via
resolve_connection_key (cr:/sid:/net:). The mismatch made TLS-metadata
stamping (version/sni/alpn/cipher) and the ENDED/DESTROYED removal path
dead-on-arrival. These tests prove the keys now agree.

METADATA IS OFFLINE-ONLY: the live MessageRouter lifecycle path carries NO TLS
metadata (it emits identity + lifecycle only). The _stamp_tls_metadata mechanism
is exercised here via SessionEvents emitted DIRECTLY on the bus, exactly as the
offline pcap->tap producer emits them. A dedicated test pins the live router's
no-metadata contract.
"""

from friTap.connection_index import resolve_connection_key
from friTap.events import (
    DatalogEvent,
    EventBus,
    SESSION_ENDED,
    SESSION_STARTED,
)
from friTap.flow.collector import FlowCollector
from friTap.message_router import MessageRouter


SRC_ADDR = "10.0.0.2"
SRC_PORT = 51000
DST_ADDR = "93.184.216.34"
DST_PORT = 443
CLIENT_RANDOM = "ab" * 32  # 64 hex chars, unique per connection


def _make_datalog(client_random="", ssl_session_id="", timestamp=1000.0):
    """A write DatalogEvent that creates a flow on the matching 4-tuple."""
    return DatalogEvent(
        data=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
        function="SSL_write",
        direction="write",
        src_addr=SRC_ADDR,
        src_port=SRC_PORT,
        dst_addr=DST_ADDR,
        dst_port=DST_PORT,
        ssl_session_id=ssl_session_id,
        client_random=client_random,
        timestamp=timestamp,
    )


def _lifecycle_payload(event, *, client_random="", ssl_session_id="",
                       server_name="example.com", protocol_version="TLS 1.3",
                       alpn="h2", cipher_suite="TLS_AES_128_GCM_SHA256"):
    return {
        "contentType": "connection_lifecycle",
        "event": event,
        "src_addr": SRC_ADDR,
        "src_port": SRC_PORT,
        "dst_addr": DST_ADDR,
        "dst_port": DST_PORT,
        "ss_family": "AF_INET",
        "client_random": client_random,
        "ssl_session_id": ssl_session_id,
        "server_name": server_name,
        "protocol_version": protocol_version,
        "alpn": alpn,
        "cipher_suite": cipher_suite,
        "protocol": "tls",
    }


def _offline_session_event(event, *, connection_id, client_random="",
                           ssl_session_id="", server_name="example.com",
                           protocol_version="TLS 1.3", alpn="h2",
                           cipher_suite="TLS_AES_128_GCM_SHA256"):
    """A metadata-bearing SessionEvent as the OFFLINE producer emits it.

    Direct on the bus, carrying TLS handshake metadata + a pre-resolved
    connection_id. The live MessageRouter lifecycle path never carries this
    metadata (offline-only rule), so stamping coverage drives the mechanism the
    way the offline pcap->tap pipeline does.
    """
    from friTap.events import SessionEvent
    return SessionEvent(
        session_id=ssl_session_id,
        event_type=event,
        connection_id=connection_id,
        client_random=client_random,
        server_name=server_name,
        protocol_version=protocol_version,
        alpn=alpn,
        cipher_suite=cipher_suite,
        src_addr=SRC_ADDR, src_port=SRC_PORT,
        dst_addr=DST_ADDR, dst_port=DST_PORT,
        protocol="tls",
    )


def _wire_up():
    bus = EventBus()
    collector = FlowCollector(event_bus=bus)
    bus.subscribe(DatalogEvent, collector.on_data)
    from friTap.events import SessionEvent
    bus.subscribe(SessionEvent, collector.on_session_event)
    router = MessageRouter(bus)
    return bus, collector, router


def test_lifecycle_connection_id_matches_resolver():
    """_emit_lifecycle must emit the canonical resolve_connection_key, not the
    plain src:port-dst:port string."""
    bus, _collector, router = _wire_up()
    captured = {}
    from friTap.events import SessionEvent
    bus.subscribe(SessionEvent, lambda ev: captured.update(connection_id=ev.connection_id))

    router.route(_lifecycle_payload(SESSION_STARTED, client_random=CLIENT_RANDOM), b"")

    expected = resolve_connection_key(
        SRC_ADDR, SRC_PORT, DST_ADDR, DST_PORT,
        session_token="", client_random=CLIENT_RANDOM,
    )
    assert captured["connection_id"] == expected
    assert captured["connection_id"] == f"cr:tls:{CLIENT_RANDOM}"


def test_session_started_stamps_tls_metadata_via_client_random():
    """A DatalogEvent creates a flow, then a STARTED SessionEvent (as the offline
    producer emits it) carrying the same client_random key stamps
    SNI/version/ALPN/cipher onto that flow."""
    bus, collector, _router = _wire_up()

    # 1. Data event -> creates a flow keyed by resolve_connection_key.
    bus.emit(_make_datalog(client_random=CLIENT_RANDOM))
    flows = collector.get_flows()
    assert len(flows) == 1
    flow = flows[0]
    assert not flow.tls.sni and not flow.tls.version and not flow.tls.alpn

    # 2. Offline-style SessionEvent (metadata-bearing) with the SAME conn key.
    conn_id = resolve_connection_key(
        SRC_ADDR, SRC_PORT, DST_ADDR, DST_PORT,
        session_token="", client_random=CLIENT_RANDOM,
    )
    bus.emit(_offline_session_event(SESSION_STARTED, connection_id=conn_id,
                                    client_random=CLIENT_RANDOM))

    stamped = collector.get_flows()[0]
    assert stamped.tls.sni == "example.com"
    assert stamped.tls.version == "TLS 1.3"
    assert stamped.tls.alpn == "h2"
    assert stamped.tls.cipher == "TLS_AES_128_GCM_SHA256"


def test_session_started_stamps_via_session_token():
    """Same proof but through the sid: tier (no client_random, real session id),
    metadata delivered the offline way (a direct SessionEvent)."""
    bus, collector, _router = _wire_up()
    session_id = "DEADBEEF" * 4  # a real (non-dummy) token

    bus.emit(_make_datalog(ssl_session_id=session_id))
    assert len(collector.get_flows()) == 1

    conn_id = resolve_connection_key(
        SRC_ADDR, SRC_PORT, DST_ADDR, DST_PORT,
        session_token=session_id, client_random="",
    )
    bus.emit(_offline_session_event(SESSION_STARTED, connection_id=conn_id,
                                    ssl_session_id=session_id,
                                    server_name="api.example.com"))
    stamped = collector.get_flows()[0]
    assert stamped.tls.sni == "api.example.com"
    assert stamped.connection_id == f"sid:tls:{session_id}"


def test_live_lifecycle_carries_no_metadata():
    """METADATA IS OFFLINE-ONLY: even when the agent payload contains TLS
    metadata, the live MessageRouter lifecycle must emit a SessionEvent with
    EMPTY cipher_suite/protocol_version/server_name/alpn (identity + lifecycle
    only). Guards against re-introducing live metadata reads."""
    bus, _collector, router = _wire_up()
    captured = {}
    from friTap.events import SessionEvent
    bus.subscribe(SessionEvent, lambda ev: captured.update(
        cipher_suite=ev.cipher_suite, protocol_version=ev.protocol_version,
        server_name=ev.server_name, alpn=ev.alpn,
        connection_id=ev.connection_id))

    # The payload DOES contain metadata; the live router must drop all of it.
    router.route(_lifecycle_payload(
        SESSION_STARTED, client_random=CLIENT_RANDOM,
        server_name="example.com", protocol_version="TLS 1.3",
        alpn="h2", cipher_suite="TLS_AES_128_GCM_SHA256"), b"")

    assert captured["cipher_suite"] == ""
    assert captured["protocol_version"] == ""
    assert captured["server_name"] == ""
    assert captured["alpn"] == ""
    # Identity/keying still flow through unchanged.
    assert captured["connection_id"] == f"cr:tls:{CLIENT_RANDOM}"


def test_session_ended_removes_connection():
    """The ENDED path must locate and remove the matching connection."""
    bus, collector, router = _wire_up()

    bus.emit(_make_datalog(client_random=CLIENT_RANDOM))
    conn_key = resolve_connection_key(
        SRC_ADDR, SRC_PORT, DST_ADDR, DST_PORT,
        session_token="", client_random=CLIENT_RANDOM,
    )
    assert conn_key in collector._connections

    router.route(_lifecycle_payload(SESSION_ENDED, client_random=CLIENT_RANDOM), b"")

    assert conn_key not in collector._connections
    # The flow itself survives, marked complete.
    flows = collector.get_flows()
    assert len(flows) == 1
    assert flows[0].connection_id == conn_key


# ---------------------------------------------------------------------------
# #46 — protocol must flow into the connection key on BOTH sites
# ---------------------------------------------------------------------------

QUIC_CLIENT_RANDOM = "ef" * 32  # 64 hex chars, distinct from the TLS test


def test_quic_session_and_data_resolve_to_same_quic_key():
    """A QUIC SessionEvent (via MessageRouter) and a QUIC DatalogEvent for the
    SAME 4-tuple/client_random must resolve to the SAME conn_id, and that key
    must carry the ``quic`` protocol prefix — not ``tls``."""
    bus, collector, router = _wire_up()

    captured = {}
    from friTap.events import SessionEvent
    bus.subscribe(SessionEvent, lambda ev: captured.update(connection_id=ev.connection_id))

    # Lifecycle side: payload declares protocol "quic".
    quic_payload = _lifecycle_payload(SESSION_STARTED, client_random=QUIC_CLIENT_RANDOM)
    quic_payload["protocol"] = "quic"
    router.route(quic_payload, b"")

    # Data side: a QUIC DatalogEvent (protocol="quic", udp transport).
    quic_data = DatalogEvent(
        data=b"\x00\x01\x02",
        function="SSL_write",
        direction="write",
        src_addr=SRC_ADDR,
        src_port=SRC_PORT,
        dst_addr=DST_ADDR,
        dst_port=DST_PORT,
        client_random=QUIC_CLIENT_RANDOM,
        transport="udp",
        protocol="quic",
        timestamp=2000.0,
    )
    bus.emit(quic_data)

    # The flow created by the data event is keyed with the quic prefix...
    flows = collector.get_flows()
    assert len(flows) == 1
    data_key = flows[0].connection_id
    assert data_key == f"cr:quic:{QUIC_CLIENT_RANDOM}"
    # ...and the lifecycle event resolved to the SAME key.
    assert captured["connection_id"] == data_key


# ---------------------------------------------------------------------------
# #35 — SessionEvent.cipher reads through to cipher_suite (single source)
# ---------------------------------------------------------------------------

def test_session_event_cipher_reflects_cipher_suite():
    """The public ``.cipher`` accessor must remain readable and mirror
    ``cipher_suite`` so consumers see one authoritative value."""
    from friTap.events import SessionEvent

    ev = SessionEvent(event_type=SESSION_STARTED, cipher_suite="TLS_AES_128_GCM_SHA256")
    assert ev.cipher == "TLS_AES_128_GCM_SHA256"

    # Empty cipher_suite -> empty cipher (no stale/drifted value).
    ev_empty = SessionEvent(event_type=SESSION_STARTED)
    assert ev_empty.cipher == ""
