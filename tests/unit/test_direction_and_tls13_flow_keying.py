"""Regressions from end-to-end testing (CPython on macOS, legacy mode).

A. ``SSL_read_ex`` records were classified as writes: the message router only
   knew ``SSL_read``, and the flow collector trusts ``event.direction`` first,
   so every CPython response landed in the request direction. Direction now
   comes from ONE canonical classification in :mod:`friTap.constants`.

B. A TLS 1.3 connection split into two flows: ``SSL_write`` carries no session
   id yet (it only exists after the server's NewSessionTicket) and keyed as
   ``net:<4tuple>``, while ``SSL_read`` carried the id and keyed as ``sid:<id>``.
   A later-seen session id on a live 4-tuple is now aliased to that connection.
"""

from __future__ import annotations

import pytest

from friTap.connection_index import (
    ConnectionKeyAliases,
    has_usable_endpoints,
    resolve_connection_key,
)
from friTap.constants import (
    SSL_READ,
    SSL_WRITE,
    direction_for_function,
    is_read_function,
)
from friTap.events import SESSION_ENDED, DatalogEvent, EventBus, SessionEvent
from friTap.flow.collector import FlowCollector
from friTap.message_router import MessageRouter

CLIENT = ("192.168.1.10", 50123)
SERVER = ("93.184.215.14", 443)
SID = "AB" * 32

READ_LABELS = [
    "SSL_read", "SSL_read_ex", "wolfSSL_read", "gnutls_record_recv",
    "mbedtls_ssl_read", "PR_Read", "PR_Recv", "NSS_read", "s2n_recv",
    "DecryptMessage", "readApplicationData", "SSLRead", "Go_Conn_Read",
    "matrixSslReceivedData", "Full_read", "quiche_stream_recv",
    "QuicSpdyStream_OnDataFramePayload", "ssh_packet_read_poll2",
    "mtproto_decrypt", "SessionCipher.decrypt",
]
WRITE_LABELS = [
    "SSL_write", "SSL_write_ex", "wolfSSL_write", "gnutls_record_send",
    "mbedtls_ssl_write", "PR_Write", "PR_Send", "NSS_write", "s2n_send",
    "EncryptMessage", "writeApplicationData", "SSLWrite", "Go_Conn_Write",
    "matrixSslEncodeWritebuf", "Full_write", "quiche_stream_send",
    "QuicSpdyStream_WriteOrBufferBody", "ssh_packet_send2", "mtproto_encrypt",
]


# A: canonical direction classification ------------------------------------ #

@pytest.mark.parametrize("label", READ_LABELS)
def test_read_labels_classify_as_read(label):
    assert is_read_function(label)
    assert direction_for_function(label) == "read"


@pytest.mark.parametrize("label", WRITE_LABELS)
def test_write_labels_classify_as_write(label):
    assert not is_read_function(label)
    assert direction_for_function(label) == "write"


def test_read_and_write_sets_are_disjoint():
    assert not SSL_READ & SSL_WRITE


def test_signature_suffix_and_unknown_labels():
    assert is_read_function("SSL_read_ex(ssl, buf, n, &rd)")
    assert is_read_function("SomeLib_recv_record")  # heuristic fallback
    assert not is_read_function("SomeLib_send_record")
    assert not is_read_function("")


def test_explicit_agent_direction_wins():
    assert direction_for_function("mtproto_custom", "read") == "read"
    assert direction_for_function("SSL_read", "write") == "write"
    assert direction_for_function("SSL_read", "bogus") == "read"


def _router_datalog(function: str, **extra) -> DatalogEvent:
    bus = EventBus()
    seen: list[DatalogEvent] = []
    bus.subscribe(DatalogEvent, seen.append)
    payload = {
        "contentType": "datalog", "function": function, "ss_family": "AF_INET",
        "src_addr": "93.184.215.14", "src_port": 443,
        "dst_addr": "192.168.1.10", "dst_port": 50123, **extra,
    }
    MessageRouter(bus).route(payload, b"HTTP/1.1 200 OK\r\n\r\n")
    assert len(seen) == 1
    return seen[0]


def test_router_classifies_ssl_read_ex_as_read():
    assert _router_datalog("SSL_read_ex").direction == "read"


def test_router_classifies_ssl_write_ex_as_write():
    assert _router_datalog("SSL_write_ex").direction == "write"


# B: TLS 1.3 legacy keying -------------------------------------------------- #

def _datalog(direction, data, ssl_session_id="", timestamp=1000.0, addressed=True):
    if direction == "write":
        src, dst, function = CLIENT, SERVER, "SSL_write"
    else:
        src, dst, function = SERVER, CLIENT, "SSL_read_ex"
    if not addressed:
        src, dst = ("", 0), ("", 0)
    return DatalogEvent(
        data=data, function=function, direction=direction,
        src_addr=src[0], src_port=src[1], dst_addr=dst[0], dst_port=dst[1],
        ssl_session_id=ssl_session_id, timestamp=timestamp,
    )


REQUEST = b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
RESPONSE = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"


def _collector():
    bus = EventBus()
    collector = FlowCollector(event_bus=bus)
    bus.subscribe(DatalogEvent, collector.on_data)
    bus.subscribe(SessionEvent, collector.on_session_event)
    return bus, collector


def test_tls13_write_without_sid_then_read_with_sid_is_one_flow():
    bus, collector = _collector()
    bus.emit(_datalog("write", REQUEST))
    bus.emit(_datalog("read", RESPONSE, ssl_session_id=SID, timestamp=1000.1))
    collector.flush()

    flows = collector.get_flows()
    assert len(flows) == 1
    flow = flows[0]
    assert flow.connection_id == resolve_connection_key(*CLIENT, *SERVER)
    assert {c.direction for c in flow.chunks} == {"read", "write"}


def test_sid_only_record_follows_alias_and_end_event_closes_connection():
    bus, collector = _collector()
    bus.emit(_datalog("write", REQUEST))
    bus.emit(_datalog("read", RESPONSE[:20], ssl_session_id=SID, timestamp=1000.1))
    # A later record without addresses but with the session id joins too.
    bus.emit(_datalog("read", RESPONSE[20:], ssl_session_id=SID,
                      timestamp=1000.2, addressed=False))
    assert len({f.connection_id for f in collector.get_flows()}) == 1

    sid_key = resolve_connection_key(*SERVER, *CLIENT, session_token=SID)
    bus.emit(SessionEvent(event_type=SESSION_ENDED, connection_id=sid_key,
                          session_id=SID, timestamp=1001.0))
    assert collector._connections == {}


def test_sid_only_records_without_addresses_keep_sid_keying():
    bus, collector = _collector()
    bus.emit(_datalog("write", REQUEST, ssl_session_id=SID, addressed=False))
    flows = collector.get_flows()
    assert [f.connection_id for f in flows] == [f"sid:tls:{SID}"]


def test_client_random_keys_are_never_rekeyed():
    aliases = ConnectionKeyAliases()
    live = {"net:x"}.__contains__
    key = "cr:tls:" + "cd" * 32
    assert aliases.resolve(key, *CLIENT, *SERVER, "tls", live) == key


def test_finished_owner_no_longer_captures_its_tuple():
    aliases = ConnectionKeyAliases()
    net_key = resolve_connection_key(*CLIENT, *SERVER)
    sid_key = f"sid:tls:{SID}"
    assert aliases.resolve(net_key, *CLIENT, *SERVER, "tls", lambda k: True) == net_key
    assert aliases.resolve(sid_key, *SERVER, *CLIENT, "tls", lambda k: False) == sid_key


@pytest.mark.parametrize("addrs, expected", [
    (("10.0.0.1", 1, "10.0.0.2", 443), True),
    (("", 0, "", 0), False),
    (("0.0.0.0", 1, "10.0.0.2", 443), False),
    (("10.0.0.1", 0, "10.0.0.2", 443), False),
])
def test_has_usable_endpoints(addrs, expected):
    assert has_usable_endpoints(*addrs) is expected
