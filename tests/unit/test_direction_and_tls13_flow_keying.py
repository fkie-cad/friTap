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


# C: client_random (cr:) keys join the 4-tuple aliasing ---------------------- #
#
# Chromium records lack the client_random until the agent's SSL layout lookup
# resolves, so one connection keys first as net:<4tuple> and later as
# cr:<client_random>. Those must stay ONE connection (one flow stack, one
# HTTP/2 parser with its HPACK state), while a different client_random on the
# same 4-tuple is a new connection reusing the port.

CR_A = "a1" * 32
CR_B = "b2" * 32


def _cr_key(client_random: str) -> str:
    return f"cr:tls:{client_random}"


def test_cr_key_aliases_to_live_net_owner_of_its_tuple():
    aliases = ConnectionKeyAliases()
    net_key = resolve_connection_key(*CLIENT, *SERVER)
    live = {net_key}.__contains__
    assert aliases.resolve(net_key, *CLIENT, *SERVER, "tls", live) == net_key
    assert aliases.resolve(_cr_key(CR_A), *SERVER, *CLIENT, "tls", live) == net_key
    # A later address-less record with the same client_random follows the alias.
    assert aliases.resolve(_cr_key(CR_A), "", 0, "", 0, "tls", live) == net_key


def test_cr_key_claims_tuple_for_later_records_without_cr():
    aliases = ConnectionKeyAliases()
    cr_key = _cr_key(CR_A)
    live = {cr_key}.__contains__
    assert aliases.resolve(cr_key, *CLIENT, *SERVER, "tls", live) == cr_key
    net_key = resolve_connection_key(*SERVER, *CLIENT)
    assert aliases.resolve(net_key, *SERVER, *CLIENT, "tls", live) == cr_key


def test_different_cr_key_on_live_cr_owner_is_a_new_connection():
    aliases = ConnectionKeyAliases()
    live = {_cr_key(CR_A), _cr_key(CR_B)}.__contains__
    assert aliases.resolve(_cr_key(CR_A), *CLIENT, *SERVER, "tls", live) == _cr_key(CR_A)
    assert aliases.resolve(_cr_key(CR_B), *CLIENT, *SERVER, "tls", live) == _cr_key(CR_B)
    # The newer connection now owns the 4-tuple.
    net_key = resolve_connection_key(*CLIENT, *SERVER)
    assert aliases.resolve(net_key, *CLIENT, *SERVER, "tls", live) == _cr_key(CR_B)


def test_net_owner_absorbs_only_one_client_random():
    aliases = ConnectionKeyAliases()
    net_key = resolve_connection_key(*CLIENT, *SERVER)
    live = {net_key, _cr_key(CR_A), _cr_key(CR_B)}.__contains__
    aliases.resolve(net_key, *CLIENT, *SERVER, "tls", live)
    assert aliases.resolve(_cr_key(CR_A), *CLIENT, *SERVER, "tls", live) == net_key
    assert aliases.resolve(_cr_key(CR_B), *CLIENT, *SERVER, "tls", live) == _cr_key(CR_B)


def _cr_datalog(direction, data, client_random="", timestamp=1000.0):
    event = _datalog(direction, data, timestamp=timestamp)
    event.client_random = client_random
    return event


def test_net_then_cr_records_are_one_flow():
    bus, collector = _collector()
    bus.emit(_cr_datalog("write", REQUEST))
    bus.emit(_cr_datalog("read", RESPONSE, client_random=CR_A, timestamp=1000.1))
    collector.flush()

    (flow,) = collector.get_flows()
    assert flow.connection_id == resolve_connection_key(*CLIENT, *SERVER)
    assert {c.direction for c in flow.chunks} == {"read", "write"}
    assert flow.tls.client_random == CR_A


def test_cr_then_no_cr_records_are_one_flow():
    bus, collector = _collector()
    bus.emit(_cr_datalog("write", REQUEST, client_random=CR_A))
    bus.emit(_cr_datalog("read", RESPONSE, timestamp=1000.1))
    collector.flush()

    (flow,) = collector.get_flows()
    assert flow.connection_id == _cr_key(CR_A)
    assert {c.direction for c in flow.chunks} == {"read", "write"}
    assert flow.tls.client_random == CR_A


def test_two_client_randoms_on_one_tuple_are_two_flows():
    bus, collector = _collector()
    bus.emit(_cr_datalog("write", REQUEST, client_random=CR_A))
    bus.emit(_cr_datalog("read", RESPONSE, client_random=CR_A, timestamp=1000.1))
    bus.emit(_cr_datalog("write", REQUEST, client_random=CR_B, timestamp=1000.2))
    bus.emit(_cr_datalog("read", RESPONSE, client_random=CR_B, timestamp=1000.3))
    collector.flush()

    flows = collector.get_flows()
    assert {f.connection_id for f in flows} == {_cr_key(CR_A), _cr_key(CR_B)}
    assert {f.tls.client_random for f in flows} == {CR_A, CR_B}


def _h2_frame(frame_type: int, flags: int, stream_id: int, payload: bytes) -> bytes:
    import struct
    return (struct.pack("!I", len(payload))[1:] + bytes([frame_type, flags])
            + struct.pack("!I", stream_id) + payload)


def _h2_get(encoder, stream_id: int, path: str) -> bytes:
    block = encoder.encode([(":method", "GET"), (":scheme", "https"),
                            (":authority", "example.com"), (":path", path),
                            ("user-agent", "fritap-test")])
    return _h2_frame(0x1, 0x4 | 0x1, stream_id, block)  # END_HEADERS|END_STREAM


def test_http2_connection_keeps_one_parser_across_net_to_cr_switch():
    hpack = pytest.importorskip("hpack")
    from friTap.parsers.http2 import _CONNECTION_PREFACE

    encoder = hpack.Encoder()
    settings = _h2_frame(0x4, 0, 0, b"")
    first = _CONNECTION_PREFACE + settings + _h2_get(encoder, 1, "/one")
    # Stream 3 reuses HPACK dynamic-table entries from stream 1: a split
    # connection (fresh parser) could not decode it.
    second = _h2_get(encoder, 3, "/three")

    bus, collector = _collector()
    bus.emit(_cr_datalog("write", first))
    bus.emit(_cr_datalog("write", second, client_random=CR_A, timestamp=1000.1))
    collector.flush()

    assert len(collector._connections) == 1
    flows = [f for f in collector.get_flows()
             if f.request is not None and not f.request.is_control_frame]
    paths = sorted(f.request.url for f in flows)
    assert [p.rsplit("/", 1)[-1] for p in paths] == ["one", "three"]
    assert {f.connection_id for f in collector.get_flows()} == {
        resolve_connection_key(*CLIENT, *SERVER)}
    assert {f.tls.client_random for f in flows} == {CR_A}
