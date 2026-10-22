"""Protocol-scoped ``net:`` connection keys (friTap.connection_index).

The endpoint tier of :func:`resolve_connection_key` keeps the historical
``net:<normalize_4tuple>`` spelling for TLS (and the coerced ""/None protocol),
and scopes every other protocol as ``net:<protocol>:<canonical_4tuple>`` so a
non-TLS connection never folds into a TLS flow sharing its 4-tuple.
"""

from __future__ import annotations

import pytest

from friTap.connection_index import (
    canonical_4tuple,
    normalize_4tuple,
    resolve_connection_key,
)
from friTap.events import SESSION_STARTED, DatalogEvent, EventBus, SessionEvent
from friTap.filter.protocols import canonical_protocols
from friTap.flow.collector import FlowCollector
from friTap.message_router import MessageRouter

CLIENT = ("10.0.0.2", 51000)
SERVER = ("93.184.216.34", 443)
CR = "cd" * 32
SID = "FEEDFACE" * 4


def _legacy_net_key(src, sport, dst, dport) -> str:
    return f"net:{normalize_4tuple(src, sport, dst, dport)}"


def _wire_up():
    bus = EventBus()
    collector = FlowCollector(event_bus=bus)
    bus.subscribe(DatalogEvent, collector.on_data)
    bus.subscribe(SessionEvent, collector.on_session_event)
    return bus, collector


def _datalog(protocol: str, timestamp: float, **extra) -> DatalogEvent:
    return DatalogEvent(
        data=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
        function="SSL_write", direction="write",
        src_addr=CLIENT[0], src_port=CLIENT[1],
        dst_addr=SERVER[0], dst_port=SERVER[1],
        protocol=protocol, timestamp=timestamp, **extra)


# (1) TLS / "" / None keep the legacy string ---------------------------------- #

@pytest.mark.parametrize("protocol", ["tls", "", None])
def test_tls_endpoint_key_is_the_legacy_string(protocol):
    key = resolve_connection_key(*CLIENT, *SERVER, protocol=protocol)
    assert key == _legacy_net_key(*CLIENT, *SERVER)
    assert key == f"net:{CLIENT[0]}:{CLIENT[1]}-{SERVER[0]}:{SERVER[1]}"


def test_tls_endpoint_key_does_not_canonicalize_addresses():
    """Byte-identical to the old format: no IPv6 re-spelling for TLS."""
    key = resolve_connection_key("[2001:db8:0::1]", 443, "10.0.0.2", 5000)
    assert key == _legacy_net_key("[2001:db8:0::1]", 443, "10.0.0.2", 5000)


# (2) non-TLS protocols are scoped ------------------------------------------- #

@pytest.mark.parametrize("protocol", ["rc4", "signal", "mtproto", "quic", "ssh"])
def test_non_tls_endpoint_key_is_protocol_scoped(protocol):
    key = resolve_connection_key(*CLIENT, *SERVER, protocol=protocol)
    assert key == f"net:{protocol}:{canonical_4tuple(*CLIENT, *SERVER)}"
    assert key != resolve_connection_key(*CLIENT, *SERVER, protocol="tls")


def test_non_tls_key_is_perspective_independent():
    fwd = resolve_connection_key(*CLIENT, *SERVER, protocol="rc4")
    rev = resolve_connection_key(*SERVER, *CLIENT, protocol="rc4")
    assert fwd == rev


def test_non_tls_key_is_ipv6_spelling_independent():
    spellings = ["2001:db8::1", "[2001:db8::1]", "2001:0db8:0:0:0:0:0:1",
                 "2001:db8::1%eth0"]
    keys = {resolve_connection_key(s, 443, "10.0.0.2", 5000, protocol="quic")
            for s in spellings}
    assert keys == {"net:quic:" + canonical_4tuple("2001:db8::1", 443, "10.0.0.2", 5000)}


def test_different_protocols_never_share_a_key():
    keys = {resolve_connection_key(*CLIENT, *SERVER, protocol=p)
            for p in ("tls", "rc4", "signal", "mtproto", "quic")}
    assert len(keys) == 5


# (3) cr: / sid: tiers unchanged --------------------------------------------- #

@pytest.mark.parametrize("protocol, expected_proto", [("tls", "tls"), ("", "tls"),
                                                      ("quic", "quic")])
def test_client_random_and_session_tiers_unchanged(protocol, expected_proto):
    assert resolve_connection_key(*CLIENT, *SERVER, client_random=CR,
                                  protocol=protocol) == f"cr:{expected_proto}:{CR}"
    assert resolve_connection_key(*CLIENT, *SERVER, session_token=SID,
                                  protocol=protocol) == f"sid:{expected_proto}:{SID}"
    assert resolve_connection_key(
        *CLIENT, *SERVER, session_token="telegram_e2e:ab12",
        protocol="telegram_e2e") == "sid:telegram_e2e:telegram_e2e:ab12"


# (4) collector: TLS + another protocol on one 4-tuple -> two flows ---------- #

@pytest.mark.parametrize("protocol", ["rc4", "signal", "mtproto"])
def test_collector_splits_tls_and_other_protocol_on_same_4tuple(protocol):
    bus, collector = _wire_up()
    bus.emit(_datalog("tls", 1000.0))
    bus.emit(_datalog(protocol, 1000.5))  # well within the idle gap
    flows = collector.get_flows()
    assert len(flows) == 2
    assert {f.connection_id for f in flows} == {
        _legacy_net_key(*CLIENT, *SERVER),
        f"net:{protocol}:{canonical_4tuple(*CLIENT, *SERVER)}",
    }


def test_standalone_rc4_flow_without_token_is_not_tagged_tls():
    """B2: RC4 events carry no ssl_session_id any more, so the display filter
    no longer infers ``tls`` for a standalone RC4 flow."""
    bus, collector = _wire_up()
    bus.emit(_datalog("rc4", 1000.0))
    (flow,) = collector.get_flows()
    assert flow.ssl_session_id == ""
    assert "tls" not in canonical_protocols(flow)


# (5) QUIC session key == data key ------------------------------------------- #

def test_quic_session_event_and_data_event_share_one_key():
    from friTap.offline import pcap_to_tap as p2t

    bus, collector = _wire_up()
    seen = []
    bus.subscribe(SessionEvent, lambda ev: seen.append(ev.connection_id))
    p2t._emit_quic_session_event(bus, {
        "src_addr": CLIENT[0], "src_port": CLIENT[1],
        "dst_addr": SERVER[0], "dst_port": SERVER[1],
        "version": "1", "sni": "example.com", "alpn": "h3", "cipher": "x"})
    bus.emit(_datalog("quic", 1000.0, transport="udp"))
    (flow,) = collector.get_flows()
    assert seen == [flow.connection_id]
    assert flow.connection_id.startswith("net:quic:")


# (6) MessageRouter lifecycle key == collector data key (ssh) ---------------- #

def _router_payload(content_type: str, **extra) -> dict:
    return {"contentType": content_type, "protocol": "ssh",
            "src_addr": CLIENT[0], "src_port": CLIENT[1],
            "dst_addr": SERVER[0], "dst_port": 22, "ss_family": "AF_INET",
            "ssl_session_id": "", "client_random": "", **extra}


def test_router_ssh_lifecycle_key_matches_collector_data_key():
    bus, collector = _wire_up()
    lifecycle_ids = []
    bus.subscribe(SessionEvent, lambda ev: lifecycle_ids.append(ev.connection_id))
    router = MessageRouter(bus)
    router.route(_router_payload("connection_lifecycle", event=SESSION_STARTED), b"")
    router.route(_router_payload("datalog", function="SSL_write"), b"SSH-2.0-x\r\n")
    (flow,) = collector.get_flows()
    assert lifecycle_ids == [flow.connection_id]
    assert flow.connection_id == "net:ssh:" + canonical_4tuple(
        CLIENT[0], CLIENT[1], SERVER[0], 22)


# (7) live default (protocol "tls") pair unchanged --------------------------- #

def test_live_default_tls_lifecycle_and_data_keep_legacy_key():
    bus, collector = _wire_up()
    lifecycle_ids = []
    bus.subscribe(SessionEvent, lambda ev: lifecycle_ids.append(ev.connection_id))
    router = MessageRouter(bus)
    payload = {"src_addr": CLIENT[0], "src_port": CLIENT[1],
               "dst_addr": SERVER[0], "dst_port": SERVER[1],
               "ss_family": "AF_INET", "ssl_session_id": "", "client_random": "",
               "protocol": "tls"}
    router.route({**payload, "contentType": "connection_lifecycle",
                  "event": SESSION_STARTED}, b"")
    router.route({**payload, "contentType": "datalog", "function": "SSL_write"},
                 b"GET / HTTP/1.1\r\n\r\n")
    (flow,) = collector.get_flows()
    assert lifecycle_ids == [flow.connection_id] == [_legacy_net_key(*CLIENT, *SERVER)]
