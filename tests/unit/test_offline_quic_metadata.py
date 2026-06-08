#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Unit tests for the offline QUIC metadata producer.

Mirrors the style of ``test_offline_metadata.py``: the pure parser
(:func:`parse_quic_metadata_fields`) and the version mapper
(:func:`_map_quic_version`) are fed hand-built tab-separated tshark rows, so
they need no tshark binary. The wiring test monkeypatches the tshark boundary
(``extract_quic_metadata``) and runs the QUIC SessionEvent path through a real
FlowCollector + EventBus, asserting the resulting flow carries the stamped
``flow.quic`` metadata.
"""

from __future__ import annotations

from friTap.offline import tshark as tshark_mod
from friTap.offline import pcap_to_tap as p2t
from friTap.connection_index import resolve_connection_key
from friTap.events import DatalogEvent, EventBus, SessionEvent
from friTap.flow.collector import FlowCollector


# ---------------------------------------------------------------------------
# parse_quic_metadata_fields (pure)
# ---------------------------------------------------------------------------

def _quic_row(stream, ip_src="", ipv6_src="", ip_dst="", ipv6_dst="",
              srcport="", dstport="", version="", hs_type="",
              cipher="", alpn="", sni=""):
    """Build one tab-separated QUIC-metadata row in the canonical column order.

    Column order mirrors :data:`tshark._QUIC_META_FIELDS`: udp.stream, ip.src,
    ipv6.src, ip.dst, ipv6.dst, udp.srcport, udp.dstport, quic.version,
    tls.handshake.type, tls.handshake.ciphersuite,
    tls.handshake.extensions_alpn_str, tls.handshake.extensions_server_name.
    """
    return "\t".join([
        str(stream), ip_src, ipv6_src, ip_dst, ipv6_dst,
        str(srcport), str(dstport), version, hs_type, cipher, alpn, sni,
    ])


def test_parse_quic_metadata_serverhello_row():
    output = _quic_row(
        0, ip_src="10.0.0.1", ip_dst="2.2.2.2",
        srcport=50000, dstport=443,
        version="0x00000001", hs_type="2", cipher="0x1301", alpn="h3")
    meta = tshark_mod.parse_quic_metadata_fields(output)
    assert meta == {0: {
        "src_addr": "10.0.0.1",
        "src_port": 50000,
        "dst_addr": "2.2.2.2",
        "dst_port": 443,
        "version": "1",
        "sni": "",
        "alpn": "h3",
        "cipher": "TLS_AES_128_GCM_SHA256",
    }}


def test_parse_quic_metadata_sni_from_clienthello():
    """SNI is taken from the ClientHello (handshake type 1) in the Initial and
    merged with the ServerHello's cipher/alpn for the same udp.stream."""
    output = "\n".join([
        # ClientHello (type 1) carries version + SNI (no selected cipher).
        _quic_row(0, ip_src="10.0.0.1", ip_dst="2.2.2.2",
                  srcport=50000, dstport=443, version="0x00000001",
                  hs_type="1", sni="example.com"),
        # ServerHello (type 2) carries the negotiated cipher + ALPN.
        _quic_row(0, version="0x00000001", hs_type="2",
                  cipher="0x1301", alpn="h3"),
    ])
    meta = tshark_mod.parse_quic_metadata_fields(output)
    assert meta[0]["sni"] == "example.com"
    assert meta[0]["version"] == "1"
    assert meta[0]["alpn"] == "h3"
    assert meta[0]["cipher"] == "TLS_AES_128_GCM_SHA256"


# ---------------------------------------------------------------------------
# _map_quic_version (pure)
# ---------------------------------------------------------------------------

def test_map_quic_version_known_codepoints():
    assert tshark_mod._map_quic_version("0x00000001") == "1"
    assert tshark_mod._map_quic_version("0x6b3343cf") == "2"
    assert tshark_mod._map_quic_version("0xff00001d") == "draft-29"


def test_map_quic_version_unknown_passthrough():
    assert tshark_mod._map_quic_version("0xcafe0000") == "0xcafe0000"


def test_map_quic_version_empty():
    assert tshark_mod._map_quic_version("") == ""


# ---------------------------------------------------------------------------
# Merge across rows
# ---------------------------------------------------------------------------

def test_parse_quic_metadata_merges_initial_and_serverhello():
    output = "\n".join([
        # Initial packet (no/empty handshake type): carries version + endpoints
        # only.
        _quic_row(0, ip_src="10.0.0.1", ip_dst="2.2.2.2",
                  srcport=50000, dstport=443, version="0x00000001"),
        # Later ServerHello (type 2) for the SAME udp.stream carries the
        # negotiated cipher + ALPN.
        _quic_row(0, ip_src="2.2.2.2", ip_dst="10.0.0.1",
                  srcport=443, dstport=50000,
                  version="0x00000001", hs_type="2",
                  cipher="0x1301", alpn="h3"),
    ])
    meta = tshark_mod.parse_quic_metadata_fields(output)
    assert meta[0]["version"] == "1"
    assert meta[0]["alpn"] == "h3"
    assert meta[0]["cipher"] == "TLS_AES_128_GCM_SHA256"
    # Endpoints anchored from the first row that carried them (the Initial).
    assert (meta[0]["src_addr"], meta[0]["src_port"]) == ("10.0.0.1", 50000)
    assert (meta[0]["dst_addr"], meta[0]["dst_port"]) == ("2.2.2.2", 443)


def test_parse_quic_metadata_cipher_only_from_serverhello():
    # A ClientHello (type 1) carrying a ciphersuite LIST must NOT set cipher;
    # only the ServerHello's SELECTED suite (type 2) does.
    output = "\n".join([
        _quic_row(0, ip_src="10.0.0.1", ip_dst="2.2.2.2",
                  srcport=50000, dstport=443,
                  version="0x00000001", hs_type="1",
                  cipher="0x1301,0x1302,0x1303"),
    ])
    meta = tshark_mod.parse_quic_metadata_fields(output)
    assert meta[0]["cipher"] == ""
    assert meta[0]["version"] == "1"


# ---------------------------------------------------------------------------
# Defensive parsing
# ---------------------------------------------------------------------------

def test_parse_quic_metadata_skips_malformed_rows():
    output = "\n".join([
        "garbage-without-tabs-or-stream",
        "\t\t\t",  # empty stream column
        _quic_row(5, ip_src="10.0.0.1", ip_dst="2.2.2.2",
                  srcport=50000, dstport=443, version="0x00000001"),
    ])
    meta = tshark_mod.parse_quic_metadata_fields(output)
    assert set(meta) == {5}
    assert meta[5]["version"] == "1"


def test_parse_quic_metadata_empty_output():
    assert tshark_mod.parse_quic_metadata_fields("") == {}


# ---------------------------------------------------------------------------
# Wiring: QUIC SessionEvent stamps flow.quic onto the flow
# ---------------------------------------------------------------------------

def test_quic_session_event_stamps_flow_quic_layer():
    """The QUIC SessionEvent path stamps version/alpn/cipher onto flow.quic.

    Mirrors test_offline_metadata.py's TLS wiring: build an EventBus +
    FlowCollector, subscribe on_data + on_session_event, emit the QUIC
    SessionEvent BEFORE a QUIC DatalogEvent for the SAME 4-tuple, flush, and
    assert the resulting flow is transport=="quic" with the stamped metadata.
    """
    quic_meta = {0: {
        "src_addr": "10.0.0.1",
        "src_port": 50000,
        "dst_addr": "2.2.2.2",
        "dst_port": 443,
        "version": "1",
        "sni": "example.com",
        "alpn": "h3",
        "cipher": "TLS_AES_128_GCM_SHA256",
    }}

    bus = EventBus()
    collector = FlowCollector(event_bus=bus)
    bus.subscribe(DatalogEvent, collector.on_data)
    bus.subscribe(SessionEvent, collector.on_session_event)

    meta = quic_meta[0]

    # Confirm the SessionEvent the producer emits keys to the SAME net: key the
    # QUIC DatalogEvent (protocol="quic") will derive — otherwise stamping would
    # silently miss.
    session_key = resolve_connection_key(
        meta["src_addr"], meta["src_port"],
        meta["dst_addr"], meta["dst_port"], protocol="quic")
    data_key = resolve_connection_key(
        meta["src_addr"], meta["src_port"],
        meta["dst_addr"], meta["dst_port"], protocol="quic")
    assert session_key == data_key
    assert session_key.startswith("net:")

    # Emit the SessionEvent first (handshake-before-data ordering).
    p2t._emit_quic_session_event(bus, meta)

    # Then emit a QUIC DatalogEvent for the same 4-tuple.
    bus.emit(DatalogEvent(
        timestamp=1.0,
        data=b"GET / HTTP/3 payload bytes here for the parser to chew on",
        function="tshark_offline",
        direction="write",
        src_addr=meta["src_addr"],
        src_port=meta["src_port"],
        dst_addr=meta["dst_addr"],
        dst_port=meta["dst_port"],
        ss_family="AF_INET",
        ssl_session_id="",
        transport="udp",
        protocol="quic",
        stream_id=0,
    ))

    collector.flush()
    flows = collector.get_flows()

    quic_flows = [f for f in flows if getattr(f, "transport", "") == "quic"]
    assert quic_flows, "no QUIC flow was created"
    flow = quic_flows[0]
    assert flow.transport == "quic"
    assert flow.quic.version == "1"
    assert flow.quic.sni == "example.com"
    assert flow.quic.alpn == "h3"
    assert flow.quic.cipher == "TLS_AES_128_GCM_SHA256"
