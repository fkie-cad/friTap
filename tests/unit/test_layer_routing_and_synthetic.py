#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Unit tests for the just-landed layer-stack routing + synthetic-flow features.

Covers four production surfaces, all pure Python (no device/Frida):

  * ``FlowCollector.add_synthetic_flow`` — metadata-only flows (SSH/IPsec) that
    emit CREATED then COMPLETED and carry a single typed layer, round-tripping
    through ``encode_flow``/``decode_flow`` with no data blob.
  * ``LayerPipeline.push_layer`` — the generic event-fed seam (mirror mode via
    ``parsed_field``; owned mode via directional bytes; idempotent on name).
  * ``reparse.reparse_flow`` / ``LayerPipeline.reparse`` — per-layer refresh that
    rebuilds the mirrored stack and re-parses OWNED inner layers without
    duplicating them.
  * ``FlowCollector.on_ohttp`` and ``FlowCollector._propagate_trailing_data`` —
    the collector routes event-fed inner protocols (OHTTP) and trailing data
    into the layer model while their legacy flow fields stay source of truth.
"""

from __future__ import annotations

import types
from types import SimpleNamespace

from friTap.flow.collector import FlowCollector
from friTap.flow.layer_pipeline import LayerPipeline
from friTap.flow.layers import AppLayer, IpsecLayer, SshLayer
from friTap.flow.models import Flow, FlowChunk, FlowEventType, FlowState
from friTap.flow.reparse import reparse_flow
from friTap.flow.tap_format import decode_flow, encode_flow
from friTap.parsers.base import ParseResult
from friTap.parsers.varint import encode_varint


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _data_event(data, direction, function, *, timestamp=1000.0,
                src_addr="10.0.0.2", src_port=51000,
                dst_addr="93.184.216.34", dst_port=443,
                ssl_session_id="sess-1"):
    """A DatalogEvent-shaped namespace for ``FlowCollector.on_data``."""
    return SimpleNamespace(
        src_addr=src_addr,
        src_port=src_port,
        dst_addr=dst_addr,
        dst_port=dst_port,
        data=data,
        direction=direction,
        timestamp=timestamp,
        function=function,
        ssl_session_id=ssl_session_id,
    )


def _vbytes(b: bytes) -> bytes:
    """A varint-length-prefixed byte string (RFC 9292 field encoding)."""
    return encode_varint(len(b)) + b


def _bhttp_request() -> bytes:
    """A valid known-length RFC 9292 bhttp request: GET https example.com / .

    No existing test ships a bhttp fixture, so we build one directly from the
    encoder: framing 0x00, the four request control fields, then an empty
    (length-0) header section. ``parse_bhttp`` accepts this as a complete
    request (verified by test 9's assertions).
    """
    return (
        bytes([0x00])
        + _vbytes(b"GET")
        + _vbytes(b"https")
        + _vbytes(b"example.com")
        + _vbytes(b"/")
        + encode_varint(0)  # empty header section
    )


def _collect_events(collector: FlowCollector) -> list:
    """Subscribe a recording listener; returns the (flow, event_type) list."""
    events: list = []
    collector.subscribe(lambda flow, event_type: events.append((flow, event_type)))
    return events


def _drive_http1_request(collector: FlowCollector) -> Flow:
    """Push one HTTP/1 request through on_data and return the live flow."""
    collector.on_data(_data_event(
        b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
        "write", "SSL_write", timestamp=1000.0,
    ))
    # The flow lives in the collector's internal dict; grab the live object.
    return next(iter(collector._flows.values()))


# ---------------------------------------------------------------------------
# add_synthetic_flow (FlowCollector)
# ---------------------------------------------------------------------------

class TestAddSyntheticFlow:
    def test_ssh_synthetic_flow_emits_created_then_completed(self):
        fc = FlowCollector()
        events = _collect_events(fc)

        flow = fc.add_synthetic_flow(
            src_addr="10.0.0.1", src_port=55000,
            dst_addr="2.2.2.2", dst_port=22,
            layer=SshLayer(
                client_version="SSH-2.0-OpenSSH_9.6",
                server_version="SSH-2.0-OpenSSH_8.9",
                kex="curve25519-sha256",
                cipher="aes256-gcm@openssh.com",
                mac="hmac-sha2-256",
            ),
            detected_protocol="SSH", transport="tcp", protocol="ssh",
        )

        # Exactly one CREATED then one COMPLETED, in that order.
        types_emitted = [et for _, et in events]
        assert types_emitted == [FlowEventType.CREATED, FlowEventType.COMPLETED]
        assert types_emitted.count(FlowEventType.CREATED) == 1
        assert types_emitted.count(FlowEventType.COMPLETED) == 1

        assert flow.state == FlowState.COMPLETE
        assert flow.detected_protocol == "SSH"
        assert flow.ssh.kex == "curve25519-sha256"
        assert flow.ssh.cipher == "aes256-gcm@openssh.com"
        assert flow.ssh.client_version == "SSH-2.0-OpenSSH_9.6"
        assert flow.chunks == []
        assert [ly.name for ly in flow.layers] == ["ssh"]

    def test_ssh_synthetic_flow_roundtrips_with_no_blob(self):
        fc = FlowCollector()
        flow = fc.add_synthetic_flow(
            src_addr="10.0.0.1", src_port=55000,
            dst_addr="2.2.2.2", dst_port=22,
            layer=SshLayer(
                client_version="SSH-2.0-OpenSSH_9.6",
                server_version="SSH-2.0-OpenSSH_8.9",
                kex="curve25519-sha256",
                cipher="aes256-gcm@openssh.com",
                mac="hmac-sha2-256",
            ),
            detected_protocol="SSH", transport="tcp", protocol="ssh",
        )

        decoded = decode_flow(encode_flow(flow))

        assert decoded.detected_protocol == "SSH"
        assert decoded.ssh.client_version == "SSH-2.0-OpenSSH_9.6"
        assert decoded.ssh.server_version == "SSH-2.0-OpenSSH_8.9"
        assert decoded.ssh.mac == "hmac-sha2-256"
        # The ssh layer serialized without an owned data blob.
        assert decoded.ssh.data.data_source == "none"

    def test_ipsec_synthetic_flow(self):
        fc = FlowCollector()
        events = _collect_events(fc)

        flow = fc.add_synthetic_flow(
            src_addr="10.0.0.1", src_port=500,
            dst_addr="2.2.2.2", dst_port=500,
            layer=IpsecLayer(
                ike_version="2", enc="aes-gcm", integ="sha256", dh="19",
            ),
            detected_protocol="IPsec", transport="udp", protocol="ipsec",
        )

        assert [et for _, et in events] == [
            FlowEventType.CREATED, FlowEventType.COMPLETED,
        ]
        assert flow.state == FlowState.COMPLETE
        assert flow.detected_protocol == "IPsec"
        assert flow.chunks == []
        assert [ly.name for ly in flow.layers] == ["ipsec"]

        decoded = decode_flow(encode_flow(flow))
        assert decoded.detected_protocol == "IPsec"
        assert decoded.ipsec.ike_version == "2"
        assert decoded.ipsec.enc == "aes-gcm"
        assert decoded.ipsec.integ == "sha256"
        assert decoded.ipsec.dh == "19"
        assert decoded.ipsec.data.data_source == "none"


# ---------------------------------------------------------------------------
# push_layer (LayerPipeline)
# ---------------------------------------------------------------------------

class TestPushLayer:
    def test_mirror_mode_points_parsed_at_flow_field(self):
        flow = Flow(flow_id="f1", connection_id="c1")
        flow.ohttp_inner_request = ParseResult(
            protocol="bhttp", is_request=True, method="GET",
        )
        layer = LayerPipeline().push_layer(
            flow, protocol="ohttp", parsed_field="ohttp_inner_request")
        assert layer.name == "ohttp"
        assert layer.parsed is flow.ohttp_inner_request

    def test_owned_mode_holds_directional_bytes(self):
        flow = Flow(flow_id="f1", connection_id="c1")
        layer = LayerPipeline().push_layer(
            flow, protocol="signal", data_read=b"DEC", data_write=b"")
        assert layer.data.data_source == "owned"
        assert layer.data.read == b"DEC"

    def test_idempotent_on_protocol_name(self):
        flow = Flow(flow_id="f1", connection_id="c1")
        pipeline = LayerPipeline()
        pipeline.push_layer(flow, protocol="signal", data_read=b"DEC")
        layer = pipeline.push_layer(flow, protocol="signal", data_read=b"DEC2")
        assert layer.data.read == b"DEC2"
        assert [ly.name for ly in flow.layers].count("signal") == 1


# ---------------------------------------------------------------------------
# reparse_flow per-layer (reparse.py)
# ---------------------------------------------------------------------------

class TestReparsePerLayer:
    def test_reparse_flow_upgrades_and_builds_layers(self):
        flow = Flow(flow_id="f1", connection_id="c1")
        flow.chunks.append(FlowChunk(
            data=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
            direction="write", timestamp=1.0, function="SSL_write",
        ))
        flow.chunks.append(FlowChunk(
            data=b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
            direction="read", timestamp=2.0, function="SSL_read",
        ))
        assert flow.layers == []

        upgraded = reparse_flow(flow)

        assert upgraded is True
        names = [ly.name for ly in flow.layers]
        assert "tls" in names
        assert "http1" in names
        assert flow.layer("http1").parsed is flow.request

    def test_reparse_does_not_duplicate_owned_inner_layer(self):
        flow = Flow(flow_id="f1", connection_id="c1")
        flow.chunks.append(FlowChunk(
            data=b"server-bytes", direction="read", timestamp=1.0,
            function="SSL_read",
        ))
        inner = AppLayer()
        inner._name = "inner"
        inner.data.set_owned(
            read=b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
        flow.add_layer(inner)

        pipeline = LayerPipeline()
        pipeline.reparse(flow)
        pipeline.reparse(flow)

        # Exactly one "inner" layer (reparse re-parses in place; never appends).
        inner_layers = [ly for ly in flow.layers if ly.name == "inner"]
        assert len(inner_layers) == 1
        # The owned bytes were parsed into the inner layer's parsed result.
        assert inner_layers[0].parsed is not None
        assert inner_layers[0].parsed.status_code == 200


# ---------------------------------------------------------------------------
# on_ohttp routing (FlowCollector)
# ---------------------------------------------------------------------------

class TestOnOhttpRouting:
    def test_on_ohttp_routes_inner_request_into_layer(self):
        # A valid bhttp request fixture is constructible from the varint
        # encoder, so we exercise the REAL on_ohttp path end-to-end.
        fc = FlowCollector()
        _drive_http1_request(fc)

        ohttp_event = types.SimpleNamespace(
            data=_bhttp_request(), direction="request")
        fc.on_ohttp(ohttp_event)

        flow = next(iter(fc._flows.values()))
        layer = flow.layer("ohttp")
        assert layer is not None
        assert flow.ohttp_inner_request is not None
        assert layer.parsed is flow.ohttp_inner_request


# ---------------------------------------------------------------------------
# _propagate_trailing_data routing (FlowCollector)
# ---------------------------------------------------------------------------

class TestPropagateTrailingData:
    def test_trailing_data_routes_into_mirror_layer(self):
        fc = FlowCollector()
        flow = _drive_http1_request(fc)

        fake_parser = SimpleNamespace(
            trailing_data=b"leftover",
            trailing_protocol="websocket",
            trailing_sub_parse=ParseResult(
                protocol="WebSocket", is_request=False),
        )
        fc._propagate_trailing_data(fake_parser, flow)

        assert flow.trailing_bytes == b"leftover"
        trailing_layer = flow.layer("trailing")
        assert trailing_layer is not None
        assert trailing_layer.parsed is flow.trailing_parse
        # Trailing bytes are NOT duplicated into the layer's owned buffers.
        assert trailing_layer.data.data_source == "none"

        # Round-trip: trailing bytes serialize exactly once (via meta), and the
        # decoded flow still mirrors trailing_parse in a "trailing" layer.
        decoded = decode_flow(encode_flow(flow))
        assert decoded.trailing_bytes == b"leftover"
        decoded_trailing = decoded.layer("trailing")
        assert decoded_trailing is not None
        assert decoded_trailing.parsed is decoded.trailing_parse
