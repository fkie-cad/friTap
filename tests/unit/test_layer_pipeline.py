#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Unit + integration tests for the Phase 1b LayerPipeline.

Covers the protocol-string normalization helper (``app_layer_name``), the
generic ``AppLayer`` model, the protocol registry's application descriptors,
Flow attribute resolution for application layers, the LayerPipeline's
transport/application/nested-decryption behaviour, and the FlowCollector
integration that drives ``finalize`` for real flows. Pure Python — no
device/Frida.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from friTap.flow.collector import FlowCollector
from friTap.flow.decryptors import DecryptorRegistry, LayerDecryptor
from friTap.flow.layer_pipeline import LayerPipeline, app_layer_name
from friTap.flow.layer_registry import (
    APP_PROTOCOL_NAMES,
    ProtocolDescriptor,
    get_registry,
)
from friTap.flow.layers import AppLayer, TlsLayer
from friTap.flow.models import Flow, FlowChunk, FlowState
from friTap.parsers.base import ParseResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _tls_flow_with_chunks() -> Flow:
    """A fresh TLS flow (default transport) carrying read+write chunks."""
    flow = Flow(flow_id="f1", connection_id="c1")
    flow.chunks.append(
        FlowChunk(data=b"client->server", direction="write", timestamp=1.0)
    )
    flow.chunks.append(
        FlowChunk(data=b"server->client", direction="read", timestamp=2.0)
    )
    return flow


def _h2_request() -> ParseResult:
    return ParseResult(protocol="HTTP/2", is_request=True, method="GET")


def _h2_response() -> ParseResult:
    return ParseResult(protocol="HTTP/2", is_request=False, status_code=200)


# ---------------------------------------------------------------------------
# 1. app_layer_name() normalization
# ---------------------------------------------------------------------------

class TestAppLayerName:
    @pytest.mark.parametrize(
        "protocol,expected",
        [
            ("HTTP/2", "http2"),
            ("HTTP/3", "http3"),
            ("WebSocket", "websocket"),
            ("HTTP/1.1", "http1"),
            ("HTTP/1.0", "http1"),
            ("HTTP/1.x", "http1"),
        ],
    )
    def test_known_protocols_map(self, protocol, expected):
        assert app_layer_name(protocol) == expected

    @pytest.mark.parametrize("protocol", ["bhttp", "unknown", ""])
    def test_unmapped_protocols_return_none(self, protocol):
        assert app_layer_name(protocol) is None

    def test_case_insensitive(self):
        assert app_layer_name("http/2") == "http2"
        assert app_layer_name("WEBSOCKET") == "websocket"


# ---------------------------------------------------------------------------
# 2. AppLayer model
# ---------------------------------------------------------------------------

class TestAppLayerModel:
    def test_class_name_is_empty_sentinel(self):
        assert AppLayer.NAME == ""

    def test_instance_name_from_per_instance_field(self):
        layer = AppLayer()
        layer._name = "http2"
        assert layer.name == "http2"

    def test_fresh_layer_is_empty(self):
        assert AppLayer().is_empty()

    def test_to_dict_contains_name_and_depth(self):
        layer = AppLayer(depth=1)
        layer._name = "http2"
        d = layer.to_dict()
        assert d["name"] == "http2"
        assert d["depth"] == 1

    def test_from_dict_roundtrips_name_and_depth(self):
        layer = AppLayer(depth=3)
        layer._name = "websocket"
        restored = AppLayer.from_dict(layer.to_dict())
        assert restored.name == "websocket"
        assert restored.depth == 3


# ---------------------------------------------------------------------------
# 3. Registry
# ---------------------------------------------------------------------------

class TestRegistry:
    @pytest.mark.parametrize("name", APP_PROTOCOL_NAMES)
    def test_app_descriptors_use_applayer_chunks(self, name):
        desc = get_registry().get(name)
        assert desc is not None
        assert desc.layer_cls is AppLayer
        assert desc.data_source == "chunks"

    def test_generic_descriptor_constructs(self):
        desc = ProtocolDescriptor("http2", AppLayer, data_source="chunks")
        assert desc.name == "http2"
        assert desc.layer_cls is AppLayer

    def test_generic_descriptor_requires_nonempty_name(self):
        with pytest.raises(AssertionError):
            ProtocolDescriptor("", AppLayer)

    def test_typed_descriptor_name_mismatch_raises(self):
        with pytest.raises(AssertionError):
            ProtocolDescriptor("wrong", TlsLayer)

    def test_typed_descriptor_matching_name_ok(self):
        desc = ProtocolDescriptor("tls", TlsLayer)
        assert desc.layer_cls is TlsLayer


# ---------------------------------------------------------------------------
# 4. Flow attribute resolution for app layers
# ---------------------------------------------------------------------------

class TestFlowAppAttributeResolution:
    def test_flow_http2_resolves_to_named_applayer(self):
        flow = Flow()
        assert isinstance(flow.http2, AppLayer)
        assert flow.http2.name == "http2"

    def test_flow_http2_is_cached_same_instance(self):
        flow = Flow()
        assert flow.http2 is flow.http2

    def test_layer_helper_returns_after_access(self):
        flow = Flow()
        accessed = flow.http2
        assert flow.layer("http2") is accessed

    def test_unknown_protocol_attribute_raises(self):
        flow = Flow()
        with pytest.raises(AttributeError):
            _ = flow.definitely_not_a_protocol


# ---------------------------------------------------------------------------
# 5. LayerPipeline unit tests
# ---------------------------------------------------------------------------

class TestLayerPipelineTransport:
    def test_ensure_transport_tls_default(self):
        flow = _tls_flow_with_chunks()
        layer = LayerPipeline().ensure_transport(flow)
        assert layer.name == "tls"
        assert layer.data.data_source == "chunks"
        assert layer.data.read == flow.get_direction_bytes("read")
        assert layer.data.write == flow.get_direction_bytes("write")

    def test_ensure_transport_is_idempotent(self):
        flow = _tls_flow_with_chunks()
        pipeline = LayerPipeline()
        first = pipeline.ensure_transport(flow)
        second = pipeline.ensure_transport(flow)
        assert first is second

    def test_ensure_transport_quic(self):
        flow = Flow(flow_id="q", connection_id="c", transport="quic")
        layer = LayerPipeline().ensure_transport(flow)
        assert layer.name == "quic"


class TestLayerPipelinePushAppResult:
    def test_push_request_mirrors_request_field(self):
        flow = _tls_flow_with_chunks()
        flow.request = _h2_request()
        layer = LayerPipeline().push_app_result(flow, flow.request, "HTTP/2")
        assert layer.name == "http2"
        assert layer._parsed_field == "request"
        assert flow.http2.parsed is flow.request

    def test_push_response_only_mirrors_response_field(self):
        flow = _tls_flow_with_chunks()
        flow.response = _h2_response()
        layer = LayerPipeline().push_app_result(flow, flow.response, "HTTP/2")
        assert layer._parsed_field == "response"
        assert flow.http2.parsed is flow.response

    def test_request_wins_over_earlier_response(self):
        flow = _tls_flow_with_chunks()
        flow.request = _h2_request()
        flow.response = _h2_response()
        pipeline = LayerPipeline()
        pipeline.push_app_result(flow, flow.response, "HTTP/2")
        pipeline.push_app_result(flow, flow.request, "HTTP/2")
        assert flow.http2._parsed_field == "request"
        assert flow.http2.parsed is flow.request

    def test_unmapped_protocol_returns_none_and_adds_no_layer(self):
        flow = _tls_flow_with_chunks()
        result = LayerPipeline().push_app_result(flow, _h2_request(), "bhttp")
        assert result is None
        assert flow.layer("bhttp") is None
        assert all(ly.name != "bhttp" for ly in flow.layers)


class TestLayerPipelineFinalize:
    def test_finalize_builds_transport_and_app(self):
        flow = _tls_flow_with_chunks()
        flow.request = _h2_request()
        LayerPipeline().finalize(flow)
        names = [ly.name for ly in flow.layers]
        assert "tls" in names
        assert "http2" in names
        assert flow.http2.parsed is flow.request

    def test_finalize_uses_detected_protocol_without_request(self):
        flow = _tls_flow_with_chunks()
        flow.detected_protocol = "HTTP/2"
        LayerPipeline().finalize(flow)
        names = [ly.name for ly in flow.layers]
        assert "http2" in names

    def test_finalize_no_protocol_only_transport(self):
        flow = _tls_flow_with_chunks()
        LayerPipeline().finalize(flow)
        names = [ly.name for ly in flow.layers]
        assert names == ["tls"]


# ---------------------------------------------------------------------------
# 6. Nested-decryption seam (_maybe_decrypt)
# ---------------------------------------------------------------------------

class _FakeDecryptor(LayerDecryptor):
    """A decryptor that handles tls parents and prefixes b'DEC:' to bytes."""

    name = "fake"

    def can_handle(self, parent_layer, flow) -> bool:
        return parent_layer.name == "tls"

    def feed(self, data: bytes, direction: str) -> bytes:
        return b"DEC:" + data


class TestNestedDecryptionSeam:
    def test_empty_registry_adds_no_inner_layer(self):
        flow = _tls_flow_with_chunks()
        flow.request = _h2_request()
        LayerPipeline().finalize(flow)
        # Only transport + app; no inner decrypted layer.
        assert all(ly.name != "fake" for ly in flow.layers)

    def test_fake_decryptor_adds_owned_inner_layer(self):
        fake_registry = DecryptorRegistry()
        fake_registry.register(_FakeDecryptor)
        pipeline = LayerPipeline(decryptor_registry=fake_registry)

        flow = _tls_flow_with_chunks()
        transport = pipeline.ensure_transport(flow)
        inner = pipeline._maybe_decrypt(flow, transport)

        assert inner is not None
        assert inner.name == "fake"
        assert flow.layer("fake") is inner
        assert inner.data.data_source == "owned"
        assert inner.data.read == b"DEC:" + flow.get_direction_bytes("read")
        assert inner.data.write == b"DEC:" + flow.get_direction_bytes("write")


# ---------------------------------------------------------------------------
# 7. Collector integration (on_data + flush)
# ---------------------------------------------------------------------------

def _event(data, direction, function, *, protocol=None, timestamp=1000.0,
           src_addr="10.0.0.2", src_port=51000,
           dst_addr="93.184.216.34", dst_port=443,
           ssl_session_id="sess-1"):
    ns = SimpleNamespace(
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
    if protocol is not None:
        ns.protocol = protocol
    return ns


class TestCollectorIntegration:
    def test_http1_response_flow_layers(self):
        fc = FlowCollector()
        fc.on_data(_event(
            b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
            "write", "SSL_write", timestamp=1000.0,
        ))
        fc.on_data(_event(
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n"
            b"Content-Type: text/plain\r\n\r\nhello",
            "read", "SSL_read", timestamp=1000.1,
        ))
        fc.flush()

        flows = fc.get_flows()
        assert len(flows) == 1
        flow = flows[0]
        assert [ly.name for ly in flow.layers] == ["tls", "http1"]
        assert flow.transport == "tls"
        assert flow.layer("http1").parsed is flow.request
        assert flow.tls.data.read == flow.get_direction_bytes("read")

    def test_quic_transport_stamping(self):
        fc = FlowCollector()
        fc.on_data(_event(
            b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
            "write", "SSL_write", protocol="quic",
            ssl_session_id="quic-sess",
        ))
        fc.flush()

        flow = fc.get_flows()[0]
        assert flow.transport == "quic"
        assert flow.layer("quic") is not None
        assert flow.layer("quic").name == "quic"

    def test_zero_behavior_change_existing_fields_preserved(self):
        fc = FlowCollector()
        fc.on_data(_event(
            b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
            "write", "SSL_write", timestamp=2000.0,
        ))
        fc.on_data(_event(
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n"
            b"Content-Type: text/plain\r\n\r\nhello",
            "read", "SSL_read", timestamp=2000.1,
        ))
        fc.flush()

        flow = fc.get_flows()[0]
        assert flow.request is not None
        assert flow.response is not None
        assert flow.detected_protocol
        assert flow.state == FlowState.COMPLETE
