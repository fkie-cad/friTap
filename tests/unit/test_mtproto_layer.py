"""Tests for MtprotoLayer: metadata round-trip, registry, and .tap persistence."""

from __future__ import annotations

from friTap.flow import layer_registry
from friTap.flow.layers import MtprotoLayer
from friTap.flow.models import Flow, FlowChunk
from friTap.flow.tap_format import decode_flow, encode_flow


def test_mtproto_layer_to_from_dict_roundtrip():
    layer = MtprotoLayer(
        transport="intermediate",
        obfuscated=True,
        dc_id=2,
        auth_key_id="a1b2c3d4e5f60718",
        message_count=3,
    )
    restored = MtprotoLayer.from_dict(layer.to_dict())
    assert restored.transport == "intermediate"
    assert restored.obfuscated is True
    assert restored.dc_id == 2
    assert restored.auth_key_id == "a1b2c3d4e5f60718"
    assert restored.message_count == 3


def test_mtproto_descriptor_registered_as_chunks():
    desc = layer_registry.get("mtproto")
    assert desc is not None
    assert desc.layer_cls is MtprotoLayer
    # Decrypted message bytes arrive as flow chunks (live datalog / offline
    # decryptor), like tls/quic — so the auto-created transport layer is chunks-backed.
    assert desc.data_source == "chunks"


def test_flow_mtproto_attribute_resolves():
    flow = Flow()
    assert isinstance(flow.mtproto, MtprotoLayer)
    assert flow.mtproto.is_empty()


def test_mtproto_layer_survives_tap_roundtrip():
    """Decrypted bytes live in chunks; the MtprotoLayer carries typed metadata.

    Mirrors how the live datalog hook / offline decryptor populate a flow: the
    decrypted message bytes are the flow's chunks (chunks-view layer), and the
    layer adds transport/identity metadata.
    """
    flow = Flow(flow_id="tg1", connection_id="c1")
    flow.transport = "mtproto"
    flow.chunks.append(FlowChunk(data=b"client->server TL bytes", direction="write", timestamp=1.0))
    flow.chunks.append(FlowChunk(data=b"server->client TL bytes", direction="read", timestamp=2.0))
    layer = flow.mtproto  # auto-created, chunks-bound via the registry descriptor
    layer.transport = "intermediate"
    layer.obfuscated = True
    layer.dc_id = 2
    layer.auth_key_id = "a1b2c3d4e5f60718"
    layer.message_count = 3

    decoded = decode_flow(encode_flow(flow))
    layers = [ly for ly in decoded.layers if ly.name == "mtproto"]
    assert len(layers) == 1
    ly = layers[0]
    assert isinstance(ly, MtprotoLayer)
    assert ly.transport == "intermediate"
    assert ly.obfuscated is True
    assert ly.dc_id == 2
    assert ly.auth_key_id == "a1b2c3d4e5f60718"
    assert ly.message_count == 3
    # decrypted bytes round-trip via the flow's chunks (the chunks-view layer)
    assert decoded.get_direction_bytes("write") == b"client->server TL bytes"
    assert decoded.get_direction_bytes("read") == b"server->client TL bytes"
    assert decoded.mtproto.data.write == b"client->server TL bytes"
