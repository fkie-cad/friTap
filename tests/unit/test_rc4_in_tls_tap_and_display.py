#!/usr/bin/env python3

"""RC4-in-TLS: owned TLS-layer bytes survive a tap round trip, and the layered
protocol label renders ``TLS[RC4]`` while other labels stay unchanged."""

import json

from friTap.flow.display import display_protocol_layered
from friTap.flow.layers import AppLayer, Rc4Layer
from friTap.flow.models import Flow, FlowChunk, FlowState, TlsMetadata
from friTap.flow.tap_format import (
    _META_LEN,
    decode_flow,
    decode_flow_summary,
    encode_flow,
)

TLS_WRITE = b"\x00\x00\x00\x05hello"
TLS_READ = b"\x00\x00\x00\x03abc"


def _layer_meta(payload: bytes) -> dict:
    meta_len = _META_LEN.unpack(payload[:4])[0]
    meta = json.loads(payload[4:4 + meta_len].decode("utf-8"))
    return {ly["name"]: ly for ly in meta.get("layers", [])}


def _rc4_in_tls_flow() -> Flow:
    flow = Flow(flow_id="rc4tls-1", state=FlowState.COMPLETE, transport="rc4")
    flow.chunks.append(FlowChunk(
        data=b"hello", direction="write", timestamp=1.0, function="rc4",
    ))
    flow.set_layer(TlsMetadata(library="SChannel", version="TLS 1.2"))
    flow.tls.data.set_owned(read=TLS_READ, write=TLS_WRITE)
    rc4 = Rc4Layer()
    rc4.framing = "u32be-length"
    rc4.records = [{
        "direction": "write", "length": 5, "tls_frames": [7],
        "timestamp": 1.0, "cipher_offset": 0, "frame_header_len": 4,
    }]
    flow.add_layer(rc4)
    return flow


def _flow_with_layers(*names: str) -> Flow:
    flow = Flow(flow_id="-".join(names), state=FlowState.COMPLETE)
    for name in names:
        layer = AppLayer()
        layer._name = name
        flow.add_layer(layer)
    return flow


# ---------------------------------------------------------------------------
# Tap round trip
# ---------------------------------------------------------------------------

def test_owned_tls_layer_bytes_are_written_not_marked_chunks():
    layers = _layer_meta(encode_flow(_rc4_in_tls_flow()))
    assert "data_from_chunks" not in layers["tls"]
    assert "data_owned" in layers["tls"]


def test_owned_tls_layer_bytes_survive_roundtrip():
    decoded = decode_flow(encode_flow(_rc4_in_tls_flow()))
    assert [ly.name for ly in decoded.layers] == ["tls", "rc4"]
    assert decoded.tls.data.data_source == "owned"
    assert decoded.tls.data.write == TLS_WRITE
    assert decoded.tls.data.read == TLS_READ
    assert decoded.tls.library == "SChannel"
    # The inner RC4 layer still views the flow's chunks (RC4 plaintext).
    assert decoded.rc4.data.write == b"hello"
    assert decoded.rc4.framing == "u32be-length"
    assert decoded.rc4.records[0]["tls_frames"] == [7]


def test_chunks_backed_tls_layer_still_marked_chunks():
    flow = Flow(flow_id="plain-tls", state=FlowState.COMPLETE)
    flow.chunks.append(FlowChunk(data=b"x", direction="write", timestamp=1.0))
    flow.set_layer(TlsMetadata(library="BoringSSL"))
    layers = _layer_meta(encode_flow(flow))
    assert layers["tls"]["data_from_chunks"] is True
    assert "data_owned" not in layers["tls"]


# ---------------------------------------------------------------------------
# Layered display labels
# ---------------------------------------------------------------------------

def test_rc4_in_tls_renders_nested_label():
    assert display_protocol_layered(_rc4_in_tls_flow()) == "TLS[RC4]"


def test_rc4_in_tls_label_survives_roundtrip_and_summary():
    payload = encode_flow(_rc4_in_tls_flow())
    assert display_protocol_layered(decode_flow(payload)) == "TLS[RC4]"
    summary = decode_flow_summary(payload)
    assert summary.outer_app_protocol == "TLS"
    assert summary.inner_e2e_protocol == "RC4"
    assert display_protocol_layered(summary) == "TLS[RC4]"


def test_standalone_rc4_renders_plain_label():
    assert display_protocol_layered(_flow_with_layers("rc4")) == "RC4"


def test_existing_nested_labels_unchanged():
    assert display_protocol_layered(_flow_with_layers("tls", "http2", "signal")) \
        == "HTTP/2[Signal]"
    assert display_protocol_layered(_flow_with_layers("mtproto", "telegram_e2e")) \
        == "MTProto[Telegram-E2E]"
    assert display_protocol_layered(_flow_with_layers("tls", "mtproto")) == "MTProto"


def test_tls_not_added_to_filter_vocabulary():
    from friTap.constants import LAYER_DISPLAY_NAMES
    assert "tls" not in LAYER_DISPLAY_NAMES


def test_metadata_less_owned_tls_carrier_survives_roundtrip():
    # A capture without a TLS handshake leaves version/SNI/cipher empty, so
    # TlsLayer.is_empty() is True; the owned plaintext must still be written.
    flow = Flow(flow_id="rc4tls-nometa", state=FlowState.COMPLETE,
                transport="rc4")
    flow.chunks.append(FlowChunk(data=b"hello", direction="write",
                                 timestamp=1.0, function="rc4"))
    flow.set_layer(TlsMetadata())
    flow.tls.data.set_owned(read=TLS_READ, write=TLS_WRITE)
    flow.add_layer(Rc4Layer())
    decoded = decode_flow(encode_flow(flow))
    assert decoded.layer("tls") is not None
    assert decoded.tls.data.write == TLS_WRITE
    assert decoded.tls.data.read == TLS_READ
