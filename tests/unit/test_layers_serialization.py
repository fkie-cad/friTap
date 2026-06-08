"""Unit tests for Phase 2 protocol-layer-stack serialization (schema v3).

Covers the ``meta["layers"]`` ordered stack written by ``encode_flow`` and
rebuilt by ``decode_flow``: mirrored transport/app layers (no byte/parse
duplication), owned inner layers (decryptor output, bytes once via blobs),
QUIC transport, v2 backward-compat rebuild, and empty-layer skipping. Pure
Python — no device/Frida.
"""

import json

from friTap.flow.layers import AppLayer
from friTap.flow.models import Flow, FlowChunk, FlowState, TlsMetadata
from friTap.flow.tap_format import (
    FLOW_SCHEMA_VERSION,
    _META_LEN,
    decode_flow,
    encode_flow,
)
from friTap.parsers.base import ParseResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _meta_and_blob(payload: bytes) -> tuple[dict, bytes]:
    """Split a FLOW record payload into its decoded JSON meta + blob section."""
    meta_len = _META_LEN.unpack(payload[:4])[0]
    meta = json.loads(payload[4 : 4 + meta_len].decode("utf-8"))
    blob_section = payload[4 + meta_len :]
    return meta, blob_section


def _blob_len(payload: bytes) -> int:
    """Length of the blob section = total - 4-byte prefix - meta bytes."""
    meta_len = _META_LEN.unpack(payload[:4])[0]
    return len(payload) - 4 - meta_len


def _layers_by_name(meta: dict) -> dict[str, dict]:
    return {ly["name"]: ly for ly in meta.get("layers", [])}


def _tls_http2_flow(*, chunk_sizes=(10, 20), parse_body=b"") -> Flow:
    """A TLS flow with a write+read chunk, a TLS layer and an http2 app layer
    mirroring the request field."""
    flow = Flow(
        flow_id="f-1",
        connection_id="c-1",
        src_addr="10.0.0.2",
        src_port=51000,
        dst_addr="93.184.216.34",
        dst_port=443,
        state=FlowState.COMPLETE,
        started=1000.0,
        ended=1001.0,
    )
    flow.chunks.append(FlowChunk(
        data=b"W" * chunk_sizes[0], direction="write",
        timestamp=1000.0, function="SSL_write",
    ))
    flow.chunks.append(FlowChunk(
        data=b"R" * chunk_sizes[1], direction="read",
        timestamp=1000.1, function="SSL_read",
    ))
    flow.set_layer(TlsMetadata(
        library="BoringSSL", version="TLS 1.3", sni="example.com",
        alpn="h2", cipher="C",
    ))
    flow.request = ParseResult(
        protocol="HTTP/2", is_request=True, method="GET", url="/",
        body=parse_body,
    )
    layer = flow.http2
    layer._parsed_field = "request"
    return flow


# ---------------------------------------------------------------------------
# 1. Version
# ---------------------------------------------------------------------------

def test_flow_schema_version_is_three():
    assert FLOW_SCHEMA_VERSION == 3


# ---------------------------------------------------------------------------
# 2. v3 round-trip (transport + app mirrored layers)
# ---------------------------------------------------------------------------

def test_v3_roundtrip_transport_and_app_layers():
    flow = _tls_http2_flow()
    decoded = decode_flow(encode_flow(flow))

    assert [ly.name for ly in decoded.layers] == ["tls", "http2"]

    # TLS scalar fields round-trip.
    assert decoded.tls.sni == "example.com"
    assert decoded.tls.alpn == "h2"
    assert decoded.tls.version == "TLS 1.3"
    assert decoded.tls.library == "BoringSSL"
    assert decoded.tls.cipher == "C"

    # http2 app layer mirrors the flow's request (identity), not a copy.
    assert decoded.http2.parsed is decoded.request
    assert decoded.http2.parsed.method == "GET"

    assert decoded.transport == "tls"

    # Chunks views rebound on decode: layer data == flow direction bytes.
    assert decoded.tls.data.read == decoded.get_direction_bytes("read")
    assert decoded.http2.data.write == decoded.get_direction_bytes("write")


# ---------------------------------------------------------------------------
# 3. No transport-byte duplication
# ---------------------------------------------------------------------------

def test_transport_and_app_layers_add_zero_blobs():
    flow = _tls_http2_flow(chunk_sizes=(10, 20), parse_body=b"")
    payload = encode_flow(flow)

    # Only the 30 chunk bytes live in the blob section; the request body is
    # de-duped (body_from_chunks) and the tls/http2 layers carry no bytes.
    assert _blob_len(payload) == 30

    meta, _ = _meta_and_blob(payload)
    layers = _layers_by_name(meta)

    assert layers["tls"]["data_from_chunks"] is True
    assert "data_owned" not in layers["tls"]

    assert layers["http2"]["data_from_chunks"] is True
    assert "data_owned" not in layers["http2"]
    assert layers["http2"]["parsed_field"] == "request"
    assert "parsed" not in layers["http2"]


# ---------------------------------------------------------------------------
# 4. Owned inner layer round-trip
# ---------------------------------------------------------------------------

def test_owned_inner_layer_roundtrip():
    flow = Flow(flow_id="owned-1", state=FlowState.COMPLETE)
    flow.chunks.append(FlowChunk(
        data=b"chunk-bytes", direction="write", timestamp=1.0, function="SSL_write",
    ))
    chunk_blob_len = len(b"chunk-bytes")

    inner = AppLayer()
    inner._name = "signal"
    inner.data.set_owned(read=b"DEC-READ", write=b"DEC-WRITE")
    inner.set_parsed(ParseResult(
        protocol="HTTP/1.1", is_request=False, status_code=200,
    ))
    flow.add_layer(inner)

    payload = encode_flow(flow)
    decoded = decode_flow(payload)

    sig = decoded.layer("signal")
    assert sig is not None
    assert sig.data.data_source == "owned"
    assert sig.data.read == b"DEC-READ"
    assert sig.data.write == b"DEC-WRITE"
    assert sig.parsed.status_code == 200

    # Owned bytes appear in the blob section, beyond the chunk bytes.
    assert _blob_len(payload) == chunk_blob_len + len(b"DEC-READ") + len(b"DEC-WRITE")


# ---------------------------------------------------------------------------
# 5. QUIC transport round-trip
# ---------------------------------------------------------------------------

def test_quic_transport_roundtrip():
    flow = Flow(flow_id="quic-1", state=FlowState.COMPLETE)
    flow.transport = "quic"
    flow.quic.alpn = "h3"
    flow.quic.version = "1"

    payload = encode_flow(flow)
    meta, _ = _meta_and_blob(payload)
    assert meta["transport"] == "quic"

    decoded = decode_flow(payload)
    assert decoded.transport == "quic"
    assert decoded.layer("quic") is not None
    assert decoded.quic.alpn == "h3"
    assert decoded.quic.version == "1"


# ---------------------------------------------------------------------------
# 6. v2 backward-compat rebuild (no meta["layers"])
# ---------------------------------------------------------------------------

def test_v2_backward_compat_rebuilds_layer_stack():
    flow = _tls_http2_flow()
    payload = encode_flow(flow)

    # Simulate a v2 record: drop the explicit layer stack, mark schema v2.
    meta, blob_section = _meta_and_blob(payload)
    assert "layers" in meta  # v3 wrote it
    meta.pop("layers")
    meta["_v"] = 2
    new_meta_bytes = json.dumps(meta, separators=(",", ":")).encode("utf-8")
    v2_payload = _META_LEN.pack(len(new_meta_bytes)) + new_meta_bytes + blob_section

    decoded = decode_flow(v2_payload)

    # TLS layer rebuilt from meta["tls"].
    assert decoded.layer("tls") is not None
    assert decoded.tls.sni == "example.com"
    # App layer rebuilt from the legacy request field by the LayerPipeline.
    assert decoded.layer("http2") is not None


# ---------------------------------------------------------------------------
# 7. Empty layers skipped
# ---------------------------------------------------------------------------

def test_empty_layers_not_serialized():
    flow = Flow(flow_id="empty-1", state=FlowState.COMPLETE)
    # Lazily create an EMPTY tls layer (set nothing on it).
    _ = flow.tls

    payload = encode_flow(flow)
    meta, _ = _meta_and_blob(payload)
    assert "layers" not in meta

    decoded = decode_flow(payload)
    assert decoded is not None
    assert decoded.flow_id == "empty-1"
