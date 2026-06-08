#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Integration tests for the Flow <-> protocol-layer-stack wiring.

Covers flow.<protocol> resolution via __getattr__, the never-None ergonomics
that replace the old TlsMetadata value object, the decrypted-data view over
chunks, and copy semantics.
"""

from __future__ import annotations

import copy

import pytest

from friTap.flow.models import Flow, FlowChunk, TlsMetadata
from friTap.flow.layers import TlsLayer, QuicLayer, SshLayer, LayerData


def _flow_with_chunks() -> Flow:
    flow = Flow(flow_id="f1", connection_id="c1")
    flow.chunks.append(FlowChunk(data=b"GET / HTTP/1.1\r\n", direction="write", timestamp=1.0))
    flow.chunks.append(FlowChunk(data=b"HTTP/1.1 200 OK\r\n", direction="read", timestamp=2.0))
    return flow


# --- flow.<protocol> resolution -------------------------------------------

def test_flow_tls_resolves_to_tls_layer():
    flow = Flow()
    assert isinstance(flow.tls, TlsLayer)
    # never-None ergonomics: empty fields, not an error.
    assert flow.tls.sni == ""
    assert flow.tls.is_empty()


def test_tlsmetadata_is_alias_of_tlslayer():
    assert TlsMetadata is TlsLayer


def test_flow_tls_is_cached_same_instance():
    flow = Flow()
    a = flow.tls
    b = flow.tls
    assert a is b  # resolved once, cached in flow.layers


def test_flow_tls_field_mutation_persists():
    flow = Flow()
    flow.tls.sni = "api.example.com"
    flow.tls.version = "TLS 1.3"
    assert flow.tls.sni == "api.example.com"
    assert flow.tls.version == "TLS 1.3"
    assert not flow.tls.is_empty()
    # one tls layer in the stack, not duplicated
    assert sum(1 for ly in flow.layers if ly.name == "tls") == 1


def test_flow_quic_and_ssh_resolve():
    flow = Flow()
    assert isinstance(flow.quic, QuicLayer)
    assert isinstance(flow.ssh, SshLayer)


def test_unknown_attribute_raises_attributeerror():
    flow = Flow()
    with pytest.raises(AttributeError):
        _ = flow.bogus_protocol
    # getattr-with-default (filter engine / copy probing) keeps working.
    assert getattr(flow, "bogus_protocol", None) is None


def test_layer_helper_and_set_layer():
    flow = Flow()
    assert flow.layer("tls") is None  # not created until accessed/added
    flow.set_layer(TlsLayer(sni="x.example"))
    assert flow.layer("tls").sni == "x.example"
    # set_layer replaces in place (no duplicate)
    flow.set_layer(TlsLayer(sni="y.example"))
    assert flow.tls.sni == "y.example"
    assert sum(1 for ly in flow.layers if ly.name == "tls") == 1


# --- decrypted data view (flow.<protocol>.data) ---------------------------

def test_transport_data_is_view_over_chunks():
    flow = _flow_with_chunks()
    assert flow.tls.data.write == flow.get_direction_bytes("write")
    assert flow.tls.data.read == flow.get_direction_bytes("read")
    assert flow.tls.data.write == b"GET / HTTP/1.1\r\n"
    assert flow.tls.data.read == b"HTTP/1.1 200 OK\r\n"


def test_data_direction_aliases():
    flow = _flow_with_chunks()
    assert flow.tls.data.c2s == flow.tls.data.write
    assert flow.tls.data.s2c == flow.tls.data.read


def test_transport_data_view_tracks_new_chunks():
    flow = _flow_with_chunks()
    before = flow.tls.data.write
    flow.chunks.append(FlowChunk(data=b"more", direction="write", timestamp=3.0))
    # The view is lazy, so it reflects appended chunks (no stale copy).
    assert flow.tls.data.write == before + b"more"


# --- copy semantics --------------------------------------------------------

def test_copy_relists_layers_and_chunks():
    flow = _flow_with_chunks()
    _ = flow.tls  # materialize a layer
    snap = copy.copy(flow)
    # Distinct list objects (appending to one must not affect the other).
    assert snap.layers is not flow.layers
    assert snap.chunks is not flow.chunks
    flow.set_layer(TlsLayer(sni="late.example"))
    flow.chunks.append(FlowChunk(data=b"x", direction="write", timestamp=9.0))
    assert len(snap.layers) == 1
    assert len(snap.chunks) == 2
