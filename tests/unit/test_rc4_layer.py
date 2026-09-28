#!/usr/bin/env python3

"""Tests for the RC4 flow layer registration.

``Rc4Layer`` must be registered under the name ``rc4`` with ``chunks`` data, and
``rc4`` must appear in the inner-E2E layer names so it renders inside TLS when
both ``tls`` and ``rc4`` are selected.
"""

from friTap.flow import layer_registry
from friTap.flow.display import INNER_E2E_LAYER_NAMES
from friTap.flow.layers import Rc4Layer


def test_rc4_layer_registered():
    desc = layer_registry.get("rc4")
    assert desc is not None
    assert desc.layer_cls is Rc4Layer
    assert desc.name == "rc4"


def test_rc4_layer_data_source_is_chunks():
    desc = layer_registry.get("rc4")
    assert desc.data_source == "chunks"


def test_rc4_in_registered_names():
    assert "rc4" in layer_registry.get_registry().names()


def test_rc4_is_inner_e2e_layer():
    # So the layered display renders TLS[RC4] when both are present.
    assert "rc4" in INNER_E2E_LAYER_NAMES


def test_rc4_layer_roundtrip_dict():
    layer = Rc4Layer()
    layer.source = "RC4_set_key"
    layer.direction = "out"
    layer.key_len = 19
    layer.assoc = "4711"
    layer.message_count = 2
    restored = Rc4Layer.from_dict(layer.to_dict())
    assert restored.source == "RC4_set_key"
    assert restored.direction == "out"
    assert restored.key_len == 19
    assert restored.assoc == "4711"
    assert restored.message_count == 2


def test_rc4_layer_name():
    assert Rc4Layer().name == "rc4"


# ---------------------------------------------------------------------------
# RC4-in-TLS framing + per-record metadata
# ---------------------------------------------------------------------------

_SAMPLE_RECORD = {
    "direction": "write",
    "length": 42,
    "tls_frames": [3, 4],
    "timestamp": 1000.5,
    "cipher_offset": 128,
    "frame_header_len": 4,
}


def test_rc4_layer_defaults_for_framing_and_records():
    layer = Rc4Layer()
    assert layer.framing == ""
    assert layer.records == []
    assert Rc4Layer().records is not layer.records  # no shared mutable default


def test_rc4_layer_roundtrip_framing_and_records():
    layer = Rc4Layer()
    layer.framing = "u32be-length"
    layer.records = [dict(_SAMPLE_RECORD)]
    d = layer.to_dict()
    assert d["framing"] == "u32be-length"
    assert d["records"] == [_SAMPLE_RECORD]
    restored = Rc4Layer.from_dict(d)
    assert restored.framing == "u32be-length"
    assert restored.records == [_SAMPLE_RECORD]


def test_rc4_layer_loads_old_dict_without_new_fields():
    old = {"name": "rc4", "depth": 1, "source": "RC4_set_key", "key_len": 16}
    restored = Rc4Layer.from_dict(old)
    assert restored.framing == ""
    assert restored.records == []
    assert restored.source == "RC4_set_key"


def test_rc4_layer_records_make_it_non_empty():
    layer = Rc4Layer()
    assert layer.is_empty()
    layer.records = [dict(_SAMPLE_RECORD)]
    assert not layer.is_empty()
    assert not hasattr(layer, "messages")  # must not look like a chat transcript
