"""Unit tests for friTap.filter.layer_fields (per-protocol filter attributes).

Builds real protocol layers, serializes them with ``to_dict()`` (live path) and
through a tap FLOW record's ``meta["layers"]`` (replay path), and checks both
yield the same attributes. Pure Python — no device/Frida.
"""

from __future__ import annotations

import pytest

from friTap.filter import layer_fields as lf
from friTap.filter.layer_fields import (
    LAYER_FIELD_SPECS,
    MAX_STR_LEN,
    MAX_VALUES_PER_FIELD,
    _split_path,
    _walk,
    all_methods,
    extract_filter_attrs,
    extract_filter_attrs_from_flow,
    layer_field_names,
    layer_field_spec,
    lookup_attr,
)
from friTap.flow.layers import (
    IpsecLayer,
    MtprotoLayer,
    QuicLayer,
    Rc4Layer,
    SignalLayer,
    SshLayer,
    TelegramE2ELayer,
    TlsLayer,
)
from friTap.flow.models import Flow, FlowChunk
from friTap.flow.tap_format import encode_flow
from tests.unit._display_filter_helpers import tg_message as _tg_message
from tests.unit.test_layers_serialization import _meta_and_blob


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------

def _mtproto_layer() -> MtprotoLayer:
    layer = MtprotoLayer(
        transport="intermediate", obfuscated=True, dc_id=2,
        auth_key_id="aabbccdd11223344", message_count=2,
    )
    layer.messages = [
        _tg_message("messages.sendMessage", "hello", peer_id=777, user_id=42),
        _tg_message("updateShortMessage", "hello", peer_id=0, user_id=0),
    ]
    layer.envelope = {
        "auth_key_id": "aabbccdd11223344", "salt": "0102030405060708",
        "session_id": "deadbeefcafebabe", "msg_id": "0x65f0000000000004",
        "seq_no": 0, "transport": "intermediate", "obfuscated": True,
    }
    return layer


def _e2e_layer() -> TelegramE2ELayer:
    layer = TelegramE2ELayer(
        chat_id=12345, key_fingerprint="ff00ff00ff00ff00", message_count=1,
        origin="decrypted", layer_version=144,
    )
    layer.messages = [_tg_message("decryptedMessage", "secret hi", peer_id=99)]
    return layer


def _signal_layer() -> SignalLayer:
    layer = SignalLayer(chat_type="one_to_one", identifier="abcd", message_count=1)
    layer.messages = [{
        "sender": "+491234", "direction": "write", "timestamp": 2.0,
        "kind": "text", "body": "signal hi", "attachments": False,
        "quote": False, "reaction": False,
    }]
    return layer


def _transport_layers() -> list:
    return [
        TlsLayer(library="BoringSSL", version="TLS 1.3", sni="example.com",
                 alpn="h2", cipher="TLS_AES_128_GCM_SHA256"),
        QuicLayer(version="1", sni="q.example", alpn="h3", cipher="C",
                  scid="0a0b", dcid="0c0d"),
        SshLayer(client_version="SSH-2.0-OpenSSH_9", server_version="SSH-2.0-x",
                 kex="curve25519-sha256", cipher="aes256-gcm", mac="hmac-sha2-256"),
        IpsecLayer(ike_version="2", enc="AES-GCM", integ="SHA256", dh="19"),
        Rc4Layer(source="RC4_set_key", direction="out", key_len=16, assoc="t1"),
    ]


def _meta_layers(flow: Flow) -> list:
    meta, _blob = _meta_and_blob(encode_flow(flow))
    return meta.get("layers", [])


def _flow_with(*layers) -> Flow:
    flow = Flow(flow_id="f1", connection_id="c1")
    flow.chunks.append(FlowChunk(data=b"x", direction="read", timestamp=1.0))
    for layer in layers:
        flow.add_layer(layer)
    return flow


# ---------------------------------------------------------------------------
# Spec table
# ---------------------------------------------------------------------------

def test_spec_names_unique_lowercase_and_typed():
    names = layer_field_names()
    assert len(names) == len(set(names))
    for spec in LAYER_FIELD_SPECS:
        assert spec.field == spec.field.lower()
        assert spec.value_type in ("str", "int", "float", "bool")
        if spec.union_of:
            assert not spec.layers and not spec.path
            assert all(not layer_field_spec(m).union_of for m in spec.union_of)
        else:
            assert spec.layers and spec.path


def test_telegram_union_fields_are_listed_for_help():
    names = layer_field_names()
    for suffix in ("method", "msg", "kind", "peer_id", "user_id", "sender",
                   "chat_id", "key_fingerprint"):
        assert f"telegram.{suffix}" in names


def test_layer_field_spec_is_case_insensitive():
    assert layer_field_spec("MTProto.DC_ID").field == "mtproto.dc_id"
    assert layer_field_spec("nope.field") is None
    assert layer_field_spec(None) is None


# ---------------------------------------------------------------------------
# Path walker
# ---------------------------------------------------------------------------

def test_walk_dotted_and_fanout():
    obj = {"envelope": {"session_id": "ab"}, "messages": [{"m": 1}, {"m": 2}, {}]}
    assert _walk(obj, _split_path("envelope.session_id")) == ["ab"]
    assert _walk(obj, _split_path("messages[].m")) == [1, 2]
    assert _walk(obj, _split_path("missing.key")) == []
    assert _walk(obj, _split_path("envelope[].x")) == []      # fan-out over a non-list
    assert _walk("not a dict", _split_path("a.b")) == []


def test_split_path_is_precomputed_on_specs():
    assert _split_path("messages[].method") == (("messages", True), ("method", False))
    assert layer_field_spec("mtproto.session_id").segments == (
        ("envelope", False), ("session_id", False))


# ---------------------------------------------------------------------------
# Live extraction (to_dict)
# ---------------------------------------------------------------------------

def test_mtproto_attrs():
    attrs = extract_filter_attrs([_mtproto_layer().to_dict()])
    assert attrs["mtproto.dc_id"] == (2,)
    assert attrs["mtproto.auth_key_id"] == ("aabbccdd11223344",)
    assert attrs["mtproto.transport"] == ("intermediate",)
    assert attrs["mtproto.obfuscated"] == (True,)
    assert attrs["mtproto.message_count"] == (2,)
    assert attrs["mtproto.session_id"] == ("deadbeefcafebabe",)
    assert attrs["mtproto.msg_id"] == ("0x65f0000000000004",)
    assert attrs["mtproto.seq_no"] == (0,)          # a real 0 seq_no is kept
    assert attrs["mtproto.salt"] == ("0102030405060708",)
    assert attrs["mtproto.method"] == ("messages.sendMessage", "updateShortMessage")
    assert attrs["mtproto.msg"] == ("hello",)       # deduped
    assert attrs["mtproto.kind"] == ("text",)
    assert attrs["mtproto.peer_id"] == (777,)       # 0 = unknown, dropped
    assert attrs["mtproto.user_id"] == (42,)


def test_mtproto_default_zero_ids_absent():
    attrs = extract_filter_attrs([MtprotoLayer(transport="abridged").to_dict()])
    assert "mtproto.dc_id" not in attrs
    assert "mtproto.auth_key_id" not in attrs       # "" dropped
    assert attrs["mtproto.obfuscated"] == (False,)  # False is a real bool value


def test_telegram_union_and_e2e_attrs():
    attrs = extract_filter_attrs([_mtproto_layer().to_dict(), _e2e_layer().to_dict()])
    assert not any(k.startswith("telegram.") for k in attrs)  # unions not stored
    assert lookup_attr(attrs, "telegram.method") == (
        "messages.sendMessage", "updateShortMessage", "decryptedMessage")
    assert lookup_attr(attrs, "telegram.msg") == ("hello", "secret hi")
    assert lookup_attr(attrs, "telegram.peer_id") == (777, 99)
    assert lookup_attr(attrs, "telegram.chat_id") == (12345,)
    assert lookup_attr(attrs, "telegram.key_fingerprint") == ("ff00ff00ff00ff00",)
    assert attrs["telegram_e2e.chat_id"] == (12345,)
    assert attrs["telegram_e2e.layer_version"] == (144,)
    assert attrs["telegram_e2e.origin"] == ("decrypted",)
    assert attrs["telegram_e2e.method"] == ("decryptedMessage",)
    assert attrs["telegram_e2e.msg"] == ("secret hi",)


def test_signal_attrs():
    attrs = extract_filter_attrs([_signal_layer().to_dict()])
    assert attrs["signal.chat_type"] == ("one_to_one",)
    assert attrs["signal.identifier"] == ("abcd",)
    assert attrs["signal.message_count"] == (1,)
    assert attrs["signal.msg"] == ("signal hi",)
    assert attrs["signal.kind"] == ("text",)
    assert attrs["signal.sender"] == ("+491234",)
    assert attrs["signal.direction"] == ("write",)
    assert not any(k.startswith("telegram") for k in attrs)


def test_transport_layer_attrs():
    attrs = extract_filter_attrs([ly.to_dict() for ly in _transport_layers()])
    assert attrs["tls.sni"] == ("example.com",)
    assert attrs["tls.version"] == ("TLS 1.3",)
    assert attrs["tls.library"] == ("BoringSSL",)
    assert attrs["quic.scid"] == ("0a0b",)
    assert attrs["quic.dcid"] == ("0c0d",)
    assert attrs["quic.alpn"] == ("h3",)
    assert attrs["ssh.kex"] == ("curve25519-sha256",)
    assert attrs["ssh.mac"] == ("hmac-sha2-256",)
    assert attrs["ipsec.dh"] == ("19",)
    assert attrs["rc4.key_len"] == (16,)
    assert attrs["rc4.source"] == ("RC4_set_key",)


def test_layer_name_matching_is_case_insensitive():
    d = TlsLayer(sni="a.example").to_dict()
    d["name"] = "TLS"
    assert extract_filter_attrs([d])["tls.sni"] == ("a.example",)


def test_all_methods_unions_mtproto_and_e2e():
    attrs = extract_filter_attrs([_mtproto_layer().to_dict(), _e2e_layer().to_dict()])
    assert all_methods(attrs) == (
        "messages.sendMessage", "updateShortMessage", "decryptedMessage")
    assert all_methods({}) == ()


# ---------------------------------------------------------------------------
# Flow + tap round trip
# ---------------------------------------------------------------------------

def test_extract_from_flow_matches_to_dict():
    layers = [_mtproto_layer(), _e2e_layer()]
    flow = _flow_with(*layers)
    assert extract_filter_attrs_from_flow(flow) == extract_filter_attrs(
        [ly.to_dict() for ly in flow.layers])
    assert lookup_attr(extract_filter_attrs_from_flow(flow), "telegram.chat_id") == (12345,)


def test_extract_from_flow_without_layers():
    assert extract_filter_attrs_from_flow(Flow()) == {}
    assert extract_filter_attrs_from_flow(object()) == {}


def test_extract_from_flow_skips_broken_layer():
    class Broken:
        def to_dict(self):
            raise RuntimeError("boom")

    class Holder:
        layers = [Broken(), TlsLayer(sni="ok.example")]

    assert extract_filter_attrs_from_flow(Holder())["tls.sni"] == ("ok.example",)


@pytest.mark.parametrize("builder", [
    lambda: [_mtproto_layer(), _e2e_layer()],
    lambda: [_signal_layer()],
    lambda: [TlsLayer(library="OpenSSL", version="TLS 1.2", sni="s.example",
                      alpn="http/1.1", cipher="X")],
])
def test_tap_meta_layers_roundtrip_gives_same_attrs(builder):
    flow = _flow_with(*builder())
    live = extract_filter_attrs_from_flow(flow)
    replay = extract_filter_attrs(_meta_layers(flow))
    assert live
    assert replay == live


# ---------------------------------------------------------------------------
# Robustness and caps
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("bad", [
    None,
    [],
    [None, 1, "str", b"bytes", ["list"]],
    [{"name": 5}, {"no_name": True}, {"name": "mtproto", "messages": "notalist"}],
    [{"name": "mtproto", "messages": [None, 3, {"method": {"x": 1}}],
      "envelope": ["wrong"], "dc_id": "not-an-int"}],
])
def test_malformed_input_never_raises(bad):
    attrs = extract_filter_attrs(bad)
    assert isinstance(attrs, dict)


def test_malformed_values_are_coerced_or_dropped():
    attrs = extract_filter_attrs([{
        "name": "mtproto", "dc_id": "not-an-int",
        "messages": [{"method": {"nested": 1}}, {"method": b"\x01\x02"}],
    }])
    assert attrs["mtproto.dc_id"] == ("not-an-int",)
    assert attrs["mtproto.method"] == ("0102",)     # bytes -> hex; dict dropped


def test_broken_iterable_does_not_raise():
    def gen():
        yield TlsLayer(sni="first.example").to_dict()
        raise RuntimeError("iteration failure")

    assert extract_filter_attrs(gen())["tls.sni"] == ("first.example",)


def test_value_count_cap():
    layer = SignalLayer(chat_type="group")
    layer.messages = [{"body": f"m{i}"} for i in range(MAX_VALUES_PER_FIELD + 500)]
    values = extract_filter_attrs([layer.to_dict()])["signal.msg"]
    assert len(values) == MAX_VALUES_PER_FIELD
    assert values[0] == "m0"


def test_string_length_cap():
    layer = SignalLayer(chat_type="group")
    layer.messages = [{"body": "x" * (MAX_STR_LEN * 3)}]
    (body,) = extract_filter_attrs([layer.to_dict()])["signal.msg"]
    assert len(body) == MAX_STR_LEN


def test_layer_name_key_constant():
    assert lf.LAYER_NAME_KEY == "name"
    assert TlsLayer().to_dict()[lf.LAYER_NAME_KEY] == "tls"


def test_lookup_attr_dedupes_union_and_passes_base_fields_through():
    attrs = {"mtproto.kind": ("text", "service"), "telegram_e2e.kind": ("text", "photo")}
    assert lookup_attr(attrs, "telegram.kind") == ("text", "service", "photo")
    assert lookup_attr(attrs, "mtproto.kind") == ("text", "service")
    assert lookup_attr(attrs, "telegram.sender") == ()
    assert lookup_attr(None, "telegram.kind") == ()
    assert lookup_attr(attrs, "not.a.field") == ()
