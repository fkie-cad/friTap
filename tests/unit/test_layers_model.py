"""Unit tests for the typed protocol-layer model (Phase 1).

Covers LayerData (owned + chunks modes), ProtocolLayer.parsed resolution,
typed layer is_empty/to_dict/from_dict round-trips, the protocol registry,
and the (empty) decryptor registry seam. Pure Python — no device/Frida.
"""

import pytest

from friTap.flow.decryptors import (
    DecryptorRegistry,
    LayerDecryptor,
    get_default_decryptor_registry,
)
from friTap.flow.layer_registry import (
    ProtocolDescriptor,
    ProtocolRegistry,
    get_registry,
)
from friTap.flow.layers import (
    IpsecLayer,
    LayerData,
    ProtocolLayer,
    QuicLayer,
    SshLayer,
    TlsLayer,
)


# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------

class _FakeOwner:
    """Minimal flow-like owner exposing get_direction_bytes."""

    def __init__(self, read: bytes = b"", write: bytes = b"") -> None:
        self._read = read
        self._write = write

    def get_direction_bytes(self, direction: str) -> bytes:
        return self._write if direction == "write" else self._read


class _FakeFlow:
    """Minimal flow object exposing a mutable .request attribute."""

    def __init__(self, request=None) -> None:
        self.request = request


# ---------------------------------------------------------------------------
# 1. LayerData owned mode
# ---------------------------------------------------------------------------

def test_layerdata_owned_mode():
    ld = LayerData()
    assert ld.is_empty()
    assert ld.read == b"" and ld.write == b""

    ld.set_owned(read=b"resp", write=b"req")
    assert ld.data_source == "owned"
    assert ld.read == b"resp"
    assert ld.write == b"req"
    assert ld.s2c == b"resp"
    assert ld.c2s == b"req"
    assert ld.direction("write") == b"req"
    assert ld.direction("read") == b"resp"
    assert not ld.is_empty()


def test_layerdata_owned_is_empty_transition():
    ld = LayerData()
    assert ld.is_empty()
    ld.set_owned(write=b"x")
    assert not ld.is_empty()
    ld.set_owned()  # back to empty buffers
    assert ld.is_empty()


# ---------------------------------------------------------------------------
# 2. LayerData chunks mode
# ---------------------------------------------------------------------------

def test_layerdata_chunks_mode_delegates():
    owner = _FakeOwner(read=b"server->client", write=b"client->server")
    ld = LayerData(data_source="chunks")
    ld._owner = owner
    assert ld.read == b"server->client"
    assert ld.write == b"client->server"
    assert ld.s2c == b"server->client"
    assert ld.c2s == b"client->server"
    assert not ld.is_empty()


def test_layerdata_chunks_mode_none_owner():
    ld = LayerData(data_source="chunks")
    assert ld._owner is None
    assert ld.read == b""
    assert ld.write == b""
    assert ld.is_empty()


# ---------------------------------------------------------------------------
# 3. ProtocolLayer.parsed resolution
# ---------------------------------------------------------------------------

def test_protocollayer_parsed_mirrors_flow_attr():
    sentinel = object()
    flow = _FakeFlow(request=sentinel)
    layer = ProtocolLayer(_flow=flow, _parsed_field="request")
    assert layer.parsed is sentinel

    # Reassigning the flow attribute is reflected live.
    new_request = object()
    flow.request = new_request
    assert layer.parsed is new_request


def test_protocollayer_parsed_owned_set_parsed():
    pr = object()
    layer = ProtocolLayer()
    assert layer.parsed is None
    layer.set_parsed(pr)
    assert layer.parsed is pr


def test_protocollayer_name_and_is_empty():
    layer = ProtocolLayer()
    assert layer.name == ""
    assert layer.is_empty()


# ---------------------------------------------------------------------------
# 4. Typed layer is_empty + to_dict/from_dict round-trips
# ---------------------------------------------------------------------------

def test_tls_layer_is_empty_and_roundtrip():
    empty = TlsLayer()
    assert empty.is_empty()
    assert empty.name == "tls"

    layer = TlsLayer(
        depth=2,
        library="BoringSSL",
        version="TLS 1.3",
        sni="api.example.com",
        alpn="h2",
        cipher="TLS_AES_128_GCM_SHA256",
    )
    assert not layer.is_empty()

    d = layer.to_dict()
    assert d["name"] == "tls"
    assert d["depth"] == 2

    restored = TlsLayer.from_dict(d)
    assert restored.depth == 2
    assert restored.library == "BoringSSL"
    assert restored.version == "TLS 1.3"
    assert restored.sni == "api.example.com"
    assert restored.alpn == "h2"
    assert restored.cipher == "TLS_AES_128_GCM_SHA256"


def test_ssh_layer_is_empty_and_roundtrip():
    empty = SshLayer()
    assert empty.is_empty()
    assert empty.name == "ssh"

    layer = SshLayer(
        depth=1,
        client_version="SSH-2.0-OpenSSH_9.6",
        server_version="SSH-2.0-OpenSSH_8.9",
        kex="curve25519-sha256",
        cipher="chacha20-poly1305@openssh.com",
        mac="hmac-sha2-256",
    )
    assert not layer.is_empty()

    d = layer.to_dict()
    restored = SshLayer.from_dict(d)
    assert restored.depth == 1
    assert restored.client_version == "SSH-2.0-OpenSSH_9.6"
    assert restored.server_version == "SSH-2.0-OpenSSH_8.9"
    assert restored.kex == "curve25519-sha256"
    assert restored.cipher == "chacha20-poly1305@openssh.com"
    assert restored.mac == "hmac-sha2-256"


def test_quic_and_ipsec_roundtrip():
    quic = QuicLayer(version="1", alpn="h3", cipher="AEAD", scid="ab", dcid="cd")
    assert not quic.is_empty()
    assert QuicLayer.from_dict(quic.to_dict()).dcid == "cd"

    ipsec = IpsecLayer(ike_version="2", enc="aes-gcm", integ="sha256", dh="19")
    assert not ipsec.is_empty()
    assert IpsecLayer.from_dict(ipsec.to_dict()).enc == "aes-gcm"
    assert IpsecLayer().is_empty()


# ---------------------------------------------------------------------------
# 5. Protocol registry
# ---------------------------------------------------------------------------

def test_registry_builtins():
    reg = get_registry()
    tls = reg.get("tls")
    assert tls is not None
    assert tls.layer_cls is TlsLayer
    assert tls.data_source == "chunks"

    quic = reg.get("quic")
    assert quic.layer_cls is QuicLayer
    assert quic.data_source == "chunks"

    names = reg.names()
    assert {"tls", "quic", "ssh", "ipsec"}.issubset(names)
    assert reg.get("nonexistent") is None


def test_registry_descriptor_name_mismatch_raises():
    with pytest.raises(AssertionError):
        ProtocolDescriptor("not-tls", TlsLayer)


def test_registry_register_and_list():
    reg = ProtocolRegistry()
    assert reg.names() == frozenset()
    desc = ProtocolDescriptor("tls", TlsLayer, data_source="chunks")
    reg.register(desc)
    assert reg.get("tls") is desc
    assert desc in reg.list()


# ---------------------------------------------------------------------------
# 6. Decryptor registry (empty seam)
# ---------------------------------------------------------------------------

def test_default_decryptor_registry_is_empty():
    reg = get_default_decryptor_registry()
    assert reg.resolve(object(), object()) is None


def test_decryptor_registry_resolves_registered():
    class _FakeDecryptor(LayerDecryptor):
        name = "fake"

        def can_handle(self, parent_layer, flow) -> bool:
            return True

        def feed(self, data: bytes, direction: str) -> bytes:
            return data

    reg = DecryptorRegistry()
    assert reg.resolve(object(), object()) is None
    reg.register(_FakeDecryptor)
    resolved = reg.resolve(object(), object())
    assert isinstance(resolved, _FakeDecryptor)


def test_decryptor_registry_priority_and_skip_on_error():
    class _Boom(LayerDecryptor):
        def __init__(self) -> None:
            raise RuntimeError("boom")

        def can_handle(self, parent_layer, flow) -> bool:
            return True

        def feed(self, data: bytes, direction: str) -> bytes:
            return data

    class _Good(LayerDecryptor):
        def can_handle(self, parent_layer, flow) -> bool:
            return True

        def feed(self, data: bytes, direction: str) -> bytes:
            return data

    reg = DecryptorRegistry()
    reg.register(_Good, priority=10)
    reg.register(_Boom, priority=100)  # higher priority but raises -> skipped
    resolved = reg.resolve(object(), object())
    assert isinstance(resolved, _Good)
