"""Typed protocol-layer model: a flow is an ordered stack of protocol layers.

Each layer is a dataclass with protocol metadata plus a directional decrypted-data
accessor (:class:`LayerData`) and a parsed-result reference
(:attr:`ProtocolLayer.parsed`). Pure module: ``friTap.flow.models`` is never
imported at runtime. A flow-like owner exposes ``get_direction_bytes(direction)``
(``"read"`` server->client, ``"write"`` client->server).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, ClassVar, Optional

if TYPE_CHECKING:  # pragma: no cover - typing only
    from friTap.parsers.base import ParseResult


@dataclass
class LayerData:
    """Directional decrypted bytes for one protocol layer.

    ``data_source``: ``"chunks"`` (delegated to the flow-like ``_owner`` via
    ``get_direction_bytes``, no copy), ``"owned"`` (own buffers, for bytes produced
    by an inner decryptor) or ``"none"`` (accessors return ``b""``).
    """

    data_source: str = "none"
    _owner: Optional[object] = field(default=None, repr=False)
    _owned_read: bytes = b""
    _owned_write: bytes = field(default=b"", repr=False)

    @property
    def write(self) -> bytes:
        """Client->server decrypted bytes for this layer."""
        if self.data_source == "chunks":
            if self._owner is None:
                return b""
            return self._owner.get_direction_bytes("write")
        if self.data_source == "owned":
            return self._owned_write
        return b""

    @property
    def read(self) -> bytes:
        """Server->client decrypted bytes for this layer."""
        if self.data_source == "chunks":
            if self._owner is None:
                return b""
            return self._owner.get_direction_bytes("read")
        if self.data_source == "owned":
            return self._owned_read
        return b""

    @property
    def c2s(self) -> bytes:
        """Alias for :attr:`write` (client-to-server)."""
        return self.write

    @property
    def s2c(self) -> bytes:
        """Alias for :attr:`read` (server-to-client)."""
        return self.read

    def direction(self, d: str) -> bytes:
        """Return bytes for direction *d* (``"write"`` else ``"read"``)."""
        return self.write if d == "write" else self.read

    def set_owned(self, read: bytes = b"", write: bytes = b"") -> None:
        """Switch to ``"owned"`` mode, holding the given directional buffers."""
        self.data_source = "owned"
        self._owned_read = read
        self._owned_write = write

    def is_empty(self) -> bool:
        """Return True when neither direction has any bytes."""
        return not (self.read or self.write)


@dataclass
class ProtocolLayer:
    """Base class for a typed protocol layer in a flow's stack.

    Knows its place (:attr:`depth`, :attr:`parent`, :attr:`child`), carries its
    decrypted :attr:`data`, and resolves a parsed result from a backing flow
    attribute (``_parsed_field`` + ``_flow``) or from :meth:`set_parsed` (owned layers).
    """

    NAME: ClassVar[str] = ""

    depth: int = 0
    parent: Optional["ProtocolLayer"] = field(default=None, repr=False)
    child: Optional["ProtocolLayer"] = field(default=None, repr=False)
    data: LayerData = field(default_factory=LayerData)
    _flow: Optional[object] = field(default=None, repr=False)
    _parsed_field: str = ""
    _inner_parsed: Optional["ParseResult"] = field(default=None, repr=False)
    # Per-instance name for generic layers (AppLayer serves every app protocol);
    # typed subclasses leave it empty and use ``NAME``. Set by ``Flow._create_layer``.
    _name: str = field(default="", repr=False)
    # Metadata-only marker: carries typed metadata (e.g. TLS SNI, HTTP/2/WebSocket
    # markers on an offline-decrypted Signal flow) but none of its own bytes (they
    # belong to the innermost layer). Not skipped at serialization; never rebinds
    # to the flow's chunks view.
    metadata_only: bool = False

    @property
    def name(self) -> str:
        """The layer name: per-instance ``_name`` (generic layers), else class ``NAME``."""
        return self._name or self.NAME

    @property
    def parsed(self) -> Optional["ParseResult"]:
        """The parsed result: mirrors the flow attribute named by ``_parsed_field`` live, else the owned result from :meth:`set_parsed`."""
        if self._parsed_field and self._flow is not None:
            return getattr(self._flow, self._parsed_field, None)
        return self._inner_parsed

    def set_parsed(self, pr: Optional["ParseResult"]) -> None:
        """Set the owned parsed result."""
        self._inner_parsed = pr

    def is_empty(self) -> bool:
        """True when there is no parsed result and no data."""
        return self.parsed is None and self.data.is_empty()

    def to_dict(self) -> dict:
        """Serialize the layer's identity; subclasses add metadata fields."""
        return {"name": self.name, "depth": self.depth}

    @classmethod
    def from_dict(cls, d: dict) -> "ProtocolLayer":
        """Reconstruct a layer from :meth:`to_dict` output; subclasses restore their fields."""
        layer = cls()
        layer.depth = d.get("depth", 0)
        return layer


@dataclass
class TlsLayer(ProtocolLayer):
    """TLS protocol layer.

    ``client_random`` is the hex ClientHello random the agent stamped (live flows
    only); like :attr:`QuicLayer.library` it is serialized only when non-empty so
    older flows keep their ``to_dict`` shape.
    """

    NAME: ClassVar[str] = "tls"

    library: str = ""
    version: str = ""
    sni: str = ""
    alpn: str = ""
    cipher: str = ""
    client_random: str = ""

    def is_empty(self) -> bool:
        return not (self.library or self.version or self.sni
                    or self.alpn or self.cipher or self.client_random)

    def to_dict(self) -> dict:
        d = super().to_dict()
        d.update({
            "library": self.library,
            "version": self.version,
            "sni": self.sni,
            "alpn": self.alpn,
            "cipher": self.cipher,
        })
        if self.client_random:
            d["client_random"] = self.client_random
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "TlsLayer":
        layer = cls()
        layer.depth = d.get("depth", 0)
        layer.library = d.get("library", "")
        layer.version = d.get("version", "")
        layer.sni = d.get("sni", "")
        layer.alpn = d.get("alpn", "")
        layer.cipher = d.get("cipher", "")
        layer.client_random = d.get("client_random", "")
        return layer


@dataclass
class QuicLayer(ProtocolLayer):
    """QUIC protocol layer.

    ``library`` and ``client_random`` mirror :class:`TlsLayer` and are serialized
    only when non-empty, so offline QUIC flows keep their ``to_dict`` shape.
    """

    NAME: ClassVar[str] = "quic"

    library: str = ""
    version: str = ""
    sni: str = ""
    alpn: str = ""
    cipher: str = ""
    scid: str = ""
    dcid: str = ""
    client_random: str = ""

    def is_empty(self) -> bool:
        return not (self.library or self.version or self.sni or self.alpn
                    or self.cipher or self.scid or self.dcid or self.client_random)

    def to_dict(self) -> dict:
        d = super().to_dict()
        if self.library:
            d["library"] = self.library
        d.update({
            "version": self.version,
            "sni": self.sni,
            "alpn": self.alpn,
            "cipher": self.cipher,
            "scid": self.scid,
            "dcid": self.dcid,
        })
        if self.client_random:
            d["client_random"] = self.client_random
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "QuicLayer":
        layer = cls()
        layer.depth = d.get("depth", 0)
        layer.library = d.get("library", "")
        layer.version = d.get("version", "")
        layer.sni = d.get("sni", "")
        layer.alpn = d.get("alpn", "")
        layer.cipher = d.get("cipher", "")
        layer.scid = d.get("scid", "")
        layer.dcid = d.get("dcid", "")
        layer.client_random = d.get("client_random", "")
        return layer


@dataclass
class SshLayer(ProtocolLayer):
    """SSH protocol layer."""

    NAME: ClassVar[str] = "ssh"

    client_version: str = ""
    server_version: str = ""
    kex: str = ""
    cipher: str = ""
    mac: str = ""

    def is_empty(self) -> bool:
        return not (self.client_version or self.server_version
                    or self.kex or self.cipher or self.mac)

    def to_dict(self) -> dict:
        d = super().to_dict()
        d.update({
            "client_version": self.client_version,
            "server_version": self.server_version,
            "kex": self.kex,
            "cipher": self.cipher,
            "mac": self.mac,
        })
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "SshLayer":
        layer = cls()
        layer.depth = d.get("depth", 0)
        layer.client_version = d.get("client_version", "")
        layer.server_version = d.get("server_version", "")
        layer.kex = d.get("kex", "")
        layer.cipher = d.get("cipher", "")
        layer.mac = d.get("mac", "")
        return layer


@dataclass
class IpsecLayer(ProtocolLayer):
    """IPsec protocol layer."""

    NAME: ClassVar[str] = "ipsec"

    ike_version: str = ""
    enc: str = ""
    integ: str = ""
    dh: str = ""

    def is_empty(self) -> bool:
        return not (self.ike_version or self.enc or self.integ or self.dh)

    def to_dict(self) -> dict:
        d = super().to_dict()
        d.update({
            "ike_version": self.ike_version,
            "enc": self.enc,
            "integ": self.integ,
            "dh": self.dh,
        })
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "IpsecLayer":
        layer = cls()
        layer.depth = d.get("depth", 0)
        layer.ike_version = d.get("ike_version", "")
        layer.enc = d.get("enc", "")
        layer.integ = d.get("integ", "")
        layer.dh = d.get("dh", "")
        return layer


@dataclass
class MtprotoLayer(ProtocolLayer):
    """Telegram MTProto protocol layer.

    Decrypted message bytes ride the flow's chunks (``data_source="chunks"``); TL
    parsing is left to a downstream parser, so this layer carries only
    transport/identity metadata.
    """

    NAME: ClassVar[str] = "mtproto"

    transport: str = ""        # "abridged" / "intermediate" / "padded_intermediate" / "full"
    obfuscated: bool = False
    fake_tls: bool = False
    dc_id: int = 0
    auth_key_id: str = ""      # hex of the auth_key_id that decrypted this flow
    message_count: int = 0
    # Per-message metadata dicts {direction, kind, body, sender_id, peer_id,
    # has_media}, filled by the offline TL parser (friTap.offline.mtproto.content).
    messages: list = field(default_factory=list)
    # Per-packet forensic metadata (offline, one record per flow): MTProto envelope
    # (salt, session_id, msg_id, seq_no, ...), cross-references, users seen.
    envelope: dict = field(default_factory=dict)
    refs: dict = field(default_factory=dict)
    users: list = field(default_factory=list)

    def is_empty(self) -> bool:
        return not (
            self.transport or self.obfuscated or self.fake_tls
            or self.dc_id or self.auth_key_id or self.message_count
            or self.messages or _has_packet_meta(self)
        ) and self.data.is_empty()

    def to_dict(self) -> dict:
        d = super().to_dict()
        d.update({
            "transport": self.transport,
            "obfuscated": self.obfuscated,
            "fake_tls": self.fake_tls,
            "dc_id": self.dc_id,
            "auth_key_id": self.auth_key_id,
            "message_count": self.message_count,
            "messages": self.messages,
        })
        d.update(_packet_meta_to_dict(self))
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "MtprotoLayer":
        layer = cls()
        layer.depth = d.get("depth", 0)
        layer.transport = d.get("transport", "")
        layer.obfuscated = d.get("obfuscated", False)
        layer.fake_tls = d.get("fake_tls", False)
        layer.dc_id = d.get("dc_id", 0)
        layer.auth_key_id = d.get("auth_key_id", "")
        layer.message_count = d.get("message_count", 0)
        layer.messages = d.get("messages", []) or []
        _packet_meta_from_dict(layer, d)
        return layer


# Additive per-packet metadata shared by MtprotoLayer and TelegramE2ELayer.
# Serialized only when set, so older taps load with empty defaults and layers
# without it keep their exact shape.
_PACKET_META_FIELDS = (("envelope", dict), ("refs", dict), ("users", list))
_E2E_EXTRA_META = (("peer", dict),)


def _has_packet_meta(layer) -> bool:
    return any(getattr(layer, name, None) for name, _ in _PACKET_META_FIELDS) or bool(
        getattr(layer, "peer", None)
    )


def _packet_meta_to_dict(layer, extra: tuple = ()) -> dict:
    names = [name for name, _ in _PACKET_META_FIELDS + tuple(extra)]
    return {name: getattr(layer, name) for name in names if getattr(layer, name)}


def _packet_meta_from_dict(layer, d: dict, extra: tuple = ()) -> None:
    for name, kind in _PACKET_META_FIELDS + tuple(extra):
        value = d.get(name)
        setattr(layer, name, value if isinstance(value, kind) else kind())


@dataclass
class TelegramE2ELayer(ProtocolLayer):
    """Telegram secret-chat (end-to-end) layer, riding INSIDE the MTProto transport.

    Decrypted inner payload bytes ride the flow's chunks (``data_source="chunks"``),
    from the offline decryptor (``origin="decrypted"``) or a plaintext hook
    (``origin="plaintext_hook"``). TL parsing is left to a downstream parser.
    """

    NAME: ClassVar[str] = "telegram_e2e"

    chat_id: int = 0
    key_fingerprint: str = ""   # hex of the key_fingerprint that decrypted this flow
    message_count: int = 0
    origin: str = "decrypted"   # "decrypted" / "plaintext_hook"
    layer_version: int = 0
    # Per-message metadata dicts, as on MtprotoLayer.
    messages: list = field(default_factory=list)
    # Per-packet forensic metadata as on MtprotoLayer, plus the Secret-Chat ``peer`` when linkable.
    envelope: dict = field(default_factory=dict)
    refs: dict = field(default_factory=dict)
    users: list = field(default_factory=list)
    peer: dict = field(default_factory=dict)

    def is_empty(self) -> bool:
        return not (
            self.chat_id or self.key_fingerprint or self.message_count
            or self.layer_version or self.messages or _has_packet_meta(self)
        ) and self.data.is_empty()

    def to_dict(self) -> dict:
        d = super().to_dict()
        d.update({
            "chat_id": self.chat_id,
            "key_fingerprint": self.key_fingerprint,
            "message_count": self.message_count,
            "origin": self.origin,
            "layer_version": self.layer_version,
            "messages": self.messages,
        })
        d.update(_packet_meta_to_dict(self, extra=_E2E_EXTRA_META))
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "TelegramE2ELayer":
        layer = cls()
        layer.depth = d.get("depth", 0)
        layer.chat_id = d.get("chat_id", 0)
        layer.key_fingerprint = d.get("key_fingerprint", "")
        layer.message_count = d.get("message_count", 0)
        layer.origin = d.get("origin", "decrypted")
        layer.layer_version = d.get("layer_version", 0)
        layer.messages = d.get("messages", []) or []
        _packet_meta_from_dict(layer, d, extra=_E2E_EXTRA_META)
        return layer


@dataclass
class SignalLayer(ProtocolLayer):
    """Signal protocol layer.

    Decrypted inner ``Content`` bytes ride the flow's chunks (``data_source="chunks"``);
    protobuf parsing is left to a downstream parser, so this layer carries only identity metadata.
    """

    NAME: ClassVar[str] = "signal"

    chat_type: str = ""        # "one_to_one" / "group"
    identifier: str = ""       # hex of the eph_pub (1:1) or auth_tag (group)
    message_count: int = 0
    # Per-message metadata dicts {sender, direction, timestamp, kind, body, attachments,
    # quote, reaction}. Plaintext WS/REST records (kind in {rest, ws-request, ws-response,
    # profile, device-list, prekey}) add optional {verb, path, status, request_id, meta}.
    messages: list = field(default_factory=list)

    def is_empty(self) -> bool:
        return not (
            self.chat_type or self.identifier or self.message_count or self.messages
        ) and self.data.is_empty()

    def to_dict(self) -> dict:
        d = super().to_dict()
        d.update({
            "chat_type": self.chat_type,
            "identifier": self.identifier,
            "message_count": self.message_count,
            "messages": self.messages,
        })
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "SignalLayer":
        layer = cls()
        layer.depth = d.get("depth", 0)
        layer.chat_type = d.get("chat_type", "")
        layer.identifier = d.get("identifier", "")
        layer.message_count = d.get("message_count", 0)
        layer.messages = d.get("messages", []) or []
        return layer


@dataclass
class Rc4Layer(ProtocolLayer):
    """RC4 cipher layer.

    Decrypted RC4 plaintext rides the flow's chunks (``data_source="chunks"``). Under
    ``--protocol tls,rc4`` it renders INSIDE the TLS layer, standalone it is the
    sole cipher layer. Carries only identity metadata (which hook recovered the key).
    """

    NAME: ClassVar[str] = "rc4"

    source: str = ""          # hook that recovered the key (RC4_set_key, BCrypt…, …)
    direction: str = ""       # "out" / "in" / "unknown"
    key_len: int = 0          # RC4 key length in bytes
    assoc: str = ""           # association hint (agent thread id) for the nested case
    message_count: int = 0
    # Framing of the RC4 stream inside TLS plaintext: "u32be-length" (4-byte BE length
    # prefix per record) or "continuous" (one unframed keystream); empty if unknown/standalone.
    framing: str = ""
    # Per-record dicts {"direction", "length", "tls_frames", "timestamp", "cipher_offset",
    # "frame_header_len"}. Not named ``messages``: the TUI treats that as a chat transcript.
    records: list = field(default_factory=list)

    def is_empty(self) -> bool:
        return not (
            self.source or self.direction or self.key_len
            or self.assoc or self.message_count
            or self.framing or self.records
        ) and self.data.is_empty()

    def to_dict(self) -> dict:
        d = super().to_dict()
        d.update({
            "source": self.source,
            "direction": self.direction,
            "key_len": self.key_len,
            "assoc": self.assoc,
            "message_count": self.message_count,
            "framing": self.framing,
            "records": self.records,
        })
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Rc4Layer":
        layer = cls()
        layer.depth = d.get("depth", 0)
        layer.source = d.get("source", "")
        layer.direction = d.get("direction", "")
        layer.key_len = d.get("key_len", 0)
        layer.assoc = d.get("assoc", "")
        layer.message_count = d.get("message_count", 0)
        layer.framing = d.get("framing", "") or ""
        layer.records = d.get("records", []) or []
        return layer


@dataclass
class AppLayer(ProtocolLayer):
    """Generic application-protocol layer (http1/http2/http3/websocket).

    Mirrors the flow's parsed request/response via ``_parsed_field`` (so
    ``flow.http2.parsed is flow.request``); the protocol name is per-instance in
    ``_name`` (``NAME = ""`` lets the registry bind several names to this class).
    Also backs generic inner owned-data layers from the nested-decryption seam.
    """

    NAME: ClassVar[str] = ""

    def is_empty(self) -> bool:
        return self.parsed is None and self.data.is_empty()

    def to_dict(self) -> dict:
        # Base to_dict (name + depth) is the full identity of an app layer.
        return super().to_dict()

    @classmethod
    def from_dict(cls, d: dict) -> "AppLayer":
        layer = cls()
        layer.depth = d.get("depth", 0)
        layer._name = d.get("name", "")
        return layer
