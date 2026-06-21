"""Typed protocol-layer model for friTap's protocol-layer-stack feature.

A flow becomes an ordered stack of typed protocol layers. Each layer is a
dataclass carrying its protocol metadata fields plus two shared facets:

  * a directional decrypted-data accessor (:class:`LayerData`), and
  * a parsed-result reference (:attr:`ProtocolLayer.parsed`).

These modules are pure and self-contained: nothing here imports
``friTap.flow.models`` at runtime. ``Flow`` and ``ParseResult`` are referenced
only under :data:`typing.TYPE_CHECKING` for type hints.

A flow-like owner is anything exposing ``get_direction_bytes(direction)`` where
*direction* is ``"read"`` (server->client) or ``"write"`` (client->server).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import ClassVar, Optional, TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - typing only
    from friTap.parsers.base import ParseResult


@dataclass
class LayerData:
    """Directional decrypted bytes for a single protocol layer.

    Three data sources are supported:

      * ``"chunks"`` — bytes are delegated to an owning flow-like object via
        ``get_direction_bytes`` (no copy is held here). Set :attr:`_owner`
        externally.
      * ``"owned"`` — bytes are held in this object's own buffers (used by
        layers whose decrypted data is produced by an inner decryptor and does
        not live in the flow's raw chunks).
      * ``"none"`` — no data available; accessors return ``b""``.

    Fields:
        data_source: One of ``"chunks"``, ``"owned"`` or ``"none"``.
        _owner: Flow-like owner exposing ``get_direction_bytes`` (chunks mode).
        _owned_read: Owned read-direction (server->client) bytes.
        _owned_write: Owned write-direction (client->server) bytes.
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
    """Base class for a single typed protocol layer in a flow's stack.

    A layer knows its position in the stack (:attr:`depth`, :attr:`parent`,
    :attr:`child`), carries its directional decrypted data (:attr:`data`), and
    resolves a parsed result either from a backing flow attribute
    (``_parsed_field`` + ``_flow``) or from an inner parsed result set via
    :meth:`set_parsed` (for owned layers).

    Subclasses set :attr:`NAME` and add protocol metadata fields.
    """

    NAME: ClassVar[str] = ""

    depth: int = 0
    parent: Optional["ProtocolLayer"] = field(default=None, repr=False)
    child: Optional["ProtocolLayer"] = field(default=None, repr=False)
    data: LayerData = field(default_factory=LayerData)
    _flow: Optional[object] = field(default=None, repr=False)
    _parsed_field: str = ""
    _inner_parsed: Optional["ParseResult"] = field(default=None, repr=False)
    # Per-instance name override. Concrete subclasses leave this empty and
    # report their ClassVar :attr:`NAME`; generic layers (e.g. :class:`AppLayer`,
    # which serves every application protocol from one class) carry their name
    # here. Set by ``Flow._create_layer`` from the registry/descriptor name.
    _name: str = field(default="", repr=False)
    # Metadata-only marker: this layer carries typed metadata (e.g. a TLS SNI or
    # the HTTP/2/WebSocket encapsulation markers on an offline-decrypted Signal
    # flow) but NONE of its own bytes — the decrypted bytes belong to the
    # innermost layer. Such a layer is "empty of bytes" yet meaningful, so it is
    # NOT skipped at serialization and never rebinds to the flow's chunks view.
    metadata_only: bool = False

    @property
    def name(self) -> str:
        """The protocol name of this layer.

        Returns the per-instance :attr:`_name` when set (generic layers),
        otherwise the class-level :attr:`NAME` (typed transport layers).
        """
        return self._name or self.NAME

    @property
    def parsed(self) -> Optional["ParseResult"]:
        """The parsed result for this layer.

        When :attr:`_parsed_field` and :attr:`_flow` are set, mirror the named
        flow attribute (e.g. ``"request"``) live. Otherwise fall back to an
        owned parsed result set via :meth:`set_parsed`.
        """
        if self._parsed_field and self._flow is not None:
            return getattr(self._flow, self._parsed_field, None)
        return self._inner_parsed

    def set_parsed(self, pr: Optional["ParseResult"]) -> None:
        """Set the owned parsed result (used by owned layers)."""
        self._inner_parsed = pr

    def is_empty(self) -> bool:
        """Return True when this layer has no parsed result and no data."""
        return self.parsed is None and self.data.is_empty()

    def to_dict(self) -> dict:
        """Serialize the layer's identity. Subclasses add metadata fields."""
        return {"name": self.name, "depth": self.depth}

    @classmethod
    def from_dict(cls, d: dict) -> "ProtocolLayer":
        """Reconstruct a layer from :meth:`to_dict` output.

        Subclasses override to restore their metadata fields.
        """
        layer = cls()
        layer.depth = d.get("depth", 0)
        return layer


@dataclass
class TlsLayer(ProtocolLayer):
    """TLS protocol layer.

    Carries exactly the five fields mirrored from the legacy
    ``friTap.flow.models.TlsMetadata`` value object, which this layer will
    eventually replace.
    """

    NAME: ClassVar[str] = "tls"

    library: str = ""
    version: str = ""
    sni: str = ""
    alpn: str = ""
    cipher: str = ""

    def is_empty(self) -> bool:
        return not (self.library or self.version or self.sni
                    or self.alpn or self.cipher)

    def to_dict(self) -> dict:
        d = super().to_dict()
        d.update({
            "library": self.library,
            "version": self.version,
            "sni": self.sni,
            "alpn": self.alpn,
            "cipher": self.cipher,
        })
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
        return layer


@dataclass
class QuicLayer(ProtocolLayer):
    """QUIC protocol layer."""

    NAME: ClassVar[str] = "quic"

    version: str = ""
    sni: str = ""
    alpn: str = ""
    cipher: str = ""
    scid: str = ""
    dcid: str = ""

    def is_empty(self) -> bool:
        return not (self.version or self.sni or self.alpn or self.cipher
                    or self.scid or self.dcid)

    def to_dict(self) -> dict:
        d = super().to_dict()
        d.update({
            "version": self.version,
            "sni": self.sni,
            "alpn": self.alpn,
            "cipher": self.cipher,
            "scid": self.scid,
            "dcid": self.dcid,
        })
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "QuicLayer":
        layer = cls()
        layer.depth = d.get("depth", 0)
        layer.version = d.get("version", "")
        layer.sni = d.get("sni", "")
        layer.alpn = d.get("alpn", "")
        layer.cipher = d.get("cipher", "")
        layer.scid = d.get("scid", "")
        layer.dcid = d.get("dcid", "")
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

    The decrypted MTProto *message* bytes ride the flow's chunks (the registry
    descriptor registers this layer with ``data_source="chunks"``, like tls/quic),
    fed by the agent's datalog hook (Phase A) or the offline decryptor (Phase B).
    TL parsing of those bytes is intentionally left to a downstream parser, so this
    layer carries only transport/identity metadata.
    """

    NAME: ClassVar[str] = "mtproto"

    transport: str = ""        # "abridged" / "intermediate" / "padded_intermediate" / "full"
    obfuscated: bool = False
    fake_tls: bool = False
    dc_id: int = 0
    auth_key_id: str = ""      # hex of the auth_key_id that decrypted this flow
    message_count: int = 0
    # Parsed per-message metadata; each entry is a JSON-native dict:
    # {direction, kind, body, sender_id, peer_id, has_media}. Populated by the
    # offline TL parser (friTap.offline.mtproto.content) at emit time.
    messages: list = field(default_factory=list)

    def is_empty(self) -> bool:
        return not (
            self.transport or self.obfuscated or self.fake_tls
            or self.dc_id or self.auth_key_id or self.message_count
            or self.messages
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
        return layer


@dataclass
class TelegramE2ELayer(ProtocolLayer):
    """Telegram secret-chat (end-to-end) protocol layer.

    A secret-chat layer rides INSIDE the MTProto transport: its decrypted inner
    payload bytes ride the flow's chunks (the registry descriptor registers this
    layer with ``data_source="chunks"``, like mtproto/signal), fed by the offline
    secret-chat decryptor (``origin="decrypted"``) or a future plaintext agent
    hook (``origin="plaintext_hook"``). TL parsing of those bytes is intentionally
    left to a downstream parser, so this layer carries only identity metadata.
    """

    NAME: ClassVar[str] = "telegram_e2e"

    chat_id: int = 0
    key_fingerprint: str = ""   # hex of the key_fingerprint that decrypted this flow
    message_count: int = 0
    origin: str = "decrypted"   # "decrypted" / "plaintext_hook"
    layer_version: int = 0
    # Parsed per-message metadata; each entry is a JSON-native dict:
    # {direction, kind, body, sender_id, peer_id, has_media}. Populated by the
    # offline TL parser (friTap.offline.mtproto.content) at emit time.
    messages: list = field(default_factory=list)

    def is_empty(self) -> bool:
        return not (
            self.chat_id or self.key_fingerprint or self.message_count
            or self.layer_version or self.messages
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
        return layer


@dataclass
class SignalLayer(ProtocolLayer):
    """Signal protocol layer.

    The decrypted inner Signal ``Content`` bytes ride the flow's chunks (the
    registry descriptor registers this layer with ``data_source="chunks"``, like
    tls/quic/mtproto), fed by the offline Signal decryptor. Protobuf parsing of
    those bytes is intentionally left to a downstream parser, so this layer
    carries only identity metadata.
    """

    NAME: ClassVar[str] = "signal"

    chat_type: str = ""        # "one_to_one" / "group"
    identifier: str = ""       # hex of the eph_pub (1:1) or auth_tag (group)
    message_count: int = 0
    # Parsed per-message metadata; each entry is a JSON-native dict:
    # {sender, direction, timestamp, kind, body, attachments, quote, reaction}.
    # Plaintext WS/REST metadata records (kind in {rest, ws-request, ws-response,
    # profile, device-list, prekey}) additionally carry the optional keys
    # {verb, path, status, request_id, meta} — all backward-compatible (.get).
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
class AppLayer(ProtocolLayer):
    """Generic application-protocol layer (http1/http2/http3/websocket).

    Unlike the transport layers, application layers carry no distinct typed
    metadata fields — they MIRROR the flow's parsed request/response via
    :attr:`ProtocolLayer._parsed_field` (so ``flow.http2.parsed is
    flow.request``). One class therefore serves every application protocol;
    the concrete protocol name is held per-instance in
    :attr:`ProtocolLayer._name` (a sentinel ``NAME = ""`` lets the registry
    bind several names to this single class).

    The same class also backs generic inner (owned-data) layers produced by
    the nested-decryption seam, where :meth:`ProtocolLayer.set_parsed` supplies
    an owned parsed result instead of mirroring a flow field.
    """

    NAME: ClassVar[str] = ""

    def is_empty(self) -> bool:
        return self.parsed is None and self.data.is_empty()

    def to_dict(self) -> dict:
        # Base ``to_dict`` already records ``name`` (the per-instance protocol)
        # and ``depth`` — that is the full identity of an app layer.
        return super().to_dict()

    @classmethod
    def from_dict(cls, d: dict) -> "AppLayer":
        layer = cls()
        layer.depth = d.get("depth", 0)
        layer._name = d.get("name", "")
        return layer
