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
