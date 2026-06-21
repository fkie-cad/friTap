"""Registry of protocol descriptors for the protocol-layer-stack feature.

Each :class:`ProtocolDescriptor` binds a protocol name to its typed
:class:`~friTap.flow.layers.ProtocolLayer` subclass and declares how that
layer obtains its decrypted data, plus optional offline-extraction,
decryptor, and flow-creation hooks.

A process-global default registry is created at import time, pre-populated with
the built-in protocols. Use :func:`get_registry` / :func:`register` for the
common case.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional

from friTap.flow.layers import (
    AppLayer,
    IpsecLayer,
    MtprotoLayer,
    QuicLayer,
    SignalLayer,
    SshLayer,
    TelegramE2ELayer,
    TlsLayer,
)


@dataclass(frozen=True)
class ProtocolDescriptor:
    """Immutable description of a protocol and how friTap handles it.

    Fields:
        name: Protocol name. For a typed layer (one declaring a non-empty
            ``layer_cls.NAME``) it must equal that ``NAME``. For a generic layer
            (``NAME == ""`` — e.g. :class:`~friTap.flow.layers.AppLayer`, which
            backs several application protocols) the name is the per-instance
            layer name and only has to be non-empty.
        layer_cls: The :class:`ProtocolLayer` subclass for this protocol.
        data_source: Default ``LayerData.data_source`` for layers of this type
            (``"chunks"``, ``"owned"`` or ``"none"``).
        offline_extractor: Optional callable that extracts this layer's metadata
            from an offline source (e.g. a pcap).
        decryptor: Optional callable producing a layer decryptor.
        creates_flows: True when this protocol multiplexes/creates child flows.
    """

    name: str
    layer_cls: type
    data_source: str = "none"
    offline_extractor: Optional[Callable] = None
    decryptor: Optional[Callable] = None
    creates_flows: bool = False

    def __post_init__(self) -> None:
        self._validate()

    def _validate(self) -> None:
        """Validate the descriptor name against its layer class.

        A typed layer (non-empty ``NAME``) must be registered under exactly
        that name. A generic layer (``NAME == ""``) may be registered under any
        non-empty name (the name becomes the layer's per-instance identity).
        """
        layer_name = getattr(self.layer_cls, "NAME", None)
        if layer_name:
            assert self.name == layer_name, (
                f"ProtocolDescriptor name {self.name!r} does not match "
                f"{self.layer_cls.__name__}.NAME {layer_name!r}"
            )
        else:
            assert self.name, (
                f"ProtocolDescriptor for generic layer "
                f"{self.layer_cls.__name__} requires a non-empty name"
            )


class ProtocolRegistry:
    """A collection of :class:`ProtocolDescriptor` keyed by protocol name."""

    def __init__(self) -> None:
        self._descriptors: dict[str, ProtocolDescriptor] = {}

    def register(self, desc: ProtocolDescriptor) -> None:
        """Register *desc*, replacing any existing entry with the same name."""
        self._descriptors[desc.name] = desc

    def get(self, name: str) -> Optional[ProtocolDescriptor]:
        """Return the descriptor for *name*, or ``None`` if unregistered."""
        return self._descriptors.get(name)

    def names(self) -> frozenset[str]:
        """Return the set of registered protocol names."""
        return frozenset(self._descriptors)

    def list(self) -> list[ProtocolDescriptor]:
        """Return all registered descriptors."""
        return list(self._descriptors.values())


_DEFAULT_REGISTRY = ProtocolRegistry()


# Application-protocol layer names. These are attribute-friendly identifiers
# (so ``flow.http2`` resolves) distinct from the human-readable parser protocol
# strings ("HTTP/2", "WebSocket", …); the LayerPipeline maps between them. All
# share the single generic :class:`AppLayer` class and read the flow's already
# decrypted bytes (``data_source="chunks"``), mirroring request/response.
APP_PROTOCOL_NAMES: tuple[str, ...] = ("http1", "http2", "http3", "websocket")


def _register_builtins(registry: ProtocolRegistry) -> None:
    """Pre-register the built-in protocol descriptors."""
    registry.register(ProtocolDescriptor("tls", TlsLayer, data_source="chunks"))
    registry.register(ProtocolDescriptor("quic", QuicLayer, data_source="chunks"))
    registry.register(ProtocolDescriptor("ssh", SshLayer, data_source="none"))
    registry.register(ProtocolDescriptor("ipsec", IpsecLayer, data_source="none"))
    registry.register(ProtocolDescriptor("mtproto", MtprotoLayer, data_source="chunks"))
    registry.register(ProtocolDescriptor("telegram_e2e", TelegramE2ELayer, data_source="chunks"))
    registry.register(ProtocolDescriptor("signal", SignalLayer, data_source="chunks"))
    for app_name in APP_PROTOCOL_NAMES:
        registry.register(
            ProtocolDescriptor(app_name, AppLayer, data_source="chunks")
        )


_register_builtins(_DEFAULT_REGISTRY)


def get_registry() -> ProtocolRegistry:
    """Return the process-global default protocol registry."""
    return _DEFAULT_REGISTRY


def register(desc: ProtocolDescriptor) -> None:
    """Register *desc* in the process-global default registry."""
    _DEFAULT_REGISTRY.register(desc)


def get(name: str) -> Optional[ProtocolDescriptor]:
    """Look up *name* in the process-global default registry."""
    return _DEFAULT_REGISTRY.get(name)
