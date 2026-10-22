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
    Rc4Layer,
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
        is_message_transport: True when this protocol is a transport whose
            decrypted bytes are a self-contained message stream (not HTTP), so
            generic application-protocol detection must not run on it.
        inner_e2e_rank: Set when this layer is a candidate innermost E2E layer
            for the layered protocol display (e.g. ``HTTP/2[Signal]``): the
            ordering key among those layers, outermost first; ties keep
            registration order. ``None`` (the default) means not an E2E layer.
        carrier: Name of the layer that can wrap this inner E2E layer in a
            genuine ``outer[inner]`` nesting (e.g. ``telegram_e2e`` in
            ``mtproto``), or ``None``.
    """

    name: str
    layer_cls: type
    data_source: str = "none"
    offline_extractor: Optional[Callable] = None
    decryptor: Optional[Callable] = None
    creates_flows: bool = False
    is_message_transport: bool = False
    inner_e2e_rank: Optional[int] = None
    carrier: Optional[str] = None

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
    registry.register(ProtocolDescriptor(
        "mtproto", MtprotoLayer, data_source="chunks",
        is_message_transport=True, inner_e2e_rank=20,
    ))
    registry.register(ProtocolDescriptor(
        "telegram_e2e", TelegramE2ELayer, data_source="chunks",
        is_message_transport=True, inner_e2e_rank=30, carrier="mtproto",
    ))
    registry.register(ProtocolDescriptor(
        "signal", SignalLayer, data_source="chunks",
        inner_e2e_rank=10,
    ))
    # RC4 is independent of TLS; its decrypted plaintext rides the flow's chunks.
    # RC4-in-TLS: TLS plaintext carries an RC4 stream -> TLS[RC4].
    registry.register(ProtocolDescriptor(
        "rc4", Rc4Layer, data_source="chunks",
        inner_e2e_rank=40, carrier="tls",
    ))
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


# ---------------------------------------------------------------------------
# Protocol facts derived from the descriptors
# ---------------------------------------------------------------------------

def _descriptors(registry: Optional[ProtocolRegistry]) -> list[ProtocolDescriptor]:
    """Descriptors of *registry* (default: the global one) in registration order."""
    return (registry or _DEFAULT_REGISTRY).list()


def message_transport_names(
    registry: Optional[ProtocolRegistry] = None,
) -> tuple[str, ...]:
    """Names of the message-stream transports, in registration order."""
    return tuple(d.name for d in _descriptors(registry) if d.is_message_transport)


def inner_e2e_layer_names(
    registry: Optional[ProtocolRegistry] = None,
) -> tuple[str, ...]:
    """Inner E2E layer names ordered by ``inner_e2e_rank`` (outermost first)."""
    inner = [d for d in _descriptors(registry) if d.inner_e2e_rank is not None]
    return tuple(d.name for d in sorted(inner, key=lambda d: d.inner_e2e_rank))


def carrier_for_inner(
    registry: Optional[ProtocolRegistry] = None,
) -> dict[str, str]:
    """Map each inner layer that declares a carrier to that carrier's name."""
    return {d.name: d.carrier for d in _descriptors(registry) if d.carrier}
