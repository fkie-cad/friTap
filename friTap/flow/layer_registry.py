"""Registry of protocol descriptors for the layer stack.

A :class:`ProtocolDescriptor` binds a protocol name to its typed ``ProtocolLayer``
subclass and declares how the layer obtains its data, plus optional hooks. A
process-global default registry is pre-populated with the built-ins
(:func:`get_registry` / :func:`register`).
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

    ``name`` must equal ``layer_cls.NAME`` for a typed layer; a generic layer
    (``NAME == ""``, e.g. ``AppLayer``) only needs a non-empty per-instance name.
    ``data_source`` is the default ``LayerData.data_source``. ``is_message_transport``
    marks a self-contained message stream (not HTTP) that generic app-protocol
    detection must skip. ``inner_e2e_rank`` marks a candidate innermost E2E layer for
    the layered display (``HTTP/2[Signal]``), ordered outermost first, ties by
    registration order. ``carrier`` names the layer that can wrap it in ``outer[inner]``
    nesting (``telegram_e2e`` in ``mtproto``).
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
        """Assert a typed layer is registered under its ``NAME`` and a generic one under a non-empty name."""
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


class LayerRegistry:
    """Descriptors keyed by protocol name (unrelated to ``friTap.protocols.registry.ProtocolRegistry``)."""

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


_DEFAULT_REGISTRY = LayerRegistry()


# Application-protocol layer names: attribute-friendly identifiers (``flow.http2``)
# distinct from parser strings ("HTTP/2"); LayerPipeline maps between them. All
# share the generic AppLayer and read the flow's decrypted bytes.
APP_PROTOCOL_NAMES: tuple[str, ...] = ("http1", "http2", "http3", "websocket")


def _register_builtins(registry: LayerRegistry) -> None:
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
        # RC4 is independent of TLS; RC4-in-TLS renders as TLS[RC4].
    registry.register(ProtocolDescriptor(
        "rc4", Rc4Layer, data_source="chunks",
        inner_e2e_rank=40, carrier="tls",
    ))
    for app_name in APP_PROTOCOL_NAMES:
        registry.register(
            ProtocolDescriptor(app_name, AppLayer, data_source="chunks")
        )


_register_builtins(_DEFAULT_REGISTRY)


def get_registry() -> LayerRegistry:
    """Return the process-global default protocol registry."""
    return _DEFAULT_REGISTRY


def register(desc: ProtocolDescriptor) -> None:
    """Register *desc* in the process-global default registry."""
    _DEFAULT_REGISTRY.register(desc)


def get(name: str) -> Optional[ProtocolDescriptor]:
    """Look up *name* in the process-global default registry."""
    return _DEFAULT_REGISTRY.get(name)


def _descriptors(registry: Optional[LayerRegistry]) -> list[ProtocolDescriptor]:
    """Descriptors of *registry* (default: the global one) in registration order."""
    return (registry or _DEFAULT_REGISTRY).list()


def message_transport_names(
    registry: Optional[LayerRegistry] = None,
) -> tuple[str, ...]:
    """Names of the message-stream transports, in registration order."""
    return tuple(d.name for d in _descriptors(registry) if d.is_message_transport)


def inner_e2e_layer_names(
    registry: Optional[LayerRegistry] = None,
) -> tuple[str, ...]:
    """Inner E2E layer names ordered by ``inner_e2e_rank`` (outermost first)."""
    inner = [d for d in _descriptors(registry) if d.inner_e2e_rank is not None]
    return tuple(d.name for d in sorted(inner, key=lambda d: d.inner_e2e_rank))


def carrier_for_inner(
    registry: Optional[LayerRegistry] = None,
) -> dict[str, str]:
    """Map each inner layer that declares a carrier to that carrier's name."""
    return {d.name: d.carrier for d in _descriptors(registry) if d.carrier}
