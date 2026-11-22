"""Populates a flow's protocol layer stack (transport -> application -> inner-decrypted).

The collector keeps the horizontal concerns (flow identity, stream demux,
orphan matching); this pipeline owns the vertical structure. Layers reference
the flow's parsed results through ``_parsed_field`` (no copying). The collector
calls :meth:`finalize` once per flow inside its locked section, immediately
before the flow flips to ``COMPLETE`` (binding write-ordering deadline).
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Optional

from friTap.constants import (
    PROTOCOL_HTTP1,
    PROTOCOL_HTTP2,
    PROTOCOL_HTTP3,
    PROTOCOL_WEBSOCKET,
)
from friTap.flow.decryptors import (
    DecryptorRegistry,
    get_default_decryptor_registry,
)
from friTap.flow.layer_registry import (
    LayerRegistry,
    get_registry,
    message_transport_names,
)
from friTap.flow.layers import AppLayer, ProtocolLayer
from friTap.parsers.registry import get_default_registry

if TYPE_CHECKING:  # pragma: no cover - typing only
    from friTap.flow.models import Flow

logger = logging.getLogger(__name__)

# Parser protocol of streams that never resolved; such flows get no app layer.
_UNKNOWN_PROTOCOL = "unknown"

# Parser protocol strings ("HTTP/2") -> registry names ("http2").
_APP_NAME_BY_PROTOCOL: dict[str, str] = {
    PROTOCOL_HTTP1: "http1",
    PROTOCOL_HTTP2: "http2",
    PROTOCOL_HTTP3: "http3",
    PROTOCOL_WEBSOCKET: "websocket",
}

# Generic app-protocol detection must NOT run on these transports: the HTTP/3
# varint heuristic false-positives on MTProto records and would graft a bogus
# ``http3`` layer over the real ``mtproto`` transport. Derived from the
# ``is_message_transport`` descriptors of the layer registry.
_NON_HTTP_E2E_TRANSPORTS = frozenset(message_transport_names())
# Public alias: transports whose flows are message streams, not HTTP exchanges.
MESSAGE_TRANSPORTS = _NON_HTTP_E2E_TRANSPORTS


def _is_transport_descriptor(descriptor) -> bool:
    """True when *descriptor* describes a layer-0 transport that owns the chunks.

    Registry-driven so plugin transports join without an edit here: the descriptor
    owns the decrypted bytes (``data_source == "chunks"``) and declares a non-empty
    ``layer_cls.NAME`` (excludes the generic AppLayer and the SSH/IPsec markers).
    """
    if descriptor is None or descriptor.data_source != "chunks":
        return False
    return bool(getattr(descriptor.layer_cls, "NAME", ""))


def app_layer_name(protocol: str) -> Optional[str]:
    """Return the registry layer name for a parser *protocol* string, or None.

    Accepts the canonical constants and the version-specific strings parsers emit
    ("HTTP/1.1" -> "http1"). Hexdump, "bhttp", "unknown" and "" return ``None``.
    """
    if not protocol:
        return None
    exact = _APP_NAME_BY_PROTOCOL.get(protocol)
    if exact is not None:
        return exact
    normalized = protocol.strip().lower()
    if normalized.startswith("http/1"):
        return "http1"
    if normalized.startswith("http/2"):
        return "http2"
    if normalized.startswith("http/3"):
        return "http3"
    if "websocket" in normalized:
        return "websocket"
    return None


class LayerPipeline:
    """Builds and maintains a flow's ordered protocol layer stack."""

    def __init__(
        self,
        registry: Optional[LayerRegistry] = None,
        decryptor_registry: Optional[DecryptorRegistry] = None,
    ) -> None:
        # Same process-global registry Flow's lazy attribute resolution uses.
        self._registry = registry or get_registry()
        self._decryptors = decryptor_registry or get_default_decryptor_registry()

    def ensure_transport(self, flow: "Flow") -> Optional[ProtocolLayer]:
        """Ensure the flow's layer-0 transport layer exists (idempotent).

        ``flow.transport`` is used when it names a registered chunk-owning
        transport (``quic``/``mtproto``/...), otherwise ``tls``. The layer's data
        is the zero-copy decrypted-chunk view.
        """
        if _is_transport_descriptor(self._registry.get(flow.transport)):
            name = flow.transport
        else:
            name = "tls"
        if self._registry.get(name) is None:  # pragma: no cover - defensive
            return None
        existing = flow.layer(name)
        if existing is not None:
            return existing
        # getattr triggers Flow.__getattr__ -> _create_layer.
        return getattr(flow, name)

    def push_app_result(
        self, flow: "Flow", result, protocol: str
    ) -> Optional[ProtocolLayer]:
        """Ensure an application layer for *protocol* exists and mirrors *result*.

        The layer points ``_parsed_field`` at the flow's request/response field
        (no copy). A request always wins; a response is referenced only when no
        request was seen. *result* may be ``None`` to record the protocol alone.
        """
        name = app_layer_name(protocol)
        if name is None or self._registry.get(name) is None:
            return None
        layer = flow.layer(name) or getattr(flow, name)
        if result is not None and getattr(result, "is_request", False):
            layer._parsed_field = "request"
        elif not layer._parsed_field:
            layer._parsed_field = "response"
        return layer

    def finalize(self, flow: "Flow") -> None:
        """Populate the layer stack from the flow's parsed state, then run the decryption seam."""
        transport = self._rebuild_mirrors(flow)
        if transport is not None:
            self._maybe_decrypt(flow, transport)

    def reparse(self, flow: "Flow") -> None:
        """Refresh the layer stack after a reparse changed request/response.

        Re-parses every OWNED inner layer in place; unlike :meth:`finalize` it does
        not re-run the decryption seam (which would append duplicate inner layers).
        """
        self._rebuild_mirrors(flow)
        for layer in list(flow.layers):
            if layer.data.data_source == "owned":
                self._parse_layer(flow, layer)

    def push_layer(
        self,
        flow: "Flow",
        *,
        protocol: str,
        source: str = "",
        data_read: bytes = b"",
        data_write: bytes = b"",
        parsed=None,
        parsed_field: str = "",
        parent: Optional[ProtocolLayer] = None,
    ) -> ProtocolLayer:
        """Add or update (idempotent on *protocol*) a generic event-fed layer.

        Used for protocols found post-hoc (OHTTP, HTTP/1->WebSocket upgrade, trailing
        data). Parsed result either mirrors a flow attribute (*parsed_field*) or is
        owned (*parsed*); *source* is a free-form provenance tag.
        """
        layer = flow.layer(protocol)
        if layer is None:
            layer = AppLayer()
            layer._name = protocol
            flow.add_layer(layer)
        if data_read or data_write:
            layer.data.set_owned(read=data_read, write=data_write)
        if parsed_field:
            layer._parsed_field = parsed_field
        elif parsed is not None:
            layer.set_parsed(parsed)
        return layer

    def _rebuild_mirrors(self, flow: "Flow") -> Optional[ProtocolLayer]:
        """Build/refresh the mirrored transport + application layers; returns the transport."""
        transport = self.ensure_transport(flow)
        protocol = self._app_protocol(flow)
        if protocol:
            if flow.request is not None:
                self.push_app_result(flow, flow.request, protocol)
            if flow.response is not None:
                self.push_app_result(flow, flow.response, protocol)
            if flow.request is None and flow.response is None:
                # Protocol detected but no ParseResult (e.g. HTTP/2 SETTINGS-only).
                self.push_app_result(flow, None, protocol)
        return transport

    def _app_protocol(self, flow: "Flow") -> str:
        """Best application protocol for *flow*, or "" when undetermined.

        Prefers request, then response, then ``detected_protocol``. Returns "" for
        non-HTTP E2E transports so they never get a coincidental HTTP layer.
        """
        if flow.transport in _NON_HTTP_E2E_TRANSPORTS:
            return ""
        for parsed in (flow.request, flow.response):
            if parsed is not None:
                protocol = getattr(parsed, "protocol", "")
                if protocol and protocol != _UNKNOWN_PROTOCOL:
                    return protocol
        detected = flow.detected_protocol
        if detected and detected != _UNKNOWN_PROTOCOL:
            return detected
        return ""

    def _maybe_decrypt(
        self, flow: "Flow", parent: ProtocolLayer
    ) -> Optional[ProtocolLayer]:
        """Nested-decryption seam: feed the parent's bytes through a matching decryptor into an inner owned layer."""
        decryptor = self._decryptors.resolve(parent, flow)
        if decryptor is None:
            return None
        try:
            read = decryptor.feed(parent.data.read, "read")
            write = decryptor.feed(parent.data.write, "write")
        except Exception:
            logger.debug("LayerDecryptor.feed raised", exc_info=True)
            return None
        inner = AppLayer()
        inner._name = decryptor.name
        inner.data.set_owned(read=read or b"", write=write or b"")
        flow.add_layer(inner)
        self._parse_layer(flow, inner)
        return inner

    def _parse_layer(self, flow: "Flow", layer: ProtocolLayer):
        """Detect, feed and flush an OWNED layer's bytes; store and return its last parsed result."""
        write = layer.data.write
        read = layer.data.read
        if not (write or read):
            return None
        try:
            # No ``transport=``: a decryptor's inner bytes are not the outer
            # transport's protocol, so its pins must not apply.
            parser = get_default_registry().detect(write or read)
            results: list = []
            if write:
                results += list(parser.feed(write, "write"))
            if read:
                results += list(parser.feed(read, "read"))
            results += list(parser.flush())
        except Exception:
            logger.debug("LayerPipeline._parse_layer failed", exc_info=True)
            return None
        if results:
            layer.set_parsed(results[-1])
            return results[-1]
        return None
