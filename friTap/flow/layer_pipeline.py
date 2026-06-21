"""The layer pipeline: populates a flow's protocol layer stack.

The :class:`LayerPipeline` owns the *vertical* structure of a flow — the
transport -> application -> inner-decrypted recursion — while the
:class:`~friTap.flow.collector.FlowCollector` keeps owning the *horizontal*
concerns (flow identity, HTTP/2 stream demux, orphan matching).

Phase 1b scope (this module): build the transport and application layers from
data that ALREADY exists on the flow (``flow.transport``, ``flow.request`` /
``flow.response`` / ``flow.detected_protocol``), and reference those parsed
results via the layers' ``_parsed_field`` mirror — no copying, no byte
duplication, no serialization change. The collector invokes :meth:`finalize`
once per flow inside its locked section, immediately before the flow flips to
``COMPLETE`` (the binding write-ordering deadline).

Also wired here is the nested-decryption *seam* (:meth:`_maybe_decrypt` +
:meth:`_parse_layer`). The decryptor registry is EMPTY today, so the seam is a
no-op for all live traffic; a fake decryptor in the tests proves it fires.
Concrete decryptors (Signal/MTProto) and routing OHTTP/upgrade/trailing through
a generic ``push_layer`` are deferred to later phases.
"""

from __future__ import annotations

import logging
from typing import Optional, TYPE_CHECKING

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
from friTap.flow.layers import AppLayer, ProtocolLayer
from friTap.flow.layer_registry import ProtocolRegistry, get_registry
from friTap.parsers.registry import get_default_registry

if TYPE_CHECKING:  # pragma: no cover - typing only
    from friTap.flow.models import Flow

logger = logging.getLogger(__name__)

# Parser protocol detected for streams that never resolved to a concrete
# protocol (BaseParser/HexdumpParser default, and the collector's failure
# reset). Such flows get no application layer.
_UNKNOWN_PROTOCOL = "unknown"

# Map the human-readable parser protocol strings ("HTTP/2", "WebSocket", …) to
# the attribute-friendly registry names ("http2", "websocket") so ``flow.http2``
# resolves. The registry names are defined alongside their descriptors in
# :mod:`friTap.flow.layer_registry`.
_APP_NAME_BY_PROTOCOL: dict[str, str] = {
    PROTOCOL_HTTP1: "http1",
    PROTOCOL_HTTP2: "http2",
    PROTOCOL_HTTP3: "http3",
    PROTOCOL_WEBSOCKET: "websocket",
}

# Transports whose decrypted bytes are a self-contained non-HTTP protocol
# (MTProto cloud TL, Telegram Secret-Chat TL). Generic application-protocol
# detection must NOT run on them: the HTTP/3 parser's varint heuristic
# false-positives on MTProto records and would graft a bogus ``http3`` layer on
# top of the real ``mtproto`` transport (mislabelling the flow ``HTTP/3`` / ``???``
# instead of ``MTProto``). These transports own their decrypted chunks and their
# payload is parsed by the protocol's own offline decryptor, not the app parsers.
# (Signal is unaffected: it rides inside real HTTP/2, so its transport is ``tls``
# and ``signal`` is an inner owned layer — not a transport in this set.)
_NON_HTTP_E2E_TRANSPORTS = frozenset({"mtproto", "telegram_e2e"})


def _is_transport_descriptor(descriptor) -> bool:
    """True when *descriptor* describes a layer-0 transport that owns the chunks.

    Replaces the old hardcoded ``{"tls","quic","mtproto","signal"}`` frozenset
    with a registry-driven test so plugin transport decryptors join without an
    edit here. A transport layer is one whose descriptor (a) owns the flow's
    decrypted bytes (``data_source == "chunks"``) and (b) declares a non-empty
    typed ``layer_cls.NAME``. This excludes the generic application layer
    (``AppLayer.NAME == ""``, which rides on top of a transport) and the
    synthetic/marker SSH and IPsec layers (``data_source == "none"``) — exactly
    the set the frozenset enumerated, for every ``transport`` value that occurs.
    """
    if descriptor is None or descriptor.data_source != "chunks":
        return False
    return bool(getattr(descriptor.layer_cls, "NAME", ""))


def app_layer_name(protocol: str) -> Optional[str]:
    """Return the registry layer name for a parser *protocol* string, or None.

    Handles both the canonical constants ("HTTP/2", "WebSocket") and the
    version-specific strings the parsers actually emit in ``ParseResult.protocol``
    ("HTTP/1.1", "HTTP/1.0", "HTTP/1.x"):
    ``app_layer_name("HTTP/1.1") == "http1"``. Unknown/unmapped protocols (raw
    hexdump, "bhttp", "unknown", "") return ``None``.
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
        registry: Optional[ProtocolRegistry] = None,
        decryptor_registry: Optional[DecryptorRegistry] = None,
    ) -> None:
        # The protocol registry is the SAME process-global one ``Flow``'s lazy
        # attribute resolution uses; we read it to confirm a name is registered
        # before materializing its layer.
        self._registry = registry or get_registry()
        self._decryptors = decryptor_registry or get_default_decryptor_registry()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def ensure_transport(self, flow: "Flow") -> Optional[ProtocolLayer]:
        """Ensure the flow's layer-0 transport layer exists (idempotent).

        The transport name comes from the stamped :attr:`Flow.transport` when it
        names a known transport-layer protocol with a registry descriptor
        (``quic``/``mtproto``/…); everything else defaults to ``tls``. The layer's
        data is the flow's decrypted-chunk view (``data_source="chunks"`` from its
        descriptor) — zero copy, never serialized. New transport-level decryptors
        join purely by registering a ``data_source="chunks"`` descriptor (no edit
        here): a transport layer is one whose descriptor owns the flow's decrypted
        chunks. Non-transport registry entries — synthetic/marker layers like SSH
        and IPsec (``data_source="none"``) and application layers that ride on top
        of a transport — are excluded, so they default to ``tls`` as before.
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
        # ``getattr`` triggers Flow.__getattr__ -> _create_layer, which binds the
        # chunks-view LayerData declared by the registry descriptor.
        return getattr(flow, name)

    def push_app_result(
        self, flow: "Flow", result, protocol: str
    ) -> Optional[ProtocolLayer]:
        """Ensure an application layer for *protocol* exists and mirrors *result*.

        The layer does NOT copy the ParseResult; it points its
        ``_parsed_field`` at the flow's ``request``/``response`` field so
        ``flow.http2.parsed is flow.request``. A request always wins as the
        canonical parsed reference; a response is referenced only when no
        request has been seen. *result* may be ``None`` to merely record that
        the flow speaks *protocol* (e.g. an HTTP/2 control-frame-only flow).
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
        """Populate the flow's layer stack from its existing parsed state.

        Called by the collector inside the lock, just before the flow flips to
        ``COMPLETE``. Builds the transport layer and (when the flow resolved an
        application protocol) the application layer mirroring request/response,
        then fires the nested-decryption seam (no-op with the empty registry).
        """
        transport = self._rebuild_mirrors(flow)
        if transport is not None:
            self._maybe_decrypt(flow, transport)

    def reparse(self, flow: "Flow") -> None:
        """Refresh the layer stack after a flow's bytes/parse results changed.

        Rebuilds the mirrored transport + application layers (so ``flow.<proto>``
        tracks the re-detected protocol after a reparse reassigns
        ``request``/``response``) and re-parses every OWNED inner layer's bytes
        in place. Unlike :meth:`finalize` it does NOT re-run the decryption seam
        (which appends a fresh inner layer per call) — existing inner layers are
        re-parsed, not duplicated.
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
        """Add (or update) a generic layer — the seam for event-fed inner layers.

        Routes protocols the collector discovers post-hoc into the layer model
        while their legacy flow fields stay the source of truth: OHTTP
        (event-fed decrypted bhttp), a protocol upgrade (HTTP/1->WebSocket), and
        trailing data. The layer's name is *protocol*; owned directional bytes
        come from *data_read*/*data_write*; its parsed result either MIRRORS a
        flow attribute (*parsed_field*, e.g. ``"ohttp_inner_request"``) or is an
        owned result (*parsed*). *source* is a free-form provenance tag
        (``"event:ohttp"``, ``"upgrade"``, ``"trailing"``). Idempotent on the
        protocol name (updates the existing layer rather than duplicating it).
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
        """Build/refresh the mirrored transport + application layers.

        Shared by :meth:`finalize` (initial build) and :meth:`reparse` (refresh)
        — the part that derives the stack purely from the flow's mirrored
        source-of-truth fields, with no side effects beyond layer (re)creation.
        Returns the transport layer (or ``None`` if it could not be created).
        """
        transport = self.ensure_transport(flow)
        protocol = self._app_protocol(flow)
        if protocol:
            if flow.request is not None:
                self.push_app_result(flow, flow.request, protocol)
            if flow.response is not None:
                self.push_app_result(flow, flow.response, protocol)
            if flow.request is None and flow.response is None:
                # Protocol detected but no ParseResult (e.g. HTTP/2 SETTINGS-only
                # prelude) — still record the application layer.
                self.push_app_result(flow, None, protocol)
        return transport

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _app_protocol(self, flow: "Flow") -> str:
        """Best application protocol for *flow*, or "" when undetermined.

        Prefers a concrete protocol from the parsed request, then the response,
        then the flow's ``detected_protocol`` display fallback.

        Returns "" for a non-HTTP E2E transport (``mtproto``/``telegram_e2e``):
        those own their decrypted bytes and must never receive a coincidental
        HTTP application layer (e.g. an HTTP/3 varint false-positive), which would
        mislabel the flow. See :data:`_NON_HTTP_E2E_TRANSPORTS`.
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
        """Nested-decryption seam.

        Resolve a :class:`~friTap.flow.decryptors.LayerDecryptor` for *parent*;
        if one matches, feed the parent's decrypted bytes through it and add an
        inner owned-data layer carrying the result. The default decryptor
        registry is empty, so this is a no-op for all live traffic today.
        """
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
        """Detect+feed+flush an OWNED-data layer's bytes; store its inner parsed.

        The single shared parse path the design collapses the collector's three
        duplicated detect/feed/flush blocks onto in a later phase. Here it
        serves only inner (owned-data) layers from the decryption seam; mirrored
        transport/app layers take their parsed result from the flow's fields and
        never pass through here.
        """
        write = layer.data.write
        read = layer.data.read
        if not (write or read):
            return None
        try:
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
