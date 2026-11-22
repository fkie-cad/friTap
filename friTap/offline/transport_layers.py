"""Transport metadata layers for TLS-riding offline-decrypted flows.

Rebuilds each TLS-riding flow's layer stack (TLS -> [HTTP/2] -> WebSocket ->
inner protocol) from the companion ``transport="tls"`` flow on the same
endpoint pair. Entry point: :func:`_attach_transport_metadata_layers`.
"""

from __future__ import annotations

import logging

from .registry import get_offline_decryptor_registry

# Keeps the converter's logger name, which log config and tests key on.
logger = logging.getLogger("friTap.offline.pcap_to_tap")


def _tls_riding_protocol_names() -> set:
    """Names of registered decryptors with ``requires_tls_strip`` (TLS-riding protocols)."""
    return {
        e.protocol_name
        for e in get_offline_decryptor_registry().list()
        if e.requires_tls_strip
    }


def _make_metadata_marker(layer_cls, name: str):
    """Build a metadata-only (no-bytes) layer marker named *name*."""
    from friTap.flow.layers import LayerData
    marker = layer_cls()
    marker._name = name
    marker.metadata_only = True
    marker.data = LayerData(data_source="none")
    return marker


def _apply_inner_meta(layer, meta: dict | None) -> None:
    """Fold parsed inner metadata onto the innermost flow layer; no-op when either is absent."""
    if layer is None or not meta:
        return
    layer.chat_type = meta.get("chat_type", "")
    layer.identifier = meta.get("identifier", "")
    messages = meta.get("messages", []) or []
    layer.messages = messages
    layer.message_count = len(messages)


def _tls_layers_by_endpoint(flows, endpoint_key) -> dict:
    """The TLS layer per endpoint pair that has a ``transport="tls"`` flow.

    A TLS flow with no materialized layer (e.g. mid-stream recovery, no handshake)
    still proves TLS and maps to an empty TLS layer; a materialized layer wins.
    """
    from friTap.flow.layers import TlsLayer

    by_endpoint: dict = {}
    unstamped: set = set()
    for flow in flows:
        if getattr(flow, "transport", "") != "tls":
            continue
        tls_layer = flow.layer("tls")
        if tls_layer is not None:
            by_endpoint.setdefault(endpoint_key(flow), tls_layer)
        else:
            unstamped.add(endpoint_key(flow))
    for key in unstamped - set(by_endpoint):
        by_endpoint[key] = TlsLayer()
    return by_endpoint


def _carries_http2(flow) -> bool:
    """True when *flow* was detected as HTTP/2 (protocol, request/response or ``http2`` layer)."""
    from friTap.constants import PROTOCOL_HTTP2

    if getattr(flow, "detected_protocol", "") == PROTOCOL_HTTP2:
        return True
    messages = (getattr(flow, "request", None), getattr(flow, "response", None))
    if any(getattr(msg, "protocol", "") == PROTOCOL_HTTP2 for msg in messages):
        return True
    return flow.layer("http2") is not None


def _http2_endpoints(flows, endpoint_key) -> set:
    """Endpoint pairs whose TLS companion flow carries HTTP/2 (the proof when no ALPN was captured)."""
    return {
        endpoint_key(flow) for flow in flows
        if getattr(flow, "transport", "") == "tls" and _carries_http2(flow)
    }


def _attach_transport_metadata_layers(flows, inner_meta: dict | None = None) -> None:
    """Attach TLS/HTTP-2/WebSocket layers onto TLS-riding flows.

    The TLS handshake metadata sits on a separate ``protocol="tls"`` flow over the
    same 4-tuple. Correlates by :func:`canonical_4tuple` and rebuilds the stack::

        TlsLayer(metadata-only) -> [AppLayer("http2")] -> AppLayer("websocket")
            -> <inner protocol layer>(chunks)

    Only the innermost layer owns the plaintext. The HTTP/2 marker needs h2 ALPN
    or an HTTP/2 companion flow. Flows with no TLS metadata stay payload-only.
    """
    from friTap.connection_index import canonical_4tuple, normalize_addr
    from friTap.flow.layers import AppLayer, TlsLayer

    def endpoint_key(flow) -> str:
        # Must match the key the TLS-riding emitter stored the metadata under.
        return canonical_4tuple(flow.src_addr, flow.src_port,
                                flow.dst_addr, flow.dst_port)

    # Keeps the fallback match from handing the same messages to two flows.
    consumed_meta_keys: set = set()

    def lookup_inner_meta(flow):
        """This flow's parsed-message metadata: exact key hit, else the single
        unconsumed entry with the same endpoint pair (address-spelling drift)."""
        if not inner_meta:
            return None
        key = endpoint_key(flow)
        if key in inner_meta and key not in consumed_meta_keys:
            consumed_meta_keys.add(key)
            return inner_meta[key]
        flow_eps = {
            f"{normalize_addr(flow.src_addr)}:{flow.src_port}",
            f"{normalize_addr(flow.dst_addr)}:{flow.dst_port}",
        }
        candidates = [
            k for k in inner_meta
            if k not in consumed_meta_keys and "-" in k
            and set(k.split("-", 1)) == flow_eps
        ]
        if len(candidates) == 1:
            chosen = candidates[0]
            consumed_meta_keys.add(chosen)
            logger.debug(
                "inner meta fallback-matched flow %s to key %s",
                getattr(flow, "flow_id", "?"), chosen,
            )
            return inner_meta[chosen]
        return None

    tls_riding = _tls_riding_protocol_names()
    if not tls_riding:
        return

    tls_layer_by_endpoint = _tls_layers_by_endpoint(flows, endpoint_key)
    http2_endpoints = _http2_endpoints(flows, endpoint_key)

    for flow in flows:
        inner_name = getattr(flow, "transport", "")
        if inner_name not in tls_riding:
            continue
        meta = lookup_inner_meta(flow)

        source = tls_layer_by_endpoint.get(endpoint_key(flow))
        if source is None:
            # No TLS metadata (mid-connection capture): stay payload-only but
            # still fold decrypted messages onto the inner layer.
            if meta:
                inner = flow.layer(inner_name)
                if inner is None:
                    getattr(flow, inner_name)  # lazily materialize the chunks layer
                    inner = flow.layer(inner_name)
                _apply_inner_meta(inner, meta)
            continue

        inner_layer = flow.layer(inner_name)

        tls_marker = _make_metadata_marker(TlsLayer, "tls")
        tls_marker.version = source.version
        tls_marker.sni = source.sni
        tls_marker.cipher = source.cipher
        tls_marker.alpn = source.alpn
        tls_marker.client_random = source.client_random

        rebuilt = [tls_marker]
        # An observed ALPN is authoritative; HTTP/2 detection on the companion
        # flow is only the fallback when no ALPN was captured.
        alpn = (source.alpn or "").lower()
        if "h2" in alpn or (not alpn and endpoint_key(flow) in http2_endpoints):
            rebuilt.append(_make_metadata_marker(AppLayer, "http2"))
        rebuilt.append(_make_metadata_marker(AppLayer, "websocket"))

        flow.layers = []
        for marker in rebuilt:
            flow.add_layer(marker)
        if inner_layer is not None:
            inner_layer.metadata_only = False
            _apply_inner_meta(inner_layer, meta)
            flow.add_layer(inner_layer)
        else:
            # Lazily built: ``getattr`` runs _create_layer, which already appends
            # the layer, so it must not be added again.
            getattr(flow, inner_name)
            _apply_inner_meta(flow.layer(inner_name), meta)
