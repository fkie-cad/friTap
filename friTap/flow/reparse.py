"""Lightweight protocol re-detection and re-parsing for flows.

Used to upgrade flows with ``protocol="unknown"`` (e.g. from legacy .tap
files or HexdumpParser fallback) by running proper protocol detection on
the raw chunk data.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from friTap.flow.models import Flow

logger = logging.getLogger(__name__)


def _parser_protocol_label(parser) -> str:
    """Map a parser instance to a human-readable protocol name.

    A parser's own ``PROTOCOL`` wins when it declares one; the class-name
    heuristics remain for parsers that leave it at ``"unknown"``.
    """
    declared = getattr(parser, "PROTOCOL", "unknown")
    if declared and declared != "unknown":
        return declared
    name = type(parser).__name__
    if "Http1" in name:
        return "HTTP/1.x"
    if "Http2" in name:
        return "HTTP/2"
    if "Http3" in name:
        return "HTTP/3"
    if "WebSocket" in name:
        return "WebSocket"
    return name


def detect_protocol_from_bytes(data: bytes, transport: str | None = None) -> str:
    """Lightweight protocol detection from first bytes.

    *transport* (a ``Flow.transport`` value) selects a pinned parser first, so
    decrypted TL transports are labelled by transport rather than by sniffing.

    Returns a human-readable protocol name (e.g. ``"HTTP/1.1"``,
    ``"HTTP/2"``) or ``"unknown"`` if no parser matches.

    Cost: O(1) — only checks byte prefixes, no actual parsing.
    """
    if not data:
        return "unknown"

    from friTap.parsers.hexdump import HexdumpParser
    from friTap.parsers.registry import get_default_registry

    try:
        registry = get_default_registry()
        parser = registry.detect(data, transport=transport)
    except Exception:
        return "unknown"

    if isinstance(parser, HexdumpParser):
        return "unknown"

    return _parser_protocol_label(parser)


def reparse_flow(flow: "Flow") -> bool:
    """Re-parse a flow's chunks through protocol detection.

    Feeds the flow's raw chunks through the detected parser and assigns
    the resulting ``request`` / ``response`` to the flow.

    Returns ``True`` if the protocol was successfully upgraded from
    ``"unknown"`` to a real protocol.
    """
    from friTap.parsers.base import SafeParserAdapter, unwrap_parser
    from friTap.parsers.hexdump import HexdumpParser
    from friTap.parsers.registry import get_default_registry

    if not flow.chunks:
        return False

    transport = getattr(flow, "transport", None)
    try:
        registry = get_default_registry()
        if registry.pinned_parser_for(transport) is not None:
            return _reparse_pinned_flow(flow, registry, transport)
    except Exception:
        logger.debug("Pinned reparse failed for flow %s",
                     getattr(flow, "flow_id", "?"), exc_info=True)
        return False

    # Try write-direction bytes first (client request), fall back to read
    write_bytes = flow.get_direction_bytes("write", max_bytes=512)
    read_bytes = flow.get_direction_bytes("read", max_bytes=512)

    detect_data = write_bytes or read_bytes
    if not detect_data:
        return False

    try:
        registry = get_default_registry()
        raw_parser = registry.detect(detect_data)
    except Exception:
        return False

    if isinstance(raw_parser, HexdumpParser):
        # Try the other direction
        alt_data = read_bytes if detect_data is write_bytes else write_bytes
        if alt_data:
            try:
                raw_parser = registry.detect(alt_data)
            except Exception:
                return False
        if isinstance(raw_parser, HexdumpParser):
            return False

    # Wrap in SafeParserAdapter so a single malformed chunk can no longer
    # raise out of feed/flush; on first failure, subsequent feeds are
    # short-circuited and the adapter's friTap.parsers.safe logger records
    # the traceback. This replaces the prior per-iteration try/except blocks.
    parser = SafeParserAdapter(raw_parser)

    # Clear existing results so the new parser can replace them.
    # This handles both "unknown" protocol upgrades and re-parsing with
    # improved parsers (e.g., WebSocket decompression, H2 control frames).
    flow.request = None
    flow.response = None

    # Feed all chunks through the detected parser
    for chunk in flow.chunks:
        results = parser.feed(chunk.data, chunk.direction)
        for result in results:
            if result.is_request and flow.request is None:
                flow.request = result
            elif not result.is_request and flow.response is None:
                flow.response = result

    # Flush remaining partial messages
    for result in parser.flush():
        if result.is_request and flow.request is None:
            flow.request = result
        elif not result.is_request and flow.response is None:
            flow.response = result

    upgraded = False
    if flow.request and flow.request.protocol != "unknown":
        upgraded = True
    elif flow.response and flow.response.protocol != "unknown":
        upgraded = True

    # Fallback: parser detected a real protocol but produced no results
    # (e.g. HTTP/2 control-only frames with no HEADERS).  Set a minimal
    # protocol indicator so the flow list shows the correct label.
    if not upgraded and flow.request is None:
        from friTap.parsers.base import ParseResult
        # Unwrap the adapter so the protocol label reflects the concrete parser.
        proto_label = _parser_protocol_label(unwrap_parser(parser))
        if proto_label != "unknown":
            flow.request = ParseResult(
                protocol=proto_label,
                is_request=True,
                is_complete=True,
            )
            upgraded = True

    # Per-layer generalization: after the app-level request/response are
    # re-detected, refresh the protocol layer stack so flow.<proto> reflects the
    # new protocol and any OWNED inner layers (decryptor output) are re-parsed
    # against their current bytes. Mirrored transport/app layers track the
    # reassigned request/response automatically; this rebuilds their identity.
    _refresh_layer_stack(flow)

    if upgraded:
        logger.debug(
            "Reparsed flow %s: protocol=%s method=%s",
            flow.flow_id,
            flow.display_protocol,
            flow.display_method,
        )

    return upgraded


def _refresh_layer_stack(flow: "Flow") -> None:
    """Rebuild the flow's protocol layer stack after request/response changed."""
    try:
        from friTap.flow.layer_pipeline import LayerPipeline
        LayerPipeline().reparse(flow)
    except Exception:
        logger.debug("Layer-stack reparse failed for flow %s",
                     getattr(flow, "flow_id", "?"), exc_info=True)


def clear_trailing_data(flow: "Flow") -> None:
    """Drop trailing-data state a byte-sniffing parser left on *flow*."""
    flow.trailing_bytes = None
    flow.trailing_protocol = ""
    flow.trailing_parse = None
    if getattr(flow, "response_trailing_bytes", None) is not None:
        flow.response_trailing_bytes = None
        flow.response_trailing_protocol = ""
        flow.response_trailing_parse = None
    invalidate = getattr(flow, "invalidate_body_cache", None)
    if callable(invalidate):
        invalidate()


def _first_result_for_direction(registry, transport: str, flow: "Flow", direction: str):
    """Feed only *direction*'s chunks to a fresh pinned parser; return its first result."""
    from friTap.parsers.base import SafeParserAdapter

    parser = SafeParserAdapter(registry.detect(b"", transport=transport))
    for chunk in flow.chunks:
        if chunk.direction != direction:
            continue
        for result in parser.feed(chunk.data, chunk.direction):
            return result
    for result in parser.flush():
        return result
    return None


def _reparse_pinned_flow(flow: "Flow", registry, transport: str) -> bool:
    """Re-parse a transport-pinned flow (decrypted TL) per direction.

    Each direction gets its own parser so the request holds only write data and
    the response only read data; stale trailing-data segments from an earlier
    byte-sniffed parse (e.g. a bogus WebSocket PING) are cleared.
    """
    clear_trailing_data(flow)
    flow.request = _first_result_for_direction(registry, transport, flow, "write")
    flow.response = _first_result_for_direction(registry, transport, flow, "read")
    _refresh_layer_stack(flow)
    upgraded = flow.request is not None or flow.response is not None
    if upgraded:
        logger.debug("Reparsed pinned flow %s (transport=%s)",
                     getattr(flow, "flow_id", "?"), transport)
    return upgraded
