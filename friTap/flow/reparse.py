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
    """Map a parser instance to a human-readable protocol name."""
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


def detect_protocol_from_bytes(data: bytes) -> str:
    """Lightweight protocol detection from first bytes.

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
        parser = registry.detect(data)
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
    try:
        from friTap.flow.layer_pipeline import LayerPipeline
        LayerPipeline().reparse(flow)
    except Exception:
        logger.debug("Layer-stack reparse failed for flow %s",
                     getattr(flow, "flow_id", "?"), exc_info=True)

    if upgraded:
        logger.debug(
            "Reparsed flow %s: protocol=%s method=%s",
            flow.flow_id,
            flow.display_protocol,
            flow.display_method,
        )

    return upgraded
