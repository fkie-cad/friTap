"""Shared trailing-data detection and sub-parsing, used by WebSocketParser and Http1Parser for bytes left after valid frames."""

from __future__ import annotations

from typing import Optional

from .base import BaseParser, ParseResult


def detect_trailing_protocol(
    data: bytes, transport: Optional[str] = None,
) -> tuple[str, bytes, BaseParser | None]:
    """Detect a protocol in trailing bytes: ``(protocol_name, cleaned_data, parser)`` or ``("", data, None)``.

    Fast path: strip leading nulls and try ``registry.detect()`` at offset 0; else
    boundary-scan forward past garbage. *transport* (``Flow.transport``) applies its
    pins/restrictions (``quic`` only sniffs HTTP/3); None is pure byte-sniffing.
    """
    from .boundary_scan import scan_protocol_boundary
    from .hexdump import HexdumpParser
    from .registry import get_default_registry

    registry = get_default_registry()

    # --- Fast path: try detection at offset 0 (existing behavior) ---
    stripped = data.lstrip(b"\x00") if data[:1] == b"\x00" else data
    if len(stripped) >= 4:
        try:
            parser = registry.detect(stripped, transport=transport)
        except Exception:
            parser = None

        if parser is not None and not isinstance(parser, HexdumpParser):
            return parser.PROTOCOL, stripped, parser

    # --- Slow path: scan for protocol boundary past garbage bytes ---
    result = scan_protocol_boundary(data)
    if result is not None:
        cleaned = data[result.skip_bytes:]
        try:
            parser = registry.detect(cleaned, transport=transport)
            if not isinstance(parser, HexdumpParser):
                return result.protocol, cleaned, parser
        except Exception:
            pass

    return "", data, None


def try_sub_parse(
    data: bytes, parser: BaseParser | None, direction: str,
) -> Optional[ParseResult]:
    """Parse trailing data with the detected parser; Http1Parser keeps no body bytes, so the body is cut from *data* at the header/body separator."""
    if parser is None:
        return None
    try:
        results = parser.feed(data, direction)
        if not results:
            results = parser.flush()
        if not results:
            return None
        result = results[0]
        # Extract body from raw data (Http1Parser doesn't store it)
        if not result.body and result.body_size > 0:
            sep = data.find(b"\r\n\r\n")
            if sep >= 0:
                result.body = data[sep + 4:sep + 4 + result.body_size]
        return result
    except Exception:
        return None
