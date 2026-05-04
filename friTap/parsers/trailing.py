"""Shared trailing data detection and sub-parsing utilities.

Used by WebSocketParser and Http1Parser to detect and parse unconsumed
bytes after valid protocol frames.
"""

from __future__ import annotations

from typing import Optional

from .base import BaseParser, ParseResult


def detect_trailing_protocol(data: bytes) -> tuple[str, bytes, BaseParser | None]:
    """Detect protocol in trailing bytes.

    Two-phase detection:
    1. **Fast path** — strip leading nulls, try ``registry.detect()`` at offset 0.
    2. **Boundary scan** — if fast path fails, scan forward through garbage bytes
       looking for a protocol signature (e.g. HTTP method token).

    Returns ``(protocol_name, cleaned_data, parser_instance)``
    or ``("", data, None)`` if nothing matched.
    """
    from .registry import get_default_registry
    from .hexdump import HexdumpParser
    from .boundary_scan import scan_protocol_boundary

    registry = get_default_registry()

    # --- Fast path: try detection at offset 0 (existing behavior) ---
    stripped = data.lstrip(b"\x00") if data[:1] == b"\x00" else data
    if len(stripped) >= 4:
        try:
            parser = registry.detect(stripped)
        except Exception:
            parser = None

        if parser is not None and not isinstance(parser, HexdumpParser):
            return parser.PROTOCOL, stripped, parser

    # --- Slow path: scan for protocol boundary past garbage bytes ---
    result = scan_protocol_boundary(data)
    if result is not None:
        cleaned = data[result.skip_bytes:]
        try:
            parser = registry.detect(cleaned)
            if not isinstance(parser, HexdumpParser):
                return result.protocol, cleaned, parser
        except Exception:
            pass

    return "", data, None


def try_sub_parse(
    data: bytes, parser: BaseParser | None, direction: str,
) -> Optional[ParseResult]:
    """Attempt to parse trailing data using the detected parser.

    Since Http1Parser tracks body_size but doesn't store body bytes
    (they're normally reconstructed from raw chunks), we extract the
    body directly from the data using the header/body separator.
    """
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
