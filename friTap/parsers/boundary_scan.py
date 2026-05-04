"""Protocol boundary scanner for trailing data detection.

When a parser (e.g. WebSocket) consumes part of a buffer and leaves
unconsumed trailing bytes, and those bytes don't start with a
recognizable protocol signature at offset 0 (due to null padding,
binary metadata, etc.), this module scans forward to find the first
plausible protocol boundary.

The scan uses an anchor-byte pre-filter to avoid calling expensive
``can_parse()`` at every offset. Each candidate position is validated
with multi-byte context to prevent false positives.
"""

from __future__ import annotations

from dataclasses import dataclass

from friTap.constants import PROTOCOL_HTTP1, PROTOCOL_HTTP2


@dataclass
class BoundaryScanResult:
    """Result of a successful protocol boundary scan."""
    skip_bytes: int   # bytes of garbage/padding before the protocol starts
    protocol: str     # protocol constant (PROTOCOL_HTTP1, etc.)


# ---------------------------------------------------------------------------
# HTTP/1.x signatures — method + space + path-start
# We require the path to start with '/' or 'h' (absolute-form URI)
# to reject random occurrences of method names in binary data.
# ---------------------------------------------------------------------------

_HTTP_REQUEST_SIGS: tuple[bytes, ...] = (
    b"GET /", b"GET h",
    b"POST /", b"POST h",
    b"PUT /", b"PUT h",
    b"DELETE /",
    b"HEAD /", b"HEAD h",
    b"OPTIONS /", b"OPTIONS *",
    b"PATCH /",
    b"CONNECT ",
)

_HTTP_RESPONSE_PREFIX = b"HTTP/1."

# HTTP/2 connection preface (24 bytes)
_H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

# First bytes that could start an HTTP/1.x request or response
_HTTP_ANCHOR_BYTES = frozenset(b"CDGHOPT")


# ---------------------------------------------------------------------------
# Structural validation helpers
# ---------------------------------------------------------------------------

def _try_http_at(data: bytes, offset: int) -> BoundaryScanResult | None:
    """Check for HTTP/1.x or HTTP/2 signature at *offset*.

    Uses ``bytes.startswith(prefix, start)`` to avoid allocating slices.
    """
    # HTTP/2 connection preface (24 bytes — very low false-positive rate)
    if data.startswith(_H2_PREFACE, offset):
        return BoundaryScanResult(offset, PROTOCOL_HTTP2)

    # HTTP/1.x response: "HTTP/1.0" or "HTTP/1.1"
    if data.startswith(_HTTP_RESPONSE_PREFIX, offset) and len(data) - offset >= 9:
        version_byte = data[offset + 7:offset + 8]
        if version_byte in (b"0", b"1"):
            crlf_pos = data.find(b"\r\n", offset + 8, offset + 2048)
            if crlf_pos >= 0:
                return BoundaryScanResult(offset, PROTOCOL_HTTP1)

    # HTTP/1.x request methods
    for sig in _HTTP_REQUEST_SIGS:
        if data.startswith(sig, offset):
            crlf_pos = data.find(b"\r\n", offset + len(sig), offset + 2048)
            if crlf_pos >= 0:
                return BoundaryScanResult(offset, PROTOCOL_HTTP1)

    return None


# ---------------------------------------------------------------------------
# Main scan function
# ---------------------------------------------------------------------------

def scan_protocol_boundary(
    data: bytes,
    max_scan: int = 1024,
) -> BoundaryScanResult | None:
    """Scan *data* for the first plausible protocol boundary.

    Skips null bytes and other garbage, then checks for HTTP/1.x
    and HTTP/2 signatures at each position.

    Returns ``None`` if no boundary is found within *max_scan* bytes.

    Performance: O(n) where n = min(len(data), max_scan).
    The anchor-byte pre-filter means only ~3% of positions trigger
    the more expensive validation checks.
    """
    limit = min(len(data), max_scan)
    i = 0

    while i < limit:
        b = data[i]

        # Fast skip: null bytes
        if b == 0x00:
            i += 1
            continue

        # HTTP/1.x and HTTP/2 anchors: C, D, G, H, O, P, T
        if b in _HTTP_ANCHOR_BYTES:
            result = _try_http_at(data, i)
            if result is not None:
                return result

        # Note: WebSocket is intentionally NOT scanned here because its
        # 2-byte frame header produces too many false positives in binary
        # data.  WebSocket at offset 0 is handled by the registry fast
        # path in _detect_trailing_protocol().

        i += 1

    return None
