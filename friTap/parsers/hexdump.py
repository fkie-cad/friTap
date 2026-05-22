"""Fallback parser that wraps raw bytes into ParseResult."""

from friTap.constants import PROTOCOL_QUIC_UNPROCESSED
from .base import BaseParser, ParseResult


# Known QUIC version identifiers
_QUIC_VERSIONS = frozenset({
    0x00000001,  # QUIC v1 (RFC 9000)
    0x6B3343CF,  # QUIC v2 (RFC 9369)
    0xFF000000 | 29,  # draft-29
    0xFF000000 | 30,  # draft-30
    0xFF000000 | 31,  # draft-31
    0xFF000000 | 32,  # draft-32
})


def _detect_quic_pattern(data: bytes) -> bool:
    """Check if data looks like a QUIC packet.

    Only checks for QUIC long header with known version field.
    HTTP/3 frame detection is handled by Http3Parser (priority 80) which
    runs before this fallback — no need to duplicate that heuristic here.
    The previous varint-based HTTP/3 check caused false positives on small
    HTTP/2 payloads (e.g., PING frame data matching as HTTP/3 DATA frame).
    """
    if not data or len(data) < 5:
        return False

    # Check for QUIC long header pattern (first byte: 11xxxxxx)
    first_byte = data[0]
    if (first_byte & 0xC0) == 0xC0:  # Both form bit and fixed bit set
        # Version field at bytes 1-4 must match known QUIC versions
        version = int.from_bytes(data[1:5], "big")
        if version in _QUIC_VERSIONS:
            return True

    return False


class HexdumpParser(BaseParser):
    """Fallback parser for unrecognized protocols.

    Always accepts data and wraps raw bytes into a ParseResult.
    Detects QUIC/HTTP/3 traffic patterns to avoid mislabeling as "unknown".
    """

    # Inherits PROTOCOL = "unknown" from BaseParser

    def can_parse(self, data: bytes) -> bool:
        """Always returns True - this is the last-resort fallback."""
        return True

    def feed(self, data: bytes, direction: str,
             stream_id: int | None = None) -> list[ParseResult]:
        """Wrap raw bytes into a ParseResult."""
        protocol = "unknown"
        if _detect_quic_pattern(data):
            protocol = PROTOCOL_QUIC_UNPROCESSED

        return [
            ParseResult(
                protocol=protocol,
                raw=data,
                body=data,
                body_size=len(data),
                is_complete=True,
                is_request=(direction == "write"),
            )
        ]

    def flush(self) -> list[ParseResult]:
        """Nothing to flush - feed() always returns complete results."""
        return []
