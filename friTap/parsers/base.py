"""Base abstractions for protocol parsers."""

from dataclasses import dataclass, field
from abc import ABC, abstractmethod


@dataclass
class ParseResult:
    """Result of parsing a protocol message."""

    protocol: str = "unknown"
    method: str = ""
    url: str = ""
    host: str = ""
    status_code: int = 0
    status_text: str = ""
    headers: dict = field(default_factory=dict)
    body: bytes = b""
    body_size: int = 0
    is_complete: bool = False
    is_request: bool = True
    content_encoding: str = ""
    content_type: str = ""
    error: str = ""
    raw: bytes = b""
    stream_id: int = 0  # HTTP/2 stream ID for multiplexing correlation
    is_control_frame: bool = False  # HTTP/2 connection-level control frame


def apply_http2_headers(stream, headers: list[tuple[str, str]]) -> None:
    """Apply decoded HTTP/2 or HTTP/3 headers to a stream state object.

    Expects stream to have: headers, method, url, host, status_code,
    is_request, content_encoding, content_type attributes.
    Headers should be a list of (name, value) string tuples.
    """
    for name, value in headers:
        stream.headers[name] = value
        if name == ":method":
            stream.method = value
            stream.is_request = True
        elif name == ":path":
            stream.url = value
        elif name == ":authority":
            stream.host = value
        elif name == ":status":
            try:
                stream.status_code = int(value)
            except ValueError:
                pass
            stream.is_request = False
        elif name == "content-encoding":
            stream.content_encoding = value
        elif name == "content-type":
            stream.content_type = value


# Cap on per-stream/per-message body accumulation in parser internal buffers.
# Raw data is preserved in Flow.chunks and written to PCAP independently.
MAX_PARSER_BODY = 2 * 1024 * 1024  # 2 MB


def accumulate_body(body: bytearray, data: bytes,
                    max_size: int = MAX_PARSER_BODY) -> bool:
    """Append *data* to *body* up to *max_size*. Return True if truncated."""
    space = max_size - len(body)
    if space <= 0:
        return True
    if len(data) <= space:
        body += data
        return False
    body += data[:space]
    return True


class BaseParser(ABC):
    """Abstract base class for protocol parsers."""

    PROTOCOL: str = "unknown"

    @abstractmethod
    def feed(self, data: bytes, direction: str) -> list[ParseResult]:
        """Feed data to parser, return any completed results."""
        ...

    @abstractmethod
    def flush(self) -> list[ParseResult]:
        """Flush any pending partial data as results."""
        ...

    @abstractmethod
    def can_parse(self, data: bytes) -> bool:
        """Return True if this parser can handle this data."""
        ...
