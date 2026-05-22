"""Base abstractions for protocol parsers."""

import logging
import traceback as _traceback
from dataclasses import dataclass, field
from abc import ABC, abstractmethod
from typing import Callable, Optional


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
    def feed(self, data: bytes, direction: str,
             stream_id: int | None = None) -> list[ParseResult]:
        """Feed data to parser, return any completed results.

        ``stream_id`` is the transport-level stream identifier (e.g. a QUIC
        stream id) when the caller knows it. Parsers that derive their own
        stream id from the wire (HTTP/2) or do not multiplex (HTTP/1,
        websocket, hexdump) ignore it; HTTP/3 uses it for multiplexing.
        """
        ...

    @abstractmethod
    def flush(self) -> list[ParseResult]:
        """Flush any pending partial data as results."""
        ...

    @abstractmethod
    def can_parse(self, data: bytes) -> bool:
        """Return True if this parser can handle this data."""
        ...


@dataclass
class ParserFailure:
    """Describes a single parser exception captured by SafeParserAdapter."""

    parser_name: str
    exc_class: str
    exc_message: str
    direction: str
    traceback_text: str


_safe_parser_logger = logging.getLogger("friTap.parsers.safe")


class SafeParserAdapter(BaseParser):
    """Wraps a concrete BaseParser and contains all parser-level exceptions.

    A single uncaught streaming-parser error (h11.RemoteProtocolError,
    hpack/hyperframe errors, malformed websocket frames, struct.error from
    truncated buffers, etc.) used to crash the FlowCollector callback that
    feeds it. This adapter:

      * delegates feed/flush/can_parse to *inner* on the happy path,
      * catches **any** exception from feed/flush, marks the adapter as
        failed, invokes ``on_failure(ParserFailure)`` exactly once, and
        short-circuits subsequent calls to return [].

    Raw bytes still accumulate at the FlowCollector layer because empty
    parser results are handled there. The ``failed`` state is exposed via
    the property of the same name. Attribute reads/writes for any name
    that is not part of the adapter's own state are transparently
    forwarded to the inner parser, so callers that access protocol-
    specific attributes (e.g. ``trailing_data``, ``upgrade_protocol``)
    keep working without unwrapping.
    """

    # Names that live on the adapter itself; everything else proxies to inner.
    _OWN_ATTRS = frozenset({
        "_inner", "_on_failure", "_failed", "PROTOCOL",
    })

    def __init__(
        self,
        inner: BaseParser,
        on_failure: Optional[Callable[[ParserFailure], None]] = None,
    ) -> None:
        # object.__setattr__ to bypass our overridden __setattr__ during init,
        # since _inner is not yet defined when the first assignment runs.
        object.__setattr__(self, "_inner", inner)
        object.__setattr__(self, "_on_failure", on_failure)
        object.__setattr__(self, "_failed", False)
        # Mirror inner's PROTOCOL so callers introspecting `parser.PROTOCOL`
        # see the wrapped protocol, not "unknown".
        object.__setattr__(
            self, "PROTOCOL", getattr(inner, "PROTOCOL", "unknown")
        )

    @property
    def inner(self) -> BaseParser:
        return self._inner

    @property
    def failed(self) -> bool:
        return self._failed

    def feed(self, data: bytes, direction: str,
             stream_id: int | None = None) -> list[ParseResult]:
        if self._failed:
            return []
        try:
            # Forward stream_id only when set, so parsers that keep the legacy
            # two-argument feed(data, direction) signature still work.
            if stream_id is None:
                return self._inner.feed(data, direction)
            return self._inner.feed(data, direction, stream_id=stream_id)
        except Exception as exc:
            self._record_failure(exc, direction)
            return []

    def flush(self) -> list[ParseResult]:
        if self._failed:
            return []
        try:
            return self._inner.flush()
        except Exception as exc:
            self._record_failure(exc, "flush")
            return []

    def can_parse(self, data: bytes) -> bool:
        # Detection should never crash; if it does, treat as "no".
        try:
            return self._inner.can_parse(data)
        except Exception:
            return False

    def __getattr__(self, name: str):
        # Only called for attrs not found on the adapter itself.
        # Note: _inner is set in __init__ via object.__setattr__, so the
        # AttributeError here means caller asked for something inner lacks too.
        return getattr(self._inner, name)

    def __setattr__(self, name: str, value) -> None:
        if name in self._OWN_ATTRS:
            object.__setattr__(self, name, value)
        else:
            setattr(self._inner, name, value)

    def _record_failure(self, exc: BaseException, direction: str) -> None:
        # Use object.__setattr__ to skip the proxy in __setattr__.
        object.__setattr__(self, "_failed", True)
        failure = ParserFailure(
            parser_name=type(self._inner).__name__,
            exc_class=type(exc).__name__,
            exc_message=str(exc),
            direction=direction,
            traceback_text=_traceback.format_exc(),
        )
        # Always log the first failure with traceback so the debug log
        # captures the root cause even if no on_failure callback is wired.
        _safe_parser_logger.warning(
            "Parser %s failed on %s: %s: %s",
            failure.parser_name,
            failure.direction,
            failure.exc_class,
            failure.exc_message,
            exc_info=True,
        )
        if self._on_failure is None:
            return
        try:
            self._on_failure(failure)
        except Exception:
            _safe_parser_logger.exception(
                "on_failure callback raised while handling %s failure",
                failure.parser_name,
            )


def unwrap_parser(parser):
    """Return the underlying parser if *parser* is a SafeParserAdapter, else *parser*.

    Useful for ``isinstance(unwrap_parser(p), Http2Parser)`` style checks
    where the caller cares about the concrete protocol class rather than
    whether containment is in place.
    """
    if isinstance(parser, SafeParserAdapter):
        return parser.inner
    return parser
