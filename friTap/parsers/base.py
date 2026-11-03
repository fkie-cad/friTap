"""Base abstractions for protocol parsers."""

import logging
import traceback as _traceback
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
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

    def to_dict(self, include_body: bool = False) -> dict:
        """Return a JSON-safe dict view of this parse result.

        The raw byte buffers (``body``/``raw``) are omitted by default so the
        result is cheap and JSON-serializable for web/API consumers; pass
        ``include_body=True`` to include ``body`` hex-encoded.
        """
        result = {
            "protocol": self.protocol,
            "method": self.method,
            "url": self.url,
            "host": self.host,
            "status_code": self.status_code,
            "status_text": self.status_text,
            "headers": dict(self.headers),
            "body_size": self.body_size,
            "is_complete": self.is_complete,
            "is_request": self.is_request,
            "content_encoding": self.content_encoding,
            "content_type": self.content_type,
            "error": self.error,
            "stream_id": self.stream_id,
            "is_control_frame": self.is_control_frame,
        }
        if include_body:
            result["body"] = self.body.hex()
        return result


# Joiners for repeated header fields. Set-Cookie cannot be comma-joined
# (cookie attributes such as ``Expires`` contain commas), so its values are
# newline-separated; Cookie crumbs rejoin with "; " (RFC 9113 8.2.3); every
# other field uses the RFC 9110 5.3 list form ", ".
_SET_COOKIE_JOINER = "\n"
_COOKIE_JOINER = "; "
_DEFAULT_HEADER_JOINER = ", "


def _header_joiner(name: str) -> str:
    """Return the separator used when *name* appears more than once."""
    lower = name.lower()
    if lower == "set-cookie":
        return _SET_COOKIE_JOINER
    if lower == "cookie":
        return _COOKIE_JOINER
    return _DEFAULT_HEADER_JOINER


def merge_header_value(headers: dict, name: str, value: str) -> None:
    """Add *name*: *value* to *headers*, joining instead of overwriting repeats.

    Callers normalize the name case before calling (HTTP/1 Title-Cases,
    HTTP/2 and HTTP/3 are lowercase on the wire), so an exact key lookup is
    a case-insensitive match and the first-seen key is kept. The dict stays
    ``str -> str`` so existing consumers keep working.
    """
    existing = headers.get(name)
    if existing is None:
        headers[name] = value
    else:
        headers[name] = f"{existing}{_header_joiner(name)}{value}"


def parse_ascii_uint(value) -> Optional[int]:
    """Parse a non-negative decimal integer made of ASCII digits only.

    Surrounding whitespace is stripped; signs, underscores, inner spaces and
    non-ASCII digits are rejected (``int()`` accepts ``"-1"``, ``"+5"`` and
    ``"1_0"``, which an attacker can use to fake message boundaries).
    Returns None when *value* is not a valid unsigned integer.
    """
    if isinstance(value, bytes):
        value = value.decode("latin-1")
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text or not (text.isascii() and text.isdigit()):
        return None
    return int(text)


def parse_content_length(value) -> Optional[int]:
    """Strictly parse a Content-Length value; None means unknown length."""
    return parse_ascii_uint(value)


def apply_http2_headers(stream, headers: list[tuple[str, str]]) -> None:
    """Apply decoded HTTP/2 or HTTP/3 headers to a stream state object.

    Expects stream to have: headers, method, url, host, status_code,
    is_request, content_encoding, content_type attributes.
    Headers should be a list of (name, value) string tuples.
    """
    for name, value in headers:
        if name.startswith(":"):
            # Pseudo-headers keep last-wins semantics (e.g. a 1xx HEADERS
            # block followed by the final response on the same stream).
            stream.headers[name] = value
        else:
            merge_header_value(stream.headers, name, value)
        if name == ":method":
            stream.method = value
            stream.is_request = True
        elif name == ":path":
            stream.url = value
        elif name == ":authority":
            stream.host = value
        elif name == ":status":
            status = parse_ascii_uint(value)
            if status is not None:
                stream.status_code = status
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
    # The owning flow's ``Flow.transport`` (``tls``/``quic``/...), stamped by
    # the FlowCollector when it installs the parser. Parsers that re-enter the
    # registry for trailing bytes pass it on, so transport pins/restrictions
    # still apply there. None keeps pure byte-sniffing.
    flow_transport: Optional[str] = None

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

    def recognized_any(self) -> bool:
        """Whether the fed bytes were actually recognized as this protocol.

        The collector stamps ``Flow.detected_protocol`` only when this is
        True. Default True: a parser may legitimately recognize its protocol
        without emitting a ParseResult (e.g. an HTTP/2 SETTINGS-only prelude).
        Parsers whose detection is weak override it.
        """
        return True


@dataclass
class ParserFailure:
    """Describes a single parser exception captured by SafeParserAdapter."""

    parser_name: str
    exc_class: str
    exc_message: str
    direction: str
    traceback_text: str


_safe_parser_logger = logging.getLogger("friTap.parsers.safe")

# How many times SafeParserAdapter swaps in a fresh parser after an exception
# before it disables parsing for the rest of the connection.
MAX_PARSER_RESETS = 3


class SafeParserAdapter(BaseParser):
    """Wraps a concrete BaseParser and contains all parser-level exceptions.

    A single uncaught streaming-parser error (h11.RemoteProtocolError,
    hpack/hyperframe errors, malformed websocket frames, struct.error from
    truncated buffers, etc.) used to crash the FlowCollector callback that
    feeds it. This adapter:

      * delegates feed/flush/can_parse to *inner* on the happy path,
      * catches **any** exception from feed/flush, logs it, invokes
        ``on_failure(ParserFailure)``, drops the offending chunk (it is
        never re-fed, so a poison chunk cannot loop) and replaces *inner*
        with a fresh instance from ``parser_factory`` (default
        ``type(inner)``), so one transient error does not hide the rest of
        the connection,
      * after ``MAX_PARSER_RESETS`` resets, the next exception disables the
        adapter: later calls short-circuit to return [].

    A fresh parser starts without the old one's stream state: HTTP/2
    re-attaches mid-connection, HTTP/1 resyncs on the next message start,
    and WebSocket resumes at a frame boundary only by luck (it reports a
    bad frame header as trailing data rather than raising).

    Raw bytes still accumulate at the FlowCollector layer because empty
    parser results are handled there. ``failed`` is True while the adapter
    is disabled and right after a call whose chunk was dropped (until the
    next call succeeds); ``disabled`` and ``reset_count`` expose the
    recovery state. Attribute reads/writes for any name that is not part
    of the adapter's own state are transparently forwarded to the inner
    parser, so callers that access protocol-specific attributes (e.g.
    ``trailing_data``, ``upgrade_protocol``) keep working without
    unwrapping.
    """

    # Names that live on the adapter itself; everything else proxies to inner.
    _OWN_ATTRS = frozenset({
        "_inner", "_on_failure", "_parser_factory", "_reset_count",
        "_disabled", "_last_call_failed", "PROTOCOL",
    })

    def __init__(
        self,
        inner: BaseParser,
        on_failure: Optional[Callable[[ParserFailure], None]] = None,
        parser_factory: Optional[Callable[[], BaseParser]] = None,
    ) -> None:
        # object.__setattr__ to bypass our overridden __setattr__ during init,
        # since _inner is not yet defined when the first assignment runs.
        object.__setattr__(self, "_on_failure", on_failure)
        object.__setattr__(
            self, "_parser_factory", parser_factory or type(inner)
        )
        object.__setattr__(self, "_reset_count", 0)
        object.__setattr__(self, "_disabled", False)
        object.__setattr__(self, "_last_call_failed", False)
        self._install_inner(inner)

    def _install_inner(self, inner: BaseParser) -> None:
        object.__setattr__(self, "_inner", inner)
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
        """True while disabled, or when the latest feed/flush raised."""
        return self._disabled or self._last_call_failed

    @property
    def disabled(self) -> bool:
        """True once the reset budget is spent and parsing has stopped."""
        return self._disabled

    @property
    def reset_count(self) -> int:
        """How many times the wrapped parser was replaced after an error."""
        return self._reset_count

    @property
    def flow_transport(self) -> Optional[str]:
        # Explicit forward: BaseParser's class default would shadow __getattr__.
        # Writes already reach inner through __setattr__.
        return getattr(self._inner, "flow_transport", None)

    def feed(self, data: bytes, direction: str,
             stream_id: int | None = None) -> list[ParseResult]:
        if self._disabled:
            return []
        try:
            # Forward stream_id only when set, so parsers that keep the legacy
            # two-argument feed(data, direction) signature still work.
            if stream_id is None:
                results = self._inner.feed(data, direction)
            else:
                results = self._inner.feed(data, direction, stream_id=stream_id)
        except Exception as exc:
            # The chunk is dropped: re-feeding it could raise again forever.
            self._handle_failure(exc, direction)
            return []
        object.__setattr__(self, "_last_call_failed", False)
        return results

    def flush(self) -> list[ParseResult]:
        if self._disabled:
            return []
        try:
            results = self._inner.flush()
        except Exception as exc:
            self._handle_failure(exc, "flush")
            return []
        object.__setattr__(self, "_last_call_failed", False)
        return results

    def can_parse(self, data: bytes) -> bool:
        # Detection should never crash; if it does, treat as "no".
        try:
            return self._inner.can_parse(data)
        except Exception:
            return False

    def recognized_any(self) -> bool:
        # Explicit forward: BaseParser's default would shadow __getattr__.
        try:
            return bool(self._inner.recognized_any())
        except Exception:
            return True

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

    def _handle_failure(self, exc: BaseException, direction: str) -> None:
        """Record *exc*, then swap in a fresh parser or, past the budget, disable."""
        # Use object.__setattr__ to skip the proxy in __setattr__.
        object.__setattr__(self, "_last_call_failed", True)
        can_reset = self._reset_count < MAX_PARSER_RESETS
        self._record_failure(exc, direction, resetting=can_reset)
        if not (can_reset and self._reset_inner()):
            object.__setattr__(self, "_disabled", True)

    def _reset_inner(self) -> bool:
        """Replace the wrapped parser with a fresh one; False if that fails."""
        try:
            fresh = self._parser_factory()
        except Exception:
            _safe_parser_logger.exception(
                "Could not re-create parser %s; disabling it",
                type(self._inner).__name__,
            )
            return False
        # Keep the transport the collector stamped on the old parser.
        transport = getattr(self._inner, "flow_transport", None)
        if transport is not None:
            fresh.flow_transport = transport
        self._install_inner(fresh)
        object.__setattr__(self, "_reset_count", self._reset_count + 1)
        return True

    def _record_failure(self, exc: BaseException, direction: str,
                        resetting: bool = False) -> None:
        failure = ParserFailure(
            parser_name=type(self._inner).__name__,
            exc_class=type(exc).__name__,
            exc_message=str(exc),
            direction=direction,
            traceback_text=_traceback.format_exc(),
        )
        action = (f"resetting parser ({self._reset_count + 1}/{MAX_PARSER_RESETS})"
                  if resetting else "parsing disabled for this connection")
        # Always log every failure with traceback so the debug log captures
        # the root cause even if no on_failure callback is wired.
        _safe_parser_logger.warning(
            "Parser %s failed on %s: %s: %s; %s",
            failure.parser_name,
            failure.direction,
            failure.exc_class,
            failure.exc_message,
            action,
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
