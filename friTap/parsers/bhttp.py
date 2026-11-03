"""RFC 9292 Binary HTTP parser.

Parses Binary HTTP (bhttp) messages used as the inner payload of
OHTTP (RFC 9458) encapsulated requests and responses.

Both known-length (0x00 request, 0x01 response) and indeterminate-length
(0x02 request, 0x03 response) framing are supported. The input is
attacker-controlled: every length is bounds-checked against the bytes left
in its section. A truncated or overrunning field stops parsing of that
section and sets ``ParseResult.error`` instead of yielding garbage fields.
A known-length section's end is still known after a bad field, so the
following sections are parsed; in the indeterminate-length form the framing
is lost, so parsing stops there. A message that simply ends at a section
boundary is valid (RFC 9292 section 3.8 truncation): the missing sections
are empty.
"""

from typing import Optional

from .base import ParseResult, merge_header_value
from .http2 import decode_header_text
from .varint import decode_quic_varint

_STATUS_TEXT = {
    100: "Continue", 101: "Switching Protocols", 103: "Early Hints",
    200: "OK", 201: "Created", 204: "No Content",
    301: "Moved Permanently", 302: "Found", 304: "Not Modified",
    400: "Bad Request", 401: "Unauthorized", 403: "Forbidden",
    404: "Not Found", 405: "Method Not Allowed",
    500: "Internal Server Error", 502: "Bad Gateway", 503: "Service Unavailable",
}

_FRAMINGS = (0x00, 0x01, 0x02, 0x03)
_REQUEST_FRAMINGS = (0x00, 0x02)
_KNOWN_LENGTH_FRAMINGS = (0x00, 0x01)

# Caps on the fields of one message (header and trailer sections combined),
# matching the HTTP/2 and HTTP/3 parsers.
MAX_BHTTP_HEADER_FIELDS = 512
MAX_BHTTP_HEADER_BYTES = 256 * 1024

# Indeterminate-length field sections and content end with a zero varint.
_TERMINATOR = 0
_MIN_STATUS = 100
_MAX_STATUS = 999
_FINAL_STATUS = 200
_ERROR_PREFIX = "bhttp parse error: "


def can_parse_bhttp(data: bytes) -> bool:
    """Check if data starts with a valid bhttp framing indicator."""
    return len(data) >= 2 and data[0] in _FRAMINGS


def parse_bhttp(data: bytes) -> Optional[ParseResult]:
    """Parse a complete RFC 9292 Binary HTTP message.

    Returns ParseResult or None if data is not valid bhttp. A malformed
    message yields a ParseResult with ``error`` set and the fields parsed
    before the error.
    """
    if not data or not can_parse_bhttp(data):
        return None

    framing = data[0]
    message = _Message(is_request=framing in _REQUEST_FRAMINGS,
                       known_length=framing in _KNOWN_LENGTH_FRAMINGS)
    reader = _Reader(data, 1, len(data))
    try:
        if message.is_request:
            _parse_request(reader, message)
        else:
            _parse_response(reader, message)
    except (IndexError, ValueError, OverflowError) as e:
        message.fail(f"{_ERROR_PREFIX}{e}")
    return message.to_result(data)


class _BhttpError(ValueError):
    """A truncated, overrunning or invalid bhttp field or section."""


def _field_text(raw: bytes) -> str:
    """UTF-8 with a per-field latin-1 fallback, exactly as HTTP/2 decodes."""
    return decode_header_text(raw)


def _read_varint(data: bytes, offset: int) -> tuple[int, int]:
    """Read a QUIC-style varint, returning (value, new_offset)."""
    value, consumed = decode_quic_varint(data, offset)
    return value, offset + consumed


class _Reader:
    """Cursor over ``data[pos:end]``; no read ever crosses ``end``."""

    __slots__ = ("data", "pos", "end")

    def __init__(self, data: bytes, pos: int, end: int) -> None:
        self.data = data
        self.pos = pos
        self.end = end

    def at_end(self) -> bool:
        return self.pos >= self.end

    def remaining(self) -> int:
        return self.end - self.pos

    def varint(self, what: str) -> int:
        """Read a QUIC varint that must fit in this section."""
        try:
            value, new_pos = _read_varint(self.data, self.pos)
        except ValueError:
            raise _BhttpError(f"truncated {what}") from None
        if new_pos > self.end:
            raise _BhttpError(f"truncated {what}")
        self.pos = new_pos
        return value

    def take(self, length: int, what: str) -> bytes:
        """Read *length* bytes, which must fit in this section."""
        self._check_fits(length, what)
        chunk = self.data[self.pos:self.pos + length]
        self.pos += length
        return chunk

    def vlen(self, what: str) -> bytes:
        """Read a varint-length-prefixed byte sequence."""
        return self.take(self.varint(f"{what} length"), what)

    def section(self, what: str) -> "_Reader":
        """Split off a varint-length-prefixed section and skip past it."""
        length = self.varint(f"{what} length")
        self._check_fits(length, what)
        sub = _Reader(self.data, self.pos, self.pos + length)
        self.pos += length
        return sub

    def _check_fits(self, length: int, what: str) -> None:
        if length > self.remaining():
            raise _BhttpError(
                f"{what} length {length} exceeds the {self.remaining()} "
                f"bytes left in its section")


class _FieldSink:
    """Collects field lines into a ``str -> str`` dict under the caps.

    Repeated names (compared case-insensitively, first-seen spelling kept)
    are joined with :func:`merge_header_value`. Past a cap, further fields
    are dropped and ``overflow`` describes why.
    """

    def __init__(self) -> None:
        self.headers: dict[str, str] = {}
        self.overflow = ""
        self._keys: dict[str, str] = {}  # lowercase name -> stored key
        self._count = 0
        self._size = 0

    def add(self, name: bytes, value: bytes) -> None:
        if self.overflow:
            return
        self._count += 1
        self._size += len(name) + len(value)
        self.overflow = self._cap_error()
        if self.overflow:
            return
        text = _field_text(name)
        key = self._keys.setdefault(text.lower(), text)
        merge_header_value(self.headers, key, _field_text(value))

    def get(self, name: str) -> str:
        """Value of *name* (lowercase), or "" when absent."""
        key = self._keys.get(name)
        return self.headers[key] if key is not None else ""

    def _cap_error(self) -> str:
        if self._count > MAX_BHTTP_HEADER_FIELDS:
            return f"bhttp message has more than {MAX_BHTTP_HEADER_FIELDS} header fields"
        if self._size > MAX_BHTTP_HEADER_BYTES:
            return f"bhttp header fields exceed {MAX_BHTTP_HEADER_BYTES} bytes"
        return ""


class _Message:
    """Mutable state of one bhttp message while it is parsed."""

    def __init__(self, is_request: bool, known_length: bool) -> None:
        self.is_request = is_request
        self.known_length = known_length
        self.method = ""
        self.authority = ""
        self.path = ""
        self.status_code = 0
        self.fields = _FieldSink()
        self.body = b""
        self.error = ""

    def fail(self, error: str) -> None:
        """Record *error* unless an earlier one is already set."""
        if error and not self.error:
            self.error = error

    def to_result(self, raw: bytes) -> ParseResult:
        return ParseResult(
            protocol="bhttp",
            method=self.method,
            url=self.path,
            host=self.authority,
            status_code=self.status_code,
            status_text=_STATUS_TEXT.get(self.status_code, ""),
            headers=self.fields.headers,
            body=self.body,
            body_size=len(self.body),
            is_complete=not self.error,
            is_request=self.is_request,
            content_type=self.fields.get("content-type"),
            content_encoding=self.fields.get("content-encoding"),
            error=self.error,
            raw=raw,
        )


def _parse_request(reader: _Reader, message: _Message) -> None:
    """Request control data, then the shared field/content sections."""
    message.method = _field_text(reader.vlen("method"))
    reader.vlen("scheme")
    message.authority = _field_text(reader.vlen("authority"))
    message.path = _field_text(reader.vlen("path"))
    _parse_sections(reader, message)


def _parse_response(reader: _Reader, message: _Message) -> None:
    """Informational (1xx) responses, final status, then the sections."""
    status = _read_status(reader)
    while status < _FINAL_STATUS:
        # Informational fields are validated but not kept (as before).
        _read_field_section(reader, message, _FieldSink())
        status = _read_status(reader)
    message.status_code = status
    _parse_sections(reader, message)


def _read_status(reader: _Reader) -> int:
    status = reader.varint("status code")
    if not _MIN_STATUS <= status <= _MAX_STATUS:
        raise _BhttpError(f"invalid status code {status}")
    return status


def _parse_sections(reader: _Reader, message: _Message) -> None:
    """Header section, content, then trailers merged into the headers.

    Trailers share the header caps, so the merged dict stays bounded.
    """
    _read_field_section(reader, message, message.fields)
    message.body = _read_content(reader, message.known_length)
    _read_field_section(reader, message, message.fields)


def _read_field_section(reader: _Reader, message: _Message,
                        sink: _FieldSink) -> None:
    """Read one field section into *sink*; absent (truncated) means empty."""
    if reader.at_end():
        return
    if message.known_length:
        _read_known_field_section(reader, message, sink)
    else:
        _read_field_lines(reader, sink, terminated=True)
    message.fail(sink.overflow)


def _read_known_field_section(reader: _Reader, message: _Message,
                              sink: _FieldSink) -> None:
    """A length-prefixed section: a bad field stops only this section."""
    section = reader.section("field section")
    try:
        _read_field_lines(section, sink, terminated=False)
    except _BhttpError as e:
        message.fail(f"{_ERROR_PREFIX}{e}")


def _read_field_lines(reader: _Reader, sink: _FieldSink,
                      terminated: bool) -> None:
    """Read field lines until the section ends or, if *terminated*, a zero."""
    while not reader.at_end():
        name_length = reader.varint("field name length")
        if name_length == _TERMINATOR:
            if terminated:
                return
            raise _BhttpError("empty field name")
        name = reader.take(name_length, "field name")
        sink.add(name, reader.vlen("field value"))


def _read_content(reader: _Reader, known_length: bool) -> bytes:
    """Read the content; absent (truncated) means empty."""
    if reader.at_end():
        return b""
    if known_length:
        return reader.vlen("content")
    return _read_content_chunks(reader)


def _read_content_chunks(reader: _Reader) -> bytes:
    """Indeterminate-length content: chunks up to a zero-length terminator."""
    body = bytearray()
    while not reader.at_end():
        length = reader.varint("content chunk length")
        if length == _TERMINATOR:
            break
        body += reader.take(length, "content chunk")
    return bytes(body)
