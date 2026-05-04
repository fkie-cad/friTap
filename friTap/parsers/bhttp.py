"""RFC 9292 Binary HTTP parser.

Parses Binary HTTP (bhttp) messages used as the inner payload of
OHTTP (RFC 9458) encapsulated requests and responses.

Only known-length framing (0x00 request, 0x01 response) is supported.
Indeterminate-length framing (0x02, 0x03) returns None.
"""

from typing import Optional

from .base import ParseResult
from .varint import decode_varint


_STATUS_TEXT = {
    100: "Continue", 101: "Switching Protocols", 103: "Early Hints",
    200: "OK", 201: "Created", 204: "No Content",
    301: "Moved Permanently", 302: "Found", 304: "Not Modified",
    400: "Bad Request", 401: "Unauthorized", 403: "Forbidden",
    404: "Not Found", 405: "Method Not Allowed",
    500: "Internal Server Error", 502: "Bad Gateway", 503: "Service Unavailable",
}


def can_parse_bhttp(data: bytes) -> bool:
    """Check if data starts with a valid bhttp framing indicator."""
    return len(data) >= 2 and data[0] in (0x00, 0x01, 0x02, 0x03)


def parse_bhttp(data: bytes) -> Optional[ParseResult]:
    """Parse a complete RFC 9292 Binary HTTP message.

    Returns ParseResult or None if data is not valid bhttp.
    """
    if not data or len(data) < 2:
        return None

    framing = data[0]
    if framing not in (0x00, 0x01, 0x02, 0x03):
        return None

    if framing in (0x02, 0x03):
        return ParseResult(
            protocol="bhttp",
            error="indeterminate-length bhttp not yet supported",
            is_request=(framing == 0x02),
            raw=data,
        )

    try:
        if framing == 0x00:
            return _parse_request(data)
        else:
            return _parse_response(data)
    except (IndexError, ValueError, OverflowError) as e:
        return ParseResult(
            protocol="bhttp",
            error=f"bhttp parse error: {e}",
            is_request=(framing == 0x00),
            raw=data,
        )


def _read_varint(data: bytes, offset: int) -> tuple[int, int]:
    """Read a QUIC-style varint, returning (value, new_offset)."""
    value, consumed = decode_varint(data, offset)
    return value, offset + consumed


def _read_vlen_bytes(data: bytes, offset: int) -> tuple[bytes, int]:
    """Read a varint-length-prefixed byte sequence."""
    length, offset = _read_varint(data, offset)
    if offset + length > len(data):
        raise IndexError(f"vlen_bytes: need {length} bytes at offset {offset}, have {len(data) - offset}")
    return data[offset:offset + length], offset + length


def _read_header_section(data: bytes, offset: int) -> tuple[dict[str, str], int]:
    """Read a varint-length-prefixed header field section."""
    section_bytes, offset = _read_vlen_bytes(data, offset)
    headers: dict[str, str] = {}
    pos = 0
    while pos < len(section_bytes):
        name_len, pos = _read_varint(section_bytes, pos)
        name = section_bytes[pos:pos + name_len]
        pos += name_len

        value_len, pos = _read_varint(section_bytes, pos)
        value = section_bytes[pos:pos + value_len]
        pos += value_len

        headers[name.decode("ascii", errors="replace")] = value.decode("ascii", errors="replace")

    return headers, offset


def _parse_request(data: bytes) -> ParseResult:
    """Parse a known-length bhttp request (framing 0x00)."""
    offset = 1

    method_bytes, offset = _read_vlen_bytes(data, offset)
    scheme_bytes, offset = _read_vlen_bytes(data, offset)
    authority_bytes, offset = _read_vlen_bytes(data, offset)
    path_bytes, offset = _read_vlen_bytes(data, offset)

    headers, offset = _read_header_section(data, offset)

    body = b""
    if offset < len(data):
        body, offset = _read_vlen_bytes(data, offset)

    method = method_bytes.decode("ascii", errors="replace")
    authority = authority_bytes.decode("ascii", errors="replace")
    path = path_bytes.decode("ascii", errors="replace")

    content_type = ""
    content_encoding = ""
    for k, v in headers.items():
        kl = k.lower()
        if kl == "content-type":
            content_type = v
        elif kl == "content-encoding":
            content_encoding = v

    return ParseResult(
        protocol="bhttp",
        method=method,
        url=path,
        host=authority,
        headers=headers,
        body=body,
        body_size=len(body),
        is_complete=True,
        is_request=True,
        content_type=content_type,
        content_encoding=content_encoding,
        raw=data,
    )


def _parse_response(data: bytes) -> ParseResult:
    """Parse a known-length bhttp response (framing 0x01)."""
    offset = 1

    while True:
        status_code, offset = _read_varint(data, offset)
        headers, offset = _read_header_section(data, offset)
        if status_code >= 200:
            break

    body = b""
    if offset < len(data):
        body, offset = _read_vlen_bytes(data, offset)

    content_type = ""
    content_encoding = ""
    for k, v in headers.items():
        kl = k.lower()
        if kl == "content-type":
            content_type = v
        elif kl == "content-encoding":
            content_encoding = v

    return ParseResult(
        protocol="bhttp",
        status_code=status_code,
        status_text=_STATUS_TEXT.get(status_code, ""),
        headers=headers,
        body=body,
        body_size=len(body),
        is_complete=True,
        is_request=False,
        content_type=content_type,
        content_encoding=content_encoding,
        raw=data,
    )
