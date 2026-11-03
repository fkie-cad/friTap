"""Unit tests for the RFC 9292 Binary HTTP parser (friTap.parsers.bhttp).

The parsed bytes are attacker-controlled (decrypted OHTTP payloads, possibly
malware), so besides valid round trips these cover truncation, lengths that
overrun their section, non-UTF-8 field bytes, duplicate fields and the caps.
"""

from friTap.parsers.bhttp import (
    MAX_BHTTP_HEADER_BYTES,
    MAX_BHTTP_HEADER_FIELDS,
    can_parse_bhttp,
    parse_bhttp,
)
from friTap.parsers.varint import encode_varint

KNOWN_REQUEST, KNOWN_RESPONSE = b"\x00", b"\x01"
INDETERMINATE_REQUEST, INDETERMINATE_RESPONSE = b"\x02", b"\x03"
TERMINATOR = b"\x00"


# --------------------------------------------------------------------------- #
# Encoders (RFC 9292 section 3)
# --------------------------------------------------------------------------- #

def _vlen(data: bytes) -> bytes:
    return encode_varint(len(data)) + data


def _field_lines(pairs) -> bytes:
    return b"".join(_vlen(name) + _vlen(value) for name, value in pairs)


def _known_fields(pairs) -> bytes:
    return _vlen(_field_lines(pairs))


def _indeterminate_fields(pairs) -> bytes:
    return _field_lines(pairs) + TERMINATOR


def _control(method=b"GET", scheme=b"https", authority=b"example.com", path=b"/"):
    return _vlen(method) + _vlen(scheme) + _vlen(authority) + _vlen(path)


def _chunks(*parts: bytes) -> bytes:
    return b"".join(_vlen(part) for part in parts) + TERMINATOR


_REQUEST_FIELDS = [(b"content-type", b"application/json"), (b"user-agent", b"probe/1")]


# --------------------------------------------------------------------------- #
# Valid round trips
# --------------------------------------------------------------------------- #

class TestKnownLength:
    def test_request_round_trip(self):
        data = (KNOWN_REQUEST + _control(b"POST", b"https", b"api.example", b"/v1?q=1")
                + _known_fields(_REQUEST_FIELDS) + _vlen(b'{"a":1}')
                + _known_fields([(b"x-checksum", b"abc")]))
        result = parse_bhttp(data)
        assert result.error == ""
        assert result.is_complete is True
        assert result.is_request is True
        assert (result.method, result.host, result.url) == ("POST", "api.example", "/v1?q=1")
        assert result.headers == {"content-type": "application/json",
                                  "user-agent": "probe/1", "x-checksum": "abc"}
        assert result.body == b'{"a":1}'
        assert result.body_size == 7
        assert result.content_type == "application/json"
        assert result.raw == data

    def test_response_round_trip_with_informational(self):
        data = (KNOWN_RESPONSE + encode_varint(103) + _known_fields([(b"link", b"</a>")])
                + encode_varint(200)
                + _known_fields([(b"content-encoding", b"gzip"), (b"server", b"s")])
                + _vlen(b"payload") + _known_fields([]))
        result = parse_bhttp(data)
        assert result.error == ""
        assert result.is_complete is True
        assert result.is_request is False
        assert (result.status_code, result.status_text) == (200, "OK")
        # Informational fields are not merged into the final headers.
        assert result.headers == {"content-encoding": "gzip", "server": "s"}
        assert result.content_encoding == "gzip"
        assert result.body == b"payload"

    def test_truncated_at_section_boundary_is_valid(self):
        # RFC 9292 section 3.8: absent trailing sections are empty.
        result = parse_bhttp(KNOWN_REQUEST + _control())
        assert result.error == ""
        assert result.is_complete is True
        assert result.headers == {}
        assert result.body == b""

    def test_trailing_padding_is_ignored(self):
        data = KNOWN_RESPONSE + encode_varint(204) + _known_fields([]) + _vlen(b"") \
            + _known_fields([]) + b"\x00" * 16
        result = parse_bhttp(data)
        assert result.error == ""
        assert result.status_code == 204


class TestIndeterminateLength:
    def test_request_round_trip(self):
        data = (INDETERMINATE_REQUEST + _control(b"PUT", b"https", b"h.example", b"/up")
                + _indeterminate_fields(_REQUEST_FIELDS)
                + _chunks(b"hello ", b"world")
                + _indeterminate_fields([(b"x-trailer", b"t")]) + b"\x00" * 4)
        result = parse_bhttp(data)
        assert result.error == ""
        assert result.is_complete is True
        assert result.is_request is True
        assert (result.method, result.host, result.url) == ("PUT", "h.example", "/up")
        assert result.headers == {"content-type": "application/json",
                                  "user-agent": "probe/1", "x-trailer": "t"}
        assert result.body == b"hello world"

    def test_response_round_trip(self):
        data = (INDETERMINATE_RESPONSE + encode_varint(100) + _indeterminate_fields([])
                + encode_varint(404) + _indeterminate_fields([(b"content-type", b"text/plain")])
                + _chunks(b"not ", b"found") + _indeterminate_fields([]))
        result = parse_bhttp(data)
        assert result.error == ""
        assert result.is_request is False
        assert (result.status_code, result.status_text) == (404, "Not Found")
        assert result.content_type == "text/plain"
        assert result.body == b"not found"

    def test_missing_terminators_are_valid_truncation(self):
        data = INDETERMINATE_REQUEST + _control() + _field_lines([(b"a", b"1")])
        result = parse_bhttp(data)
        assert result.error == ""
        assert result.headers == {"a": "1"}


class TestNotBhttp:
    def test_rejects_unknown_framing_and_short_input(self):
        assert parse_bhttp(b"") is None
        assert parse_bhttp(b"\x00") is None
        assert parse_bhttp(b"\x04abc") is None
        assert can_parse_bhttp(b"\x07\x00") is False
        assert can_parse_bhttp(b"\x02\x00") is True


# --------------------------------------------------------------------------- #
# Truncation and overrun
# --------------------------------------------------------------------------- #

class TestTruncation:
    def test_truncated_name_known_length(self):
        # Name length 10 but only 3 bytes left inside the section.
        section = _field_lines([(b"ok", b"1")]) + encode_varint(10) + b"abc"
        data = KNOWN_REQUEST + _control() + _vlen(section) + _vlen(b"body")
        result = parse_bhttp(data)
        assert "field name length 10 exceeds" in result.error
        assert result.is_complete is False
        assert result.headers == {"ok": "1"}
        # The section end is known, so the content after it still parses.
        assert result.body == b"body"

    def test_truncated_value_known_length(self):
        section = _vlen(b"x-key") + encode_varint(20) + b"short"
        result = parse_bhttp(KNOWN_REQUEST + _control() + _vlen(section))
        assert "field value length 20 exceeds" in result.error
        assert result.headers == {}

    def test_missing_value_length_known_length(self):
        section = _vlen(b"x-key")
        result = parse_bhttp(KNOWN_REQUEST + _control() + _vlen(section))
        assert "truncated field value length" in result.error
        assert result.headers == {}

    def test_truncated_name_indeterminate_stops_parsing(self):
        data = (INDETERMINATE_REQUEST + _control() + _field_lines([(b"ok", b"1")])
                + encode_varint(9) + b"ab")
        result = parse_bhttp(data)
        assert "field name length 9 exceeds" in result.error
        assert result.headers == {"ok": "1"}
        assert result.body == b""

    def test_truncated_value_indeterminate(self):
        data = INDETERMINATE_RESPONSE + encode_varint(200) + _vlen(b"name") + encode_varint(6) + b"v"
        result = parse_bhttp(data)
        assert "field value length 6 exceeds" in result.error
        assert result.status_code == 200
        assert result.headers == {}

    def test_truncated_control_data(self):
        result = parse_bhttp(KNOWN_REQUEST + _vlen(b"GET") + encode_varint(5) + b"ht")
        assert "scheme length 5 exceeds" in result.error
        assert result.is_complete is False

    def test_truncated_multibyte_varint(self):
        # A 4-byte varint prefix with only two bytes present.
        result = parse_bhttp(KNOWN_RESPONSE + b"\x80\x00")
        assert "truncated status code" in result.error


class TestLengthPastSectionEnd:
    def test_value_length_past_section_end_but_inside_message(self):
        # The value claims 12 bytes; the section holds 2, the message has more.
        section = _vlen(b"k") + encode_varint(12) + b"v1"
        data = KNOWN_REQUEST + _control() + _vlen(section) + _vlen(b"body-bytes")
        result = parse_bhttp(data)
        assert "field value length 12 exceeds the 2 bytes left" in result.error
        # No bytes from beyond the section leaked into the header value.
        assert result.headers == {}
        assert result.body == b"body-bytes"

    def test_section_length_past_message_end(self):
        data = KNOWN_REQUEST + _control() + encode_varint(500) + _field_lines([(b"a", b"b")])
        result = parse_bhttp(data)
        assert "field section length 500 exceeds" in result.error
        assert result.headers == {}
        assert result.body == b""

    def test_content_length_past_message_end(self):
        data = KNOWN_REQUEST + _control() + _known_fields([(b"a", b"b")]) + encode_varint(64) + b"xy"
        result = parse_bhttp(data)
        assert "content length 64 exceeds" in result.error
        assert result.headers == {"a": "b"}
        assert result.body == b""

    def test_indeterminate_chunk_past_message_end(self):
        data = (INDETERMINATE_REQUEST + _control() + _indeterminate_fields([])
                + _vlen(b"ok") + encode_varint(40) + b"short")
        result = parse_bhttp(data)
        assert "content chunk length 40 exceeds" in result.error

    def test_huge_varint_length(self):
        data = KNOWN_REQUEST + _control() + encode_varint((1 << 62) - 1) + b"\x00" * 8
        result = parse_bhttp(data)
        assert "exceeds" in result.error

    def test_empty_field_name_in_known_section(self):
        section = encode_varint(0) + _vlen(b"v")
        result = parse_bhttp(KNOWN_REQUEST + _control() + _vlen(section))
        assert "empty field name" in result.error

    def test_invalid_status_code(self):
        result = parse_bhttp(KNOWN_RESPONSE + encode_varint(42) + _known_fields([]))
        assert "invalid status code 42" in result.error


# --------------------------------------------------------------------------- #
# Decoding and duplicates
# --------------------------------------------------------------------------- #

class TestFieldDecoding:
    def test_utf8_value(self):
        data = KNOWN_REQUEST + _control() + _known_fields([(b"x-name", "café".encode())])
        assert parse_bhttp(data).headers == {"x-name": "café"}

    def test_non_utf8_value_falls_back_to_latin1(self):
        data = KNOWN_REQUEST + _control() + _known_fields([(b"x-raw", b"caf\xe9\xff")])
        result = parse_bhttp(data)
        assert result.error == ""
        assert result.headers == {"x-raw": "caf\xe9\xff"}
        # Lossless: the original bytes are recoverable.
        assert result.headers["x-raw"].encode("latin-1") == b"caf\xe9\xff"

    def test_fallback_is_per_field(self):
        pairs = [(b"x-bad", b"\xc3"), (b"x-good", "ü".encode())]
        result = parse_bhttp(KNOWN_REQUEST + _control() + _known_fields(pairs))
        assert result.headers == {"x-bad": "\xc3", "x-good": "ü"}

    def test_non_utf8_control_data(self):
        result = parse_bhttp(KNOWN_REQUEST + _control(path=b"/\xfe"))
        assert result.url == "/\xfe"


class TestDuplicateFields:
    def test_generic_duplicates_joined_with_comma(self):
        pairs = [(b"accept", b"a/b"), (b"accept", b"c/d")]
        result = parse_bhttp(KNOWN_REQUEST + _control() + _known_fields(pairs))
        assert result.headers == {"accept": "a/b, c/d"}

    def test_set_cookie_joined_with_newline(self):
        pairs = [(b"set-cookie", b"a=1; Expires=Wed, 21 Oct 2026"), (b"set-cookie", b"b=2")]
        data = KNOWN_RESPONSE + encode_varint(200) + _known_fields(pairs)
        result = parse_bhttp(data)
        assert result.headers == {"set-cookie": "a=1; Expires=Wed, 21 Oct 2026\nb=2"}

    def test_cookie_joined_with_semicolon(self):
        pairs = [(b"cookie", b"a=1"), (b"cookie", b"b=2")]
        result = parse_bhttp(KNOWN_REQUEST + _control() + _known_fields(pairs))
        assert result.headers == {"cookie": "a=1; b=2"}

    def test_case_insensitive_merge_keeps_first_spelling(self):
        pairs = [(b"X-Trace", b"1"), (b"x-trace", b"2")]
        result = parse_bhttp(INDETERMINATE_REQUEST + _control() + _indeterminate_fields(pairs))
        assert result.headers == {"X-Trace": "1, 2"}

    def test_trailer_merges_with_header(self):
        data = (KNOWN_REQUEST + _control() + _known_fields([(b"x-sig", b"h")])
                + _vlen(b"") + _known_fields([(b"x-sig", b"t")]))
        assert parse_bhttp(data).headers == {"x-sig": "h, t"}


# --------------------------------------------------------------------------- #
# Caps
# --------------------------------------------------------------------------- #

class TestCaps:
    def test_field_count_cap(self):
        pairs = [(b"x-%d" % i, b"v") for i in range(MAX_BHTTP_HEADER_FIELDS + 10)]
        data = KNOWN_REQUEST + _control() + _known_fields(pairs) + _vlen(b"body")
        result = parse_bhttp(data)
        assert len(result.headers) == MAX_BHTTP_HEADER_FIELDS
        assert f"more than {MAX_BHTTP_HEADER_FIELDS} header fields" in result.error
        assert result.body == b"body"

    def test_duplicate_flood_is_capped(self):
        pairs = [(b"a", b"b")] * 50000
        result = parse_bhttp(KNOWN_REQUEST + _control() + _known_fields(pairs))
        assert result.headers["a"].count("b") == MAX_BHTTP_HEADER_FIELDS
        assert "header fields" in result.error

    def test_header_bytes_cap(self):
        big = b"v" * (64 * 1024)
        pairs = [(b"x-%d" % i, big) for i in range(6)]
        data = KNOWN_REQUEST + _control() + _known_fields(pairs)
        result = parse_bhttp(data)
        assert f"exceed {MAX_BHTTP_HEADER_BYTES} bytes" in result.error
        total = sum(len(k) + len(v) for k, v in result.headers.items())
        assert total <= MAX_BHTTP_HEADER_BYTES

    def test_trailers_share_the_caps(self):
        headers = [(b"h-%d" % i, b"v") for i in range(MAX_BHTTP_HEADER_FIELDS)]
        data = (KNOWN_REQUEST + _control() + _known_fields(headers) + _vlen(b"")
                + _known_fields([(b"trailer", b"t")]))
        result = parse_bhttp(data)
        assert "trailer" not in result.headers
        assert len(result.headers) == MAX_BHTTP_HEADER_FIELDS
        assert "header fields" in result.error

    def test_indeterminate_overflow_still_finds_content(self):
        pairs = [(b"x-%d" % i, b"v") for i in range(MAX_BHTTP_HEADER_FIELDS + 5)]
        data = (INDETERMINATE_REQUEST + _control() + _indeterminate_fields(pairs)
                + _chunks(b"after"))
        result = parse_bhttp(data)
        assert len(result.headers) == MAX_BHTTP_HEADER_FIELDS
        assert result.body == b"after"
        assert "header fields" in result.error
