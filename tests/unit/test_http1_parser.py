"""Unit tests for the hardened HTTP/1 parser (friTap.parsers.http1).

Input is attacker-controlled decrypted traffic: these tests pin that h11
can never be parked in a terminal state where later messages are buffered
and silently dropped, that body framing follows the observed request
method, and that repeated header fields are not lost.
"""

from types import SimpleNamespace

import pytest

from friTap.flow.collector import FlowCollector
from friTap.parsers.base import (
    ParseResult,
    apply_http2_headers,
    merge_header_value,
    parse_ascii_uint,
    parse_content_length,
)
from friTap.parsers.http1 import (
    H1_DESYNC_ERROR,
    MAX_PENDING_METHODS,
    MAX_RESYNC_BUFFER,
    Http1Parser,
    _find_message_start,
)
from friTap.parsers.websocket import WebSocketParser


def _req(path: str, *extra: str) -> bytes:
    lines = [f"GET {path} HTTP/1.1", "Host: example.com", *extra, "", ""]
    return "\r\n".join(lines).encode()


def _resp(body: bytes = b"", *extra: str) -> bytes:
    lines = ["HTTP/1.1 200 OK", f"Content-Length: {len(body)}", *extra, "", ""]
    return "\r\n".join(lines).encode() + body


def _urls(results: list[ParseResult]) -> list[str]:
    return [r.url for r in results]


# --------------------------------------------------------------------------- #
# Baseline behaviour
# --------------------------------------------------------------------------- #

class TestBasicParsing:
    def test_request_and_response_parsed(self):
        parser = Http1Parser()
        req = parser.feed(_req("/a"), "write")
        resp = parser.feed(_resp(b"hello"), "read")
        assert _urls(req) == ["/a"]
        assert req[0].method == "GET" and req[0].host == "example.com"
        assert resp[0].status_code == 200 and resp[0].body_size == 5
        assert req[0].error == "" and resp[0].error == ""

    def test_keep_alive_pipeline(self):
        parser = Http1Parser()
        results = parser.feed(_req("/1") + _req("/2") + _req("/3"), "write")
        assert _urls(results) == ["/1", "/2", "/3"]

    def test_can_parse(self):
        parser = Http1Parser()
        assert parser.can_parse(b"GET / HTTP/1.1\r\n")
        assert parser.can_parse(b"HTTP/1.1 200 OK\r\n")
        assert not parser.can_parse(b"\x16\x03\x01")

    def test_flush_returns_partial_message(self):
        parser = Http1Parser()
        assert parser.feed(_req("/p", "Content-Length: 10") + b"abc", "write") == []
        flushed = parser.flush()
        assert len(flushed) == 1 and not flushed[0].is_complete
        assert flushed[0].body_size == 3


# --------------------------------------------------------------------------- #
# Finding 1: h11 desync / terminal states
# --------------------------------------------------------------------------- #

class TestConnectionCloseResync:
    def test_requests_after_connection_close_same_chunk(self):
        parser = Http1Parser()
        data = _req("/first", "Connection: close") + _req("/hidden") * 1000
        results = parser.feed(data, "write")
        assert len(results) == 1001
        assert results[-1].url == "/hidden"
        assert all(r.error == "" for r in results)

    def test_requests_after_connection_close_later_chunk(self):
        parser = Http1Parser()
        parser.feed(_req("/first", "Connection: close"), "write")
        assert _urls(parser.feed(_req("/second"), "write")) == ["/second"]
        assert _urls(parser.feed(_req("/third"), "write")) == ["/third"]

    def test_http10_requests_keep_being_parsed(self):
        parser = Http1Parser()
        data = b"GET /a HTTP/1.0\r\n\r\nGET /b HTTP/1.0\r\n\r\n"
        assert _urls(parser.feed(data, "write")) == ["/a", "/b"]

    def test_responses_after_connection_close(self):
        parser = Http1Parser()
        parser.feed(_req("/1") + _req("/2"), "write")
        data = _resp(b"x", "Connection: close") + _resp(b"yy")
        results = parser.feed(data, "read")
        assert [r.body_size for r in results] == [1, 2]


class TestProtocolErrorResync:
    def test_malformed_header_line_resyncs(self):
        parser = Http1Parser()
        bad = b"GET /bad HTTP/1.1\r\nHost: x\r\nnot a header line\r\n\r\n"
        results = parser.feed(bad + _req("/next"), "write")
        assert _urls(results) == ["/bad", "/next"]
        assert results[0].error == H1_DESYNC_ERROR
        assert not results[0].is_complete
        assert results[1].error == "" and results[1].is_complete

    def test_requests_in_later_chunks_after_error(self):
        parser = Http1Parser()
        first = parser.feed(b"GET /bad HTTP/1.1\r\nbroken\r\n\r\n", "write")
        assert _urls(first) == ["/bad"] and first[0].error == H1_DESYNC_ERROR
        assert _urls(parser.feed(_req("/later"), "write")) == ["/later"]

    def test_garbage_between_messages_flags_desync(self):
        parser = Http1Parser()
        parser.feed(b"\x00\x01garbage\r\n\r\n", "write")
        results = parser.feed(b"more junk " + _req("/after"), "write")
        assert _urls(results) == ["/after"]
        assert results[0].error == H1_DESYNC_ERROR

    def test_message_start_split_across_chunks(self):
        parser = Http1Parser()
        parser.feed(b"junk\r\n\r\nGET /spl", "write")
        results = parser.feed(b"it HTTP/1.1\r\nHost: x\r\n\r\n", "write")
        assert _urls(results) == ["/split"]

    def test_leftover_buffer_is_capped(self):
        parser = Http1Parser()
        parser.feed(b"GET /bad HTTP/1.1\r\nbroken\r\n\r\n", "write")
        for _ in range(1024):
            parser.feed(b"x" * 1024, "write")  # 1 MiB with no message start
        assert len(parser._resync_bufs["write"]) <= MAX_RESYNC_BUFFER
        # still recovers after the flood
        assert _urls(parser.feed(_req("/recovered"), "write")) == ["/recovered"]

    def test_bad_response_resyncs_to_next_response(self):
        parser = Http1Parser()
        parser.feed(_req("/1") + _req("/2"), "write")
        bad = b"HTTP/1.1 200 OK\r\nbroken header\r\n\r\n"
        results = parser.feed(bad + _resp(b"ok"), "read")
        assert [r.status_code for r in results] == [200, 200]
        assert results[0].error == H1_DESYNC_ERROR
        assert results[1].body_size == 2 and results[1].error == ""

    def test_find_message_start_is_linear_on_near_misses(self):
        # many candidates with no CRLF must not hang
        buf = b"GET h" * 20000
        assert _find_message_start(buf, (b"GET h", b"POST /"), 0) == -1


def _feed_bytewise(parser: Http1Parser, data: bytes, direction: str) -> list[ParseResult]:
    results: list[ParseResult] = []
    for index in range(len(data)):
        results += parser.feed(data[index:index + 1], direction)
    return results


def _desynced(direction: str) -> Http1Parser:
    """A parser whose *direction* is hunting for the next message start."""
    parser = Http1Parser()
    bad = b"HTTP/1.1 200 OK\r\nbroken\r\n\r\n" if direction == "read" else b"GET /bad HTTP/1.1\r\nbroken\r\n\r\n"
    parser.feed(bad, direction)
    assert direction in parser._resync_bufs
    return parser


class TestResyncAcrossChunkBoundaries:
    def test_request_signature_split_bytewise_after_garbage(self):
        parser = _desynced("write")
        results = _feed_bytewise(parser, b"junk\x00\xff" + _req("/split"), "write")
        assert _urls(results) == ["/split"]

    def test_response_signature_split_bytewise_after_garbage(self):
        parser = _desynced("read")
        results = _feed_bytewise(parser, b"\x00junk HTTP/2 " + _resp(b"ok"), "read")
        assert [r.status_code for r in results] == [200]
        assert results[0].body_size == 2

    def test_crlf_split_across_chunks_validates_candidate(self):
        parser = _desynced("write")
        assert parser.feed(b"garbage GET /cr HTTP/1.1\r", "write") == []
        results = parser.feed(b"\nHost: x\r\n\r\n", "write")
        assert _urls(results) == ["/cr"]

    def test_bytewise_resync_matches_single_chunk(self):
        data = b"\x00junk\r\nGET" * 50 + _req("/a") + b"\x00\x01\n" + _req("/b")
        whole = _desynced("write").feed(data, "write")
        bytewise = _feed_bytewise(_desynced("write"), data, "write")
        assert [repr(r) for r in bytewise] == [repr(r) for r in whole]
        assert _urls(whole) == ["/a", "/b"]

    def test_chunks_without_lf_skip_the_rescan(self, monkeypatch):
        import friTap.parsers.http1 as http1
        parser = _desynced("write")
        calls = []
        real = http1._find_message_start
        monkeypatch.setattr(http1, "_find_message_start",
                            lambda *args: calls.append(args) or real(*args))
        _feed_bytewise(parser, b"GET /no-line-end" + b"a" * 100, "write")
        assert calls == []
        assert _urls(parser.feed(b" HTTP/1.1\r\nHost: x\r\n\r\n", "write")) == ["/no-line-endaaaa" + "a" * 96]
        assert len(calls) == 1


class TestStrictContentLength:
    @pytest.mark.parametrize("value", [b"-1", b"+5", b"1_0", b"0x10", b"\xd9\xa1"])
    def test_invalid_content_length_rejected(self, value):
        parser = Http1Parser()
        data = (b"POST /up HTTP/1.1\r\nHost: x\r\nContent-Length: " + value
                + b"\r\n\r\n" + _req("/next"))
        results = parser.feed(data, "write")
        assert results[0].url == "/up"
        assert results[0].error == H1_DESYNC_ERROR and not results[0].is_complete
        assert results[-1].url == "/next" and results[-1].is_complete

    def test_negative_content_length_does_not_complete_message(self):
        parser = Http1Parser()
        results = parser.feed(_req("/n", "Content-Length: -1"), "write")
        assert all(not r.is_complete for r in results if r.url == "/n")

    @pytest.mark.parametrize("value, expected", [
        ("12", 12), (" 12 ", 12), (b"7", 7), ("0", 0),
        ("-1", None), ("+5", None), ("1_0", None), ("", None),
        ("1 2", None), ("١", None), (None, None), ("5, 5", None),
    ])
    def test_parse_ascii_uint(self, value, expected):
        assert parse_ascii_uint(value) == expected
        assert parse_content_length(value) == expected


# --------------------------------------------------------------------------- #
# Finding 2: fake request mirrors the observed method
# --------------------------------------------------------------------------- #

class TestMethodAwareResponses:
    def test_head_response_with_content_length_has_no_body(self):
        parser = Http1Parser()
        parser.feed(b"HEAD /h HTTP/1.1\r\nHost: x\r\n\r\n" + _req("/g"), "write")
        data = (b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n"
                + _resp(b"abc"))
        results = parser.feed(data, "read")
        assert [(r.status_code, r.body_size) for r in results] == [(200, 0), (200, 3)]
        assert all(r.is_complete for r in results)

    def test_head_response_split_across_feeds(self):
        parser = Http1Parser()
        parser.feed(_req("/1"), "write")
        assert len(parser.feed(_resp(b"x"), "read")) == 1
        # next request observed *after* the previous response completed
        parser.feed(b"HEAD /h HTTP/1.1\r\nHost: x\r\n\r\n", "write")
        first = parser.feed(b"HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\n", "read")
        assert [(r.status_code, r.body_size) for r in first] == [(200, 0)]

    def test_unknown_method_falls_back_to_get(self):
        parser = Http1Parser()
        results = parser.feed(_resp(b"body"), "read")
        assert results[0].body_size == 4

    def test_method_queue_is_bounded(self):
        parser = Http1Parser()
        parser.feed(_req("/x") * (MAX_PENDING_METHODS + 50), "write")
        assert len(parser._pending_methods) == MAX_PENDING_METHODS


class TestConnectTunnel:
    def test_connect_200_emits_response_and_tunnels(self):
        parser = Http1Parser()
        req = parser.feed(
            b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n",
            "write")
        assert req[0].method == "CONNECT"
        resp = parser.feed(b"HTTP/1.1 200 Connection established\r\n\r\n", "read")
        assert [(r.status_code, r.is_complete) for r in resp] == [(200, True)]
        # Opaque tunnel bytes (TLS) produce nothing and are not an upgrade.
        assert parser.feed(b"\x16\x03\x01\x02\x00" + b"\x00" * 64, "read") == []
        assert parser.feed(b"\x16\x03\x01\x02\x00" + b"\x01" * 64, "write") == []
        assert parser.upgrade_protocol == ""
        assert parser.trailing_data is None

    def test_connect_tunnel_bytes_stay_bounded(self):
        parser = Http1Parser()
        parser.feed(b"CONNECT h:443 HTTP/1.1\r\nHost: h:443\r\n\r\n", "write")
        parser.feed(b"HTTP/1.1 200 OK\r\n\r\n", "read")
        for _ in range(200):
            parser.feed(b"\x17\x03\x03" + b"\xaa" * 1021, "read")
        assert len(parser._resync_bufs["read"]) <= MAX_RESYNC_BUFFER

    def test_connect_rejected_keeps_parsing(self):
        parser = Http1Parser()
        parser.feed(b"CONNECT h:443 HTTP/1.1\r\nHost: h:443\r\n\r\n" + _req("/n"), "write")
        data = (b"HTTP/1.1 407 Proxy Auth\r\nContent-Length: 2\r\n\r\nno"
                + _resp(b"ok"))
        results = parser.feed(data, "read")
        assert [(r.status_code, r.body_size) for r in results] == [(407, 2), (200, 2)]


class TestUpgrade101:
    def _ws_handshake(self, parser):
        parser.feed(_req("/chat", "Upgrade: websocket", "Connection: Upgrade"), "write")

    def test_101_detected_with_trailing_frame(self):
        parser = Http1Parser()
        self._ws_handshake(parser)
        results = parser.feed(
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
            b"Connection: Upgrade\r\n\r\n\x81\x02hi", "read")
        assert [r.status_code for r in results] == [101]
        assert parser.upgrade_protocol == "websocket"
        assert parser.trailing_data == b"\x81\x02hi"

    def test_101_split_across_chunks(self):
        parser = Http1Parser()
        self._ws_handshake(parser)
        assert parser.feed(b"HTTP/1.1 101 Switching Protocols\r\nUpgr", "read") == []
        results = parser.feed(b"ade: websocket\r\n\r\n", "read")
        assert [r.status_code for r in results] == [101]
        assert parser.upgrade_protocol == "websocket"

    def test_101_after_earlier_response_in_same_chunk(self):
        parser = Http1Parser()
        parser.feed(_req("/1") + _req("/ws", "Upgrade: websocket"), "write")
        results = parser.feed(
            _resp(b"a") + b"HTTP/1.1 101 Switching Protocols\r\n"
            b"Upgrade: websocket\r\n\r\n", "read")
        assert [r.status_code for r in results] == [200, 101]
        assert parser.upgrade_protocol == "websocket"

    def test_101_not_re_emitted_on_later_bytes(self):
        parser = Http1Parser()
        self._ws_handshake(parser)
        parser.feed(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: h2c\r\n\r\n", "read")
        assert parser.upgrade_protocol == "h2c"
        assert parser.feed(b"\x00\x00\x00\x04\x00\x00\x00\x00\x00", "read") == []

    def test_collector_swaps_to_websocket_parser(self):
        fc = FlowCollector()
        fc.on_data(_event(
            _req("/chat", "Upgrade: websocket", "Connection: Upgrade"),
            "write", "SSL_write", 1.0))
        fc.on_data(_event(
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
            b"Connection: Upgrade\r\n\r\n", "read", "SSL_read", 1.1))
        conn = next(iter(fc._connections.values()))
        assert isinstance(getattr(conn.parser, "_inner", conn.parser), WebSocketParser)


def _event(data, direction, function, timestamp):
    return SimpleNamespace(
        src_addr="10.0.0.2", src_port=51000, dst_addr="93.184.216.34",
        dst_port=443, data=data, direction=direction, timestamp=timestamp,
        function=function, ssl_session_id="h1-sess")


# --------------------------------------------------------------------------- #
# Finding 3: duplicate headers
# --------------------------------------------------------------------------- #

class TestDuplicateHeaders:
    def test_set_cookie_and_content_encoding_joined(self):
        parser = Http1Parser()
        data = _resp(b"", "Set-Cookie: a=1; Expires=Wed, 21 Oct 2026 07:28:00 GMT",
                     "set-cookie: b=2", "Content-Encoding: gzip",
                     "Content-Encoding: br")
        result = parser.feed(data, "read")[0]
        assert result.headers["Set-Cookie"] == (
            "a=1; Expires=Wed, 21 Oct 2026 07:28:00 GMT\nb=2")
        assert result.headers["Content-Encoding"] == "gzip, br"
        assert result.content_encoding == "gzip, br"

    def test_repeated_request_header_joined_case_insensitively(self):
        parser = Http1Parser()
        result = parser.feed(_req("/", "X-Tag: one", "x-tag: two"), "write")[0]
        assert result.headers["X-Tag"] == "one, two"

    def test_merge_header_value_joiners(self):
        headers: dict = {}
        for name, value in [("accept", "a"), ("accept", "b"),
                            ("cookie", "c=1"), ("cookie", "d=2"),
                            ("set-cookie", "e=1"), ("set-cookie", "f=2")]:
            merge_header_value(headers, name, value)
        assert headers == {"accept": "a, b", "cookie": "c=1; d=2",
                           "set-cookie": "e=1\nf=2"}

    def test_apply_http2_headers_merges_regular_keeps_pseudo_last(self):
        stream = SimpleNamespace(headers={}, method="", url="", host="",
                                 status_code=0, is_request=True,
                                 content_encoding="", content_type="")
        apply_http2_headers(stream, [(":status", "100"), (":status", "200"),
                                     ("set-cookie", "a=1"), ("set-cookie", "b=2")])
        assert stream.headers[":status"] == "200"
        assert stream.status_code == 200
        assert stream.headers["set-cookie"] == "a=1\nb=2"

    @pytest.mark.parametrize("value", ["-200", "+200", "2_00", " "])
    def test_apply_http2_headers_rejects_non_digit_status(self, value):
        stream = SimpleNamespace(headers={}, method="", url="", host="",
                                 status_code=0, is_request=True,
                                 content_encoding="", content_type="")
        apply_http2_headers(stream, [(":status", value)])
        assert stream.status_code == 0
        assert stream.is_request is False
