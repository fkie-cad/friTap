"""Unit tests for Http3Parser QPACK header decoding (static table + fallbacks)."""

import pytest

from friTap.parsers.http3 import Http3Parser
from tests.unit._h3_helpers import headers_frame, qpack_encoder

pylsqpack = pytest.importorskip("pylsqpack")

_REQUEST = [
    (b":method", b"GET"),
    (b":scheme", b"https"),
    (b":authority", b"example.com"),
    (b":path", b"/index.html"),
]


def _feed_headers(headers, stream_id=0, direction="write", encoder=None):
    encoder = encoder or qpack_encoder()[0]
    _enc_bytes, frame = headers_frame(encoder, stream_id, headers)
    return Http3Parser().feed(frame, direction, stream_id=stream_id)


class TestStaticQpackDecoding:
    def test_request_pseudo_headers_decoded(self):
        results = _feed_headers(_REQUEST)
        assert len(results) == 1
        req = results[0]
        assert req.protocol == "HTTP/3"
        assert req.method == "GET"
        assert req.host == "example.com"
        assert req.url == "/index.html"
        assert req.is_request is True

    def test_response_status_decoded(self):
        results = _feed_headers(
            [(b":status", b"200"), (b"content-type", b"text/html")],
            stream_id=0, direction="read",
        )
        assert len(results) == 1
        assert results[0].status_code == 200
        assert results[0].is_request is False

    def test_uses_decoded_headers_not_raw_scan(self, monkeypatch):
        def _fail(_payload):
            raise AssertionError("raw scan must not run for a static block")
        monkeypatch.setattr(Http3Parser, "_scan_raw_headers", staticmethod(_fail))
        assert _feed_headers(_REQUEST)[0].method == "GET"


class TestToStrPairs:
    def test_bytes_pairs_decoded_latin1(self):
        pairs = Http3Parser._to_str_pairs([(b":path", b"/\xe9")])
        assert pairs == [(":path", "/é")]

    def test_str_pairs_pass_through(self):
        assert Http3Parser._to_str_pairs([(":status", "204")]) == [(":status", "204")]

    def test_empty(self):
        assert Http3Parser._to_str_pairs([]) == []


class TestStreamBlockedFallback:
    def _blocked_frame(self):
        encoder, _preamble = qpack_encoder(4096, 16)
        headers = _REQUEST + [(b"x-custom-header", b"custom-value")]
        # First encode populates the dynamic table; the second references it.
        headers_frame(encoder, 0, headers)
        _enc, frame = headers_frame(encoder, 4, headers)
        return frame

    def test_blocked_block_falls_back_without_raising(self):
        # Q5: a muxed block waits for SETTINGS/inserts and is raw-scanned at flush
        parser = Http3Parser()
        assert parser.feed(self._blocked_frame(), "write", stream_id=4) == []
        results = parser.flush()
        assert len(results) == 1
        assert results[0].protocol == "HTTP/3"
        assert results[0].is_request is True
        assert results[0].is_complete is False

    def test_legacy_blocked_block_falls_back_immediately(self):
        # Non-muxed mode keeps the legacy decoder: raw scan right away, no queue
        parser = Http3Parser()
        assert parser.feed(self._blocked_frame(), "write") == []
        flushed = parser.flush()
        assert len(flushed) == 1 and flushed[0].is_request is True

    def test_blocked_block_uses_raw_scan(self, monkeypatch):
        calls = []
        original = Http3Parser._scan_raw_headers

        def _spy(payload):
            calls.append(payload)
            return original(payload)
        monkeypatch.setattr(Http3Parser, "_scan_raw_headers", staticmethod(_spy))
        parser = Http3Parser()
        parser.feed(self._blocked_frame(), "write", stream_id=4)
        assert calls == []
        parser.flush()
        assert len(calls) == 1


class TestLegacyNonMuxedMode:
    """Without a stream id the parser keeps its single-stream-per-direction model."""

    def test_second_headers_emits_previous_complete(self):
        encoder = qpack_encoder()[0]
        _e, first = headers_frame(encoder, 0, _REQUEST)
        _e, second = headers_frame(encoder, 4, _REQUEST)
        parser = Http3Parser()
        assert parser.feed(first, "write") == []
        results = parser.feed(second, "write")
        assert len(results) == 1
        assert results[0].method == "GET" and results[0].is_complete is True

    def test_flush_returns_partial(self):
        _e, frame = headers_frame(qpack_encoder()[0], 0, _REQUEST)
        parser = Http3Parser()
        parser.feed(frame, "write")
        flushed = parser.flush()
        assert len(flushed) == 1 and flushed[0].is_complete is False

    def test_muxed_uni_stream_not_parsed_as_request(self):
        from tests.unit._h3_helpers import control_stream_bytes
        results = Http3Parser().feed(control_stream_bytes(), "write", stream_id=2)
        assert all(r.is_control_frame for r in results)


# ----------------------------------------------------------------------
# Q5: QPACK dynamic table in muxed mode
# ----------------------------------------------------------------------

from friTap.parsers import http3 as http3_module  # noqa: E402
from tests.unit._h3_helpers import (  # noqa: E402
    FRAME_HEADERS,
    UNI_QPACK_ENCODER,
    dynamic_exchange,
    h3_frame,
    settings_stream,
    uni_stream,
)

CLIENT_ENCODER_SID = 6
SERVER_CONTROL_SID = 3
SERVER_ENCODER_SID = 7
CLIENT_CONTROL_SID = 2
_DYN_PATHS = {0: b"/a", 4: b"/b", 8: b"/c"}


def _dyn_request(path):
    return [(b":method", b"GET"), (b":scheme", b"https"),
            (b":authority", b"example.com"), (b":path", path),
            (b"user-agent", b"test-agent/1.0")]


def _dyn_requests(capacity=4096):
    encoder, blocks = dynamic_exchange(
        list(_DYN_PATHS), {sid: _dyn_request(p) for sid, p in _DYN_PATHS.items()},
        capacity=capacity)
    frames = {sid: h3_frame(FRAME_HEADERS, block) for sid, block in blocks.items()}
    return uni_stream(UNI_QPACK_ENCODER) + encoder, frames


def _server_settings(parser, capacity=4096):
    return parser.feed(settings_stream(capacity), "read", stream_id=SERVER_CONTROL_SID)


def _requests_only(results):
    return {r.stream_id: r.url for r in results if not r.is_control_frame}


class TestDynamicTableOrderings:
    def test_settings_then_encoder_then_headers(self):
        encoder, frames = _dyn_requests()
        parser = Http3Parser()
        _server_settings(parser)
        assert parser.feed(encoder, "write", stream_id=CLIENT_ENCODER_SID) == []
        urls = {}
        for sid, frame in frames.items():
            urls.update(_requests_only(parser.feed(frame, "write", stream_id=sid)))
        assert urls == {0: "/a", 4: "/b", 8: "/c"}

    def test_headers_before_encoder_resume_on_encoder_chunk(self):
        encoder, frames = _dyn_requests()
        parser = Http3Parser()
        _server_settings(parser)
        assert parser.feed(frames[8], "write", stream_id=8) == []
        results = parser.feed(encoder, "write", stream_id=CLIENT_ENCODER_SID)
        assert _requests_only(results) == {8: "/c"}
        assert results[0].host == "example.com" and results[0].is_request

    def test_headers_before_settings_resume_on_settings(self):
        encoder, frames = _dyn_requests()
        parser = Http3Parser()
        assert parser.feed(frames[4], "write", stream_id=4) == []
        assert parser.feed(encoder, "write", stream_id=CLIENT_ENCODER_SID) == []
        results = _server_settings(parser)
        assert results[0].is_control_frame and results[0].method == "SETTINGS"
        assert _requests_only(results) == {4: "/b"}

    def test_capacity_mismatch_falls_back_without_raising(self):
        encoder, frames = _dyn_requests(capacity=4096)
        parser = Http3Parser()
        _server_settings(parser, capacity=1024)
        parser.feed(frames[8], "write", stream_id=8)
        results = parser.feed(encoder, "write", stream_id=CLIENT_ENCODER_SID)
        assert [r.stream_id for r in results] == [8]
        assert results[0].is_request

    def test_never_unblocked_block_is_raw_scanned_at_flush(self):
        _encoder, frames = _dyn_requests()
        parser = Http3Parser()
        _server_settings(parser)
        assert parser.feed(frames[8], "write", stream_id=8) == []
        flushed = parser.flush()
        assert [r.stream_id for r in flushed] == [8]
        assert flushed[0].is_complete is False

    def test_response_waits_for_its_blocked_request(self):
        encoder, frames = _dyn_requests()
        _enc, response = headers_frame(qpack_encoder()[0], 8, [(b":status", b"204")])
        parser = Http3Parser()
        _server_settings(parser)
        parser.feed(frames[8], "write", stream_id=8)
        held = parser.feed(response, "read", stream_id=8)
        assert held[0].status_code == 204 and held[0].is_complete is False
        results = parser.feed(encoder, "write", stream_id=CLIENT_ENCODER_SID)
        assert [(r.is_request, r.is_complete) for r in results] == [(True, True), (False, True)]
        assert results[0].url == "/c"

    def test_response_context_configured_from_client_settings(self):
        status = [(b":status", b"200"), (b"server", b"test-server"),
                  (b"content-type", b"text/html"), (b"content-length", b"0")]
        encoder, blocks = dynamic_exchange([0, 4, 8], status, capacity=65536)
        parser = Http3Parser()
        _server_settings(parser, capacity=4096)  # sizes the CLIENT encoder only
        parser.feed(settings_stream(65536), "write", stream_id=CLIENT_CONTROL_SID)
        parser.feed(uni_stream(UNI_QPACK_ENCODER) + encoder, "read",
                    stream_id=SERVER_ENCODER_SID)
        results = parser.feed(h3_frame(FRAME_HEADERS, blocks[8]), "read", stream_id=8)
        assert results[0].status_code == 200
        assert results[0].headers.get("server") == "test-server"

    def test_without_pylsqpack_headers_are_raw_scanned(self, monkeypatch):
        monkeypatch.setattr(http3_module, "_qpack_available", False)
        _encoder, frames = _dyn_requests()
        parser = Http3Parser()
        assert parser._qpack_ctx is None
        results = parser.feed(frames[8], "write", stream_id=8)
        assert len(results) == 1 and results[0].is_request
