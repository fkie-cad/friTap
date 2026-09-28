"""HTTP/3 stream model: h3_streams helpers and Http3Parser muxed-mode routing."""

import pytest

from friTap.parsers.h3_streams import (
    KIND_CONTROL,
    KIND_PUSH,
    KIND_QPACK_DECODER,
    KIND_QPACK_ENCODER,
    KIND_REQUEST,
    KIND_UNKNOWN,
    UniStreamState,
    initiator_side,
    is_client_initiated,
    is_uni,
    kind_for_uni_type,
    parse_settings,
    settings_to_headers,
)
from friTap.parsers.http3 import Http3Parser
from friTap.parsers.varint import encode_varint
from tests.unit._h3_helpers import (
    FRAME_DATA,
    FRAME_SETTINGS,
    UNI_CONTROL,
    UNI_PUSH,
    UNI_QPACK_DECODER,
    UNI_QPACK_ENCODER,
    control_stream_bytes,
    h3_frame,
    headers_frame,
    qpack_encoder,
    settings_payload,
    uni_stream,
)

# Client bidi 0/4, client uni 2/6/10, server uni 3/7/11 (RFC 9000 2.1)
CLIENT_CONTROL_SID = 2
CLIENT_ENCODER_SID = 6
CLIENT_DECODER_SID = 10
SERVER_CONTROL_SID = 3
SERVER_PUSH_SID = 15
GREASE_TYPE = 0x21  # 0x1f * N + 0x21 reserved stream type

_GET = [(b":method", b"GET"), (b":scheme", b"https"),
        (b":authority", b"example.com"), (b":path", b"/")]


def _headers(stream_id, headers):
    pytest.importorskip("pylsqpack")
    _enc, frame = headers_frame(qpack_encoder()[0], stream_id, headers)
    return frame


def _response(stream_id, status=b"200", extra=()):
    return _headers(stream_id, [(b":status", status), *extra])


# ----------------------------------------------------------------------
# h3_streams helpers
# ----------------------------------------------------------------------

class TestStreamIdClassification:
    @pytest.mark.parametrize("sid,uni,client", [
        (0, False, True), (1, False, False), (2, True, True), (3, True, False),
        (4, False, True), (7, True, False), (14, True, True),
    ])
    def test_bits(self, sid, uni, client):
        assert is_uni(sid) is uni
        assert is_client_initiated(sid) is client

    def test_initiator_side(self):
        assert initiator_side(2) == "client"
        assert initiator_side(3) == "server"

    @pytest.mark.parametrize("stype,kind", [
        (UNI_CONTROL, KIND_CONTROL), (UNI_PUSH, KIND_PUSH),
        (UNI_QPACK_ENCODER, KIND_QPACK_ENCODER), (UNI_QPACK_DECODER, KIND_QPACK_DECODER),
        (GREASE_TYPE, KIND_UNKNOWN), (None, KIND_UNKNOWN),
    ])
    def test_kind_for_uni_type(self, stype, kind):
        assert kind_for_uni_type(stype) == kind

    def test_uni_state_defaults(self):
        state = UniStreamState()
        assert state.stype is None and state.push_id is None and state.buf == bytearray()


class TestSettings:
    def test_round_trip(self):
        settings = {0x01: 65536, 0x06: 262144, 0x07: 100, 0x33: 1, 0x4a4a: 7}
        assert parse_settings(settings_payload(settings)) == settings

    def test_empty(self):
        assert parse_settings(b"") == {}

    def test_truncated_pair_ignored(self):
        payload = settings_payload({0x01: 4096}) + encode_varint(0x06)
        assert parse_settings(payload) == {0x01: 4096}

    def test_headers_names(self):
        headers = settings_to_headers({0x01: 0, 0x06: 1, 0x07: 2, 0x08: 1, 0x33: 1, 0xabc: 9})
        assert headers == {
            "QPACK_MAX_TABLE_CAPACITY": "0", "MAX_FIELD_SECTION_SIZE": "1",
            "QPACK_BLOCKED_STREAMS": "2", "ENABLE_CONNECT_PROTOCOL": "1",
            "H3_DATAGRAM": "1", "0xabc": "9",
        }


# ----------------------------------------------------------------------
# Unidirectional streams
# ----------------------------------------------------------------------

class TestUniStreams:
    def test_control_stream_yields_one_settings_result(self):
        parser = Http3Parser()
        results = parser.feed(control_stream_bytes(), "write", stream_id=CLIENT_CONTROL_SID)
        assert len(results) == 1
        result = results[0]
        assert result.is_control_frame is True
        assert result.method == "SETTINGS"
        assert result.url == "connection-control"
        assert result.stream_id == CLIENT_CONTROL_SID
        assert result.is_request is True
        assert result.headers["QPACK_MAX_TABLE_CAPACITY"] == "65536"
        assert parser.stream_kind(CLIENT_CONTROL_SID) == KIND_CONTROL
        assert parser._peer_settings["client"][0x07] == 100

    def test_second_settings_and_goaway_ignored(self):
        parser = Http3Parser()
        parser.feed(control_stream_bytes(), "write", stream_id=CLIENT_CONTROL_SID)
        later = h3_frame(FRAME_SETTINGS, settings_payload({1: 1})) + h3_frame(0x07, b"\x00")
        assert parser.feed(later, "write", stream_id=CLIENT_CONTROL_SID) == []

    def test_control_stream_split_across_chunks(self):
        parser = Http3Parser()
        data = control_stream_bytes()
        results = []
        for i in range(len(data)):
            results += parser.feed(data[i:i + 1], "write", stream_id=CLIENT_CONTROL_SID)
        assert [r.method for r in results] == ["SETTINGS"]

    def test_server_control_stream_side(self):
        parser = Http3Parser()
        results = parser.feed(control_stream_bytes(), "read", stream_id=SERVER_CONTROL_SID)
        assert results[0].is_request is False
        assert "server" in parser._peer_settings

    def test_encoder_stream_buffered_no_result(self):
        parser = Http3Parser()
        results = parser.feed(uni_stream(UNI_QPACK_ENCODER) + b"\x3f\xe1\x1f", "write",
                              stream_id=CLIENT_ENCODER_SID)
        assert results == []
        assert parser.stream_kind(CLIENT_ENCODER_SID) == KIND_QPACK_ENCODER
        assert bytes(parser._encoder_bytes["client"]) == b"\x3f\xe1\x1f"

    def test_decoder_stream_ignored(self):
        parser = Http3Parser()
        assert parser.feed(uni_stream(UNI_QPACK_DECODER) + b"\x81", "write",
                           stream_id=CLIENT_DECODER_SID) == []
        assert parser.stream_kind(CLIENT_DECODER_SID) == KIND_QPACK_DECODER

    def test_grease_stream_ignored(self):
        parser = Http3Parser()
        grease = uni_stream(GREASE_TYPE) + h3_frame(0x01, b"\x00\x00\xd1")
        assert parser.feed(grease, "write", stream_id=14) == []
        assert parser.stream_kind(14) == KIND_UNKNOWN

    def test_stream_kind_bidi_and_unseen(self):
        parser = Http3Parser()
        assert parser.stream_kind(0) == KIND_REQUEST
        assert parser.stream_kind(18) == KIND_UNKNOWN

    def test_push_stream_parsed_as_response(self):
        parser = Http3Parser()
        body = b"pushed"
        data = (encode_varint(UNI_PUSH) + encode_varint(0)
                + _response(SERVER_PUSH_SID, extra=[(b"content-length", b"6")])
                + h3_frame(FRAME_DATA, body))
        results = parser.feed(data, "read", stream_id=SERVER_PUSH_SID)
        assert parser.stream_kind(SERVER_PUSH_SID) == KIND_PUSH
        assert len(results) == 1
        assert results[0].status_code == 200
        assert results[0].is_request is False
        assert results[0].is_complete is True
        assert results[0].body_size == len(body)


# ----------------------------------------------------------------------
# Request streams
# ----------------------------------------------------------------------

class TestRequestStreams:
    def test_headers_and_data_in_one_chunk_one_result(self):
        parser = Http3Parser()
        parser.feed(_headers(0, _GET), "write", stream_id=0)
        data = _response(0) + h3_frame(FRAME_DATA, b"abc") + h3_frame(FRAME_DATA, b"de")
        results = parser.feed(data, "read", stream_id=0)
        assert len(results) == 1
        assert results[0].status_code == 200
        assert results[0].body_size == 5
        assert results[0].is_complete is False  # no content-length: FIN not visible

    def test_request_complete_on_headers(self):
        results = Http3Parser().feed(_headers(0, _GET), "write", stream_id=0)
        assert results[0].is_request is True
        assert results[0].is_complete is True

    def test_request_with_body_completes_at_content_length(self):
        parser = Http3Parser()
        post = [(b":method", b"POST"), (b":path", b"/u"), (b"content-length", b"4")]
        assert parser.feed(_headers(0, post), "write", stream_id=0)[0].is_complete is False
        results = parser.feed(h3_frame(FRAME_DATA, b"body"), "write", stream_id=0)
        assert results[0].is_complete is True
        assert results[0].body_size == 4

    def test_response_completes_at_content_length(self):
        parser = Http3Parser()
        parser.feed(_headers(0, _GET), "write", stream_id=0)
        first = parser.feed(_response(0, extra=[(b"content-length", b"6")])
                            + h3_frame(FRAME_DATA, b"abc"), "read", stream_id=0)
        assert first[0].is_complete is False
        last = parser.feed(h3_frame(FRAME_DATA, b"def"), "read", stream_id=0)
        assert last[0].is_complete is True
        assert last[0].body_size == 6

    def test_late_data_after_completion_ignored(self):
        parser = Http3Parser()
        parser.feed(_response(0, extra=[(b"content-length", b"0")]), "read", stream_id=0)
        assert parser.feed(h3_frame(FRAME_DATA, b"x"), "read", stream_id=0) == []

    @pytest.mark.parametrize("status", [b"204", b"304"])
    def test_bodyless_status_completes(self, status):
        results = Http3Parser().feed(_response(0, status), "read", stream_id=0)
        assert results[0].is_complete is True

    def test_head_request_response_completes(self):
        parser = Http3Parser()
        head = [(b":method", b"HEAD"), (b":path", b"/")]
        parser.feed(_headers(0, head), "write", stream_id=0)
        results = parser.feed(_response(0, extra=[(b"content-length", b"999")]),
                              "read", stream_id=0)
        assert results[0].is_complete is True

    def test_interim_103_does_not_complete(self):
        parser = Http3Parser()
        parser.feed(_headers(0, _GET), "write", stream_id=0)
        interim = parser.feed(_response(0, b"103", [(b"link", b"</s.css>")]),
                              "read", stream_id=0)
        assert interim[0].status_code == 103
        assert interim[0].is_complete is False
        final = parser.feed(_response(0, b"204"), "read", stream_id=0)
        assert final[0].status_code == 204
        assert final[0].is_complete is True
        assert "link" not in final[0].headers

    def test_data_before_headers_yields_nothing(self):
        assert Http3Parser().feed(h3_frame(FRAME_DATA, b"x"), "read", stream_id=0) == []

    def test_flush_returns_incomplete_response(self):
        parser = Http3Parser()
        parser.feed(_response(0) + h3_frame(FRAME_DATA, b"abc"), "read", stream_id=0)
        flushed = parser.flush()
        assert len(flushed) == 1
        assert flushed[0].is_complete is False and flushed[0].body_size == 3


class TestClientDirectionInference:
    def test_default_is_write(self):
        assert Http3Parser().client_direction == "write"

    def test_server_side_capture_from_bidi_stream(self):
        parser = Http3Parser()
        # A server-side capture reads the request: client direction is "read".
        parser.feed(h3_frame(0x21, b""), "read", stream_id=0)
        assert parser.client_direction == "read"

    def test_server_uni_stream_is_conclusive(self):
        parser = Http3Parser()
        parser.feed(h3_frame(0x21, b""), "read", stream_id=0)  # heuristic guess
        parser.feed(control_stream_bytes(), "read", stream_id=SERVER_CONTROL_SID)
        assert parser.client_direction == "write"

    def test_pseudo_header_less_block_uses_client_direction(self):
        parser = Http3Parser()
        parser.feed(control_stream_bytes(), "read", stream_id=CLIENT_CONTROL_SID)
        results = parser.feed(_headers(0, [(b"x-a", b"1")]), "read", stream_id=0)
        assert results[0].is_request is True
        results = parser.feed(_headers(0, [(b"x-b", b"2")]), "write", stream_id=0)
        assert results[0].is_request is False
