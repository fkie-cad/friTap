"""HTTP/3 on QUIC connections observed mid-stream (``quic_midstream``).

Chrome connections set up before friTap attached are seen from a new request
stream on: the control stream (SETTINGS) and the QPACK encoder/decoder streams
were never captured. Header blocks must be decoded at once, and blocks that
reference the unseen dynamic table must fall back immediately to a recovery of
the static/literal pseudo-headers instead of waiting for flush.
"""

import gc
from types import SimpleNamespace

import pylsqpack

from friTap.events import DatalogEvent, EventBus
from friTap.parsers import qpack_context
from friTap.flow.collector import FlowCollector
from friTap.flow.quic_flow import QUIC_PAYLOAD_STREAM, QuicStreamFlowMixin
from friTap.message_router import MessageRouter
from friTap.parsers.h3_streams import SIDE_CLIENT
from friTap.parsers.http3 import Http3Parser
from friTap.parsers.qpack_context import (
    MIDSTREAM_TABLE_CAPACITY,
    QpackDecoderContext,
    recover_pseudo_headers,
)
from friTap.parsers.varint import encode_varint
from tests.unit._h3_helpers import (
    FRAME_DATA,
    FRAME_HEADERS,
    UNI_QPACK_ENCODER,
    dynamic_exchange,
    h3_frame,
    qpack_encoder,
    settings_stream,
)

# QPACK field-line bytes (RFC 9204 4.5)
METHOD_GET = b"\xd1"        # indexed static 17
METHOD_POST = b"\xd4"       # indexed static 20
SCHEME_HTTPS = b"\xd7"      # indexed static 23
DYNAMIC_REF = b"\x80"       # indexed dynamic, relative index 0
PREFIX_STATIC_ONLY = b"\x00\x00"
PREFIX_DYNAMIC = b"\x02\x00"  # Required Insert Count > 0
STATIC_AUTHORITY, STATIC_PATH = 0, 1


def _static_name_literal(index: int, value: bytes) -> bytes:
    """Literal field line with static name reference, plain value."""
    return bytes([0x50 | index, len(value)]) + value


def _huffman_line(name: bytes, value: bytes) -> bytes:
    """The (Huffman-coded) field line pylsqpack emits for one static-name field."""
    _enc, block = qpack_encoder()[0].encode(0, [(name, value)])
    line = block[2:]
    assert line[1] & 0x80, "expected a Huffman-coded value"
    return line


def _request_block(prefix: bytes, *lines: bytes) -> bytes:
    return prefix + b"".join(lines)


def _dynamic_request_block(path_line: bytes) -> bytes:
    return _request_block(PREFIX_DYNAMIC, METHOD_GET, SCHEME_HTTPS, DYNAMIC_REF,
                          _static_name_literal(STATIC_AUTHORITY, b"www.google.com"),
                          path_line)


# --------------------------------------------------------------------------
# recover_pseudo_headers / _scan_raw_headers
# --------------------------------------------------------------------------
class TestRecoverPseudoHeaders:
    def test_plain_static_name_literals(self):
        block = _request_block(PREFIX_STATIC_ONLY, METHOD_POST,
                               _static_name_literal(STATIC_PATH, b"/gen_204"))
        assert recover_pseudo_headers(block) == [(":method", "POST"), (":path", "/gen_204")]

    def test_huffman_literal_value(self):
        block = _request_block(PREFIX_STATIC_ONLY, METHOD_GET,
                               _huffman_line(b":path", b"/index.html"))
        assert recover_pseudo_headers(block) == [(":method", "GET"), (":path", "/index.html")]

    def test_dynamic_references_are_skipped(self):
        block = _dynamic_request_block(_huffman_line(b":path", b"/search?q=1"))
        assert recover_pseudo_headers(block) == [
            (":method", "GET"), (":scheme", "https"),
            (":authority", "www.google.com"), (":path", "/search?q=1")]

    def test_stops_at_first_regular_field(self):
        block = _request_block(PREFIX_STATIC_ONLY, METHOD_GET,
                               _static_name_literal(2, b"60"),  # age
                               _static_name_literal(STATIC_PATH, b"/late"))
        assert recover_pseudo_headers(block) == [(":method", "GET")]

    def test_malformed_input_never_raises(self):
        for block in (b"", b"\x02", b"\x00\x00\x51\x7f", b"\xff" * 40,
                      _dynamic_request_block(b"\x51\x88\x00")):
            assert isinstance(recover_pseudo_headers(block), list)

    def test_truncated_tail_keeps_earlier_fields(self):
        block = _request_block(PREFIX_STATIC_ONLY, METHOD_GET, b"\x51\x20/trunc")
        assert recover_pseudo_headers(block) == [(":method", "GET")]

    def test_one_shared_decoder_serves_every_block(self, monkeypatch):
        made = []

        def counting(capacity, blocked):
            made.append((capacity, blocked))
            return pylsqpack.Decoder(capacity, blocked)

        monkeypatch.setattr(qpack_context, "_RECOVERY_DECODER", qpack_context._RecoveryDecoder())
        monkeypatch.setattr(qpack_context, "new_qpack_decoder", counting)
        for path in (b"/a", b"/b", b"/c"):
            block = _dynamic_request_block(_static_name_literal(STATIC_PATH, path))
            assert recover_pseudo_headers(block)[-1] == (":path", path.decode())
        assert made == [(0, 0)]

    def test_bad_line_spoils_batch_but_not_neighbours(self):
        # Static name index 120 passes the pre-scan but not pylsqpack (99 entries)
        bad_static_name = b"\x5f\x69\x01a"
        block = _request_block(PREFIX_STATIC_ONLY, METHOD_GET, bad_static_name,
                               _static_name_literal(STATIC_PATH, b"/x"))
        assert recover_pseudo_headers(block) == [(":method", "GET"), (":path", "/x")]
        # The shared decoder recovers for the next block
        assert recover_pseudo_headers(PREFIX_STATIC_ONLY + METHOD_POST) == [(":method", "POST")]

    def test_scan_raw_headers_combines_decoded_and_literal_name_scan(self):
        literal_name = b"\x27\x00:status\x03404"  # 001NHxxx, name len 7 + 3
        headers = Http3Parser._scan_raw_headers(
            _request_block(PREFIX_DYNAMIC, METHOD_GET, DYNAMIC_REF) + literal_name)
        assert (":method", "GET") in headers
        assert dict(headers).get(":status") == "404"


# --------------------------------------------------------------------------
# QpackDecoderContext
# --------------------------------------------------------------------------
def _context() -> QpackDecoderContext:
    return QpackDecoderContext(fallback=Http3Parser._scan_raw_headers)


class TestContextMidstream:
    def test_start_midstream_configures_without_settings(self):
        ctx = _context()
        assert ctx.start_midstream() == []
        assert ctx.configured and ctx.capacity == MIDSTREAM_TABLE_CAPACITY

    def test_dynamic_block_falls_back_immediately(self):
        ctx = _context()
        ctx.start_midstream()
        headers = ctx.decode(0, _dynamic_request_block(
            _static_name_literal(STATIC_PATH, b"/a")))
        assert dict(headers)[":path"] == "/a"
        assert ctx.waiting_stream_ids() == [] and not ctx.poisoned

    def test_blocked_after_encoder_bytes_also_falls_back(self):
        encoder_bytes, blocks = dynamic_exchange([0, 4], [(b":method", b"GET"),
                                                          (b"x-token", b"abc")],
                                                 capacity=MIDSTREAM_TABLE_CAPACITY)
        ctx = _context()
        ctx.start_midstream()
        ctx.feed_encoder(encoder_bytes[:3])  # partial inserts only
        headers = ctx.decode(4, blocks[4])
        assert headers is not None and dict(headers).get(":method") == "GET"
        assert ctx.waiting_stream_ids() == []

    def test_queued_block_is_resolved_by_start_midstream(self):
        ctx = _context()
        block = _dynamic_request_block(_static_name_literal(STATIC_PATH, b"/q"))
        assert ctx.decode(0, block) is None
        assert ctx.start_midstream() == [0]
        assert dict(ctx.resume(0))[":path"] == "/q"

    def test_non_midstream_still_waits_for_settings(self):
        ctx = _context()
        assert ctx.decode(0, _dynamic_request_block(b"")) is None
        assert ctx.waiting_stream_ids() == [0] and not ctx.configured

    def test_static_only_block_decodes_in_main_decoder(self):
        ctx = _context()
        ctx.start_midstream()
        block = _request_block(PREFIX_STATIC_ONLY, METHOD_GET,
                               _huffman_line(b":path", b"/index.html"))
        assert ctx.decode(8, block) == [(b":method", b"GET"), (b":path", b"/index.html")]


# --------------------------------------------------------------------------
# Http3Parser
# --------------------------------------------------------------------------
class TestParserMidstream:
    def test_request_headers_decoded_without_settings(self):
        parser = Http3Parser()
        parser.mark_midstream()
        frame = h3_frame(FRAME_HEADERS, _dynamic_request_block(
            _huffman_line(b":path", b"/complete/search")))
        results = parser.feed(frame, "write", stream_id=0)
        assert len(results) == 1
        result = results[0]
        assert (result.method, result.url, result.host) == (
            "GET", "/complete/search", "www.google.com")
        assert result.is_request

    def test_non_midstream_block_waits_until_flush(self):
        parser = Http3Parser()
        frame = h3_frame(FRAME_HEADERS, _dynamic_request_block(
            _static_name_literal(STATIC_PATH, b"/p")))
        assert parser.feed(frame, "write", stream_id=0) == []
        flushed = parser.flush()
        assert [r.url for r in flushed] == ["/p"]

    def test_marking_late_returns_waiting_results_on_next_feed(self):
        parser = Http3Parser()
        frame = h3_frame(FRAME_HEADERS, _dynamic_request_block(
            _static_name_literal(STATIC_PATH, b"/late")))
        assert parser.feed(frame, "write", stream_id=0) == []
        parser.mark_midstream()
        parser.mark_midstream()  # idempotent
        results = parser.feed(b"", "write", stream_id=4)
        assert [r.url for r in results] == ["/late"]

    def test_late_resumed_results_use_the_deferred_queue(self):
        parser = Http3Parser()
        parser.feed(h3_frame(FRAME_HEADERS, _dynamic_request_block(
            _static_name_literal(STATIC_PATH, b"/q"))), "write", stream_id=0)
        parser.mark_midstream()
        assert [r.url for r in parser._deferred_results] == ["/q"]
        assert [r.url for r in parser.feed(b"", "write", stream_id=4)] == ["/q"]
        assert parser._deferred_results == []

    def test_other_streams_are_not_poisoned(self):
        parser = Http3Parser()
        parser.mark_midstream()
        parser.feed(h3_frame(FRAME_HEADERS, _dynamic_request_block(b"")), "write", stream_id=0)
        static = _request_block(PREFIX_STATIC_ONLY, METHOD_POST,
                                _static_name_literal(STATIC_PATH, b"/ok"))
        results = parser.feed(h3_frame(FRAME_HEADERS, static), "write", stream_id=4)
        assert (results[0].method, results[0].url) == ("POST", "/ok")
        assert not any(ctx.poisoned for ctx in parser._qpack_ctx.values())


# --------------------------------------------------------------------------
# Collector + router plumbing
# --------------------------------------------------------------------------
DEVICE = ("10.0.2.16", 50221)
SERVER = ("142.251.152.119", 443)


def _event(data: bytes, stream_id: int, midstream: bool, ts: float = 1.0) -> DatalogEvent:
    return DatalogEvent(
        timestamp=ts, data=data, function="QuicSession_WriteStreamData", direction="write",
        src_addr=DEVICE[0], src_port=DEVICE[1], dst_addr=SERVER[0], dst_port=SERVER[1],
        ssl_session_id="0x72004e7c00", protocol="quic", transport="udp",
        stream_id=stream_id, quic_payload=QUIC_PAYLOAD_STREAM, quic_midstream=midstream,
        library="libmonochrome_64.so")


def _request_urls(collector: FlowCollector) -> list:
    return [f.request.url for f in collector.get_flows()
            if f.request is not None and f.request.method == "GET"]


class TestCollectorMidstream:
    def _headers_event(self, midstream: bool) -> DatalogEvent:
        frame = h3_frame(FRAME_HEADERS, _dynamic_request_block(
            _huffman_line(b":path", b"/gen_204")))
        return _event(frame, 8, midstream)

    def test_midstream_flow_gets_request_line_immediately(self):
        collector = FlowCollector()
        collector.on_data(self._headers_event(midstream=True))
        assert _request_urls(collector) == ["/gen_204"]

    def test_non_midstream_flow_has_no_request_line_before_finalize(self):
        collector = FlowCollector()
        collector.on_data(self._headers_event(midstream=False))
        assert _request_urls(collector) == []

    def test_parser_is_marked_once_not_per_feed(self, monkeypatch):
        calls = []
        original = Http3Parser.mark_midstream

        def counting(parser):
            calls.append(parser)
            original(parser)

        monkeypatch.setattr(Http3Parser, "mark_midstream", counting)
        collector = FlowCollector()
        for i, sid in enumerate((8, 12, 16)):
            event = self._headers_event(midstream=True)
            event.stream_id, event.timestamp = sid, 1.0 + i
            collector.on_data(event)
        assert len(calls) == 1

    def test_encoder_stream_bytes_do_not_break_midstream(self):
        collector = FlowCollector()
        collector.on_data(self._headers_event(midstream=True))
        encoder = encode_varint(UNI_QPACK_ENCODER) + b"\x3f\xe1\x1f"
        collector.on_data(_event(encoder, 2, True, ts=1.1))
        assert _request_urls(collector) == ["/gen_204"]


def _route(**extra) -> list:
    bus = EventBus()
    seen: list[DatalogEvent] = []
    bus.subscribe(DatalogEvent, seen.append)
    payload = {"contentType": "datalog", "function": "QuicSession_WriteStreamData",
               "direction": "write", "src_addr": "10.0.0.1", "src_port": 5000,
               "dst_addr": "93.184.216.34", "dst_port": 443, "ss_family": "AF_INET",
               "stream_id": 0, "quic_payload": "stream", "transport": "udp"}
    payload.update(extra)
    MessageRouter(bus).route(payload, b"\x01\x02\x00\x00")
    return seen


class TestRouterPlumbing:
    def test_flag_is_forwarded(self):
        assert _route(quic_midstream=True)[0].quic_midstream is True

    def test_absent_flag_defaults_false(self):
        assert _route()[0].quic_midstream is False

    def test_non_bool_flag_is_ignored(self):
        assert _route(quic_midstream="true")[0].quic_midstream is False


def test_pylsqpack_static_decoder_api_used_by_recovery():
    # Recovery relies on Decoder(capacity, blocked).feed_header(sid, block).
    _control, headers = pylsqpack.Decoder(0, 0).feed_header(
        0, PREFIX_STATIC_ONLY + METHOD_GET)
    assert headers == [(b":method", b"GET")]


# --------------------------------------------------------------------------
# Late mark_midstream(): one result per stream, blocked blocks, re-marking
# --------------------------------------------------------------------------
def _late_marked_parser(path: bytes = b"/late") -> Http3Parser:
    """A parser whose stream-0 request block waited, then got marked."""
    parser = Http3Parser()
    frame = h3_frame(FRAME_HEADERS, _dynamic_request_block(
        _static_name_literal(STATIC_PATH, path)))
    assert parser.feed(frame, "write", stream_id=0) == []
    parser.mark_midstream()
    return parser


def _summary(results) -> list:
    return [(r.url, r.stream_id, r.is_complete) for r in results]


class TestLateMarkSingleResult:
    def test_flush_reports_each_stream_once(self):
        parser = _late_marked_parser()
        assert _summary(parser.flush()) == [("/late", 0, True)]

    def test_feed_data_reports_the_stream_once(self):
        parser = _late_marked_parser()
        results = parser.feed(h3_frame(FRAME_DATA, b"xy"), "write", stream_id=0)
        assert len(results) == 1
        assert (results[0].url, results[0].body_size) == ("/late", 2)

    def test_other_stream_keeps_queued_result(self):
        parser = _late_marked_parser()
        static = _request_block(PREFIX_STATIC_ONLY, METHOD_GET,
                                _static_name_literal(STATIC_PATH, b"/ok"))
        results = parser.feed(h3_frame(FRAME_HEADERS, static), "write", stream_id=4)
        assert [(r.url, r.stream_id) for r in results] == [("/late", 0), ("/ok", 4)]
        # Both are now plain active streams: flush reports each once
        assert [r.url for r in parser.flush()] == ["/late", "/ok"]

    def test_evicted_results_are_kept(self):
        parser = Http3Parser()
        parser._deferred_results.extend(
            Http3Parser._build_result(_stream(sid), is_complete=False) for sid in (0, 4))
        assert [r.stream_id for r in parser.flush()] == [0, 4]


def _stream(stream_id: int):
    from friTap.parsers.http3 import _H3StreamState
    stream = _H3StreamState(stream_id)
    stream.headers_received = True
    return stream


class TestStartMidstreamAfterConfigure:
    def test_blocked_block_is_resolved_at_once(self):
        ctx = _context()
        ctx.configure(4096, 16)
        block = _dynamic_request_block(_static_name_literal(STATIC_PATH, b"/b"))
        assert ctx.decode(0, block) is None and 0 in ctx.blocked
        assert ctx.start_midstream() == [0]
        assert ctx.waiting_stream_ids() == []
        assert dict(ctx.resume(0))[":path"] == "/b"

    def test_parser_returns_blocked_result_on_next_feed(self):
        parser = Http3Parser()
        parser.feed(h3_frame(FRAME_HEADERS, _dynamic_request_block(
            _static_name_literal(STATIC_PATH, b"/s"))), "write", stream_id=0)
        # Server SETTINGS (uni stream 3) configure the client encoder's context
        parser.feed(settings_stream(4096), "read", stream_id=3)
        assert (SIDE_CLIENT, 0) in parser._waiting_blocks
        parser.mark_midstream()
        results = parser.feed(b"", "write", stream_id=4)
        assert [r.url for r in results] == ["/s"]


class TestMidstreamMarkerIsWeak:
    def _conn(self, parser):
        return SimpleNamespace(parser=parser, quic_midstream_parser=None)

    def test_replaced_parser_is_marked_again(self):
        conn = self._conn(Http3Parser())
        QuicStreamFlowMixin._mark_parser_midstream(conn)
        assert QuicStreamFlowMixin._parser_marked_midstream(conn)
        conn.parser = Http3Parser()
        assert not QuicStreamFlowMixin._parser_marked_midstream(conn)
        QuicStreamFlowMixin._mark_parser_midstream(conn)
        assert conn.parser._midstream

    def test_marker_does_not_keep_parser_alive(self):
        conn = self._conn(Http3Parser())
        QuicStreamFlowMixin._mark_parser_midstream(conn)
        conn.parser = None
        gc.collect()
        assert conn.quic_midstream_parser() is None
