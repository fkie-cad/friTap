"""Hardening of the HTTP/3 + QPACK parsers against attacker-controlled input.

Covers the header-bomb bounds of QpackDecoderContext, the bounded frame
reader of Http3Parser (DATA counted not buffered, per-type frame caps,
unknown frames skipped), the per-connection state caps, strict integer
parsing and the static-only decoder of non-muxed mode.
"""

import tracemalloc

import pytest

pylsqpack = pytest.importorskip("pylsqpack")

from friTap.parsers import http3  # noqa: E402
from friTap.parsers.http3 import (  # noqa: E402
    ERROR_FRAME_TOO_LARGE,
    MAX_HEADERS_FRAME,
    Http3Parser,
    _FinishedStreams,
    _H3FrameReader,
    build_h3_result_from_headers,
    is_valid_status,
    parse_content_length,
)
from friTap.parsers.qpack_context import (  # noqa: E402
    ERROR_HEADER_BLOCK_MALFORMED,
    ERROR_HEADER_BLOCK_TOO_LARGE,
    ERROR_HEADER_LIST_TOO_LARGE,
    MAX_BLOCKED_BLOCKS,
    MAX_DECODE_EXPANSION,
    MAX_HEADER_BLOCK_SIZE,
    MAX_QPACK_TABLE_CAPACITY,
    QpackDecoderContext,
    block_within_budget,
    check_block,
    decoded_size_bound,
    decoder_blocked_streams,
    header_list_too_large,
)
from friTap.parsers.varint import encode_varint  # noqa: E402
from tests.unit._h3_helpers import (  # noqa: E402
    FRAME_DATA,
    FRAME_HEADERS,
    FRAME_SETTINGS,
    UNI_CONTROL,
    UNI_QPACK_ENCODER,
    h3_frame,
    headers_frame,
    qpack_encoder,
    settings_payload,
    settings_stream,
    uni_stream,
)

SERVER_CONTROL_SID = 3
CLIENT_CONTROL_SID = 2
CLIENT_ENCODER_SID = 6
GREASE_FRAME = 0x21
GREASE_UNI_TYPE = 0x21
MIB = 1024 * 1024

_REQUEST = [(b":method", b"GET"), (b":scheme", b"https"),
            (b":authority", b"example.com"), (b":path", b"/x")]
FALLBACK_MARK = [(b"x-fallback", b"1")]


def _ctx() -> QpackDecoderContext:
    return QpackDecoderContext(fallback=lambda _block: FALLBACK_MARK)


def _static_headers_frame(stream_id, headers):
    return headers_frame(qpack_encoder()[0], stream_id, headers)[1]


def _frame_header(frame_type: int, length: int) -> bytes:
    return encode_varint(frame_type) + encode_varint(length)


def _peak_during(func) -> int:
    """Peak traced Python allocation (bytes) while *func* runs."""
    tracemalloc.start()
    try:
        func()
        return tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()


def _prefix_int(value: int, prefix_bits: int, flags: int = 0) -> bytes:
    """RFC 7541 5.1 prefix integer, OR-ing *flags* into the first byte."""
    limit = (1 << prefix_bits) - 1
    if value < limit:
        return bytes([flags | value])
    out, value = [flags | limit], value - limit
    while value >= 128:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    return bytes(out + [value])


def _bomb(capacity=65536, value_size=60_000, refs=2000):
    """Hand-built QPACK bomb (pylsqpack's Encoder refuses such entries).

    Encoder bytes: Set Dynamic Table Capacity + one Insert With Literal Name
    of a *value_size* value. Block: Required Insert Count 1, Base 1, then
    *refs* one-byte indexed references to that entry (RFC 9204 4.3, 4.5).
    """
    name = b"x-bomb"
    encoder_bytes = (_prefix_int(capacity, 5, 0x20)
                     + _prefix_int(len(name), 5, 0x40) + name
                     + _prefix_int(value_size, 7) + b"A" * value_size)
    encoded_ric = 1 % (2 * (capacity // 32)) + 1
    block = _prefix_int(encoded_ric, 8) + b"\x00" + b"\x80" * refs
    return encoder_bytes, block


def _literal_field(name: bytes, value: bytes, huffman: bool = False) -> bytes:
    """Literal Field Line with Literal Name (RFC 9204 4.5.6)."""
    return (_prefix_int(len(name), 3, 0x20) + name
            + _prefix_int(len(value), 7, 0x80 if huffman else 0) + value)


def _cookie_heavy_block(cookie_bytes: int = 16 * 1024):
    """(encoder bytes, block): a ~16 KiB literal-heavy request block that also
    references one small dynamic entry (pylsqpack's Encoder cannot emit
    blocks this large, so the wire bytes are built by hand)."""
    encoder_bytes, _unused = _bomb(value_size=100, refs=0)
    fields = b"\x80" + _prefix_int(17, 6, 0xC0)  # dynamic ref + static :method GET
    for index in range(cookie_bytes // 2048):
        fields += _literal_field(b"cookie", (b"%04d" % index) * 512)
    return encoder_bytes, _prefix_int(2, 8) + b"\x00" + fields


# --------------------------------------------------------------------------
# QPACK header bomb
# --------------------------------------------------------------------------
class TestQpackCapacityClamp:
    @pytest.mark.parametrize("capacity", [2 ** 32, 2 ** 32 + 4096, MIB])
    def test_huge_capacity_poisons_without_decoder(self, capacity):
        ctx = _ctx()
        assert ctx.configure(capacity, 16) == []
        assert ctx.poisoned is True
        assert ctx.decoder is None

    def test_max_capacity_is_still_accepted(self):
        ctx = _ctx()
        ctx.configure(MAX_QPACK_TABLE_CAPACITY, 16)
        assert ctx.configured and not ctx.poisoned

    def test_poisoned_context_still_decodes_static_blocks(self):
        ctx = _ctx()
        ctx.configure(2 ** 32, 16)
        block = qpack_encoder()[0].encode(0, _REQUEST)[1]
        assert dict(ctx.decode(0, block))[b":path"] == b"/x"

    def test_queued_dynamic_block_falls_back_on_huge_capacity(self):
        encoder_bytes, block = _bomb(value_size=100, refs=2)
        ctx = _ctx()
        ctx.feed_encoder(encoder_bytes)
        assert ctx.decode(4, block) is None
        assert ctx.configure(2 ** 40, 16) == [4]
        assert ctx.resume(4) == FALLBACK_MARK

    @pytest.mark.parametrize("advertised", [0, 16, 2 ** 32 + 1, 2 ** 62 - 1])
    def test_blocked_streams_clamped(self, advertised):
        assert decoder_blocked_streams(advertised) == MAX_BLOCKED_BLOCKS
        ctx = _ctx()
        ctx.configure(4096, advertised)
        assert ctx.configured

    def test_parser_huge_settings_poisons_client_context(self):
        parser = Http3Parser()
        results = parser.feed(settings_stream(2 ** 32, 2 ** 40), "read",
                              stream_id=SERVER_CONTROL_SID)
        assert results[0].method == "SETTINGS"
        ctx = parser._qpack_ctx["client"]
        assert ctx.poisoned and ctx.decoder is None
        request = parser.feed(_static_headers_frame(0, _REQUEST), "write", stream_id=0)
        assert request[0].url == "/x"


class TestQpackBomb:
    def test_bomb_block_rejected_with_low_peak(self):
        encoder_bytes, block = _bomb()
        assert len(block) < 4096
        ctx = _ctx()
        ctx.configure(65536, 16)
        ctx.feed_encoder(encoder_bytes)
        decoded = []
        peak = _peak_during(lambda: decoded.append(ctx.decode(4, block)))
        assert decoded == [FALLBACK_MARK]
        assert ctx.take_error(4) == ERROR_HEADER_BLOCK_TOO_LARGE
        assert peak < 32 * MIB

    def test_parser_bomb_marks_error_and_stays_bounded(self):
        encoder_bytes, block = _bomb()
        parser = Http3Parser()
        parser.feed(settings_stream(65536), "read", stream_id=SERVER_CONTROL_SID)
        parser.feed(uni_stream(UNI_QPACK_ENCODER) + encoder_bytes, "write",
                    stream_id=CLIENT_ENCODER_SID)
        results = []
        peak = _peak_during(lambda: results.extend(
            parser.feed(h3_frame(FRAME_HEADERS, block), "write", stream_id=4)))
        assert peak < 32 * MIB
        assert results[0].error == ERROR_HEADER_BLOCK_TOO_LARGE

    def test_decoded_list_over_byte_cap_rejected(self):
        # 300 refs to a ~4000 byte entry: within the expansion budget, but the
        # decoded list (~1.2 MB) exceeds the 256 KiB header-list cap.
        encoder_bytes, block = _bomb(capacity=4096, value_size=4000, refs=300)
        assert block_within_budget(block, 4096)
        ctx = _ctx()
        ctx.configure(4096, 16)
        ctx.feed_encoder(encoder_bytes)
        assert ctx.decode(4, block) == FALLBACK_MARK
        assert ctx.take_error(4) == ERROR_HEADER_LIST_TOO_LARGE

    def test_decoded_list_over_count_cap_rejected(self):
        block = qpack_encoder()[0].encode(0, [(b"accept", b"*/*")] * 600)[1]
        ctx = _ctx()
        assert ctx.decode(0, block) == FALLBACK_MARK
        assert ctx.take_error(0) == ERROR_HEADER_LIST_TOO_LARGE

    def test_resumed_block_is_bounded_too(self):
        encoder_bytes, block = _bomb(capacity=4096, value_size=4000, refs=300)
        ctx = _ctx()
        ctx.configure(4096, 16)
        assert ctx.decode(4, block) is None  # blocked: inserts not seen yet
        assert ctx.feed_encoder(encoder_bytes) == [4]
        assert ctx.resume(4) == FALLBACK_MARK
        assert ctx.take_error(4) == ERROR_HEADER_LIST_TOO_LARGE

    def test_largest_admitted_bomb_is_capped_after_decoding(self):
        # 1000 refs x 64 KiB capacity sits just inside the expansion budget:
        # pylsqpack decodes it (transiently bounded by MAX_DECODE_EXPANSION),
        # then the header-list cap rejects the result.
        encoder_bytes, block = _bomb(refs=1000)
        assert block_within_budget(block, 65536)
        ctx = _ctx()
        ctx.configure(65536, 16)
        ctx.feed_encoder(encoder_bytes)
        assert ctx.decode(4, block) == FALLBACK_MARK
        assert ctx.take_error(4) == ERROR_HEADER_LIST_TOO_LARGE

    def test_block_over_absolute_cap_rejected(self):
        block = b"\x00\x00" + _literal_field(b"a", b"v" * MAX_HEADER_BLOCK_SIZE)
        assert check_block(block, 0) == ERROR_HEADER_BLOCK_TOO_LARGE

    def test_bound_counts_dynamic_refs_times_capacity(self):
        block = _bomb(refs=2000)[1]
        assert decoded_size_bound(block, 65536) == 2000 * 65536
        assert check_block(block, 65536) == ERROR_HEADER_BLOCK_TOO_LARGE
        assert check_block(_bomb(refs=1000)[1], 65536) == ""

    def test_bound_covers_every_representation(self):
        block = (b"\x02\x81"                                  # RIC, negative base
                 + _prefix_int(17, 6, 0xC0)                    # indexed static
                 + b"\x80"                                     # indexed dynamic
                 + b"\x10"                                     # indexed post-base
                 + _prefix_int(1, 4, 0x50) + b"\x03abc"         # name ref static
                 + _prefix_int(1, 4, 0x40) + b"\x02ab"          # name ref dynamic
                 + b"\x00" + b"\x01a"                           # post-base name ref
                 + _literal_field(b"nm", b"val", huffman=True))  # literal name
        assert decoded_size_bound(block, 1000) == (
            2 * 128 + 4 * 1000 + 3 + 2 + 1 + 2 + 3 * 2)

    def test_dynamic_refs_with_huge_entries_stay_within_budget_math(self):
        refs = MAX_DECODE_EXPANSION // 65536
        assert check_block(_bomb(refs=refs)[1], 65536) == ""
        assert check_block(_bomb(refs=refs + 1)[1], 65536) == ERROR_HEADER_BLOCK_TOO_LARGE

    @pytest.mark.parametrize("block", [
        b"",                                 # no prefix
        b"\x01",                             # truncated base
        b"\x01\x7f",                         # truncated base continuation
        b"\x00\x00" + b"\x2f",                # truncated literal name length
        b"\x00\x00" + _literal_field(b"n", b"value")[:-2],  # truncated string
        b"\x00\x00" + b"\xff" + b"\xff" * 12,  # integer too long
    ])
    def test_malformed_block_rejected(self, block):
        assert check_block(block, 4096) == ERROR_HEADER_BLOCK_MALFORMED
        assert not block_within_budget(block, 4096)

    def test_malformed_prefix_falls_back(self):
        ctx = _ctx()
        ctx.configure(4096, 16)
        assert ctx.decode(0, b"\x02\x7f") == FALLBACK_MARK
        assert ctx.take_error(0) == ERROR_HEADER_BLOCK_MALFORMED
        assert ctx.decode(4, b"\x00\x00\x2f") == FALLBACK_MARK  # static path
        assert ctx.take_error(4) == ERROR_HEADER_BLOCK_MALFORMED

    def test_cookie_heavy_block_decodes_with_large_table(self):
        encoder_bytes, block = _cookie_heavy_block()
        assert len(block) >= 16 * 1024
        ctx = _ctx()
        ctx.configure(65536, 16)
        ctx.feed_encoder(encoder_bytes)
        headers = ctx.decode(4, block)
        assert ctx.take_error(4) == ""
        assert [name for name, _ in headers].count(b"cookie") == 8
        assert dict(headers)[b":method"] == b"GET"

    def test_parser_decodes_cookie_heavy_request(self):
        encoder_bytes, block = _cookie_heavy_block()
        parser = Http3Parser()
        parser.feed(settings_stream(65536), "read", stream_id=SERVER_CONTROL_SID)
        parser.feed(uni_stream(UNI_QPACK_ENCODER) + encoder_bytes, "write",
                    stream_id=CLIENT_ENCODER_SID)
        result = parser.feed(h3_frame(FRAME_HEADERS, block), "write", stream_id=4)[0]
        assert result.error == "" and result.method == "GET"
        assert result.headers["x-bomb"] == "A" * 100
        assert len(result.headers["cookie"]) >= 8 * 2048  # all cookie fields kept

    def test_header_list_caps(self):
        assert not header_list_too_large([(b"a", b"b")] * 512)
        assert header_list_too_large([(b"a", b"b")] * 513)
        assert header_list_too_large([(b"a", b"x" * (256 * 1024))])

    def test_normal_dynamic_exchange_unaffected(self):
        encoder, encoder_bytes = qpack_encoder(4096, 16)
        blocks = {}
        for sid in (0, 4, 8):
            inserts, blocks[sid] = encoder.encode(sid, _REQUEST)
            encoder_bytes += inserts
        ctx = _ctx()
        ctx.configure(4096, 16)
        ctx.feed_encoder(encoder_bytes)
        assert dict(ctx.decode(8, blocks[8]))[b":path"] == b"/x"
        assert ctx.take_error(8) == ""


# --------------------------------------------------------------------------
# Bounded frame reader
# --------------------------------------------------------------------------
class TestFrameReader:
    def test_byte_by_byte_frames(self):
        data = h3_frame(FRAME_HEADERS, b"abc") + h3_frame(FRAME_DATA, b"xyz")
        reader = _H3FrameReader()
        events = [e for i in range(len(data)) for e in reader.feed(data[i:i + 1])]
        assert events[0] == (FRAME_HEADERS, b"abc", 3)
        assert sum(e.size for e in events if e.frame_type == FRAME_DATA) == 3

    def test_zero_length_data_event(self):
        events = _H3FrameReader().feed(h3_frame(FRAME_DATA, b""))
        assert [(e.frame_type, e.size) for e in events] == [(FRAME_DATA, 0)]

    def test_unknown_frame_skipped_without_buffering(self):
        reader = _H3FrameReader()
        data = h3_frame(GREASE_FRAME, b"G" * MIB) + h3_frame(FRAME_HEADERS, b"h")
        events = reader.feed(data)
        assert events == [(FRAME_HEADERS, b"h", 1)]
        assert len(reader.payload) == 0

    def test_unknown_frame_over_cap_is_error(self):
        reader = _H3FrameReader()
        reader.feed(_frame_header(GREASE_FRAME, http3._MAX_FRAME_LENGTH + 1))
        assert reader.error == ERROR_FRAME_TOO_LARGE

    def test_input_after_error_ignored(self):
        reader = _H3FrameReader()
        reader.feed(_frame_header(FRAME_SETTINGS, 5000))
        assert reader.feed(h3_frame(FRAME_HEADERS, b"x")) == []


class TestFrameLimits:
    def test_gigabyte_data_frame_counted_with_flat_memory(self):
        parser = Http3Parser()
        parser.feed(_static_headers_frame(0, _REQUEST), "write", stream_id=0)
        parser.feed(_frame_header(FRAME_DATA, 1 << 30), "write", stream_id=0)
        chunk = b"\x00" * (8 * MIB)

        def feed_chunks():
            for _ in range(4):
                parser.feed(chunk, "write", stream_id=0)

        peak = _peak_during(feed_chunks)
        assert peak < 2 * MIB
        assert parser._active_streams["write"][0].body_size == 32 * MIB

    def test_gigabyte_data_frame_non_muxed(self):
        parser = Http3Parser()
        parser.feed(_static_headers_frame(0, _REQUEST) + _frame_header(FRAME_DATA, 1 << 30),
                    "write")
        chunk = b"\x00" * (8 * MIB)
        peak = _peak_during(lambda: [parser.feed(chunk, "write") for _ in range(2)])
        assert peak < 2 * MIB
        assert parser.flush()[0].body_size == 16 * MIB

    def test_oversized_headers_frame_drops_stream(self):
        parser = Http3Parser()
        parser.feed(_static_headers_frame(0, _REQUEST), "write", stream_id=0)
        results = parser.feed(_frame_header(FRAME_HEADERS, MAX_HEADERS_FRAME + 1)
                              + b"\x00" * 1024, "write", stream_id=0)
        assert [(r.error, r.is_complete) for r in results] == [(ERROR_FRAME_TOO_LARGE, False)]
        assert 0 in parser._finished_streams
        assert parser.feed(b"\x00" * 1024, "write", stream_id=0) == []
        assert "write:0" not in parser._buffers

    def test_headers_at_cap_is_still_buffered(self):
        reader = _H3FrameReader()
        events = reader.feed(h3_frame(FRAME_HEADERS, b"\x00" * MAX_HEADERS_FRAME))
        assert events[0].size == MAX_HEADERS_FRAME and not reader.error

    def test_oversized_settings_ignored_on_control_stream(self):
        parser = Http3Parser()
        data = uni_stream(UNI_CONTROL) + _frame_header(FRAME_SETTINGS, 5000)
        assert parser.feed(data + b"\x00" * 5000, "read", stream_id=SERVER_CONTROL_SID) == []
        assert "server" not in parser._peer_settings

    def test_control_stream_skips_unknown_frames(self):
        parser = Http3Parser()
        data = (uni_stream(UNI_CONTROL) + h3_frame(GREASE_FRAME, b"g" * 10000)
                + h3_frame(FRAME_SETTINGS, settings_payload({0x01: 4096})))
        results = parser.feed(data, "read", stream_id=SERVER_CONTROL_SID)
        assert [r.method for r in results] == ["SETTINGS"]

    def test_oversized_frame_non_muxed_reports_current_message(self):
        parser = Http3Parser()
        parser.feed(_static_headers_frame(0, _REQUEST), "write")
        results = parser.feed(_frame_header(FRAME_HEADERS, MAX_HEADERS_FRAME + 1), "write")
        assert [r.error for r in results] == [ERROR_FRAME_TOO_LARGE]
        assert parser.feed(_static_headers_frame(0, _REQUEST), "write") == []


# --------------------------------------------------------------------------
# Per-connection state caps
# --------------------------------------------------------------------------
class TestStateCaps:
    def test_active_streams_lru_cap(self, monkeypatch):
        monkeypatch.setattr(http3, "MAX_ACTIVE_STREAMS", 8)
        parser = Http3Parser()
        results = []
        for sid in range(0, 4 * 20, 4):
            results += parser.feed(_static_headers_frame(sid, _REQUEST), "write", stream_id=sid)
        assert len(parser._active_streams["write"]) <= 8
        evicted = [r for r in results if not r.is_complete]
        assert [r.stream_id for r in evicted] == list(range(0, 4 * 12, 4))
        assert parser.feed(h3_frame(FRAME_DATA, b"late"), "write", stream_id=0) == []

    def test_recently_used_stream_survives(self, monkeypatch):
        monkeypatch.setattr(http3, "MAX_ACTIVE_STREAMS", 4)
        parser = Http3Parser()
        parser.feed(_static_headers_frame(0, _REQUEST), "write", stream_id=0)
        for sid in (4, 8, 12, 16, 20):
            parser.feed(h3_frame(FRAME_DATA, b"x"), "write", stream_id=0)  # touch 0
            parser.feed(_static_headers_frame(sid, _REQUEST), "write", stream_id=sid)
        assert 0 in parser._active_streams["write"]

    def test_default_cap_bounds_many_streams(self):
        parser = Http3Parser()
        for sid in range(0, 4 * 1500, 4):
            parser.feed(_static_headers_frame(sid, _REQUEST), "write", stream_id=sid)
        assert len(parser._active_streams["write"]) <= http3.MAX_ACTIVE_STREAMS
        assert len(parser._buffers) <= http3.MAX_FRAME_READERS

    def test_frame_readers_capped(self, monkeypatch):
        monkeypatch.setattr(http3, "MAX_FRAME_READERS", 4)
        parser = Http3Parser()
        for sid in range(0, 4 * 10, 4):
            parser.feed(b"\x01", "write", stream_id=sid)  # partial frame header
        assert len(parser._buffers) <= 4
        assert 0 in parser._finished_streams

    def test_uni_streams_capped_and_control_kept(self, monkeypatch):
        monkeypatch.setattr(http3, "MAX_UNI_STREAMS", 4)
        parser = Http3Parser()
        parser.feed(settings_stream(4096), "write", stream_id=CLIENT_CONTROL_SID)
        for sid in range(6, 6 + 4 * 20, 4):
            parser.feed(uni_stream(GREASE_UNI_TYPE) + b"junk", "write", stream_id=sid)
        assert len(parser._uni_streams) <= 4
        assert CLIENT_CONTROL_SID in parser._uni_streams
        # An evicted grease stream is not re-typed by its later bytes
        assert parser.feed(uni_stream(UNI_QPACK_ENCODER), "write", stream_id=6) == []
        assert parser.stream_kind(6) == "unknown"

    def test_finished_streams_bounded(self):
        finished = _FinishedStreams(cap=16)
        for sid in range(0, 4 * 100, 4):
            finished.add(sid)
        assert len(finished) == 16
        assert 0 in finished and 396 in finished
        assert 400 not in finished
        assert 1 not in finished  # other stream type unaffected

    def test_live_stream_not_retired_by_floor(self):
        parser = Http3Parser()
        parser._finished_streams = _FinishedStreams(cap=2)
        parser.feed(_static_headers_frame(0, _REQUEST), "write", stream_id=0)
        for sid in (4, 8, 12, 16):
            parser.feed(_static_headers_frame(sid, [(b":status", b"204")]), "read",
                        stream_id=sid)
        assert 0 in parser._finished_streams  # below the floor ...
        parser.feed(h3_frame(FRAME_DATA, b"abc"), "write", stream_id=0)
        assert parser._active_streams["write"][0].body_size == 3  # ... but live

    def test_finish_set_does_not_grow_forever(self):
        parser = Http3Parser()
        for sid in range(0, 4 * (http3.MAX_FINISHED_STREAMS + 50), 4):
            parser.feed(_static_headers_frame(sid, [(b":status", b"204")]), "read",
                        stream_id=sid)
        assert len(parser._finished_streams) == http3.MAX_FINISHED_STREAMS

    def test_encoder_bytes_not_retained(self):
        parser = Http3Parser()
        parser.feed(uni_stream(UNI_QPACK_ENCODER) + b"\x3f\xe1\x1f" * 1000, "write",
                    stream_id=CLIENT_ENCODER_SID)
        assert len(parser._encoder_bytes["client"]) == 0


# --------------------------------------------------------------------------
# Strict integers
# --------------------------------------------------------------------------
class TestStrictIntegers:
    @pytest.mark.parametrize("value,expected", [
        ("0", 0), ("123", 123), (" 42 ", 42), (None, None),
        ("+5", None), ("-1", None), ("1_000", None), ("", None),
        ("0x10", None), ("١٢", None), ("1 2", None),
    ])
    def test_parse_content_length(self, value, expected):
        assert parse_content_length(value) == expected

    @pytest.mark.parametrize("value,ok", [
        ("200", True), ("101", True), ("20", False), ("2000", False),
        ("+20", False), ("-20", False), (" 200", False), ("2_0", False),
        ("٢٠٠", False),
    ])
    def test_is_valid_status(self, value, ok):
        assert is_valid_status(value) is ok

    @pytest.mark.parametrize("status", [b"+20", b" 200", b"2000", b"-200"])
    def test_invalid_status_not_applied(self, status):
        results = Http3Parser().feed(_static_headers_frame(0, [(b":status", status)]),
                                     "read", stream_id=0)
        assert results[0].status_code == 0

    def test_signed_content_length_does_not_complete_response(self):
        frame = _static_headers_frame(0, [(b":status", b"200"), (b"content-length", b"+0")])
        assert Http3Parser().feed(frame, "read", stream_id=0)[0].is_complete is False

    def test_valid_content_length_completes_response(self):
        frame = _static_headers_frame(0, [(b":status", b"200"), (b"content-length", b"0")])
        assert Http3Parser().feed(frame, "read", stream_id=0)[0].is_complete is True

    def test_app_api_builder_rejects_padded_status(self):
        result = build_h3_result_from_headers([[":status", " 200"]], 3, "read")
        assert result.status_code == 0


# --------------------------------------------------------------------------
# Non-muxed mode: static-table-only decoder
# --------------------------------------------------------------------------
class TestNonMuxedStaticDecoder:
    def test_static_request_decodes(self):
        results = Http3Parser().feed(_static_headers_frame(0, _REQUEST), "write")
        assert results == [] or results[0].method == "GET"

    def test_static_request_and_response_decode(self):
        parser = Http3Parser()
        parser.feed(_static_headers_frame(0, _REQUEST), "write")
        parser.feed(_static_headers_frame(0, [(b":status", b"200")]), "read")
        by_dir = {r.is_request: r for r in parser.flush()}
        assert by_dir[True].url == "/x" and by_dir[False].status_code == 200

    def test_dynamic_block_falls_back_and_decoder_recovers(self):
        encoder, _pre = qpack_encoder(4096, 16)
        for sid in (0, 4):
            encoder.encode(sid, _REQUEST)
        dynamic = h3_frame(FRAME_HEADERS, encoder.encode(8, _REQUEST)[1])
        parser = Http3Parser()
        parser.feed(dynamic, "write")
        parser.feed(_static_headers_frame(0, _REQUEST), "write")  # second message
        results = parser.flush()
        assert results[-1].url == "/x"

    def test_malformed_static_block_raw_scanned_with_error(self):
        # ':' parses as a literal name whose value length runs past the end
        parser = Http3Parser()
        block = b"\x00\x00" + b":path/big"
        parser.feed(h3_frame(FRAME_HEADERS, block), "write")
        result = parser.flush()[0]
        assert result.error == ERROR_HEADER_BLOCK_MALFORMED
        assert result.url == "/big"

    def test_headers_frame_over_block_cap_dropped_before_decoding(self):
        parser = Http3Parser()
        block = b"\x00\x00" + b"\x00" * MAX_HEADER_BLOCK_SIZE
        parser.feed(h3_frame(FRAME_HEADERS, block), "write")
        assert parser.flush() == []
