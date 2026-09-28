"""QpackDecoderContext: QPACK dynamic-table decoding for a passive observer.

Every header block and encoder-stream byte here is produced by the real
pylsqpack Encoder (via tests/unit/_h3_helpers.py).
"""

import pytest

pytest.importorskip("pylsqpack")

from friTap.events import DatalogEvent  # noqa: E402
from friTap.flow.collector import FlowCollector  # noqa: E402
from friTap.parsers import qpack_context  # noqa: E402
from friTap.parsers.qpack_context import (  # noqa: E402
    MAX_BLOCKED_BLOCKS,
    MAX_PENDING_ENCODER_BYTES,
    QpackDecoderContext,
    is_static_only_block,
)
from tests.unit._h3_helpers import (  # noqa: E402
    FRAME_HEADERS,
    UNI_QPACK_ENCODER,
    dynamic_exchange,
    h3_frame,
    settings_stream,
    uni_stream,
)


def _request(path: bytes) -> list:
    return [(b":method", b"GET"), (b":scheme", b"https"),
            (b":authority", b"example.com"), (b":path", path),
            (b"user-agent", b"test-agent/1.0")]


_PATHS = {0: b"/a", 4: b"/b", 8: b"/c"}
FALLBACK_MARK = [(b"x-fallback", b"1")]


def _exchange(capacity=4096):
    return dynamic_exchange(list(_PATHS), {sid: _request(p) for sid, p in _PATHS.items()},
                            capacity=capacity)


def _ctx(calls=None) -> QpackDecoderContext:
    def fallback(block):
        if calls is not None:
            calls.append(block)
        return FALLBACK_MARK
    return QpackDecoderContext(fallback=fallback)


def _path(headers) -> bytes:
    return dict(headers)[b":path"]


class TestBlockPrefix:
    def test_first_block_is_static_only_later_ones_are_dynamic(self):
        _enc, blocks = _exchange()
        assert is_static_only_block(blocks[0])
        assert not is_static_only_block(blocks[4])
        assert not is_static_only_block(blocks[8])

    def test_empty_block_is_not_static_only(self):
        assert not is_static_only_block(b"")


class TestOrderings:
    def test_settings_then_encoder_then_headers(self):
        encoder, blocks = _exchange()
        ctx = _ctx()
        assert ctx.configure(4096, 16) == []
        assert ctx.feed_encoder(encoder) == []
        assert [_path(ctx.decode(sid, blocks[sid])) for sid in (0, 4, 8)] == [b"/a", b"/b", b"/c"]

    def test_headers_before_encoder_block_then_resume(self):
        encoder, blocks = _exchange()
        ctx = _ctx()
        ctx.configure(4096, 16)
        assert ctx.decode(8, blocks[8]) is None
        assert ctx.feed_encoder(encoder) == [8]
        assert _path(ctx.resume(8)) == b"/c"
        assert ctx.waiting_stream_ids() == []

    def test_headers_before_settings_are_queued_until_configure(self):
        encoder, blocks = _exchange()
        ctx = _ctx()
        assert ctx.decode(4, blocks[4]) is None
        assert ctx.feed_encoder(encoder) == []  # buffered: capacity unknown
        assert ctx.configure(4096, 16) == [4]
        assert _path(ctx.resume(4)) == b"/b"

    def test_static_only_block_decodes_before_configure(self):
        _enc, blocks = _exchange()
        assert _path(_ctx().decode(0, blocks[0])) == b"/a"

    def test_second_configure_is_ignored(self):
        ctx = _ctx()
        ctx.configure(4096, 16)
        assert ctx.configure(0, 0) == [] and ctx.capacity == 4096

    def test_resume_of_unknown_stream_is_empty(self):
        assert _ctx().resume(12) == []


class TestFallbacks:
    def test_capacity_mismatch_falls_back_without_raising(self):
        encoder, blocks = _exchange(capacity=4096)
        calls = []
        ctx = _ctx(calls)
        assert ctx.decode(8, blocks[8]) is None
        ctx.feed_encoder(encoder)
        assert ctx.configure(1024, 16) == [8]  # set-capacity 4096 > 1024
        assert ctx.poisoned
        assert ctx.resume(8) == FALLBACK_MARK and calls == [blocks[8]]

    def test_capacity_zero_means_dynamic_table_disabled(self):
        encoder, blocks = _exchange()
        ctx = _ctx()
        ctx.configure(0, 0)
        ctx.feed_encoder(encoder)
        assert ctx.poisoned
        assert _path(ctx.decode(0, blocks[0])) == b"/a"
        assert ctx.decode(8, blocks[8]) == FALLBACK_MARK

    def test_truncated_encoder_stream_poisons_static_still_decodes(self):
        encoder, blocks = _exchange()
        ctx = _ctx()
        ctx.configure(4096, 16)
        ctx.feed_encoder(encoder[:1] + encoder[4:])
        assert ctx.poisoned
        assert _path(ctx.decode(0, blocks[0])) == b"/a"
        assert ctx.decode(8, blocks[8]) == FALLBACK_MARK
        assert ctx.feed_encoder(encoder) == []  # ignored once poisoned

    def test_poisoning_releases_blocked_streams_as_fallbacks(self):
        encoder, blocks = _exchange()
        ctx = _ctx()
        ctx.configure(4096, 16)
        assert ctx.decode(4, blocks[4]) is None
        assert ctx.feed_encoder(b"\xff" * 16) == [4]
        assert ctx.resume(4) == FALLBACK_MARK

    def test_duplicate_block_for_waiting_stream_falls_back(self):
        _enc, blocks = _exchange()
        ctx = _ctx()
        ctx.configure(4096, 16)
        assert ctx.decode(8, blocks[8]) is None
        assert ctx.decode(8, blocks[4]) == FALLBACK_MARK

    def test_drain_fallback_returns_raw_waiting_blocks(self):
        _enc, blocks = _exchange()
        ctx = _ctx()
        ctx.decode(4, blocks[4])       # queued (not configured)
        ctx.configure(4096, 16)        # fed -> blocked (no inserts)
        ctx.decode(8, blocks[8])
        assert ctx.drain_fallback() == {4: blocks[4], 8: blocks[8]}
        assert ctx.drain_fallback() == {}


class TestCaps:
    def test_pending_encoder_overflow_poisons(self):
        ctx = _ctx()
        ctx.feed_encoder(b"\x00" * MAX_PENDING_ENCODER_BYTES)
        assert not ctx.poisoned
        ctx.feed_encoder(b"\x00")
        assert ctx.poisoned and len(ctx.pending_encoder) == 0

    def test_waiting_blocks_are_capped(self):
        _enc, blocks = _exchange()
        ctx = _ctx()
        for index in range(MAX_BLOCKED_BLOCKS):
            assert ctx.decode(4 * (index + 10), blocks[8]) is None
        assert ctx.decode(4, blocks[4]) == FALLBACK_MARK
        assert len(ctx.waiting_stream_ids()) == MAX_BLOCKED_BLOCKS


class TestIndependentContexts:
    def test_request_and_response_contexts_use_their_own_capacity(self):
        req_enc, req_blocks = _exchange(capacity=4096)
        status = [(b":status", b"200"), (b"server", b"test-server"),
                  (b"content-type", b"text/html")]
        resp_enc, resp_blocks = dynamic_exchange([0, 4, 8], status, capacity=65536)
        client, server = _ctx(), _ctx()
        client.configure(4096, 16)
        server.configure(65536, 100)
        client.feed_encoder(req_enc)
        server.feed_encoder(resp_enc)
        assert _path(client.decode(8, req_blocks[8])) == b"/c"
        assert dict(server.decode(8, resp_blocks[8]))[b"server"] == b"test-server"
        assert not client.poisoned and not server.poisoned


class TestWithoutPylsqpack:
    def test_no_library_means_no_decoder_and_fallback(self, monkeypatch):
        monkeypatch.setattr(qpack_context, "pylsqpack", None)
        _enc, blocks = _exchange()
        ctx = _ctx()
        assert ctx.configure(4096, 16) == [] and not ctx.configured
        assert ctx.decode(0, blocks[0]) == FALLBACK_MARK


# ----------------------------------------------------------------------
# Collector level: an unblocked request lands on its own flow
# ----------------------------------------------------------------------

CLIENT_ENCODER_SID = 6
SERVER_CONTROL_SID = 3


def _event(data, stream_id, direction, ts):
    return DatalogEvent(
        timestamp=ts, data=data, function="quiche_stream_send", direction=direction,
        src_addr="10.0.0.1", src_port=5000, dst_addr="93.184.216.34", dst_port=443,
        ssl_session_id="quic-conn-q5", protocol="quic", transport="udp",
        stream_id=stream_id,
    )


def test_collector_routes_unblocked_request_to_its_own_flow():
    encoder, blocks = _exchange()
    collector = FlowCollector(show_control_frames=True)
    events = [
        _event(settings_stream(4096), SERVER_CONTROL_SID, "read", 1.0),
        _event(h3_frame(FRAME_HEADERS, blocks[0]), 0, "write", 1.1),
        _event(h3_frame(FRAME_HEADERS, blocks[4]), 4, "write", 1.2),   # blocked
        _event(h3_frame(FRAME_HEADERS, blocks[8]), 8, "write", 1.3),   # blocked
        _event(uni_stream(UNI_QPACK_ENCODER) + encoder, CLIENT_ENCODER_SID, "write", 1.4),
    ]
    for event in events:
        collector.on_data(event)
    requests = [f for f in collector.get_flows()
                if f.request is not None and not f.request.is_control_frame]
    by_url = {f.request.url: f for f in requests}
    assert sorted(by_url) == ["/a", "/b", "/c"]
    assert len(requests) == 3  # no placeholder duplicates
    for url, sid in (("/b", 4), ("/c", 8)):
        assert by_url[url].request.host == "example.com"
        assert {c.stream_id for c in by_url[url].chunks if c.data} == {sid}
