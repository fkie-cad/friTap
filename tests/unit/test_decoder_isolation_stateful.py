"""Decoder isolation, part 2: stateful decoders in the worker.

WebSocket permessage-deflate inflaters (``zlib_stream``) and QPACK decoders
(``qpack_decoder``) as worker contexts: equality with in-process decoding,
limits, hostile context replies, worker crashes mid-session, the context
cap, lifecycle (flush / garbage collection) and the default-off path.
"""

from __future__ import annotations

import gc
import logging
import struct
import zlib

import pytest

pylsqpack = pytest.importorskip("pylsqpack")

from friTap import decoder_isolation as di  # noqa: E402
from friTap.decoder_isolation import client, contexts  # noqa: E402
from friTap.decoder_isolation import protocol as P  # noqa: E402
from friTap.decoder_isolation.errors import (  # noqa: E402
    DecoderContextLost,
    HeaderListTooLarge,
)
from friTap.decoder_isolation.inflate_proxy import IsolatedInflater  # noqa: E402
from friTap.decoder_isolation.qpack_proxy import IsolatedQpackDecoder  # noqa: E402
from friTap.decoder_isolation.supervisor import (  # noqa: E402
    DecoderSupervisor,
    set_supervisor,
)
from friTap.parsers import websocket as ws  # noqa: E402
from friTap.parsers.decompress import InflateLimitError  # noqa: E402
from friTap.parsers.http3 import Http3Parser  # noqa: E402
from friTap.parsers.qpack_context import (  # noqa: E402
    ERROR_HEADER_LIST_TOO_LARGE,
    MAX_HEADER_LIST_BYTES,
    MAX_HEADER_LIST_COUNT,
    QpackDecoderContext,
)
from tests.unit._h3_helpers import (  # noqa: E402
    FRAME_HEADERS,
    UNI_QPACK_ENCODER,
    dynamic_exchange,
    h3_frame,
    settings_stream,
    uni_stream,
)

SERVER_CONTROL_SID = 3
CLIENT_ENCODER_SID = 6
FEED = client.ContextOp.FEED


# --- fixtures ---------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _isolation_off_by_default(monkeypatch, tmp_path):
    monkeypatch.delenv(di.ISOLATE_DECODERS_ENV, raising=False)
    monkeypatch.setenv("FRITAP_DECODER_QUARANTINE_DIR", str(tmp_path / "quarantine"))
    di.enable_decoder_isolation(None)
    previous = set_supervisor(None)
    yield
    di.enable_decoder_isolation(None)
    set_supervisor(previous)


@pytest.fixture(scope="module")
def shared_supervisor():
    sup = DecoderSupervisor(test_hooks=True)
    yield sup
    sup.shutdown()


@pytest.fixture
def isolated(shared_supervisor):
    """Isolation on, parsers routed through the shared test-hook worker."""
    set_supervisor(shared_supervisor)
    di.enable_decoder_isolation(True)
    return shared_supervisor


@pytest.fixture
def own_isolated():
    """Isolation on with a private (destructible) supervisor; ``make(**kw)``."""
    created = []

    def make(**kwargs):
        kwargs.setdefault("test_hooks", True)
        sup = DecoderSupervisor(**kwargs)
        created.append(sup)
        set_supervisor(sup)
        di.enable_decoder_isolation(True)
        return sup

    yield make
    for sup in created:
        sup.shutdown()


@pytest.fixture
def error_log():
    records: list[logging.LogRecord] = []

    class _Collect(logging.Handler):
        def emit(self, record):
            records.append(record)

    logger = logging.getLogger("friTap.decoder_isolation")
    handler = _Collect(level=logging.DEBUG)
    logger.addHandler(handler)
    yield records
    logger.removeHandler(handler)


def _with_isolation(enabled: bool, fn, *args):
    previous = di._override
    di.enable_decoder_isolation(enabled)
    try:
        return fn(*args)
    finally:
        di.enable_decoder_isolation(previous)


def _crash(sup):
    assert sup.request(P.Op.TEST_EXIT, arg0=1).kind == "crash"


# --- WebSocket helpers ------------------------------------------------------------

def _pmd_messages(messages, *, takeover=True):
    """permessage-deflate payloads (sync-flush tail stripped)."""
    comp = zlib.compressobj(wbits=-15)
    wire = []
    for message in messages:
        if not takeover:
            comp = zlib.compressobj(wbits=-15)
        wire.append((comp.compress(message) + comp.flush(zlib.Z_SYNC_FLUSH))[:-4])
    return wire


def _ws_frame(payload: bytes, *, compressed=True, opcode=0x1) -> bytes:
    """One unmasked FIN frame (server -> client)."""
    first = 0x80 | (0x40 if compressed else 0) | opcode
    if len(payload) < 126:
        return bytes((first, len(payload))) + payload
    if len(payload) < 1 << 16:
        return bytes((first, 126)) + struct.pack("!H", len(payload)) + payload
    return bytes((first, 127)) + struct.pack("!Q", len(payload)) + payload


def _deflate_outcomes(wire, **ctx_kwargs):
    ctx = ws._DeflateContext(**ctx_kwargs)
    return [(*ctx.decompress(w), ctx.last_error) for w in wire]


def _ws_results(stream: bytes):
    parser = ws.WebSocketParser()
    results = parser.feed(stream, "read") + parser.flush()
    return [(r.body, r.content_encoding, getattr(r, "error", ""), r.method) for r in results]


MESSAGES = [b'{"type":"hello","seq":%d,"payload":"%s"}' % (i, b"abc" * (i * 40))
            for i in range(8)]


# --- WebSocket: equality ----------------------------------------------------------

def test_context_takeover_stream_matches_in_process(isolated):
    wire = _pmd_messages(MESSAGES)
    expected = _with_isolation(False, _deflate_outcomes, wire)
    assert all(ok for _data, ok, _err in expected)
    assert _deflate_outcomes(wire) == expected


def test_no_takeover_and_corrupt_messages_match_in_process(isolated):
    wire = _pmd_messages(MESSAGES[:3], takeover=False)
    wire.insert(1, b"\xff\xfe corrupt deflate")
    wire += _pmd_messages(MESSAGES[3:5])
    expected = _with_isolation(False, _deflate_outcomes, wire)
    assert _deflate_outcomes(wire) == expected
    assert expected[1][2] == ws._ERR_INFLATE_FAILED


def test_websocket_parser_results_match_in_process(isolated):
    stream = b"".join(_ws_frame(w) for w in _pmd_messages(MESSAGES))
    stream += _ws_frame(b"plain", compressed=False)
    expected = _with_isolation(False, _ws_results, stream)
    assert _ws_results(stream) == expected
    assert sum(1 for r in expected if r[1] == "permessage-deflate") == len(MESSAGES)


def test_isolated_inflater_is_used(isolated):
    ctx = ws._DeflateContext()
    ctx.decompress(_pmd_messages([b"x" * 100])[0])
    assert isinstance(ctx._dec, IsolatedInflater) and ctx._dec.handle is not None


# --- WebSocket: limits ------------------------------------------------------------

def test_deflate_bomb_gives_limit(isolated):
    bomb = _pmd_messages([b"\0" * (8 << 20)])[0]
    inflater = IsolatedInflater(-15)
    with pytest.raises(InflateLimitError):
        inflater.inflate_bounded(bomb + ws._DEFLATE_TAIL, 1 << 20)
    assert inflater.closed and inflater.handle is None


def test_deflate_bomb_message_error_matches_in_process(isolated):
    bomb = b"\0" * (ws._MAX_MESSAGE_INFLATE + 4096)
    wire = _pmd_messages([bomb]) + _pmd_messages([b"ok after bomb"])
    expected = _with_isolation(False, _deflate_outcomes, wire)
    got = _deflate_outcomes(wire)
    assert got == expected
    assert got[0][1:] == (False, ws._ERR_INFLATE_TOO_LARGE)
    assert got[1][1] is True  # context dropped, next message starts fresh


def test_small_message_cap_through_worker(isolated):
    wire = _pmd_messages([b"a" * 5000])
    def run():
        return _deflate_outcomes(wire, max_message=1000)

    expected = _with_isolation(False, run)
    assert run() == expected
    assert expected[0][2] == ws._ERR_INFLATE_TOO_LARGE


def test_connection_budget_stays_in_parent(isolated):
    budget = ws._InflateBudget(total=150)
    wire = _pmd_messages([b"a" * 100, b"b" * 100])
    ctx = ws._DeflateContext(budget)
    assert ctx.decompress(wire[0])[1] is True
    assert ctx.decompress(wire[1]) == (wire[1], False)
    assert ctx.last_error == ws._ERR_INFLATE_BUDGET


# --- QPACK helpers ----------------------------------------------------------------

def _request(path: bytes) -> list:
    return [(b":method", b"GET"), (b":scheme", b"https"), (b":authority", b"example.com"),
            (b":path", path), (b"user-agent", b"test-agent/1.0"),
            (b"x-session", b"s" * 40)]


PATHS = {0: b"/a", 4: b"/b", 8: b"/c", 12: b"/d"}
FALLBACK = [(b"x-fallback", b"1")]


def _exchange():
    return dynamic_exchange(list(PATHS), {sid: _request(p) for sid, p in PATHS.items()})


def _qpack_session():
    """Static decode, blocked blocks, encoder inserts in two parts, resumes."""
    encoder, blocks = _exchange()
    ctx = QpackDecoderContext(fallback=lambda _block: FALLBACK)
    log = [("static", ctx.decode(0, blocks[0]))]
    log.append(("queued", ctx.decode(4, blocks[4])))
    log.append(("configure", ctx.configure(4096, 16)))
    log.append(("blocked", ctx.decode(8, blocks[8]), ctx.decode(12, blocks[12])))
    half = len(encoder) // 2
    for part in (encoder[:half], encoder[half:]):
        unblocked = ctx.feed_encoder(part)
        log.append(("unblocked", sorted(unblocked), [ctx.resume(s) for s in sorted(unblocked)]))
    log.append(("ready", ctx.resume(4)))
    log.append(("redecode", ctx.decode(16, blocks[12])))
    log.append(("state", ctx.poisoned, ctx.waiting_stream_ids(), dict(ctx.errors)))
    return log, ctx


def _h3_results():
    encoder, blocks = _exchange()
    parser = Http3Parser()
    feeds = [(settings_stream(4096), "read", SERVER_CONTROL_SID)]
    feeds += [(h3_frame(FRAME_HEADERS, blocks[sid]), "write", sid) for sid in PATHS]
    feeds.append((uni_stream(UNI_QPACK_ENCODER) + encoder, "write", CLIENT_ENCODER_SID))
    results = []
    for data, direction, sid in feeds:
        results += parser.feed(data, direction, stream_id=sid)
    results += parser.flush()
    return [(r.stream_id, r.method, r.url, r.host, r.is_complete) for r in results]


# --- QPACK: equality --------------------------------------------------------------

def test_qpack_dynamic_blocked_resumed_matches_in_process(isolated):
    expected, local = _with_isolation(False, _qpack_session)
    got, remote = _qpack_session()
    assert got == expected
    assert isinstance(remote.decoder, IsolatedQpackDecoder)
    assert not isinstance(local.decoder, IsolatedQpackDecoder)
    paths = [dict(h).get(b":path") for entry in got if entry[0] == "unblocked"
             for h in entry[2]]
    assert paths and None not in paths


def test_http3_parser_muxed_matches_in_process(isolated):
    expected = _with_isolation(False, _h3_results)
    assert _h3_results() == expected
    assert {url for _sid, _m, url, *_ in expected} >= {"/a", "/b", "/c", "/d"}


def test_http3_non_muxed_static_matches_in_process(isolated):
    from tests.unit._h3_helpers import headers_frame, qpack_encoder

    def run():
        parser = Http3Parser()
        encoder, _ = qpack_encoder()
        _ins, frame = headers_frame(encoder, 0, _request(b"/static"))
        results = parser.feed(frame, "write") + parser.flush()
        return [(r.method, r.url, r.host) for r in results]

    expected = _with_isolation(False, run)
    assert run() == expected and expected[0][1] == "/static"


def test_qpack_exception_types_preserved(isolated):
    encoder, blocks = _exchange()
    decoder = IsolatedQpackDecoder(4096, 16, max_count=MAX_HEADER_LIST_COUNT,
                                   max_bytes=MAX_HEADER_LIST_BYTES)
    with pytest.raises(pylsqpack.StreamBlocked):
        decoder.feed_header(8, blocks[8])
    assert decoder.feed_encoder(encoder) == [8]
    assert dict(decoder.resume_header(8)[1])[b":path"] == b"/c"
    with pytest.raises(pylsqpack.DecompressionFailed):
        decoder.feed_header(20, b"\x00\x00\xff\xff\xff\xff")
    with pytest.raises(pylsqpack.EncoderStreamError):
        IsolatedQpackDecoder(4096, 16, max_count=10, max_bytes=100).feed_encoder(
            b"\x3f\xff\xff\xff\xff\xff\xff\xff\xff\x7f")


def test_qpack_header_list_cap_withheld_by_worker(isolated):
    _enc, blocks = _exchange()
    decoder = IsolatedQpackDecoder(0, 0, max_count=3, max_bytes=MAX_HEADER_LIST_BYTES)
    with pytest.raises(HeaderListTooLarge):
        decoder.feed_header(0, blocks[0])
    assert decoder.handle is not None  # a withheld list does not kill the context
    small = IsolatedQpackDecoder(0, 0, max_count=10, max_bytes=20)
    with pytest.raises(HeaderListTooLarge):
        small.feed_header(0, blocks[0])


def test_qpack_header_list_cap_records_same_error(isolated, monkeypatch):
    from friTap.parsers import qpack_context as qc
    _enc, blocks = _exchange()

    def run():
        ctx = QpackDecoderContext(fallback=lambda _b: FALLBACK)
        return ctx.decode(0, blocks[0]), ctx.take_error(0)

    monkeypatch.setattr(qc, "MAX_HEADER_LIST_COUNT", 3)
    expected = _with_isolation(False, run)
    assert run() == expected == (FALLBACK, ERROR_HEADER_LIST_TOO_LARGE)


# --- hostile context replies ------------------------------------------------------

def _crafted(status: int, flags: int = 0, payload: bytes = b"") -> bytes:
    return struct.pack("!HH", status, flags) + payload


def _blob(data: bytes) -> bytes:
    return struct.pack("!I", len(data)) + data


HEADER_OP = client.ContextOp.QPACK_FEED_HEADER
RESUME_OP = client.ContextOp.QPACK_RESUME_HEADER
ENCODER_OP = client.ContextOp.QPACK_FEED_ENCODER
S = P.Status
BIG = b"v" * 131_100


@pytest.mark.parametrize("op,reply", [
    pytest.param(HEADER_OP, _crafted(S.OK, 0, struct.pack("!I", 513)), id="count-over-cap"),
    pytest.param(HEADER_OP, _crafted(S.OK, 0, struct.pack("!I", 1) + _blob(b"a")[:-1]
                                     + b"\x00\x00\x00\x09xx"), id="name-past-end"),
    pytest.param(HEADER_OP, _crafted(S.OK, 0, struct.pack("!I", 1) + _blob(b"a")
                                     + _blob(b"b") + b"!"), id="trailing-bytes"),
    pytest.param(HEADER_OP, _crafted(S.OK, 0, struct.pack("!I", 2) + _blob(b"n") + _blob(BIG)
                                     + _blob(b"n") + _blob(BIG)), id="total-over-cap"),
    pytest.param(HEADER_OP, _crafted(S.OK, 0, b"\x00\x00"), id="truncated-count"),
    pytest.param(HEADER_OP, _crafted(S.OK, 0, struct.pack("!I", 2) + _blob(b"a") + _blob(b"b")),
                 id="count-larger-than-fields"),
    pytest.param(HEADER_OP, _crafted(S.OK, 0x1, struct.pack("!I", 0)), id="flags-on-ok"),
    pytest.param(HEADER_OP, _crafted(S.LIMIT_ERROR, 0, b"junk"), id="data-on-limit"),
    pytest.param(HEADER_OP, _crafted(S.CONTEXT_ERROR, P.REPLY_QPACK_ENCODER_STREAM_ERROR),
                 id="encoder-flag-on-header-op"),
    pytest.param(RESUME_OP, _crafted(S.BLOCKED), id="blocked-on-resume"),
    pytest.param(ENCODER_OP, _crafted(S.OK, 0, struct.pack("!IQ", 2, 4)), id="id-list-short"),
    pytest.param(ENCODER_OP, _crafted(S.OK, 0, struct.pack("!I", 5000)), id="id-list-over-cap"),
    pytest.param(ENCODER_OP, _crafted(S.LIMIT_ERROR), id="limit-on-encoder-op"),
    pytest.param(ENCODER_OP, _crafted(0x77), id="junk-status"),
])
def test_malformed_qpack_reply_kills_worker(own_isolated, error_log, op, reply):
    sup = own_isolated()
    decoder = IsolatedQpackDecoder(0, 0, max_count=MAX_HEADER_LIST_COUNT,
                                   max_bytes=MAX_HEADER_LIST_BYTES)
    decoder.KIND = "test_reply"
    sup.request(P.Op.PING)
    first_pid = sup.pid
    with pytest.raises(DecoderContextLost):
        if op == ENCODER_OP:
            decoder._call(op, reply, 4 + 8 * 1024, validate=decoder._validator(op, []))
        else:
            decoder._header_call(op, reply)
    assert decoder.closed
    assert sup.pid is None, "the worker must be killed"
    assert any("invalid reply" in r.getMessage() or "oversized" in r.getMessage()
               for r in error_log)
    sup.request(P.Op.PING)
    assert sup.pid not in (None, first_pid)


def test_wellformed_crafted_header_list_is_accepted(own_isolated):
    own_isolated()
    decoder = IsolatedQpackDecoder(0, 0, max_count=4, max_bytes=100)
    decoder.KIND = "test_reply"
    payload = P.encode_header_list([(b":path", b"/x"), (b"a", b"")])
    assert decoder._header_call(HEADER_OP, _crafted(S.OK, 0, payload)) == [
        (b":path", b"/x"), (b"a", b"")]


def test_blocked_status_rejected_for_plain_kinds(own_isolated):
    sup = own_isolated()
    handle = client.create_context("test_reply", supervisor=sup).handle
    reply = client.call_context(handle, FEED, _crafted(S.BLOCKED), 100, supervisor=sup)
    assert reply.status is client.ContextStatus.WORKER_FAILED
    assert sup.pid is None


@pytest.mark.parametrize("data,cap", [
    (P.encode_header_list([(b"a", b"b")] * 3), 2),
    (P.encode_header_list([(b"a", b"b" * 50)]), 10),
])
def test_decode_header_list_caps(data, cap):
    with pytest.raises(P.ProtocolError):
        P.decode_header_list(data, cap, 10 if cap == 10 else 1000)


def test_header_list_roundtrip_and_wire_cap():
    headers = [(b"n" * 3, b"v" * 7)] * 4
    data = P.encode_header_list(headers)
    assert P.decode_header_list(data, 4, 40) == headers
    assert len(data) <= P.header_list_wire_cap(4, 40)
    assert P.decode_u64_list(P.encode_u64_list([0, 4, 2**62]), 3) == [0, 4, 2**62]


# --- worker crash mid-session -----------------------------------------------------

def test_worker_crash_disables_websocket_direction(own_isolated):
    sup = own_isolated()
    wire = _pmd_messages(MESSAGES[:4])
    parser = ws.WebSocketParser()
    first = parser.feed(_ws_frame(wire[0]), "read")
    assert first[0].content_encoding == "permessage-deflate"
    _crash(sup)
    lost = parser.feed(_ws_frame(wire[1]), "read")
    assert lost[0].error == ws._ERR_CONTEXT_LOST
    later = parser.feed(_ws_frame(wire[2]), "read")
    assert later[0].error == ws._ERR_CONTEXT_LOST, "history gone: stays disabled"
    assert parser._directions["read"].deflate._disabled
    # A new connection (parser) decodes normally on the restarted worker.
    fresh = ws.WebSocketParser().feed(_ws_frame(_pmd_messages([b"next stream"])[0]), "read")
    assert fresh[0].body == b"next stream" and not fresh[0].error


def test_crash_during_inflate_disables_direction(own_isolated, monkeypatch):
    own_isolated()
    ctx = ws._DeflateContext()
    wire = _pmd_messages(MESSAGES[:2])
    assert ctx.decompress(wire[0])[1]

    def failed(*_a, **_k):
        return client.ContextReply(client.ContextStatus.WORKER_FAILED, error="crashed")

    monkeypatch.setattr("friTap.decoder_isolation.contexts.call_context", failed)
    assert ctx.decompress(wire[1]) == (wire[1], False)
    assert ctx.last_error == ws._ERR_CONTEXT_LOST


def test_worker_crash_poisons_qpack_and_parser_continues(own_isolated):
    sup = own_isolated()
    encoder, blocks = _exchange()
    parser = Http3Parser()
    parser.feed(settings_stream(4096), "read", stream_id=SERVER_CONTROL_SID)
    first = parser.feed(h3_frame(FRAME_HEADERS, blocks[0]), "write", stream_id=0)
    assert first[0].url == "/a"
    parser.feed(h3_frame(FRAME_HEADERS, blocks[4]), "write", stream_id=4)  # blocked
    assert parser._qpack_ctx["client"].blocked
    _crash(sup)
    resumed = parser.feed(uni_stream(UNI_QPACK_ENCODER) + encoder, "write",
                          stream_id=CLIENT_ENCODER_SID)
    ctx = parser._qpack_ctx["client"]
    assert ctx.poisoned and not ctx.waiting_stream_ids()
    assert [r.stream_id for r in resumed] == [4]  # answered via the raw-scan fallback
    later = parser.feed(h3_frame(FRAME_HEADERS, blocks[8]), "write", stream_id=8)
    assert [r.stream_id for r in later] == [8]
    static = parser.feed(h3_frame(FRAME_HEADERS, blocks[0]), "write", stream_id=16)
    assert static[0].url == "/a", "static-only blocks still decode after the crash"


def test_qpack_crash_before_encoder_feed_poisons_on_decode(own_isolated):
    sup = own_isolated()
    encoder, blocks = _exchange()
    ctx = QpackDecoderContext(fallback=lambda _b: FALLBACK)
    ctx.configure(4096, 16)
    assert ctx.feed_encoder(encoder) == []
    _crash(sup)
    assert ctx.decode(8, blocks[8]) == FALLBACK
    assert ctx.poisoned


def test_non_muxed_decoder_recovers_after_crash(own_isolated):
    from tests.unit._h3_helpers import headers_frame, qpack_encoder
    sup = own_isolated()
    parser = Http3Parser()
    encoder, _ = qpack_encoder()

    def message(stream_id, path):
        _ins, frame = headers_frame(encoder, stream_id, _request(path))
        return parser.feed(frame, "write") + parser.flush()

    assert message(0, b"/one")[0].url == "/one"
    _crash(sup)
    assert message(4, b"/two")  # raw-scanned, decoder replaced
    assert message(8, b"/three")[0].url == "/three"


def test_old_handles_lost_after_restart(own_isolated):
    sup = own_isolated()
    inflater = IsolatedInflater(-15)
    inflater.inflate_bounded(_pmd_messages([b"x" * 50])[0] + ws._DEFLATE_TAIL, 1000)
    _crash(sup)
    sup.request(P.Op.PING)  # new generation is up
    with pytest.raises(DecoderContextLost, match="context lost"):
        inflater.inflate_bounded(b"\x00", 1000)
    assert inflater.closed


# --- context cap ------------------------------------------------------------------

def test_context_cap(own_isolated):
    sup = own_isolated(max_contexts=2)
    handles = [client.create_context("zlib_stream", P.pack_i64(-15), supervisor=sup).handle
               for _ in range(2)]
    over = client.create_context("zlib_stream", P.pack_i64(-15), supervisor=sup)
    assert over.status is client.ContextStatus.ERROR and "too many contexts" in over.error
    # Parsers fall back: WebSocket disabled, QPACK poisoned.
    ctx = ws._DeflateContext()
    wire = _pmd_messages([b"m"])[0]
    assert ctx.decompress(wire) == (wire, False) and ctx.last_error == ws._ERR_CONTEXT_LOST
    encoder, blocks = _exchange()
    qctx = QpackDecoderContext(fallback=lambda _b: FALLBACK)
    qctx.configure(4096, 16)
    qctx.feed_encoder(encoder)
    assert qctx.poisoned
    # Freeing a slot makes room again.
    client.destroy_context(handles[0], supervisor=sup)
    assert client.create_context("zlib_stream", P.pack_i64(-15), supervisor=sup).handle


def test_default_context_cap_is_4096():
    from friTap.decoder_isolation import worker_main
    assert worker_main.MAX_CONTEXTS == 4096


# --- lifecycle --------------------------------------------------------------------

def _handle_alive(sup, handle) -> bool:
    reply = client.call_context(handle, FEED, b"", 10, supervisor=sup)
    return reply.status is not client.ContextStatus.LOST


def test_websocket_flush_destroys_contexts(own_isolated):
    sup = own_isolated()
    parser = ws.WebSocketParser()
    parser.feed(_ws_frame(_pmd_messages([b"r" * 64])[0]), "read")
    handle = parser._directions["read"].deflate._dec.handle
    assert _handle_alive(sup, handle)
    parser.flush()
    assert parser._directions["read"].deflate._dec is None
    assert not _handle_alive(sup, handle)


def test_http3_flush_destroys_contexts(own_isolated):
    sup = own_isolated()
    encoder, blocks = _exchange()
    parser = Http3Parser()
    parser.feed(settings_stream(4096), "read", stream_id=SERVER_CONTROL_SID)
    parser.feed(uni_stream(UNI_QPACK_ENCODER) + encoder, "write", stream_id=CLIENT_ENCODER_SID)
    parser.feed(h3_frame(FRAME_HEADERS, blocks[8]), "write", stream_id=8)
    ctx = parser._qpack_ctx["client"]
    handle = ctx.decoder.handle
    assert handle is not None and _handle_alive(sup, handle)
    parser.flush()
    assert ctx.poisoned and ctx.decoder.closed
    assert not _handle_alive(sup, handle)


def test_garbage_collected_owner_is_destroyed(own_isolated):
    sup = own_isolated()
    gc.collect()
    contexts.drain_orphans()
    inflater = IsolatedInflater(-15)
    inflater.inflate_bounded(_pmd_messages([b"gc" * 20])[0] + ws._DEFLATE_TAIL, 1000)
    handle = inflater.handle
    del inflater
    gc.collect()
    assert contexts.drain_orphans() == 1
    assert not _handle_alive(sup, handle)


def test_orphans_drained_before_next_create(own_isolated):
    sup = own_isolated(max_contexts=1)
    inflater = IsolatedInflater(-15)
    inflater.inflate_bounded(_pmd_messages([b"a"])[0] + ws._DEFLATE_TAIL, 100)
    del inflater
    gc.collect()
    replacement = IsolatedInflater(-15)  # needs the only slot
    assert replacement.inflate_bounded(_pmd_messages([b"b"])[0] + ws._DEFLATE_TAIL, 100) == b"b"
    assert sup.pid is not None


def test_parser_construction_does_not_start_worker(own_isolated):
    sup = own_isolated()
    ws.WebSocketParser()
    Http3Parser()
    assert sup.pid is None


# --- default off ------------------------------------------------------------------

def test_default_off_uses_in_process_decoders(monkeypatch):
    def no_worker(*_a, **_k):
        raise AssertionError("worker used while isolation is off")

    monkeypatch.setattr("friTap.decoder_isolation.supervisor.get_supervisor", no_worker)
    monkeypatch.setattr(contexts, "get_supervisor", no_worker)
    ctx = ws._DeflateContext()
    assert ctx.decompress(_pmd_messages([b"local"])[0]) == (b"local", True)
    assert type(ctx._dec).__name__ == "Decompress"
    log, qctx = _qpack_session()
    assert isinstance(qctx.decoder, pylsqpack.Decoder)
    assert isinstance(qctx.static_decoder, pylsqpack.Decoder)
    parser = Http3Parser()
    assert isinstance(parser._qpack_decoder, pylsqpack.Decoder)
    parser.flush()
    assert not qctx.poisoned
    qctx.release()  # in-process: no-op
    assert not qctx.poisoned
    ws_parser = ws.WebSocketParser()
    ws_parser.feed(_ws_frame(_pmd_messages([b"one"])[0]), "read")
    dec = ws_parser._directions["read"].deflate._dec
    ws_parser.flush()
    assert ws_parser._directions["read"].deflate._dec is dec


# --- worker contents --------------------------------------------------------------

def test_qpack_kind_module_imports_no_fritap():
    import ast
    from pathlib import Path
    source = Path(di.__file__).resolve().parent / "qpack_kind.py"
    imported = set()
    for node in ast.walk(ast.parse(source.read_text())):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            assert node.level == 0, "relative import in a by-path worker module"
            imported.add((node.module or "").split(".")[0])
    assert imported <= {"struct", "pylsqpack"}


def test_worker_loads_qpack_kind_by_path(isolated):
    reply = isolated.request(P.Op.TEST_LIST_MODULES, max_reply=1 << 20)
    modules = set(reply.data.decode().split("\n"))
    assert {"_fritap_decoder_qpack", "pylsqpack"} <= modules
    assert not {m for m in modules if m == "friTap" or m.startswith("friTap.")}
