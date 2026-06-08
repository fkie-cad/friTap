#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Synthetic, hermetic HTTP/2 HPACK tests for friTap's frame parser.

These tests use the ``hpack`` library to *encode* real HTTP/2 frames and feed
them through :class:`Http2Parser` directly — no tshark, no capture, no network.
They pin the regression where response ``:status`` decoded as ``0`` because the
server->client HPACK dynamic table desynced:

* dynamic-table-indexed ``:status`` must decode (the headline regression);
* a PUSH_PROMISE block must be fed to the decoder so later responses that
  reference the entry it inserts still decode (with a "teeth" assertion that the
  same response fails when PUSH_PROMISE is skipped);
* a genuinely corrupt block must *poison* the direction and surface
  ``error == "hpack-desync"`` rather than fabricate a real-looking status 0;
* trailers (a second HEADERS after the body) must still decode.
"""

from __future__ import annotations

import struct

import pytest

from friTap.parsers.http2 import Http2Parser, _hpack_available

pytestmark = pytest.mark.skipif(
    not _hpack_available, reason="hpack library not installed"
)

# Frame types / flags (mirrors friTap.parsers.http2 wire constants).
_DATA, _HEADERS, _PUSH_PROMISE, _CONTINUATION = 0x00, 0x01, 0x05, 0x09
_END_STREAM, _END_HEADERS = 0x01, 0x04


def _frame(ftype: int, flags: int, stream_id: int, payload: bytes) -> bytes:
    """Build a 9-byte-header HTTP/2 frame."""
    return (struct.pack("!I", len(payload))[1:]  # 24-bit length
            + bytes([ftype, flags])
            + struct.pack("!I", stream_id)
            + payload)


def _encoder():
    from hpack import Encoder
    return Encoder()


def _final(results):
    """Return the single completed ParseResult from a feed() call."""
    completed = [r for r in results if r.is_complete]
    assert len(completed) == 1, f"expected one completed result, got {results}"
    return completed[0]


def test_request_headers_decode():
    parser = Http2Parser()
    enc = _encoder()
    block = enc.encode([(":method", "GET"), (":path", "/"),
                        (":authority", "example.com")])
    result = _final(parser.feed(
        _frame(_HEADERS, _END_HEADERS | _END_STREAM, 1, block), "write"
    ))
    assert result.method == "GET"
    assert result.url == "/"
    assert result.host == "example.com"
    assert result.error == ""


def test_response_status_uses_dynamic_table_index():
    """The headline regression: a :status carried by a dynamic-table reference
    must decode to the real status, not 0."""
    parser = Http2Parser()
    # Prime the request direction (separate HPACK context).
    parser.feed(_frame(_HEADERS, _END_HEADERS | _END_STREAM, 1,
                       _encoder().encode([(":method", "GET"), (":path", "/")])),
                "write")

    enc_r = _encoder()
    # First response inserts :status 200 into the read dynamic table.
    r1 = _final(parser.feed(_frame(
        _HEADERS, _END_HEADERS | _END_STREAM, 1,
        enc_r.encode([(":status", "200"), ("content-type", "text/html")]),
    ), "read"))
    assert r1.status_code == 200
    assert r1.error == ""

    # Second response references the now-indexed :status 200 entry.
    r2 = _final(parser.feed(_frame(
        _HEADERS, _END_HEADERS | _END_STREAM, 3,
        enc_r.encode([(":status", "200")]),
    ), "read"))
    assert r2.status_code == 200, "dynamic-table-indexed :status failed to decode"
    assert r2.error == ""


def test_push_promise_keeps_dynamic_table_in_sync():
    """A PUSH_PROMISE block mutates the read dynamic table. Feeding it keeps a
    later response that references the inserted entry decodable."""
    parser = Http2Parser()
    enc_r = _encoder()

    # PUSH_PROMISE (read direction) inserts x-custom into the dynamic table.
    pp_block = enc_r.encode([(":method", "GET"), (":path", "/push"),
                            ("x-custom", "pushed-value")])
    pp_payload = struct.pack("!I", 2) + pp_block  # promised stream id = 2
    parser.feed(_frame(_PUSH_PROMISE, _END_HEADERS, 1, pp_payload), "read")

    # Response references the PUSH_PROMISE-inserted x-custom entry.
    resp = enc_r.encode([(":status", "200"), ("x-custom", "pushed-value")])
    result = _final(parser.feed(
        _frame(_HEADERS, _END_HEADERS | _END_STREAM, 1, resp), "read"
    ))
    assert result.status_code == 200
    assert result.headers.get("x-custom") == "pushed-value"
    assert result.error == ""


def test_skipping_push_promise_desyncs_the_decoder():
    """Teeth for the fix: a parser that never sees the PUSH_PROMISE frame is
    missing the dynamic-table entry, so the same response desyncs."""
    enc_r = _encoder()
    # Encoder side still inserts x-custom (mirrors a real server that sent PP).
    enc_r.encode([(":method", "GET"), (":path", "/push"),
                  ("x-custom", "pushed-value")])
    resp = enc_r.encode([(":status", "200"), ("x-custom", "pushed-value")])

    parser = Http2Parser()  # PUSH_PROMISE deliberately NOT fed
    result = _final(parser.feed(
        _frame(_HEADERS, _END_HEADERS | _END_STREAM, 1, resp), "read"
    ))
    # Without the table entry the decode cannot reproduce status 200; it either
    # poisons (error set) or yields a wrong value — never a clean 200.
    assert not (result.status_code == 200 and result.error == ""), \
        "response decoded cleanly without the PUSH_PROMISE — test has no teeth"


def test_corrupt_block_poisons_without_fabricating_status():
    """A corrupt header block must set error and never present status 0 as real."""
    parser = Http2Parser()
    corrupt = bytes([0xFF, 0xFF, 0xFF, 0xFF])  # invalid HPACK integer
    result = _final(parser.feed(
        _frame(_HEADERS, _END_HEADERS | _END_STREAM, 1, corrupt), "read"
    ))
    assert result.error == "hpack-desync"
    assert result.status_code == 0  # leftover default — error tells consumers it's not real


def test_poison_is_terminal_for_the_direction():
    """Once poisoned, later responses on that direction also report the error
    rather than silently emitting status 0 as if decoded."""
    parser = Http2Parser()
    parser.feed(_frame(_HEADERS, _END_HEADERS | _END_STREAM, 1,
                       bytes([0xFF, 0xFF, 0xFF, 0xFF])), "read")

    # A perfectly valid block now arrives, but the decoder is already poisoned.
    valid = _encoder().encode([(":status", "200")])
    result = _final(parser.feed(
        _frame(_HEADERS, _END_HEADERS | _END_STREAM, 3, valid), "read"
    ))
    assert result.error == "hpack-desync"
    assert result.status_code == 0


def test_trailers_after_body_still_decode():
    """A second HEADERS (trailers) after DATA must feed the decoder and apply."""
    parser = Http2Parser()
    enc_r = _encoder()

    # Response headers (no END_STREAM yet).
    parser.feed(_frame(_HEADERS, _END_HEADERS, 1,
                       enc_r.encode([(":status", "200")])), "read")
    # A DATA frame for the body.
    parser.feed(_frame(_DATA, 0x00, 1, b"hello"), "read")
    # Trailers: a final HEADERS carrying a trailer, with END_STREAM.
    trailer = enc_r.encode([("grpc-status", "0")])
    result = _final(parser.feed(
        _frame(_HEADERS, _END_HEADERS | _END_STREAM, 1, trailer), "read"
    ))
    assert result.headers.get("grpc-status") == "0"
    assert result.error == ""


def test_push_promise_spanning_continuation():
    """A PUSH_PROMISE split across a CONTINUATION frame must still sync the table."""
    parser = Http2Parser()
    enc_r = _encoder()

    pp_block = enc_r.encode([(":method", "GET"), (":path", "/push"),
                            ("x-split", "split-value")])
    pp_payload = struct.pack("!I", 2) + pp_block
    half = len(pp_payload) // 2
    # PUSH_PROMISE without END_HEADERS, remainder via CONTINUATION.
    parser.feed(_frame(_PUSH_PROMISE, 0x00, 1, pp_payload[:half]), "read")
    parser.feed(_frame(_CONTINUATION, _END_HEADERS, 1, pp_payload[half:]), "read")

    resp = enc_r.encode([(":status", "200"), ("x-split", "split-value")])
    result = _final(parser.feed(
        _frame(_HEADERS, _END_HEADERS | _END_STREAM, 1, resp), "read"
    ))
    assert result.status_code == 200
    assert result.headers.get("x-split") == "split-value"
    assert result.error == ""


# --- PUSH_PROMISE / CONTINUATION isolation regressions (#15/#16/#39/#45/#51/#57) ---

_PRIORITY, _PADDED = 0x20, 0x08
from friTap.parsers.http2 import Http2Parser as _H2  # noqa: E402


def test_push_promise_with_end_stream_does_not_close_parent():
    """#15: a (malformed) PUSH_PROMISE carrying END_STREAM must NOT finalize or
    close the parent request stream. The parent stays open for its real HEADERS.
    """
    parser = Http2Parser()
    enc_r = _encoder()

    # Server pushes on parent stream 1, but the frame bogusly also sets
    # END_STREAM. The parent must not be completed by this.
    pp_block = enc_r.encode([(":method", "GET"), (":path", "/push"),
                            ("x-pp", "v")])
    pp_payload = struct.pack("!I", 2) + pp_block
    results = parser.feed(
        _frame(_PUSH_PROMISE, _END_HEADERS | _END_STREAM, 1, pp_payload), "read"
    )
    assert [r for r in results if r.is_complete] == [], \
        "PUSH_PROMISE with END_STREAM wrongly finalized the parent stream"

    # The real response for stream 1 still arrives and completes normally.
    resp = enc_r.encode([(":status", "200")])
    final = _final(parser.feed(
        _frame(_HEADERS, _END_HEADERS | _END_STREAM, 1, resp), "read"
    ))
    assert final.status_code == 200
    assert final.error == ""


def test_push_promise_hpack_failure_leaves_parent_intact():
    """#16: a PUSH_PROMISE whose HPACK block fails to decode must NOT stamp
    error on the parent stream nor disturb its already-decoded headers."""
    parser = Http2Parser()
    enc_r = _encoder()

    # A valid response for stream 1 (no END_STREAM yet) — parent is decodable.
    parser.feed(_frame(_HEADERS, _END_HEADERS, 1,
                       enc_r.encode([(":status", "200")])), "read")

    # A corrupt PUSH_PROMISE block on the same stream. Promised id (4 bytes)
    # then an invalid HPACK integer.
    corrupt_pp = struct.pack("!I", 2) + bytes([0xFF, 0xFF, 0xFF, 0xFF])
    results = parser.feed(
        _frame(_PUSH_PROMISE, _END_HEADERS, 1, corrupt_pp), "read"
    )
    # The push failure must not produce a completed parent result here.
    assert [r for r in results if r.is_complete] == []

    # Finish the parent with body + END_STREAM (DATA, never a push frame).
    final = _final(parser.feed(_frame(_DATA, _END_STREAM, 1, b"hi"), "read"))
    assert final.error == "", \
        "parent stream wrongly stamped with the push-promise's hpack error"
    assert final.status_code == 200
    assert final.body_size == 2


def test_push_promise_does_not_corrupt_half_buffered_real_headers():
    """#45: PUSH_PROMISE fragments must use a separate buffer and never bleed
    into a concurrently half-buffered real HEADERS block on the same stream."""
    parser = Http2Parser()
    enc_r = _encoder()

    # Start a real HEADERS block on stream 1 WITHOUT END_HEADERS (half buffered).
    real = enc_r.encode([(":status", "200"), ("x-real", "real-value")])
    half = len(real) // 2
    parser.feed(_frame(_HEADERS, 0x00, 1, real[:half]), "read")  # no END_HEADERS

    # A complete PUSH_PROMISE arrives on the same stream in between.
    pp_block = enc_r.encode([(":method", "GET"), (":path", "/p")])
    pp_payload = struct.pack("!I", 2) + pp_block
    parser.feed(_frame(_PUSH_PROMISE, _END_HEADERS, 1, pp_payload), "read")

    # Now complete the real HEADERS via CONTINUATION. If the PP bytes had been
    # appended to the shared buffer, this decode would be corrupt.
    final = _final(parser.feed(
        _frame(_CONTINUATION, _END_HEADERS | _END_STREAM, 1, real[half:]), "read"
    ))
    assert final.status_code == 200
    assert final.headers.get("x-real") == "real-value"
    assert final.error == ""


def test_stray_continuation_is_a_protocol_error():
    """#39: a CONTINUATION on a stream that is NOT awaiting one must be flagged
    as a protocol error, not silently appended."""
    parser = Http2Parser()
    enc_r = _encoder()
    block = enc_r.encode([(":status", "200")])
    # CONTINUATION arrives with no prior unfinished HEADERS/PUSH_PROMISE. It must
    # NOT silently complete a stream; the stream is flagged as a protocol error
    # (and, since END_STREAM on a stray CONTINUATION is not honored, it stays
    # open rather than being finalized as if it were valid).
    feed_results = parser.feed(
        _frame(_CONTINUATION, _END_HEADERS | _END_STREAM, 1, block), "read"
    )
    assert [r for r in feed_results if r.is_complete] == [], \
        "stray CONTINUATION wrongly finalized a stream"
    flushed = parser.flush()
    assert len(flushed) == 1
    assert flushed[0].error == "protocol-error", \
        "stray CONTINUATION was handled silently instead of as a protocol error"


def test_strip_padded_frame_rejects_padding_ge_remaining():
    """#57: the shared padding-strip helper rejects padding >= remaining payload
    consistently for BOTH HEADERS and PUSH_PROMISE prefix lengths."""
    # HEADERS layout: [pad_len=0xFF][priority 5][fragment...]; pad consumes all.
    headers_payload = bytes([0xFF]) + b"\x00" * 5 + b"\x10\x20"
    assert _H2._strip_padded_frame(
        headers_payload, _PADDED | _PRIORITY, _H2._headers_prefix_len(_PADDED | _PRIORITY)
    ) == b""

    # PUSH_PROMISE layout: [pad_len=0xFF][promised id 4][fragment...].
    pp_payload = bytes([0xFF]) + struct.pack("!I", 2) + b"\x10\x20"
    assert _H2._strip_padded_frame(pp_payload, _PADDED, 4) == b""
    # And via the public PP wrapper, same semantics.
    assert _H2._strip_push_promise(pp_payload, _PADDED) == b""

    # Sanity: a valid small padding is accepted (boundary is exclusive).
    ok = bytes([0x01]) + struct.pack("!I", 2) + b"\xAA\xBB" + b"\x00"  # 1 pad byte
    assert _H2._strip_padded_frame(ok, _PADDED, 4) == b"\xAA\xBB"


def test_incomplete_continuation_flushes_with_error():
    """#51: a stream left awaiting a CONTINUATION at flush time is reported with
    an error, not as a clean status-0 result."""
    parser = Http2Parser()
    enc_r = _encoder()
    # HEADERS without END_HEADERS — block stays incomplete.
    parser.feed(_frame(_HEADERS, 0x00, 1,
                       enc_r.encode([(":status", "200")])), "read")
    flushed = parser.flush()
    assert len(flushed) == 1
    assert flushed[0].error == "incomplete-headers"
