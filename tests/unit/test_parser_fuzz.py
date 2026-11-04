"""Seeded mutation-fuzz regression suite for friTap's protocol parsers.

The parsers consume decrypted, attacker-controlled traffic (e.g. malware C2),
so every target is driven with deterministic mutants of valid seeds plus a few
"bomb" seeds (huge declared lengths, floods, deep nesting, decompression
bombs). Each input must:

* raise only the target's documented exception types when called directly
  (most targets document "never raises"),
* not let any exception escape :class:`SafeParserAdapter` (stream parsers),
* finish in < 2 s (``time.perf_counter``, on an untraced run) and, for every
  ``TRACE_EVERY``-th input and every bomb, keep the ``tracemalloc`` peak
  < 64 MiB (measured on a second, traced run).

Stdlib-only: ``random.Random`` seeded per (target, seed), no fuzzing library.
A failure message carries the exact mutated bytes as a hex reproducer.
"""

from __future__ import annotations

import gzip
import json
import random
import struct
import zlib
from functools import lru_cache

import pytest

from tests.unit._fuzz_helpers import (
    MIB,
    Feed,
    describe_transcript,
    drive_parser,
    fuzz_bytes_function,
    fuzz_parser_transcripts,
    run_contract,
)

SEEDS = range(20)
MUTANTS = 32         # mutated inputs per (target, seed) case
BOMB_MUTANTS = 3     # mutated inputs per bomb seed (plus the unmutated bomb)
BOMB_LIMIT = 4 * MIB  # explicit inflate cap for decompression-bomb cases

hpack = pytest.importorskip("hpack")
pylsqpack = pytest.importorskip("pylsqpack")

from friTap.parsers.base import SafeParserAdapter  # noqa: E402
from friTap.parsers.bhttp import parse_bhttp  # noqa: E402
from friTap.parsers.decompress import (  # noqa: E402
    InflateLimitError,
    decompress_body,
    decompress_lenient,
    inflate_bounded,
)
from friTap.parsers.http1 import Http1Parser  # noqa: E402
from friTap.parsers.http2 import Http2Parser  # noqa: E402
from friTap.parsers.http3 import Http3Parser  # noqa: E402
from friTap.parsers.protobuf.grpc import (  # noqa: E402
    InflateBudget,
    decompress_grpc_payload,
    extract_grpc_messages,
    is_grpc_frame,
    split_grpc_frames_lenient,
    strip_grpc_frame,
)
from friTap.parsers.protobuf.wire import (  # noqa: E402
    decode_raw,
    decode_raw_lenient,
    format_message_bounded,
    is_likely_protobuf,
)
from friTap.parsers.varint import encode_varint  # noqa: E402
from friTap.parsers.websocket import WebSocketParser  # noqa: E402
from tests.unit import _tl_helpers as tl  # noqa: E402
from tests.unit._h3_helpers import (  # noqa: E402
    FRAME_DATA,
    FRAME_HEADERS,
    FRAME_SETTINGS,
    UNI_CONTROL,
    UNI_QPACK_ENCODER,
    dynamic_exchange,
    h3_frame,
    headers_frame,
    qpack_encoder,
    settings_payload,
    settings_stream,
    uni_stream,
)

try:
    import brotli
except ImportError:  # pragma: no cover - optional dependency
    brotli = None
try:
    import zstandard
except ImportError:  # pragma: no cover - optional dependency
    zstandard = None


def _seed_params(xfail: dict[int, str] | None = None):
    """``SEEDS`` as pytest params; seeds in *xfail* become strict xfails."""
    xfail = xfail or {}
    return [
        pytest.param(s, marks=pytest.mark.xfail(strict=True, reason=xfail[s]))
        if s in xfail else s
        for s in SEEDS
    ]


def _run_bombs(target: str, factory, bombs: list[list[Feed]]) -> None:
    """Unmutated bombs directly + via adapter, then a few mutants of each."""
    for index, feeds in enumerate(bombs):
        repro = describe_transcript(feeds)
        run_contract(f"{target}[bomb={index}] direct",
                     lambda: drive_parser(factory(), feeds), repro, trace_memory=True)
        run_contract(f"{target}[bomb={index}] adapter",
                     lambda: drive_parser(SafeParserAdapter(factory()), feeds), repro)
    for index in range(len(bombs)):
        fuzz_parser_transcripts(f"{target}-bomb{index}", index, factory,
                                bombs[index:] + bombs[:index], BOMB_MUTANTS)


# =========================================================================== #
# HTTP/1
# =========================================================================== #

_GZ_HELLO = gzip.compress(b'{"hello": "world", "n": 1}' * 4)


def _http1_pool() -> list[list[Feed]]:
    get = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: fuzz\r\nAccept: */*\r\n\r\n"
    post = (b"POST /api/login HTTP/1.1\r\nHost: c2.example\r\nContent-Type: application/x-www-form-urlencoded\r\n"
            b"Content-Length: 13\r\n\r\nuser=a&pass=b")
    chunked_req = (b"POST /up HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n"
                   b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n")
    resp_gzip = (b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Encoding: gzip\r\n"
                 b"Content-Length: " + str(len(_GZ_HELLO)).encode() + b"\r\n\r\n" + _GZ_HELLO)
    resp_chunked = (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-Sum\r\n\r\n"
                    b"4\r\nWiki\r\n5\r\npedia\r\n0\r\nX-Sum: 1\r\n\r\n")
    resp_100 = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 204 No Content\r\nSet-Cookie: a=b\r\nSet-Cookie: c=d\r\n\r\n"
    upgrade_req = (b"GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                   b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
    upgrade_resp = (b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                    b"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n\x81\x05hello")
    return [
        [Feed("write", get), Feed("read", resp_gzip)],
        [Feed("write", post), Feed("read", resp_chunked)],
        [Feed("write", chunked_req), Feed("read", resp_100)],
        [Feed("write", get + post), Feed("read", resp_gzip + resp_chunked)],
        [Feed("write", upgrade_req), Feed("read", upgrade_resp)],
        [Feed("read", resp_chunked), Feed("write", get)],
    ]


def _http1_bombs() -> list[list[Feed]]:
    get = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"
    huge_cl = b"HTTP/1.1 200 OK\r\nContent-Length: 1000000000000\r\n\r\n" + b"A" * 4096
    huge_chunk = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nffffffffffffffff\r\n" + b"B" * 4096
    many_headers = (b"GET / HTTP/1.1\r\n" + b"".join(b"X-H%d: v\r\n" % i for i in range(5000)) + b"\r\n")
    long_line = b"GET /" + b"a" * (1 * MIB) + b" HTTP/1.1\r\nHost: x\r\n\r\n"
    bomb_body = _gzip_bomb()
    gzip_bomb = (b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: "
                 + str(len(bomb_body)).encode() + b"\r\n\r\n" + bomb_body)
    return [
        [Feed("write", get), Feed("read", huge_cl)],
        [Feed("write", get), Feed("read", huge_chunk)],
        [Feed("write", many_headers)],
        [Feed("write", long_line)],
        [Feed("write", get), Feed("read", gzip_bomb)],
    ]


@pytest.mark.parametrize("seed", _seed_params())
def test_fuzz_http1(seed):
    fuzz_parser_transcripts("http1", seed, Http1Parser, _http1_pool(), MUTANTS)


def test_fuzz_http1_bombs():
    _run_bombs("http1", Http1Parser, _http1_bombs())


# Regression: h11 treats receive_data(b'') as EOF; Http1Parser.feed() used to
# loop forever on a zero-length chunk (found by this fuzz suite).


@pytest.mark.parametrize("prefix, direction", [
    pytest.param(b"", "write", id="fresh-write"),
    pytest.param(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n", "write", id="after-request-write"),
    pytest.param(b"", "read", id="fresh-read"),
    pytest.param(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", "read", id="after-response-read"),
])
def test_http1_empty_feed_terminates(prefix, direction):
    """A zero-length chunk must be a no-op, not an infinite loop."""
    feeds = ([Feed(direction, prefix)] if prefix else []) + [Feed(direction, b"")]
    run_contract(f"http1-empty-feed[{direction}]", lambda: drive_parser(Http1Parser(), feeds),
                 describe_transcript(feeds), hang_seconds=2.5)


# =========================================================================== #
# HTTP/2
# =========================================================================== #

_H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
_DATA, _HEADERS, _PRIORITY, _RST, _SETTINGS, _PUSH, _PING, _GOAWAY, _WINUP, _CONT = (
    0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9)
_END_STREAM, _END_HEADERS, _PADDED, _PRIO_FLAG = 0x1, 0x4, 0x8, 0x20


def _h2_frame(ftype: int, flags: int, sid: int, payload: bytes, length: int | None = None) -> bytes:
    size = len(payload) if length is None else length
    return struct.pack("!I", size)[1:] + bytes([ftype, flags]) + struct.pack("!I", sid) + payload


def _h2_settings(*params: tuple[int, int]) -> bytes:
    return _h2_frame(_SETTINGS, 0, 0, b"".join(struct.pack("!HI", k, v) for k, v in params))


def h2_length_offsets(data: bytes) -> list[int]:
    """Offsets of every frame's 24-bit length field (and stream id)."""
    pos = len(_H2_PREFACE) if data.startswith(_H2_PREFACE) else 0
    offsets = []
    while pos + 9 <= len(data):
        offsets += [pos, pos + 5]
        pos += 9 + int.from_bytes(data[pos:pos + 3], "big")
    return offsets


def _h2_feed(direction: str, data: bytes) -> Feed:
    return Feed(direction, data, length_offsets=tuple(h2_length_offsets(data)))


def _h2_client() -> bytes:
    enc = hpack.Encoder()
    get = enc.encode([(":method", "GET"), (":scheme", "https"), (":path", "/a?x=1"),
                      (":authority", "example.com"), ("user-agent", "fuzz"), ("cookie", "a=b")])
    post = enc.encode([(":method", "POST"), (":scheme", "https"), (":path", "/grpc.Svc/Call"),
                       (":authority", "example.com"), ("content-type", "application/grpc"),
                       ("x-long", "v" * 300)])
    half = len(post) // 2
    padded = b"\x04" + b"\x00\x00\x00\x00\x10" + enc.encode([(":method", "GET"), (":path", "/p")]) + b"\x00" * 4
    return (
        _H2_PREFACE
        + _h2_settings((1, 4096), (3, 100), (4, 65535), (5, 16384))
        + _h2_frame(_WINUP, 0, 0, struct.pack("!I", 15663105))
        + _h2_frame(_HEADERS, _END_HEADERS | _END_STREAM, 1, get)
        + _h2_frame(_HEADERS, 0, 3, post[:half])
        + _h2_frame(_CONT, _END_HEADERS, 3, post[half:])
        + _h2_frame(_DATA, 0, 3, b"\x00\x00\x00\x00\x05" + b"\x08\x96\x01\x12\x01")
        + _h2_frame(_DATA, _END_STREAM | _PADDED, 3, b"\x03ab\x00\x00\x00")
        + _h2_frame(_PRIORITY, 0, 5, b"\x00\x00\x00\x03\x10")
        + _h2_frame(_HEADERS, _END_HEADERS | _PADDED | _PRIO_FLAG | _END_STREAM, 7, padded)
        + _h2_frame(_PING, 0, 0, b"\x00" * 8)
    )


def _h2_server() -> bytes:
    enc = hpack.Encoder()
    ok = enc.encode([(":status", "200"), ("content-type", "application/json"),
                     ("content-encoding", "gzip"), ("set-cookie", "s=1")])
    grpc = enc.encode([(":status", "200"), ("content-type", "application/grpc")])
    trailers = enc.encode([("grpc-status", "0"), ("grpc-message", "ok")])
    push = struct.pack("!I", 2) + enc.encode([(":method", "GET"), (":path", "/pushed"),
                                              (":scheme", "https"), (":authority", "e")])
    return (
        _h2_settings((1, 65536), (6, 262144))
        + _h2_frame(_SETTINGS, 0x1, 0, b"")
        + _h2_frame(_HEADERS, _END_HEADERS, 1, ok)
        + _h2_frame(_DATA, _END_STREAM, 1, _GZ_HELLO)
        + _h2_frame(_PUSH, _END_HEADERS, 1, push)
        + _h2_frame(_HEADERS, _END_HEADERS, 3, grpc)
        + _h2_frame(_DATA, 0, 3, b"\x00\x00\x00\x00\x03\x08\x01\x10")
        + _h2_frame(_HEADERS, _END_HEADERS | _END_STREAM, 3, trailers)
        + _h2_frame(_RST, 0, 5, struct.pack("!I", 8))
        + _h2_frame(_GOAWAY, 0, 0, struct.pack("!II", 7, 0) + b"bye")
    )


def _http2_pool() -> list[list[Feed]]:
    client, server = _h2_client(), _h2_server()
    return [
        [_h2_feed("write", client), _h2_feed("read", server)],
        [_h2_feed("read", server), _h2_feed("write", client)],
        [_h2_feed("write", client[:len(_H2_PREFACE) + 30]), _h2_feed("write", client[len(_H2_PREFACE) + 30:]),
         _h2_feed("read", server)],
        [_h2_feed("write", client + client[len(_H2_PREFACE):])],
        [_h2_feed("read", server)],
    ]


def _http2_bombs() -> list[list[Feed]]:
    enc = hpack.Encoder()
    block = enc.encode([(":method", "GET"), (":path", "/"), (":authority", "x")])
    flood = (_H2_PREFACE + _h2_frame(_HEADERS, 0, 1, block)
             + _h2_frame(_CONT, 0, 1, b"\x00\x01a\x01b" * 3) * 3000)
    huge_data = (_h2_frame(_HEADERS, _END_HEADERS, 1, block)
                 + _h2_frame(_DATA, 0, 1, b"Z" * 64, length=0xFFFFFF))
    table_bomb = (_H2_PREFACE + _h2_settings((1, 0xFFFFFFFF))
                  + _h2_frame(_HEADERS, _END_HEADERS, 1, b"\x3f\xe1\xff\xff\x0f" + block))
    int_overflow = _H2_PREFACE + _h2_frame(_HEADERS, _END_HEADERS, 1, b"\x7f" + b"\xff" * 40 + b"\x01")
    stream_flood = _H2_PREFACE + b"".join(
        _h2_frame(_HEADERS, _END_HEADERS, 2 * i + 1, b"\x82\x84") for i in range(5000))
    return [
        [_h2_feed("write", flood)],
        [_h2_feed("read", huge_data)],
        [_h2_feed("write", table_bomb)],
        [_h2_feed("write", int_overflow)],
        [_h2_feed("write", stream_flood)],
    ]


@pytest.mark.parametrize("seed", _seed_params())
def test_fuzz_http2(seed):
    fuzz_parser_transcripts("http2", seed, Http2Parser, _http2_pool(), MUTANTS)


def test_fuzz_http2_bombs():
    _run_bombs("http2", Http2Parser, _http2_bombs())


# =========================================================================== #
# HTTP/3 (non-muxed and muxed)
# =========================================================================== #

_H3_REQUEST = [(b":method", b"GET"), (b":scheme", b"https"), (b":authority", b"example.com"),
               (b":path", b"/index"), (b"user-agent", b"fuzz")]
_H3_RESPONSE = [(b":status", b"200"), (b"content-type", b"text/html"), (b"content-encoding", b"gzip")]


def h3_length_offsets(data: bytes, start: int = 0) -> list[int]:
    """Offsets of the varint length of each HTTP/3 frame starting at *start*."""
    from friTap.parsers.varint import decode_varint

    pos, offsets = start, []
    try:
        while pos < len(data):
            _ftype, used = decode_varint(data, pos)
            length, lused = decode_varint(data, pos + used)
            offsets.append(pos + used)
            pos += used + lused + length
    except ValueError:
        pass
    return offsets


def _h3_feed(direction: str, data: bytes, sid: int | None = None, start: int = 0) -> Feed:
    return Feed(direction, data, sid, tuple(h3_length_offsets(data, start)))


def _static_headers(sid: int, headers) -> bytes:
    return headers_frame(qpack_encoder()[0], sid, headers)[1]


def _http3_plain_pool() -> list[list[Feed]]:
    req = _static_headers(0, _H3_REQUEST)
    resp = _static_headers(0, _H3_RESPONSE) + h3_frame(FRAME_DATA, _GZ_HELLO)
    post = (_static_headers(0, [(b":method", b"POST"), (b":path", b"/u"), (b":scheme", b"https")])
            + h3_frame(FRAME_DATA, b"x" * 200) + h3_frame(FRAME_DATA, b"y" * 10))
    return [
        [_h3_feed("write", req), _h3_feed("read", resp)],
        [_h3_feed("write", post), _h3_feed("read", resp + resp)],
        [_h3_feed("read", resp), _h3_feed("write", req + post)],
        [_h3_feed("write", h3_frame(FRAME_SETTINGS, settings_payload({1: 4096, 6: 1 << 16})) + req)],
    ]


def _http3_muxed_pool() -> list[list[Feed]]:
    enc_bytes, blocks = dynamic_exchange([0, 4, 8], _H3_REQUEST)
    client_ctl, server_ctl = settings_stream(4096), settings_stream(4096)
    resp = _static_headers(0, _H3_RESPONSE) + h3_frame(FRAME_DATA, b"<html>hi</html>")
    req = {sid: h3_frame(FRAME_HEADERS, blk) for sid, blk in blocks.items()}
    encoder_stream = encode_varint(UNI_QPACK_ENCODER) + enc_bytes
    base = [
        _h3_feed("write", client_ctl, 2, 1), _h3_feed("read", server_ctl, 3, 1),
        Feed("write", encoder_stream, 6),
        _h3_feed("write", req[0], 0), _h3_feed("read", resp, 0),
        _h3_feed("write", req[4] + h3_frame(FRAME_DATA, b"body"), 4), _h3_feed("read", resp, 4),
        _h3_feed("write", req[8], 8),
    ]
    blocked_first = [base[3], base[2], base[0], base[1], base[4]]  # HEADERS before encoder stream
    static_only = [
        _h3_feed("write", uni_stream(UNI_CONTROL, h3_frame(FRAME_SETTINGS, settings_payload({}))), 2, 1),
        _h3_feed("write", _static_headers(0, _H3_REQUEST), 0),
        _h3_feed("read", resp, 0),
    ]
    return [base, blocked_first, static_only]


def _http3_bombs() -> list[list[Feed]]:
    req = _static_headers(0, _H3_REQUEST)
    huge_data = req + encode_varint(FRAME_DATA) + encode_varint((1 << 62) - 1) + b"\x00" * 64
    huge_headers = encode_varint(FRAME_HEADERS) + encode_varint(0x3FFFFFFF) + b"\x00" * 128
    settings_bomb = uni_stream(UNI_CONTROL, h3_frame(FRAME_SETTINGS, settings_payload(
        {1: (1 << 62) - 1, 6: (1 << 62) - 1, 7: (1 << 62) - 1})))
    # encoder stream: Set Dynamic Table Capacity + Insert With Literal Name of huge declared size
    encoder_bomb = encode_varint(UNI_QPACK_ENCODER) + b"\x3f\xe1\x1f" + b"\x5f\xff\xff\xff\xff\x0f" + b"n" * 64
    many_uni = [Feed("write", encode_varint(0x21 + 0x1F * i) + b"\x00" * 8, 2 + 4 * i) for i in range(2000)]
    return [
        [_h3_feed("write", huge_data)],
        [_h3_feed("write", huge_data, 0)],
        [_h3_feed("read", huge_headers, 1)],
        [Feed("write", settings_bomb, 2), Feed("write", encoder_bomb, 6), _h3_feed("write", req, 0)],
        many_uni,
    ]


@pytest.mark.parametrize("seed", _seed_params())
def test_fuzz_http3_plain(seed):
    fuzz_parser_transcripts("http3-plain", seed, Http3Parser, _http3_plain_pool(), MUTANTS)


@pytest.mark.parametrize("seed", _seed_params())
def test_fuzz_http3_muxed(seed):
    fuzz_parser_transcripts("http3-muxed", seed, Http3Parser, _http3_muxed_pool(), MUTANTS)


def test_fuzz_http3_bombs():
    _run_bombs("http3", Http3Parser, _http3_bombs())


# =========================================================================== #
# WebSocket
# =========================================================================== #

def _ws_frame(first: int, payload: bytes, mask: bytes = b"", declared: int | None = None) -> bytes:
    length = len(payload) if declared is None else declared
    bit = 0x80 if mask else 0
    if length <= 125:
        hdr = bytes([first, bit | length])
    elif length <= 0xFFFF:
        hdr = bytes([first, bit | 126]) + length.to_bytes(2, "big")
    else:
        hdr = bytes([first, bit | 127]) + length.to_bytes(8, "big")
    body = bytes(b ^ mask[i % 4] for i, b in enumerate(payload)) if mask else payload
    return hdr + mask + body


def _pmd(data: bytes) -> bytes:
    comp = zlib.compressobj(9, zlib.DEFLATED, -zlib.MAX_WBITS)
    return (comp.compress(data) + comp.flush(zlib.Z_SYNC_FLUSH))[:-4]


def ws_length_offsets(data: bytes) -> list[int]:
    pos, offsets = 0, []
    while pos + 2 <= len(data):
        offsets += [pos + 1, pos + 2]
        code = data[pos + 1] & 0x7F
        masked = 4 if data[pos + 1] & 0x80 else 0
        ext = {126: 2, 127: 8}.get(code, 0)
        length = int.from_bytes(data[pos + 2:pos + 2 + ext], "big") if ext else code
        pos += 2 + ext + masked + length
    return offsets


def _ws_feed(direction: str, data: bytes) -> Feed:
    return Feed(direction, data, length_offsets=tuple(ws_length_offsets(data)))


def _websocket_pool() -> list[list[Feed]]:
    mask = b"\x37\xfa\x21\x3d"
    client = (_ws_frame(0x81, b"hello", mask)
              + _ws_frame(0x01, b'{"op": ', mask) + _ws_frame(0x80, b'"sub"}', mask)
              + _ws_frame(0x89, b"ping", mask)
              + _ws_frame(0xC1, _pmd(json.dumps({"k": "v" * 50}).encode()), mask))
    server = (_ws_frame(0x81, b"world") + _ws_frame(0x82, bytes(range(256)) * 2)
              + _ws_frame(0x8A, b"ping") + _ws_frame(0xC2, _pmd(b"\x00\x00\x00\x00\x02\x08\x01"))
              + _ws_frame(0x41, _pmd(b"part one, ")) + _ws_frame(0x80, _pmd(b"part two"))
              + _ws_frame(0x88, b"\x03\xe8bye"))
    return [
        [_ws_feed("write", client), _ws_feed("read", server)],
        [_ws_feed("read", server), _ws_feed("write", client)],
        [_ws_feed("write", client + client)],
        [_ws_feed("read", server[:7]), _ws_feed("read", server[7:])],
    ]


@lru_cache(maxsize=None)
def _ws_deflate_bomb() -> bytes:
    return _pmd(b"\x00" * (32 * MIB))


def _websocket_bombs() -> list[list[Feed]]:
    huge = _ws_frame(0x82, b"\x00" * 64, declared=0x7FFFFFFFFFFFFFFF)
    near_cap = _ws_frame(0x82, b"\x00" * 64, declared=(1 << 31))
    frag_flood = _ws_frame(0x01, b"a") + _ws_frame(0x00, b"b") * 5000 + _ws_frame(0x80, b"c")
    deflate_flood = _ws_frame(0x41, _pmd(b"\x00" * 65536)) + _ws_frame(0x00, _pmd(b"\x00" * 65536)) * 300
    return [
        [_ws_feed("read", huge)],
        [_ws_feed("read", near_cap)],
        [_ws_feed("read", _ws_frame(0xC2, _ws_deflate_bomb()))],
        [_ws_feed("write", frag_flood)],
        [_ws_feed("read", deflate_flood + _ws_frame(0x80, b""))],
    ]


@pytest.mark.parametrize("seed", _seed_params())
def test_fuzz_websocket(seed):
    fuzz_parser_transcripts("websocket", seed, WebSocketParser, _websocket_pool(), MUTANTS)


def test_fuzz_websocket_bombs():
    _run_bombs("websocket", WebSocketParser, _websocket_bombs())


# =========================================================================== #
# BHTTP (RFC 9292)
# =========================================================================== #

def _vlen(data: bytes) -> bytes:
    return encode_varint(len(data)) + data


def _bhttp_fields(pairs) -> bytes:
    return _vlen(b"".join(_vlen(k) + _vlen(v) for k, v in pairs))


def _bhttp_seeds() -> list[bytes]:
    request = (b"\x00" + _vlen(b"POST") + _vlen(b"https") + _vlen(b"example.com") + _vlen(b"/q")
               + _bhttp_fields([(b"content-type", b"application/dns-message"), (b"user-agent", b"f")])
               + _vlen(b"\x00\x01" * 20) + _bhttp_fields([]))
    response = (b"\x01" + encode_varint(103) + _bhttp_fields([(b"link", b"</a>")])
                + encode_varint(200) + _bhttp_fields([(b"content-encoding", b"gzip")])
                + _vlen(_GZ_HELLO) + _bhttp_fields([(b"x-trailer", b"1")]))
    no_body = b"\x00" + _vlen(b"GET") + _vlen(b"https") + _vlen(b"h") + _vlen(b"/") + _bhttp_fields([])
    indeterminate = b"\x02" + _vlen(b"GET") + _vlen(b"https") + _vlen(b"h") + _vlen(b"/") + b"\x00"
    return [request, response, no_body, indeterminate]


def _bhttp_bombs() -> list[bytes]:
    head = b"\x00" + _vlen(b"GET") + _vlen(b"https") + _vlen(b"h") + _vlen(b"/")
    return [
        b"\x00" + b"\xff" * 8 + b"GET",                                      # 2^62-1 method length
        head + encode_varint((1 << 62) - 1) + b"\x00" * 32,                   # header section length
        b"\x01" + (encode_varint(100) + _bhttp_fields([])) * 20000 + encode_varint(200) + b"\x00",
        head + _bhttp_fields([(b"a", b"b")] * 50000),
        head + _bhttp_fields([]) + encode_varint((1 << 62) - 1),             # body length
    ]


def _bhttp_action(data: bytes, _rng: random.Random) -> None:
    result = parse_bhttp(data)
    assert result is None or result.protocol == "bhttp"


@pytest.mark.parametrize("seed", _seed_params())
def test_fuzz_bhttp(seed):
    fuzz_bytes_function("bhttp", seed, _bhttp_seeds() + _bhttp_bombs()[:1], _bhttp_action, (), MUTANTS)


def test_fuzz_bhttp_bombs():
    for index, bomb in enumerate(_bhttp_bombs()):
        run_contract(f"bhttp[bomb={index}]", lambda: _bhttp_action(bomb, None),
                     f"  bytes.fromhex({bomb.hex()!r})", trace_memory=True)
        fuzz_bytes_function(f"bhttp-bomb{index}", index, [bomb], _bhttp_action, (), BOMB_MUTANTS)


# =========================================================================== #
# Decompression: decompress_body / decompress_lenient / inflate_bounded
# =========================================================================== #

_PLAINTEXTS = [
    b'{"user": "alice", "token": "' + b"t" * 64 + b'"}',
    b"<html><body>" + b"hello world " * 40 + b"</body></html>",
    bytes(random.Random(7).randrange(256) for _ in range(512)),
    b"A" * 2000,
]


def _raw_deflate(data: bytes) -> bytes:
    comp = zlib.compressobj(6, zlib.DEFLATED, -zlib.MAX_WBITS)
    return comp.compress(data) + comp.flush()


def _encoders() -> dict[str, callable]:
    encs = {"gzip": gzip.compress, "deflate": _raw_deflate, "zlib": zlib.compress}
    if brotli is not None:
        encs["br"] = brotli.compress
    if zstandard is not None:
        encs["zstd"] = zstandard.ZstdCompressor().compress
    return encs


def _compressed_seeds() -> list[bytes]:
    seeds = [enc(text) for enc in _encoders().values() for text in _PLAINTEXTS]
    seeds.append(b"\x00\x00\x00\x00\x05" + gzip.compress(b"grpc framed"))     # embedded gzip
    seeds.append(gzip.compress(b"one") + gzip.compress(b"two"))               # multi-member
    return seeds


_ENCODING_NAMES = ["gzip", "x-gzip", "deflate", "br", "zstd", "identity", "compress",
                   "permessage-deflate", " GZIP "]


@lru_cache(maxsize=None)
def _gzip_bomb() -> bytes:
    return gzip.compress(b"\x00" * (16 * MIB), 9)


def _decompress_bombs() -> list[bytes]:
    zeros = b"\x00" * (16 * MIB)
    bombs = [_gzip_bomb(), zlib.compress(zeros, 9), _raw_deflate(zeros), _gzip_bomb() * 4]
    if brotli is not None:
        bombs.append(brotli.compress(zeros, quality=1))
    if zstandard is not None:
        bombs.append(zstandard.ZstdCompressor(level=1).compress(zeros))
        # frame declaring a 2^62 content size (header only, then junk)
        bombs.append(b"\x28\xb5\x2f\xfd\xe4\x00" + (1 << 62).to_bytes(8, "little") + b"\x00" * 32)
    return bombs


def _decompress_action(max_out: int | None):
    def action(data: bytes, rng: random.Random) -> None:
        encoding = rng.choice(_ENCODING_NAMES)
        kwargs = {} if max_out is None else {"max_out": max_out}
        out, err = decompress_body(data, encoding, **kwargs)
        assert isinstance(out, bytes) and isinstance(err, str)
        out, notes, error = decompress_lenient(data, encoding, **kwargs)
        assert isinstance(out, bytes) and isinstance(notes, list)
        assert error is None or isinstance(error, str)
    return action


def _inflate_action(limit: int):
    def action(data: bytes, rng: random.Random) -> None:
        out = inflate_bounded(data, limit=limit, require_eof=rng.random() < 0.5)
        assert len(out) <= limit
    return action


@pytest.mark.parametrize("seed", _seed_params())
def test_fuzz_decompress(seed):
    fuzz_bytes_function("decompress", seed, _compressed_seeds(), _decompress_action(None), (), MUTANTS)


@pytest.mark.parametrize("seed", _seed_params())
def test_fuzz_inflate_bounded(seed):
    seeds = [s for s in _compressed_seeds() if s[:1] in (b"\x1f", b"\x78")]
    fuzz_bytes_function("inflate_bounded", seed, seeds, _inflate_action(1 * MIB),
                        (zlib.error, InflateLimitError), MUTANTS)


def test_fuzz_decompress_bombs():
    for index, bomb in enumerate(_decompress_bombs()):
        repro = f"  <decompression bomb #{index}, {len(bomb)} bytes>"
        run_contract(f"decompress[bomb={index}]",
                     lambda: _decompress_action(BOMB_LIMIT)(bomb, random.Random(index)),
                     repro, trace_memory=True)
        run_contract(f"inflate_bounded[bomb={index}]",
                     lambda: _inflate_action(BOMB_LIMIT)(bomb, random.Random(index)),
                     repro, (zlib.error, InflateLimitError), trace_memory=True)
        fuzz_bytes_function(f"decompress-bomb{index}", index, [bomb],
                            _decompress_action(BOMB_LIMIT), (), BOMB_MUTANTS)
        fuzz_bytes_function(f"inflate-bomb{index}", index, [bomb], _inflate_action(BOMB_LIMIT),
                            (zlib.error, InflateLimitError), BOMB_MUTANTS)


def test_decompress_body_bomb_is_rejected_not_truncated():
    """Sanity: the bounded decoders actually reject a bomb above the cap."""
    out, err = decompress_body(_gzip_bomb(), "gzip", max_out=BOMB_LIMIT)
    assert err and out == _gzip_bomb()


# =========================================================================== #
# Protobuf wire decoder
# =========================================================================== #

def _pb_varint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _pb_field(num: int, wire: int, payload: bytes) -> bytes:
    tag = _pb_varint((num << 3) | wire)
    if wire == 2:
        return tag + _pb_varint(len(payload)) + payload
    return tag + payload


def _protobuf_seeds() -> list[bytes]:
    inner = _pb_field(1, 0, _pb_varint(150)) + _pb_field(2, 2, b"testing")
    packed = _pb_field(4, 2, b"".join(_pb_varint(v) for v in (3, 270, 86942, 1 << 40)))
    msg = (_pb_field(1, 0, _pb_varint(300)) + _pb_field(2, 2, "héllo".encode())
           + _pb_field(3, 2, inner) + packed + _pb_field(5, 1, struct.pack("<d", 3.14))
           + _pb_field(6, 5, struct.pack("<f", 2.5)) + _pb_field(7, 0, _pb_varint((1 << 64) - 1)))
    nested = inner
    for depth in range(10):
        nested = _pb_field(depth + 1, 2, nested)
    group = _pb_varint((8 << 3) | 3) + _pb_field(1, 0, b"\x01") + _pb_varint((8 << 3) | 4)
    return [msg, inner, nested, msg + group, _pb_field(1, 2, bytes(range(256)))]


def _protobuf_bombs() -> list[bytes]:
    deep = b"\x08\x01"
    for _ in range(300):
        deep = _pb_field(1, 2, deep)
    return [
        deep,
        _pb_field(1, 0, b"\x01") * 100000,
        _pb_varint((1 << 3) | 2) + b"\xff" * 9 + b"\x01" + b"\x00" * 16,      # 2^64-ish length
        _pb_field(1, 2, b"\x80" * 4096),                                     # unterminated packed varints
        _pb_field(2, 2, (_pb_field(1, 2, b"\x08\x01" * 2000)) * 50),
    ]


def _protobuf_action(data: bytes, _rng: random.Random) -> None:
    is_likely_protobuf(data)
    msg, error = decode_raw_lenient(data)
    assert isinstance(error, str)
    format_message_bounded(msg, 20000)
    try:
        format_message_bounded(decode_raw(data), 20000)
    except ValueError:  # documented: malformed data
        pass


@pytest.mark.parametrize("seed", _seed_params())
def test_fuzz_protobuf(seed):
    fuzz_bytes_function("protobuf", seed, _protobuf_seeds(), _protobuf_action, (), MUTANTS)


def test_fuzz_protobuf_bombs():
    for index, bomb in enumerate(_protobuf_bombs()):
        run_contract(f"protobuf[bomb={index}]", lambda: _protobuf_action(bomb, None),
                     f"  <protobuf bomb #{index}, {len(bomb)} bytes>", trace_memory=True)
        fuzz_bytes_function(f"protobuf-bomb{index}", index, [bomb], _protobuf_action, (), BOMB_MUTANTS)


# =========================================================================== #
# gRPC framing
# =========================================================================== #

def _grpc(payload: bytes, compressed: int = 0) -> bytes:
    return bytes([compressed]) + struct.pack(">I", len(payload)) + payload


def grpc_length_offsets(data: bytes) -> list[int]:
    pos, offsets = 0, []
    while pos + 5 <= len(data):
        offsets.append(pos + 1)
        pos += 5 + int.from_bytes(data[pos + 1:pos + 5], "big")
    return offsets


def _grpc_seeds() -> list[bytes]:
    pb = _protobuf_seeds()
    seeds = [_grpc(pb[0]), _grpc(pb[0]) + _grpc(pb[1]) + _grpc(b""),
             _grpc(gzip.compress(pb[0]), 1), _grpc(zlib.compress(pb[2]), 1)]
    if zstandard is not None:
        seeds.append(_grpc(zstandard.ZstdCompressor().compress(pb[0]), 1))
    return seeds


def _grpc_bombs() -> list[bytes]:
    return [
        b"\x00\xff\xff\xff\xff" + b"\x00" * 64,
        _grpc(b"") * 100000,
        _grpc(_gzip_bomb(), 1),
        _grpc(_gzip_bomb(), 1) * 8,
    ]


def _grpc_action(data: bytes, rng: random.Random) -> None:
    is_grpc_frame(data)
    extract_grpc_messages(data, "application/grpc+proto")
    frames, error = split_grpc_frames_lenient(data)
    assert isinstance(error, str)
    budget = InflateBudget()
    for frame in frames[:64]:
        if frame.compressed:
            decompress_grpc_payload(frame.payload, rng.choice(("gzip", "deflate", "zstd", "br", "",
                                                              "identity", "snappy")), budget)
    try:
        strip_grpc_frame(data)
    except ValueError:  # documented: malformed/truncated framing
        pass


@pytest.mark.parametrize("seed", _seed_params())
def test_fuzz_grpc(seed):
    fuzz_bytes_function("grpc", seed, _grpc_seeds(), _grpc_action, (), MUTANTS,
                        hints=grpc_length_offsets)


def test_fuzz_grpc_bombs():
    for index, bomb in enumerate(_grpc_bombs()):
        run_contract(f"grpc[bomb={index}]", lambda: _grpc_action(bomb, random.Random(index)),
                     f"  <gRPC bomb #{index}, {len(bomb)} bytes>", trace_memory=True)
        fuzz_bytes_function(f"grpc-bomb{index}", index, [bomb], _grpc_action, (), BOMB_MUTANTS,
                            hints=grpc_length_offsets)


# =========================================================================== #
# MTProto TL decoder / content parsers
# =========================================================================== #

from friTap.offline.mtproto.content import (  # noqa: E402
    decode_secret_chat_fields,
    parse_mtproto_message,
    parse_secret_chat_message,
)
from friTap.offline.mtproto.tl.decoder import (  # noqa: E402
    decode_tl,
    rpc_result_ctor_id,
)
from friTap.offline.mtproto.tl_parser import (  # noqa: E402
    MtprotoParser,
    TelegramE2EParser,
)

_DECRYPTED_MESSAGE_LAYER = 0x1BE31789
_DECRYPTED_MESSAGE_L73 = 0x91CC4674
_DECRYPTED_MESSAGE_L17 = 0x204D3878


def _secret_layer(inner: bytes, layer: int) -> bytes:
    return (tl.u32(_DECRYPTED_MESSAGE_LAYER) + tl.tl_bytes(b"\x00" * 16)
            + tl.i32(layer) + tl.i32(0) + tl.i32(0) + inner)


def _mtproto_seeds() -> list[bytes]:
    l73 = tl.u32(_DECRYPTED_MESSAGE_L73) + tl.u32(0) + tl.i64(0xCAFE) + tl.i32(0) + tl.tl_str("secret hello")
    l17 = tl.u32(_DECRYPTED_MESSAGE_L17) + tl.i64(0xBEEF) + tl.i32(0) + tl.tl_str("old secret")
    return [
        tl.pong(),
        tl.msgs_ack(1, 2, 3),
        tl.container(tl.pong(), tl.msgs_ack(9), tl.synthetic_user()),
        tl.rpc_result(0x6000_0000_0000_0004, tl.gzip_packed(tl.synthetic_user())),
        tl.u32(tl.VECTOR) + tl.i32(2) + tl.synthetic_user() + tl.synthetic_user(),
        tl.u32(tl.INVOKE_WITH_LAYER) + tl.i32(158) + tl.u32(tl.HELP_GET_CONFIG),
        _secret_layer(l73, 73),
        _secret_layer(l17, 17),
        tl.tl_bytes(b"x" * 300),
    ]


def _mtproto_bombs() -> list[bytes]:
    deep = tl.pong()
    for _ in range(500):
        deep = tl.container(deep)
    return [
        tl.u32(tl.VECTOR) + tl.i32(0x7FFFFFFF) + tl.i64(1) * 16,
        tl.u32(tl.MSGS_ACK) + tl.u32(tl.VECTOR) + tl.i32(200000) + tl.i64(5) * 200000,
        deep,
        tl.rpc_result(1, tl.u32(tl.GZIP_PACKED) + tl.tl_bytes(_gzip_bomb())),
        tl.u32(tl.USER) + b"\xfe\xff\xff\xff" + b"A" * 64,
        tl.u32(tl.VECTOR) + tl.i32(100000) + tl.u32(tl.BOOL_TRUE) * 100000,
    ]


def _mtproto_action(data: bytes, _rng: random.Random) -> None:
    decode_tl(data)
    decode_tl(data, domain="secret")
    decode_tl(data, expect="messages.StickerSet")
    rpc_result_ctor_id(data)
    assert isinstance(parse_mtproto_message(data), list)
    assert isinstance(parse_secret_chat_message(data), list)
    decode_secret_chat_fields(data)
    for factory in (MtprotoParser, TelegramE2EParser):
        drive_parser(factory(), [Feed("read", data)])
        drive_parser(SafeParserAdapter(factory()), [Feed("write", data)])


@pytest.mark.parametrize("seed", _seed_params())
def test_fuzz_mtproto(seed):
    fuzz_bytes_function("mtproto", seed, _mtproto_seeds(), _mtproto_action, (), MUTANTS)


def test_fuzz_mtproto_bombs():
    for index, bomb in enumerate(_mtproto_bombs()):
        run_contract(f"mtproto[bomb={index}]", lambda: _mtproto_action(bomb, None),
                     f"  <TL bomb #{index}, {len(bomb)} bytes>", trace_memory=True)
        fuzz_bytes_function(f"mtproto-bomb{index}", index, [bomb], _mtproto_action, (), BOMB_MUTANTS)
