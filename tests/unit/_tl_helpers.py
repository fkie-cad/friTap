"""Shared TL (Telegram type-language) byte builders for the unit tests.

One definition for the synthetic-bytes constructors used by the TL decoder,
cross-reference, users, tree-render, pane and offline-reference tests.
"""

from __future__ import annotations

import gzip
import struct

VECTOR = 0x1CB5C415
MSGS_ACK = 0x62D6B459
PONG = 0x347773C5
RPC_RESULT = 0xF35C6D01
GZIP_PACKED = 0x3072CFA1
MSG_CONTAINER = 0x73F1F8DC
INVOKE_WITH_LAYER = 0xDA9B0D0D
INVOKE_AFTER_MSG = 0xCB9F372D
INIT_CONNECTION = 0xC1CD5EA9
HELP_GET_CONFIG = 0xC4F9186B
GET_DIALOGS = 0xA0F4CB4F
INPUT_PEER_EMPTY = 0x7F3B18EA
USER = 0xB1B8CC83
USER_STATUS_ONLINE = 0xEDB93949
BOOL_TRUE = 0x997275B5


def u32(value: int) -> bytes:
    return struct.pack("<I", value)


def i32(value: int) -> bytes:
    return struct.pack("<i", value)


def i64(value: int) -> bytes:
    return struct.pack("<q", value)


def tl_bytes(data: bytes) -> bytes:
    if len(data) < 254:
        head = bytes([len(data)])
    else:
        head = b"\xfe" + len(data).to_bytes(3, "little")
    body = head + data
    return body + b"\x00" * (-len(body) % 4)


def tl_str(text: str) -> bytes:
    return tl_bytes(text.encode("utf-8"))


def pong(msg_id: int = 1, ping_id: int = 2) -> bytes:
    return u32(PONG) + i64(msg_id) + i64(ping_id)


def msgs_ack(*ids: int) -> bytes:
    return u32(MSGS_ACK) + u32(VECTOR) + i32(len(ids)) + b"".join(i64(i) for i in ids)


def container(*bodies: bytes) -> bytes:
    out = u32(MSG_CONTAINER) + i32(len(bodies))
    for index, body in enumerate(bodies):
        out += i64(0x6000_0000_0000_0000 + index * 4) + i32(index * 2 + 1) + i32(len(body)) + body
    return out


def rpc_result(req_msg_id: int, result: bytes) -> bytes:
    return u32(RPC_RESULT) + i64(req_msg_id) + result


def gzip_packed(inner: bytes, compress=gzip.compress) -> bytes:
    return u32(GZIP_PACKED) + tl_bytes(compress(inner))


def synthetic_user() -> bytes:
    flags = (1 << 0) | (1 << 1) | (1 << 2) | (1 << 4) | (1 << 6) | (1 << 10)
    return (
        u32(USER) + u32(flags) + u32(1 << 4)          # flags2.4 stories_unavailable
        + i64(123456789) + i64(-42)                     # id, access_hash
        + tl_str("Alice") + tl_str("Example") + tl_str("15550000000")
        + u32(USER_STATUS_ONLINE) + i32(1700000000)
    )
