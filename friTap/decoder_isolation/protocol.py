"""Wire protocol between friTap and its decoder worker process.

Stdlib-only on purpose: the worker loads this file by path, without importing
the ``friTap`` package. Every frame is one ``send_bytes`` message::

    header (struct, fixed size) | text (UTF-8, text_len bytes) | data (data_len bytes)

There is no pickle, eval or other object deserialisation in either direction.
The parent treats every reply as hostile (the worker may be compromised by a
decoder exploit) and validates each field with :func:`parse_reply`.
"""

from __future__ import annotations

import struct
from typing import NamedTuple

MAGIC = b"FD"
VERSION = 1

# magic, version, op, status, flags, request_id, handle, arg0, arg1, text_len, data_len
HEADER = struct.Struct("!2sBBHHIIQQII")
HEADER_SIZE = HEADER.size

# Caps the parent enforces on replies.
MAX_TEXT_LEN = 4096          # bytes of error/notice text on the wire
MAX_LOG_TEXT_CHARS = 1024    # characters kept after decoding and filtering
MAX_REQUEST_DATA = 1 << 30   # inputs larger than this are not sent at all
MAX_REPLY_DATA = 1 << 30      # absolute output cap (any op); callers' max_out is lower
MAX_KIND_LEN = 64

U32_MASK = 0xFFFFFFFF


class Op:
    """Operation codes (one byte)."""

    HELLO = 1             # worker -> parent, once, after hardening
    DECOMPRESS_BODY = 2   # text=encoding, arg0=max_out, flags=REQ_ALLOW_UNPATCHED_BROTLI
    FIND_GZIP_MEMBER = 3  # arg0=max_out, arg1=max_candidates
    INFLATE_CHECKED = 4   # arg0=limit
    CTX_CREATE = 5        # text=kind, data=kind-specific params
    CTX_CALL = 6          # handle, arg0=max_out, arg1=context op, data=input
    CTX_DESTROY = 7       # handle
    PING = 8

    # Test-only ops; the worker honours them only when started with test hooks.
    TEST_EXIT = 0xF0          # os._exit(arg0)
    TEST_SEGV = 0xF1          # ctypes.string_at(0)
    TEST_SLEEP = 0xF2         # sleep arg0 milliseconds, then reply OK
    TEST_RAW_REPLY = 0xF3     # send *data* verbatim as the reply frame
    TEST_LIST_MODULES = 0xF4  # reply data = "\n".join(sorted(sys.modules))
    TEST_HARDENING = 0xF5     # reply text = hardening report

    TEST_OPS = frozenset({TEST_EXIT, TEST_SEGV, TEST_SLEEP, TEST_RAW_REPLY,
                          TEST_LIST_MODULES, TEST_HARDENING})


class Status:
    """Reply status codes."""

    OK = 0
    DECODE_ERROR = 1     # decompress_body error string in text
    ZLIB_ERROR = 2       # inflate: zlib.error message in text
    LIMIT_ERROR = 3      # inflate/context: output limit exceeded
    NOT_FOUND = 4        # find_gzip_member: no member
    HANDLE_LOST = 5      # context handle unknown to this worker
    BAD_REQUEST = 6      # malformed or unsupported request
    UNSUPPORTED = 7      # unknown context kind / op, or test op without hooks
    CONTEXT_ERROR = 8    # context call failed (message in text)
    BLOCKED = 9          # context call: input waits for more state (QPACK)


# Status values the parent accepts per op; anything else is a protocol violation.
_COMMON_FAILURES = frozenset({Status.BAD_REQUEST, Status.UNSUPPORTED})
ALLOWED_STATUSES: dict[int, frozenset[int]] = {
    Op.HELLO: frozenset({Status.OK}),
    Op.DECOMPRESS_BODY: frozenset({Status.OK, Status.DECODE_ERROR}) | _COMMON_FAILURES,
    Op.FIND_GZIP_MEMBER: frozenset({Status.OK, Status.NOT_FOUND}) | _COMMON_FAILURES,
    Op.INFLATE_CHECKED: frozenset({Status.OK, Status.ZLIB_ERROR, Status.LIMIT_ERROR})
    | _COMMON_FAILURES,
    Op.CTX_CREATE: frozenset({Status.OK, Status.CONTEXT_ERROR}) | _COMMON_FAILURES,
    Op.CTX_CALL: frozenset({Status.OK, Status.LIMIT_ERROR, Status.HANDLE_LOST,
                            Status.CONTEXT_ERROR, Status.BLOCKED}) | _COMMON_FAILURES,
    Op.CTX_DESTROY: frozenset({Status.OK, Status.HANDLE_LOST}) | _COMMON_FAILURES,
    Op.PING: frozenset({Status.OK}),
}
for _test_op in Op.TEST_OPS:
    ALLOWED_STATUSES[_test_op] = frozenset({Status.OK}) | _COMMON_FAILURES

# Flag bits.
REQ_ALLOW_UNPATCHED_BROTLI = 0x0001  # request: honour FRITAP_ALLOW_UNPATCHED_BROTLI
REPLY_COMPLETE = 0x0001              # reply (INFLATE_CHECKED): stream reached its end
# Reply flags of a CONTEXT_ERROR from a qpack_decoder context: the pylsqpack
# exception class, so the parent can re-raise the same type.
REPLY_QPACK_DECOMPRESSION_FAILED = 0x0010
REPLY_QPACK_ENCODER_STREAM_ERROR = 0x0020


class CtxOp:
    """Per-kind context operation codes (CTX_CALL ``arg1``)."""

    FEED = 1                 # zlib_stream / test kinds: feed data
    QPACK_FEED_ENCODER = 2   # data=encoder-stream bytes -> stream-id list
    QPACK_FEED_HEADER = 3    # data=u64 stream id + header block -> header list
    QPACK_RESUME_HEADER = 4  # data=u64 stream id -> header list


class Frame(NamedTuple):
    """A decoded frame. *text* is raw bytes; the parent filters it before use."""

    op: int
    status: int
    flags: int
    request_id: int
    handle: int
    arg0: int
    arg1: int
    text: bytes
    data: bytes


class ProtocolError(Exception):
    """A frame violates the protocol (always treated as a hostile worker)."""


def encode_frame(op: int, request_id: int, *, status: int = Status.OK, flags: int = 0,
                 handle: int = 0, arg0: int = 0, arg1: int = 0,
                 text: bytes = b"", data: bytes = b"") -> bytes:
    """Serialise one frame; *data* is copied once into the message."""
    header = HEADER.pack(MAGIC, VERSION, op, status, flags, request_id & U32_MASK,
                         handle & U32_MASK, arg0, arg1, len(text), len(data))
    return b"".join((header, text, data))


def decode_frame(message: bytes, max_text: int = MAX_TEXT_LEN,
                 max_data: int = MAX_REPLY_DATA) -> Frame:
    """Parse *message*; raise :class:`ProtocolError` on any shape violation."""
    if len(message) < HEADER_SIZE:
        raise ProtocolError(f"short frame ({len(message)} bytes)")
    (magic, version, op, status, flags, request_id, handle, arg0, arg1,
     text_len, data_len) = HEADER.unpack_from(message)
    if magic != MAGIC or version != VERSION:
        raise ProtocolError("bad magic or protocol version")
    if text_len > max_text or data_len > max_data:
        raise ProtocolError(f"length over cap (text={text_len}, data={data_len})")
    if HEADER_SIZE + text_len + data_len != len(message):
        raise ProtocolError("declared lengths do not match the frame size")
    text_end = HEADER_SIZE + text_len
    view = memoryview(message)
    return Frame(op, status, flags, request_id, handle, arg0, arg1,
                 bytes(view[HEADER_SIZE:text_end]), bytes(view[text_end:]))


def parse_reply(message: bytes, *, op: int, request_id: int, max_data: int) -> Frame:
    """Decode and validate a worker reply to request (*op*, *request_id*).

    Checks the shape, the request id, the op echo, the status against
    :data:`ALLOWED_STATUSES` and the data length against *max_data* (the
    caller's ``max_out``). Raises :class:`ProtocolError` on any violation.
    """
    frame = decode_frame(message, MAX_TEXT_LEN, min(max_data, MAX_REPLY_DATA))
    if frame.request_id != request_id & U32_MASK:
        raise ProtocolError(f"request id mismatch ({frame.request_id} != {request_id})")
    if frame.op != op:
        raise ProtocolError(f"op mismatch ({frame.op} != {op})")
    if frame.status not in ALLOWED_STATUSES.get(op, frozenset()):
        raise ProtocolError(f"status {frame.status} not allowed for op {op}")
    return frame


# --- Untrusted text -----------------------------------------------------------

# C0/C1 controls, DEL, and Unicode bidi/format controls that can spoof log lines.
_UNSAFE_CODEPOINTS = frozenset(
    list(range(0x00, 0x20)) + list(range(0x7F, 0xA0))
    + [0x061C, 0x200E, 0x200F, 0x2028, 0x2029, 0xFEFF]
    + list(range(0x202A, 0x202F)) + list(range(0x2066, 0x206A))
)


def safe_worker_text(raw: bytes, max_chars: int = MAX_LOG_TEXT_CHARS) -> str:
    """Decode untrusted worker text for logging or error strings.

    Length-capped (bytes and characters), decoded with ``errors="replace"``,
    and every control or bidi character is replaced by its ``\\xNN`` /
    ``\\uNNNN`` escape so the text cannot forge log lines or terminal output.
    """
    text = bytes(raw[:MAX_TEXT_LEN]).decode("utf-8", errors="replace")[:max_chars]
    return "".join(_escape_char(ch) for ch in text)


def _escape_char(ch: str) -> str:
    """*ch* itself, or its escape when it is a control/format character."""
    code = ord(ch)
    if code not in _UNSAFE_CODEPOINTS:
        return ch
    return f"\\x{code:02x}" if code <= 0xFF else f"\\u{code:04x}"


def encode_text(text: str, max_bytes: int = MAX_TEXT_LEN) -> bytes:
    """UTF-8 *text* truncated to *max_bytes* (worker side, best effort)."""
    return text.encode("utf-8", errors="replace")[:max_bytes]


def pack_i64(value: int) -> bytes:
    """8-byte big-endian signed integer (context params helper)."""
    return struct.pack("!q", value)


def unpack_i64(data: bytes) -> int | None:
    """Inverse of :func:`pack_i64`; None when *data* is not 8 bytes."""
    if len(data) != 8:
        return None
    return struct.unpack("!q", data)[0]


# --- Compact binary lists (qpack_decoder replies) ------------------------------
#
# header list: u32 count, then per field: u32 name_len, name, u32 value_len, value
# stream ids:  u32 count, then count x u64
# Both are decoded strictly: every length checked, caps enforced, no trailing bytes.

_U32 = struct.Struct("!I")
_U64 = struct.Struct("!Q")


def header_list_wire_cap(max_count: int, max_bytes: int) -> int:
    """Largest encoding of a list within *max_count* fields / *max_bytes* bytes."""
    return _U32.size + max_count * 2 * _U32.size + max_bytes


def encode_header_list(headers) -> bytes:
    """Serialise ``[(name, value), ...]`` (bytes-like) as a header list."""
    parts = [_U32.pack(len(headers))]
    for name, value in headers:
        name, value = bytes(name), bytes(value)
        parts += (_U32.pack(len(name)), name, _U32.pack(len(value)), value)
    return b"".join(parts)


def decode_header_list(data: bytes, max_count: int, max_bytes: int,
                       ) -> list[tuple[bytes, bytes]]:
    """Strict inverse of :func:`encode_header_list`; raise ProtocolError."""
    count, offset = _read_u32(data, 0)
    if count > max_count:
        raise ProtocolError(f"header list has {count} fields (cap {max_count})")
    headers, total = [], 0
    for _ in range(count):
        name, offset = _read_blob(data, offset)
        value, offset = _read_blob(data, offset)
        total += len(name) + len(value)
        if total > max_bytes:
            raise ProtocolError(f"header list exceeds {max_bytes} bytes")
        headers.append((name, value))
    if offset != len(data):
        raise ProtocolError("trailing bytes after the header list")
    return headers


def encode_u64_list(values) -> bytes:
    """Serialise non-negative integers as a stream-id list."""
    return _U32.pack(len(values)) + b"".join(_U64.pack(v) for v in values)


def decode_u64_list(data: bytes, max_count: int) -> list[int]:
    """Strict inverse of :func:`encode_u64_list`; raise ProtocolError."""
    count, offset = _read_u32(data, 0)
    if count > max_count:
        raise ProtocolError(f"id list has {count} entries (cap {max_count})")
    if len(data) != offset + count * _U64.size:
        raise ProtocolError("id list length does not match its count")
    return [_U64.unpack_from(data, offset + i * _U64.size)[0] for i in range(count)]


def _read_u32(data: bytes, offset: int) -> tuple[int, int]:
    if offset + _U32.size > len(data):
        raise ProtocolError("truncated length field")
    return _U32.unpack_from(data, offset)[0], offset + _U32.size


def _read_blob(data: bytes, offset: int) -> tuple[bytes, int]:
    length, offset = _read_u32(data, offset)
    end = offset + length
    if end > len(data):
        raise ProtocolError("field runs past the end of the list")
    return bytes(data[offset:end]), end


def pack_u64(value: int) -> bytes:
    """8-byte big-endian unsigned integer."""
    return _U64.pack(value)


def unpack_u64_prefix(data: bytes) -> tuple[int, bytes] | None:
    """``(value, rest)`` for data starting with a u64; None when too short."""
    if len(data) < _U64.size:
        return None
    return _U64.unpack_from(data)[0], bytes(data[_U64.size:])
