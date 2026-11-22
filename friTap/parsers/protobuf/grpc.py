"""gRPC length-prefixed framing support.

gRPC messages are framed with a 5-byte header:
  - 1 byte: compressed flag (0 = uncompressed, 1 = compressed)
  - 4 bytes: big-endian payload length

This module strips that framing to extract the raw protobuf payloads.

Reference: https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md
"""

from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass
from typing import Optional

from friTap.parsers.decompress import (
    MAX_INFLATE,
    InflateLimitError,
    decompress_body,
    inflate_bounded_checked,
)

PROTOBUF_CONTENT_TYPES = frozenset({
    "application/x-protobuf",
    "application/protobuf",
    "application/vnd.google.protobuf",
    "application/x-google-protobuf",
})

_GRPC_HEADER_SIZE = 5  # 1 byte flag + 4 bytes length

#: Most gRPC frames split out of one body; the rest is left unsplit.
MAX_GRPC_FRAMES_PER_BODY = 1000

#: Total decompressed bytes allowed across all compressed frames of one body.
MAX_GRPC_INFLATE_PER_BODY = 64 * 1024 * 1024

_UNSUPPORTED_ENCODING_PREFIX = "unsupported grpc-encoding"

#: Note reported when :data:`MAX_GRPC_FRAMES_PER_BODY` stopped the split.
GRPC_FRAME_LIMIT_NOTE = (
    f"gRPC frame limit ({MAX_GRPC_FRAMES_PER_BODY}) reached; remaining frames not split"
)

#: Note (``{label}`` = encoding) for a gzip/zlib message whose stream ends
#: before its end marker: the partial output is kept, flagged by this note.
GRPC_INFLATE_TRUNCATED_NOTE_FMT = "{label} stream truncated (partial inflate)"

_GUESSED_ENCODING_NOTE = (
    "compressed gRPC message without grpc-encoding; inflated as gzip/zlib"
)


@dataclass
class GrpcFrame:
    """A single gRPC framed message."""
    compressed: bool
    payload: bytes
    #: Set only by :func:`split_grpc_frames_lenient` for a final frame whose
    #: payload is shorter than its declared length.
    truncated: bool = False


def is_protobuf_content_type(content_type: str) -> bool:
    """True if *content_type* indicates protobuf (not gRPC)."""
    if not content_type:
        return False
    ct = content_type.lower().split(";")[0].strip()
    return ct in PROTOBUF_CONTENT_TYPES


def is_grpc_content_type(content_type: str) -> bool:
    """True if *content_type* indicates gRPC (``application/grpc``, ``+proto``, ``+json``, ...)."""
    if not content_type:
        return False
    ct = content_type.lower().split(";")[0].strip()
    return ct.startswith("application/grpc")


def strip_grpc_frame(data: bytes) -> list[GrpcFrame]:
    """Strip gRPC framing from *data* (possibly several concatenated frames); raises ValueError if malformed or truncated."""
    return [frame for frame, _ in strip_grpc_frame_with_end(data)]


def _read_grpc_header(data: bytes, offset: int) -> tuple[int, int]:
    """Validate the 5-byte header at *offset*: ``(compressed_flag, length)``; ValueError on a short header or a flag other than 0/1."""
    if offset + _GRPC_HEADER_SIZE > len(data):
        raise ValueError(
            f"truncated gRPC frame header at offset {offset}, "
            f"need {_GRPC_HEADER_SIZE} bytes but only {len(data) - offset} remain"
        )
    compressed_flag = data[offset]
    if compressed_flag not in (0, 1):
        raise ValueError(
            f"invalid gRPC compressed flag {compressed_flag} at offset {offset}"
        )
    return compressed_flag, struct.unpack(">I", data[offset + 1:offset + 5])[0]


def strip_grpc_frame_with_end(data: bytes) -> list[tuple[GrpcFrame, int]]:
    """Like :func:`strip_grpc_frame`, pairing each frame with its exclusive end offset in *data* (header included).

    Hitting :data:`MAX_GRPC_FRAMES_PER_BODY` is not an error: frames so far are returned.
    """
    frames, error = _walk_grpc_frames(data)
    if error and error != GRPC_FRAME_LIMIT_NOTE:
        raise ValueError(error)
    return frames


def split_grpc_frames_lenient(data: bytes) -> tuple[list[GrpcFrame], str]:
    """Split frames like :func:`strip_grpc_frame` but never raise; returns ``(frames, error)``.

    A final frame cut short (e.g. by a preview cap) is kept with ``truncated=True``.
    *error* is empty on a clean split, :data:`GRPC_FRAME_LIMIT_NOTE` if the frame cap stopped it.
    """
    frames, error = _walk_grpc_frames(data)
    return [frame for frame, _ in frames], error


def _walk_grpc_frames(data: bytes) -> tuple[list[tuple[GrpcFrame, int]], str]:
    """The single frame walker: ``(frames_with_end, error)``, collected up to the first problem.

    A cut-short final frame is included with ``truncated=True`` (strict callers raise
    on *error* first). At most :data:`MAX_GRPC_FRAMES_PER_BODY` frames.
    """
    frames: list[tuple[GrpcFrame, int]] = []
    offset = 0
    while offset < len(data):
        if len(frames) >= MAX_GRPC_FRAMES_PER_BODY:
            return frames, GRPC_FRAME_LIMIT_NOTE
        try:
            compressed_flag, payload_len = _read_grpc_header(data, offset)
        except ValueError as exc:
            return frames, str(exc)
        start = offset + _GRPC_HEADER_SIZE
        payload = data[start:start + payload_len]
        offset = start + len(payload)
        if len(payload) < payload_len:
            frames.append((GrpcFrame(bool(compressed_flag), payload, truncated=True), offset))
            return frames, (
                f"truncated gRPC payload at offset {start}, "
                f"need {payload_len} bytes but only {len(payload)} remain"
            )
        frames.append((GrpcFrame(bool(compressed_flag), payload), offset))
    return frames, ""


class InflateBudget:
    """Decompressed-byte allowance shared by all frames of one gRPC body."""

    __slots__ = ("remaining",)

    def __init__(self, limit: int = MAX_GRPC_INFLATE_PER_BODY) -> None:
        self.remaining = limit

    def per_message_limit(self) -> int:
        """Output cap for the next message: the per-message and remaining body caps."""
        return max(0, min(MAX_INFLATE, self.remaining))

    def spend(self, produced: int) -> None:
        self.remaining -= produced


def decompress_grpc_payload(
    payload: bytes, grpc_encoding: str, budget: Optional[InflateBudget] = None,
) -> tuple[Optional[bytes], str]:
    """Decompress one compressed message per ``grpc-encoding``.

    A shared *budget* (one per body) also bounds the output by what is left of
    :data:`MAX_GRPC_INFLATE_PER_BODY` and is charged; exhausted yields ``(None, reason)``.
    """
    if budget is None:
        return _decompress_grpc_bounded(payload, grpc_encoding, MAX_INFLATE)
    limit = budget.per_message_limit()
    if limit <= 0:
        return None, (
            f"gRPC body decompression budget ({MAX_GRPC_INFLATE_PER_BODY} bytes) "
            "exhausted; message left compressed"
        )
    data, note = _decompress_grpc_bounded(payload, grpc_encoding, limit)
    budget.spend(_inflate_cost(data, note, limit))
    return data, note


def _inflate_cost(data: Optional[bytes], note: str, limit: int) -> int:
    """Bytes to charge for one attempt: the output, or *limit* if it failed.

    A failed attempt may have inflated up to *limit* (decompression bomb), so it is
    charged in full; only an unsupported encoding is free.
    """
    if data is not None:
        return len(data)
    return 0 if note.startswith(_UNSUPPORTED_ENCODING_PREFIX) else limit


def _decompress_grpc_bounded(
    payload: bytes, grpc_encoding: str, max_out: int,
) -> tuple[Optional[bytes], str]:
    """Decompress one message to at most *max_out* bytes; returns ``(data, note)``.

    gzip/deflate use ``inflate_bounded_checked``, zstd/br use ``decompress_body``.
    No encoding (or ``identity``, contradicting the flag) tries gzip/zlib as a guess.
    *data* is None on failure with *note* saying why; on success *note* is non-empty
    only for a guessed encoding or a truncated stream (notes joined with ``"; "``).
    """
    encoding = (grpc_encoding or "").lower().strip()
    if encoding in ("gzip", "deflate"):
        return _inflate_grpc(payload, encoding, max_out)
    if encoding in ("zstd", "br"):
        data, error = decompress_body(payload, encoding, max_out=max_out)
        return (None, f"{encoding} decompression failed: {error}") if error else (data, "")
    if encoding in ("", "identity"):
        data, note = _inflate_grpc(payload, "gzip/zlib", max_out)
        if data is None:
            return None, "compressed gRPC message without a usable grpc-encoding; " + note
        return data, _join_notes(_GUESSED_ENCODING_NOTE, note)
    return None, f"{_UNSUPPORTED_ENCODING_PREFIX} {encoding!r}; message left compressed"


def _inflate_grpc(
    payload: bytes, label: str, max_out: int = MAX_INFLATE,
) -> tuple[Optional[bytes], str]:
    """Bounded gzip/zlib inflate: ``(data, note)`` or ``(None, reason)``.

    Never produces more than *max_out* bytes; a truncated stream keeps its partial
    output with :data:`GRPC_INFLATE_TRUNCATED_NOTE_FMT` as the note.
    """
    try:
        data, complete = inflate_bounded_checked(payload, limit=max_out)
    except (zlib.error, InflateLimitError) as exc:
        return None, f"{label} decompression failed: {exc}"
    if complete:
        return data, ""
    return data, GRPC_INFLATE_TRUNCATED_NOTE_FMT.format(label=label)


def _join_notes(*notes: str) -> str:
    """The non-empty *notes* joined with ``"; "``."""
    return "; ".join(note for note in notes if note)


def extract_grpc_messages(body: bytes, content_type: str) -> list[bytes]:
    """Extract protobuf payloads from a body: strip framing for gRPC types, else return ``[body]``.

    Compressed frames are returned as-is with a warning logged.
    """
    if not is_grpc_content_type(content_type):
        return [body] if body else []

    if not body:
        return []

    try:
        frames = strip_grpc_frame(body)
    except ValueError:
        # Framing failed -- return body as-is for raw decode attempt
        return [body]

    # Compressed frames are passed through as-is (decompression algorithm unknown)
    payloads: list[bytes] = []
    for frame in frames:
        payloads.append(frame.payload)

    return payloads


def is_grpc_frame(data: bytes) -> bool:
    """Heuristic: first byte is 0 or 1 and the declared length fits *data*."""
    if not data:
        return False
    try:
        _flag, payload_len = _read_grpc_header(data, 0)
    except ValueError:
        return False
    # Payload length should be reasonable and not exceed total data
    return payload_len <= len(data) - _GRPC_HEADER_SIZE
