"""Stateless, HPACK-free HTTP/2 DATA-frame harvesting (plugin-facing).

Signal (libsignal-net) runs its chat socket as WebSocket over HTTP/2 (tshark:
``http2 -> websocket -> data``). Recovering that byte stream needs only the DATA
frames, never the HPACK-compressed HEADERS, so this module has no HPACK dependency.
It groups DATA per stream-id; ``friTap.flow.models.Flow._extract_h2_body`` reads
one stream via :func:`http2_data_for_stream`.

Functions never raise: on a malformed or truncated frame they stop early and
report ``degraded=True`` (``SignalStats.add_degraded``), keeping what was harvested.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple

from .http2_constants import (
    HTTP2_EXTENSION_FRAME_TYPE_NAMES,
    HTTP2_FRAME_HEADER_LEN,
    HTTP2_FRAME_TYPE_NAMES,
    HTTP2_PREFACE,
    unpack_frame_header,
)

_FRAME_HEADER_LEN = HTTP2_FRAME_HEADER_LEN
_FRAME_TYPE_DATA = 0x00
_FRAME_TYPE_MAX = 0x09  # CONTINUATION is the highest standard frame type.
_FLAG_PADDED = 0x08


def _strip_preface(buf: bytes) -> bytes:
    """Drop the 24-byte connection preface from *buf* if it leads."""
    if buf[:len(HTTP2_PREFACE)] == HTTP2_PREFACE:
        return buf[len(HTTP2_PREFACE):]
    return buf


def looks_like_http2(buf: bytes) -> bool:
    """True when *buf* begins with a parseable HTTP/2 frame.

    Skips the preface, then needs a known frame type (<= 0x09) and a length that
    fits the buffer; that rejects raw RFC 6455 WebSocket frames and HTTP/1.1 text.
    """
    buf = _strip_preface(buf)
    if len(buf) < _FRAME_HEADER_LEN:
        return False
    length, frame_type, _flags, _stream_id = unpack_frame_header(buf)
    if frame_type > _FRAME_TYPE_MAX:
        return False
    # The first frame must fit in what we have. A raw WebSocket frame mis-read
    # as HTTP/2 yields an implausibly large length (its masked-length bytes land
    # in the 3-byte length field), so this rejects it.
    return _FRAME_HEADER_LEN + length <= len(buf)


@dataclass(frozen=True)
class H2FrameHeader:
    """The first HTTP/2 frame header of a buffer; ``available`` is the payload bytes present (< ``length`` when truncated)."""

    length: int
    frame_type: int
    type_name: str
    flags: int
    stream_id: int
    available: int
    preface_skipped: bool = False

    @property
    def truncated(self) -> bool:
        """True when the buffer holds fewer payload bytes than declared."""
        return self.available < self.length


def describe_frame_header(raw: bytes) -> Optional[H2FrameHeader]:
    """Describe the first frame header in *raw*, or ``None``; never raises.

    Skips a leading preface (``PRI * HTTP/2.0`` is not a frame), requires 9 header
    bytes, accepts standard types (<= 0x09) and the extension types in
    :data:`HTTP2_EXTENSION_FRAME_TYPE_NAMES`, masks the reserved stream-id bit.
    Unlike :func:`looks_like_http2` a truncated payload is allowed.
    """
    buf = _strip_preface(raw)
    if len(buf) < _FRAME_HEADER_LEN:
        return None
    length, frame_type, flags, stream_id = unpack_frame_header(buf)
    type_name = _known_frame_type_name(frame_type)
    if type_name is None:
        return None
    return H2FrameHeader(
        length=length,
        frame_type=frame_type,
        type_name=type_name,
        flags=flags,
        stream_id=stream_id,
        available=len(buf) - _FRAME_HEADER_LEN,
        preface_skipped=len(buf) != len(raw),
    )


def _known_frame_type_name(frame_type: int) -> Optional[str]:
    """Name of a standard or registered extension frame type, else ``None``."""
    name = HTTP2_FRAME_TYPE_NAMES.get(frame_type)
    return name if name is not None else HTTP2_EXTENSION_FRAME_TYPE_NAMES.get(frame_type)


def _walk_data_frames(
    buf: bytes,
    sink: Callable[[int, memoryview, int], None],
    skip_unknown_types: bool = False,
) -> bool:
    """Feed every DATA payload in *buf* to ``sink(stream_id, payload, frame_end)``; returns ``degraded``.

    The single DATA walker: skips the preface, strips PADDED padding (flag 0x8) and
    skips non-DATA frames. Payloads are memoryview slices (callers copy once);
    ``frame_end`` is the exclusive end in the ORIGINAL *buf*. A type above 0x09 is a
    desync stop (Signal mid-stream heuristic), unless *skip_unknown_types* skips it
    (RFC 9113 §5.5; its length must still fit).
    """
    stripped = _strip_preface(buf)
    preface_len = len(buf) - len(stripped)
    buf = stripped
    degraded = False
    offset = 0
    n = len(buf)
    view = memoryview(buf)
    while offset + _FRAME_HEADER_LEN <= n:
        length, frame_type, flags, stream_id = unpack_frame_header(buf, offset)
        body = offset + _FRAME_HEADER_LEN
        if frame_type > _FRAME_TYPE_MAX and not skip_unknown_types:
            degraded = True  # desync: not a valid frame header
            break
        if body + length > n:
            degraded = True  # truncated trailing frame
            break
        if frame_type == _FRAME_TYPE_DATA:
            payload = view[body:body + length]
            if flags & _FLAG_PADDED and len(payload) >= 1:
                pad_len = payload[0]
                end = len(payload) - pad_len
                if end < 1:
                    # pad length >= frame payload — a malformed PADDED frame
                    # (RFC 7540 PROTOCOL_ERROR). Contribute no data and flag it;
                    # framing stays aligned (we still advance by the declared length).
                    degraded = True
                    payload = view[0:0]
                else:
                    payload = payload[1:end]
            sink(stream_id, payload, preface_len + body + length)
        offset = body + length
    if offset != n and not degraded:
        # Trailing bytes that don't form a complete header — partial frame.
        degraded = True
    return degraded


def group_http2_data_by_stream(buf: bytes) -> Tuple[Dict[int, bytes], bool]:
    """Concatenate DATA payloads per stream-id in arrival order: ``({stream_id: data}, degraded)``.

    Skips the preface, strips PADDED padding, ignores non-DATA frames.
    """
    streams, _ends, degraded = group_http2_data_ends_by_stream(buf)
    return streams, degraded


def group_http2_data_ends_by_stream(
    buf: bytes,
) -> Tuple[Dict[int, bytes], Dict[int, List[Tuple[int, int]]], bool]:
    """:func:`group_http2_data_by_stream` plus frame ends: ``(streams, ends, degraded)``.

    ``ends[stream_id]`` lists ``(stream_end, buf_end)`` per DATA frame, mapping a
    position in the stream back to the *buf* bytes that delivered it.
    """
    streams: Dict[int, bytearray] = {}
    ends: Dict[int, List[Tuple[int, int]]] = {}

    def collect(stream_id: int, payload: memoryview, frame_end: int) -> None:
        data = streams.setdefault(stream_id, bytearray())
        data.extend(payload)
        ends.setdefault(stream_id, []).append((len(data), frame_end))

    degraded = _walk_data_frames(buf, collect)
    return {sid: bytes(data) for sid, data in streams.items()}, ends, degraded


def http2_data_for_stream(buf: bytes, stream_id: int) -> Tuple[bytes, bool]:
    """DATA payloads of *stream_id* in arrival order: ``(data, degraded)``.

    ``stream_id == 0`` keeps every stream in wire order. Unlike the grouping
    functions, unknown frame types (> 0x09: PRIORITY_UPDATE, ALTSVC, ORIGIN, GREASE) are skipped, not a stop.
    """
    data = bytearray()

    def collect(sid: int, payload: memoryview, _frame_end: int) -> None:
        if stream_id == 0 or sid == stream_id:
            data.extend(payload)

    degraded = _walk_data_frames(buf, collect, skip_unknown_types=True)
    return bytes(data), degraded
