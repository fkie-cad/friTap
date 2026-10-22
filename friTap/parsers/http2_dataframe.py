"""Stateless, HPACK-free HTTP/2 DATA-frame harvesting (plugin-facing).

Modern Signal (libsignal-net, 8.14.3) runs its chat socket as WebSocket *over*
HTTP/2 (SNI ``grpc.chat.signal.org``; tshark hierarchy ``http2 → websocket →
data``). To recover the WebSocket byte stream from a TLS-decrypted HTTP/2
connection we only need the DATA frames — never the HPACK-compressed HEADERS —
so this module deliberately avoids any HPACK dependency.

It is the single stateless DATA walker: it groups DATA per stream-id (the
WebSocket lives on one stream while control frames flow on stream 0 and
others), and ``friTap.flow.models.Flow._extract_h2_body`` reads one stream
through :func:`http2_data_for_stream`.

Functions never raise: on a malformed/truncated frame they stop early and
report ``degraded=True`` so the caller can record it (``SignalStats.add_degraded``)
and still use whatever was harvested.
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

# RFC 7540 §3.5 connection preface: a client connection opens with this
# 24-byte sequence before the first SETTINGS frame. It may or may not be
# present in a TLS-follow buffer (tshark's ``follow,tls,raw`` of the client
# direction does include it; the server direction never does), so we skip it
# only when seen rather than relying on it for detection. ``HTTP2_PREFACE`` and
# :func:`unpack_frame_header` are defined in :mod:`.http2_constants` and
# re-exported here.

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
    """Return True when *buf* begins with a parseable HTTP/2 frame.

    Skips the connection preface if present, then validates the 9-byte frame
    header at offset 0: the type byte must be a known frame type (<= 0x09) and
    the declared length must not exceed the remaining buffer. This is enough to
    distinguish HTTP/2 framing from a raw RFC 6455 WebSocket frame (which would
    decode to an implausible type byte) or HTTP/1.1 text.
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
    """The first HTTP/2 frame header of a buffer (see :func:`describe_frame_header`).

    ``available`` is how many payload bytes follow the header in the buffer;
    it is smaller than ``length`` for a truncated (partially captured) frame.
    """

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
    """Describe the first HTTP/2 frame header in *raw*, or ``None``.

    Skips the connection preface if it leads (so ``PRI * HTTP/2.0`` is never
    misread as a frame of type 0x20), requires a full 9-byte header, accepts
    the standard frame types (<= 0x09) plus the registered extension types in
    :data:`HTTP2_EXTENSION_FRAME_TYPE_NAMES` (ALTSVC, ORIGIN, PRIORITY_UPDATE)
    and masks the reserved stream-id bit. Any other type is treated as
    garbage, not a frame. Unlike :func:`looks_like_http2` a truncated payload is allowed:
    ``available`` reports what is present. Never raises.
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
    """Feed every DATA payload in *buf* to ``sink(stream_id, payload, frame_end)``.

    The single HTTP/2 DATA-frame walker: skips the preface if present, honors
    the PADDED flag (0x8; the first payload byte is the pad length and the
    trailing padding is stripped) and skips non-DATA frames. Payloads are
    memoryview slices so callers copy the bytes exactly once. ``frame_end`` is
    the frame's exclusive end offset in the ORIGINAL *buf* (preface included).
    Never raises — on a bad header or a truncated trailing frame it stops.

    A frame type above 0x09 is a desync stop by default (the Signal decoder's
    mid-stream heuristic). With *skip_unknown_types* such a frame is skipped
    like any non-DATA frame (RFC 9113 §5.5: unknown types MUST be ignored);
    its declared length must still fit the buffer.

    Returns ``degraded``.
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
    """Harvest HTTP/2 DATA payloads from *buf*, grouped by stream-id.

    Walks the frame sequence (after skipping the preface if present) and
    concatenates, per stream-id and in arrival order, the payloads of every
    DATA frame (type 0x0). Honors the PADDED flag (0x8): the first payload byte
    is the pad length and the trailing padding is stripped. Non-DATA frames are
    skipped. Never raises — on a bad header or a truncated trailing frame it
    stops and returns ``degraded=True``.

    Returns ``({stream_id: concatenated_data}, degraded)``.
    """
    streams, _ends, degraded = group_http2_data_ends_by_stream(buf)
    return streams, degraded


def group_http2_data_ends_by_stream(
    buf: bytes,
) -> Tuple[Dict[int, bytes], Dict[int, List[Tuple[int, int]]], bool]:
    """:func:`group_http2_data_by_stream` plus where each DATA frame ended.

    Returns ``(streams, ends, degraded)``. ``ends[stream_id]`` lists, per DATA
    frame of that stream in arrival order, ``(stream_end, buf_end)``: the
    exclusive end of the frame's payload in the concatenated stream bytes and
    the exclusive end of the frame itself in *buf*. That lets a caller map a
    position in a stream back to the *buf* bytes (and so the capture) that
    delivered it.
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
    """Concatenate the DATA payloads of *stream_id* in *buf*, in arrival order.

    ``stream_id == 0`` means "every stream": all DATA payloads are kept in
    wire order, interleaving included. Same walk and ``degraded`` semantics as
    :func:`group_http2_data_by_stream`, except that frames of unknown type
    (> 0x09: PRIORITY_UPDATE, ALTSVC, ORIGIN, GREASE) are skipped, not a stop.

    Returns ``(data, degraded)``.
    """
    data = bytearray()

    def collect(sid: int, payload: memoryview, _frame_end: int) -> None:
        if stream_id == 0 or sid == stream_id:
            data.extend(payload)

    degraded = _walk_data_frames(buf, collect, skip_unknown_types=True)
    return bytes(data), degraded
