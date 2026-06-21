"""Stateless, HPACK-free HTTP/2 DATA-frame harvesting (plugin-facing).

Modern Signal (libsignal-net, 8.14.3) runs its chat socket as WebSocket *over*
HTTP/2 (SNI ``grpc.chat.signal.org``; tshark hierarchy ``http2 → websocket →
data``). To recover the WebSocket byte stream from a TLS-decrypted HTTP/2
connection we only need the DATA frames — never the HPACK-compressed HEADERS —
so this module deliberately avoids any HPACK dependency.

It mirrors the stateless DATA extraction already in
``friTap.flow.models.Flow._extract_h2_body`` but as a reusable utility that
groups DATA per stream-id (the WebSocket lives on one stream while control
frames flow on stream 0 and others).

Functions never raise: on a malformed/truncated frame they stop early and
report ``degraded=True`` so the caller can record it (``SignalStats.add_degraded``)
and still use whatever was harvested.
"""

from __future__ import annotations

from typing import Dict, Tuple

# RFC 7540 §3.5 connection preface: a client connection opens with this
# 24-byte sequence before the first SETTINGS frame. It may or may not be
# present in a TLS-follow buffer (tshark's ``follow,tls,raw`` of the client
# direction does include it; the server direction never does), so we skip it
# only when seen rather than relying on it for detection.
HTTP2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

_FRAME_HEADER_LEN = 9
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
    frame_type = buf[3]
    if frame_type > _FRAME_TYPE_MAX:
        return False
    length = int.from_bytes(buf[0:3], "big")
    # The first frame must fit in what we have. A raw WebSocket frame mis-read
    # as HTTP/2 yields an implausibly large length (its masked-length bytes land
    # in the 3-byte length field), so this rejects it.
    return _FRAME_HEADER_LEN + length <= len(buf)


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
    buf = _strip_preface(buf)
    streams: Dict[int, bytearray] = {}
    degraded = False
    offset = 0
    n = len(buf)
    # Read DATA payloads through a memoryview so concatenation copies the bytes
    # exactly once (into the per-stream bytearray) rather than allocating an
    # intermediate slice per frame — matters on multi-MB chat streams.
    view = memoryview(buf)
    while offset + _FRAME_HEADER_LEN <= n:
        length = int.from_bytes(buf[offset:offset + 3], "big")
        frame_type = buf[offset + 3]
        flags = buf[offset + 4]
        stream_id = int.from_bytes(buf[offset + 5:offset + 9], "big") & 0x7FFFFFFF
        body = offset + _FRAME_HEADER_LEN
        if frame_type > _FRAME_TYPE_MAX:
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
                    payload = b""
                else:
                    payload = payload[1:end]
            streams.setdefault(stream_id, bytearray()).extend(payload)
        offset = body + length
    if offset != n and not degraded:
        # Trailing bytes that don't form a complete header — partial frame.
        degraded = True
    return {sid: bytes(data) for sid, data in streams.items()}, degraded
