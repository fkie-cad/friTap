"""gRPC length-prefixed framing support.

gRPC messages are framed with a 5-byte header:
  - 1 byte: compressed flag (0 = uncompressed, 1 = compressed)
  - 4 bytes: big-endian payload length

This module strips that framing to extract the raw protobuf payloads.

Reference: https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

PROTOBUF_CONTENT_TYPES = frozenset({
    "application/x-protobuf",
    "application/protobuf",
    "application/vnd.google.protobuf",
    "application/x-google-protobuf",
})

_GRPC_HEADER_SIZE = 5  # 1 byte flag + 4 bytes length


@dataclass
class GrpcFrame:
    """A single gRPC framed message."""
    compressed: bool
    payload: bytes


def is_protobuf_content_type(content_type: str) -> bool:
    """Check if content_type indicates protobuf (not gRPC)."""
    if not content_type:
        return False
    ct = content_type.lower().split(";")[0].strip()
    return ct in PROTOBUF_CONTENT_TYPES


def is_grpc_content_type(content_type: str) -> bool:
    """Check if *content_type* indicates gRPC.

    Matches ``application/grpc``, ``application/grpc+proto``,
    ``application/grpc+json``, etc.
    """
    if not content_type:
        return False
    ct = content_type.lower().split(";")[0].strip()
    return ct.startswith("application/grpc")


def strip_grpc_frame(data: bytes) -> list[GrpcFrame]:
    """Strip gRPC length-prefixed framing from *data*.

    Handles multiple concatenated frames in a single body.

    Args:
        data: Raw gRPC body bytes.

    Returns:
        List of :class:`GrpcFrame` objects.

    Raises:
        ValueError: If the framing is malformed or truncated.
    """
    frames: list[GrpcFrame] = []
    offset = 0

    while offset < len(data):
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
        payload_len = struct.unpack(">I", data[offset + 1:offset + 5])[0]
        offset += _GRPC_HEADER_SIZE

        if offset + payload_len > len(data):
            raise ValueError(
                f"truncated gRPC payload at offset {offset}, "
                f"need {payload_len} bytes but only {len(data) - offset} remain"
            )
        payload = data[offset:offset + payload_len]
        offset += payload_len

        frames.append(GrpcFrame(
            compressed=bool(compressed_flag),
            payload=payload,
        ))

    return frames


def extract_grpc_messages(body: bytes, content_type: str) -> list[bytes]:
    """High-level extraction of protobuf payloads from a body.

    If *content_type* is a gRPC type, strips framing and returns
    the individual protobuf payloads. Otherwise returns ``[body]``
    unchanged.

    Compressed frames are returned as-is with a warning logged.

    Args:
        body: Raw HTTP body bytes.
        content_type: The ``Content-Type`` header value.

    Returns:
        List of raw protobuf payload bytes.
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
    """Heuristic check whether *data* looks like gRPC framed content.

    Checks that the first byte is 0 or 1 (compressed flag) and that
    the declared payload length is consistent with the data size.
    """
    if not data or len(data) < _GRPC_HEADER_SIZE:
        return False
    if data[0] not in (0, 1):
        return False
    payload_len = struct.unpack(">I", data[1:5])[0]
    # Payload length should be reasonable and not exceed total data
    return payload_len <= len(data) - _GRPC_HEADER_SIZE
