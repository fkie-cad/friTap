"""Protobuf wire format decoder and gRPC framing support.

Provides schema-less decoding (zero external dependencies) and optional
schema-based decoding (requires ``google-protobuf``).

Usage::

    from friTap.parsers.protobuf import decode_raw, format_message

    msg = decode_raw(b"\\x08\\x96\\x01")
    print(format_message(msg))
    # 1: 150

    from friTap.parsers.protobuf import strip_grpc_frame
    frames = strip_grpc_frame(grpc_body)
"""

from .wire import (
    decode_raw,
    decode_varint,
    format_message,
    is_likely_protobuf,
    ProtobufField,
    ProtobufMessage,
    WireType,
)
from .grpc import (
    extract_grpc_messages,
    is_grpc_content_type,
    is_grpc_frame,
    is_protobuf_content_type,
    PROTOBUF_CONTENT_TYPES,
    strip_grpc_frame,
    GrpcFrame,
)
from .processor import ProtobufProcessor

__all__ = [
    # Wire format
    "decode_raw",
    "decode_varint",
    "format_message",
    "is_likely_protobuf",
    "ProtobufField",
    "ProtobufMessage",
    "WireType",
    # gRPC
    "extract_grpc_messages",
    "is_grpc_content_type",
    "is_grpc_frame",
    "is_protobuf_content_type",
    "PROTOBUF_CONTENT_TYPES",
    "strip_grpc_frame",
    "GrpcFrame",
    # Processor
    "ProtobufProcessor",
]
