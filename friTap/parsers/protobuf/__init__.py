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

    # One decode for every viewer: validated gRPC framing, decompression,
    # optional schema / blackboxprotobuf backend, plain-text output.
    from friTap.parsers.protobuf import decode_protobuf_view
    print(decode_protobuf_view(grpc_body, content_type="application/grpc").text())
"""

from .grpc import (
    PROTOBUF_CONTENT_TYPES,
    GrpcFrame,
    decompress_grpc_payload,
    extract_grpc_messages,
    is_grpc_content_type,
    is_grpc_frame,
    is_protobuf_content_type,
    split_grpc_frames_lenient,
    strip_grpc_frame,
)
from .processor import ProtobufProcessor
from .view import (
    DecodedProtobufMessage,
    ProtobufView,
    blackbox_available,
    decode_protobuf_view,
)
from .wire import (
    ProtobufField,
    ProtobufMessage,
    WireType,
    decode_protobuf_varint,
    decode_raw,
    decode_raw_lenient,
    decode_varint,
    format_message,
    is_likely_protobuf,
)

__all__ = [
    # Wire format
    "decode_raw",
    "decode_raw_lenient",
    "decode_varint",
    "decode_protobuf_varint",
    "format_message",
    "is_likely_protobuf",
    "ProtobufField",
    "ProtobufMessage",
    "WireType",
    # gRPC
    "decompress_grpc_payload",
    "extract_grpc_messages",
    "is_grpc_content_type",
    "is_grpc_frame",
    "is_protobuf_content_type",
    "PROTOBUF_CONTENT_TYPES",
    "split_grpc_frames_lenient",
    "strip_grpc_frame",
    "GrpcFrame",
    # Processor
    "ProtobufProcessor",
    # Viewer decode
    "decode_protobuf_view",
    "blackbox_available",
    "ProtobufView",
    "DecodedProtobufMessage",
]
