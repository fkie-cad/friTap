"""Protobuf wire format decoder and gRPC framing support.

Schema-less decoding (no dependencies) and optional schema-based decoding
(``google-protobuf``). Entry points: ``decode_raw``, ``format_message``,
``strip_grpc_frame`` and ``decode_protobuf_view`` (one decode for every viewer:
gRPC framing, decompression, optional schema/blackboxprotobuf, text output).
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
