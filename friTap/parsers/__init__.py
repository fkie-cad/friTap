"""Protocol parsers for friTap flow mode."""

from .base import BaseParser, ParseResult
from .hexdump import HexdumpParser
from .http1 import Http1Parser
from .http2 import Http2Parser
from .http3 import Http3Parser
from .registry import ParserRegistry, get_default_registry
from .decompress import decompress_body
from .varint import decode_varint, encode_varint
from .protobuf import (
    decode_raw,
    format_message,
    is_likely_protobuf,
    ProtobufField,
    ProtobufMessage,
    WireType,
    extract_grpc_messages,
    is_grpc_content_type,
    is_grpc_frame,
    strip_grpc_frame,
    GrpcFrame,
    ProtobufProcessor,
)

__all__ = [
    "BaseParser",
    "ParseResult",
    "HexdumpParser",
    "Http1Parser",
    "Http2Parser",
    "Http3Parser",
    "ParserRegistry",
    "get_default_registry",
    "decompress_body",
    "decode_varint",
    "encode_varint",
    # Protobuf
    "decode_raw",
    "format_message",
    "is_likely_protobuf",
    "ProtobufField",
    "ProtobufMessage",
    "WireType",
    "extract_grpc_messages",
    "is_grpc_content_type",
    "is_grpc_frame",
    "strip_grpc_frame",
    "GrpcFrame",
    "ProtobufProcessor",
]
