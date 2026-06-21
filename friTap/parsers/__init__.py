"""Protocol parsers for friTap flow mode."""

from .base import BaseParser, ParseResult
from .hexdump import HexdumpParser
from .http1 import Http1Parser
from .http2 import Http2Parser
from .http3 import Http3Parser
from .registry import ParserRegistry, get_default_registry
from .http2_dataframe import (
    looks_like_http2,
    group_http2_data_by_stream,
    HTTP2_PREFACE,
)
from .websocket_defray import (
    WebSocketFrame,
    iter_websocket_frames,
    looks_like_websocket_frame,
    unmask,
)
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
    # HTTP/2 stateless DATA harvesting (HPACK-free)
    "looks_like_http2",
    "group_http2_data_by_stream",
    "HTTP2_PREFACE",
    # WebSocket stateless de-framing (RFC 6455)
    "WebSocketFrame",
    "iter_websocket_frames",
    "looks_like_websocket_frame",
    "unmask",
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
