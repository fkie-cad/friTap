"""Protocol parsers for friTap flow mode."""

from .base import BaseParser, ParseResult
from .decompress import decompress_body
from .hexdump import HexdumpParser
from .http1 import Http1Parser
from .http2 import Http2Parser
from .http2_constants import HTTP2_PREFACE
from .http2_dataframe import (
    group_http2_data_by_stream,
    http2_data_for_stream,
    looks_like_http2,
)
from .http3 import Http3Parser
from .protobuf import (
    GrpcFrame,
    ProtobufField,
    ProtobufMessage,
    ProtobufProcessor,
    WireType,
    decode_protobuf_varint,
    decode_raw,
    extract_grpc_messages,
    format_message,
    is_grpc_content_type,
    is_grpc_frame,
    is_likely_protobuf,
    strip_grpc_frame,
)
from .registry import ParserRegistry, get_default_registry
from .varint import decode_quic_varint, decode_varint, encode_varint
from .websocket_defray import (
    WebSocketFrame,
    iter_websocket_frames,
    looks_like_websocket_frame,
    unmask,
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
    "http2_data_for_stream",
    "HTTP2_PREFACE",
    # WebSocket stateless de-framing (RFC 6455)
    "WebSocketFrame",
    "iter_websocket_frames",
    "looks_like_websocket_frame",
    "unmask",
    "decompress_body",
    "decode_varint",
    "decode_quic_varint",
    "encode_varint",
    # Protobuf
    "decode_raw",
    "decode_protobuf_varint",
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
