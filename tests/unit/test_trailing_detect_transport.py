"""Trailing-data detection honours the owning flow's transport rules.

``detect_trailing_protocol`` re-enters the global parser registry for bytes
left over after a frame (Http1 101-upgrade leftovers, WebSocket tails). It
must pass the owning flow's ``transport`` so restrictions (``quic`` -> HTTP/3
only) and pins (``mtproto``) apply there too. ``transport=None`` / ``"tls"``
keep the old pure byte-sniffing behaviour.
"""

from friTap.events import EventBus
from friTap.flow.collector import FlowCollector, _ConnectionState
from friTap.parsers.base import SafeParserAdapter
from friTap.parsers.http1 import Http1Parser
from friTap.parsers.trailing import detect_trailing_protocol
from friTap.parsers.websocket import WebSocketParser

_HTTP1_REQUEST = b"GET /next HTTP/1.1\r\nHost: example.com\r\n\r\n"
# Garbage before the request forces the boundary-scan slow path.
_GARBAGE_THEN_HTTP1 = b"\xff\xfe\xfd\xfc\xfb" + _HTTP1_REQUEST
_UPGRADE_101 = (
    b"HTTP/1.1 101 Switching Protocols\r\n"
    b"Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
)
# Unmasked server text frame "hi"
_WS_TEXT_FRAME = b"\x81\x02hi"


class TestDetectTrailingProtocolTransport:
    def test_default_transport_sniffs_http1(self):
        protocol, _cleaned, parser = detect_trailing_protocol(_HTTP1_REQUEST)
        assert isinstance(parser, Http1Parser)
        assert protocol == Http1Parser.PROTOCOL

    def test_tls_transport_keeps_old_behaviour(self):
        protocol, cleaned, parser = detect_trailing_protocol(
            _GARBAGE_THEN_HTTP1, transport="tls")
        assert isinstance(parser, Http1Parser)
        assert cleaned == _HTTP1_REQUEST
        assert protocol == detect_trailing_protocol(_GARBAGE_THEN_HTTP1)[0]

    def test_quic_restriction_blocks_http1_fast_path(self):
        protocol, cleaned, parser = detect_trailing_protocol(
            _HTTP1_REQUEST, transport="quic")
        assert not isinstance(parser, Http1Parser)
        assert (protocol, cleaned, parser) == ("", _HTTP1_REQUEST, None)

    def test_default_transport_finds_http1_past_garbage(self):
        _proto, cleaned, parser = detect_trailing_protocol(_GARBAGE_THEN_HTTP1)
        assert isinstance(parser, Http1Parser)
        assert cleaned == _HTTP1_REQUEST

    def test_quic_restriction_blocks_http1_boundary_scan(self):
        protocol, cleaned, parser = detect_trailing_protocol(
            _GARBAGE_THEN_HTTP1, transport="quic")
        assert (protocol, cleaned, parser) == ("", _GARBAGE_THEN_HTTP1, None)

    def test_pinned_transport_yields_pinned_parser(self):
        from friTap.parsers.registry import get_default_registry
        pinned = get_default_registry().pinned_parser_for("mtproto")
        _proto, _c, parser = detect_trailing_protocol(
            _HTTP1_REQUEST, transport="mtproto")
        assert isinstance(parser, pinned)


class TestParsersUseTheirFlowTransport:
    def test_http1_upgrade_trailing_default(self):
        parser = Http1Parser()
        parser.feed(_UPGRADE_101 + _HTTP1_REQUEST, "read")
        assert parser.trailing_protocol == Http1Parser.PROTOCOL

    def test_http1_upgrade_trailing_on_quic_is_restricted(self):
        parser = Http1Parser()
        parser.flow_transport = "quic"
        parser.feed(_UPGRADE_101 + _HTTP1_REQUEST, "read")
        assert parser.trailing_data == _HTTP1_REQUEST
        assert parser.trailing_protocol == ""
        assert parser.trailing_sub_parse is None

    def test_websocket_trailing_default(self):
        parser = WebSocketParser()
        parser.feed(_WS_TEXT_FRAME + _HTTP1_REQUEST, "read")
        assert parser.trailing_protocol == Http1Parser.PROTOCOL

    def test_websocket_trailing_on_quic_is_restricted(self):
        parser = WebSocketParser()
        parser.flow_transport = "quic"
        parser.feed(_WS_TEXT_FRAME + _HTTP1_REQUEST, "read")
        assert parser.trailing_protocol == ""


class TestFlowTransportPlumbing:
    def test_base_parser_default_is_none(self):
        assert Http1Parser().flow_transport is None

    def test_adapter_forwards_flow_transport(self):
        inner = Http1Parser()
        adapter = SafeParserAdapter(inner)
        adapter.flow_transport = "quic"
        assert inner.flow_transport == "quic"
        assert adapter.flow_transport == "quic"

    def test_collector_wrap_stamps_connection_transport(self):
        collector = FlowCollector(event_bus=EventBus())
        conn = _ConnectionState("c1", transport="quic")
        wrapped = collector._wrap_parser(WebSocketParser(), conn)
        assert wrapped.flow_transport == "quic"

    def test_collector_wrap_without_conn_leaves_default(self):
        collector = FlowCollector(event_bus=EventBus())
        assert collector._wrap_parser(Http1Parser()).flow_transport is None

    def test_reparse_stamps_flow_transport(self, monkeypatch):
        import friTap.parsers.base as base
        from friTap.flow.models import Flow, FlowChunk
        from friTap.flow.reparse import reparse_flow

        wrapped: list = []

        class _RecordingAdapter(SafeParserAdapter):
            def __init__(self, inner, *args, **kwargs):
                super().__init__(inner, *args, **kwargs)
                wrapped.append(inner)

        monkeypatch.setattr(base, "SafeParserAdapter", _RecordingAdapter)
        flow = Flow(flow_id="f1", transport="tls")
        flow.chunks.append(FlowChunk(
            data=_HTTP1_REQUEST, direction="write", timestamp=1.0))
        reparse_flow(flow)
        assert isinstance(wrapped[0], Http1Parser)
        assert wrapped[0].flow_transport == "tls"
