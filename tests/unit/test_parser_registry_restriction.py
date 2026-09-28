"""Per-transport parser restriction in ParserRegistry (QUIC -> HTTP/3 only)."""

from friTap.parsers.base import BaseParser
from friTap.parsers.hexdump import HexdumpParser
from friTap.parsers.http1 import Http1Parser
from friTap.parsers.http2 import Http2Parser
from friTap.parsers.http3 import Http3Parser
from friTap.parsers.registry import ParserRegistry, get_default_registry
from friTap.parsers.websocket import WebSocketParser
from tests.unit._h3_helpers import control_stream_bytes

_H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + b"\x00" * 9
_UNKNOWN_H3_FRAME = b"\x21\x00\x00\x00"  # reserved/grease frame type 0x21


def _builtin_registry(restrict_quic=True) -> ParserRegistry:
    reg = ParserRegistry()
    for cls, prio in ((Http1Parser, 100), (Http2Parser, 90),
                      (WebSocketParser, 85), (Http3Parser, 80),
                      (HexdumpParser, 0)):
        reg.register(cls, priority=prio)
    if restrict_quic:
        reg.restrict_transport("quic", {Http3Parser})
    return reg


class _AnyParser(BaseParser):
    PROTOCOL = "any"

    def can_parse(self, data):
        return True

    def feed(self, data, direction, stream_id=None):
        return []

    def flush(self):
        return []


class _QuicNativeParser(_AnyParser):
    PROTOCOL = "quic-native"
    TRANSPORTS = ("quic",)


class TestQuicRestriction:
    def test_control_stream_bytes_are_sniffed_by_tcp_parsers_unrestricted(self):
        # Precondition: without the restriction this is the reported bug.
        reg = _builtin_registry(restrict_quic=False)
        assert isinstance(reg.detect(control_stream_bytes(), transport="quic"), Http2Parser)

    def test_quic_control_stream_goes_to_http3(self):
        reg = _builtin_registry()
        parser = reg.detect(control_stream_bytes(), transport="quic")
        assert isinstance(parser, Http3Parser)

    def test_quic_never_http2_or_websocket(self):
        reg = _builtin_registry()
        for data in (control_stream_bytes(), _H2_PREFACE, b"\x81\x05hello"):
            parser = reg.detect(data, transport="quic")
            assert not isinstance(parser, (Http2Parser, WebSocketParser, Http1Parser))

    def test_quic_falls_back_to_hexdump(self):
        reg = _builtin_registry()
        assert isinstance(reg.detect(_UNKNOWN_H3_FRAME, transport="quic"), HexdumpParser)

    def test_candidates_for_quic_are_allowed_only(self):
        reg = _builtin_registry()
        assert reg._candidates_for("quic") == [Http3Parser]


class TestUnrestrictedTransportsUnchanged:
    def test_blind_detect_keeps_http2_preface(self):
        assert isinstance(_builtin_registry().detect(_H2_PREFACE), Http2Parser)

    def test_tls_detect_keeps_http2_preface(self):
        reg = _builtin_registry()
        assert isinstance(reg.detect(_H2_PREFACE, transport="tls"), Http2Parser)

    def test_tls_control_stream_bytes_unchanged(self):
        reg = _builtin_registry()
        assert isinstance(reg.detect(control_stream_bytes(), transport="tls"), Http2Parser)

    def test_candidates_for_unrestricted_is_all(self):
        reg = _builtin_registry()
        assert len(reg._candidates_for("tls")) == 5
        assert len(reg._candidates_for(None)) == 5


class TestPinsAndOptIn:
    def test_pinned_transport_wins_over_restriction(self):
        reg = _builtin_registry()
        reg.pin_transport("quic", _AnyParser)
        assert isinstance(reg.detect(control_stream_bytes(), transport="quic"), _AnyParser)

    def test_transports_attribute_opts_in(self):
        reg = _builtin_registry()
        reg.register(_QuicNativeParser, priority=200)
        assert isinstance(reg.detect(b"\x21\x00", transport="quic"), _QuicNativeParser)

    def test_non_opted_in_parser_excluded_from_quic(self):
        reg = _builtin_registry()
        reg.register(_AnyParser, priority=200)
        assert isinstance(reg.detect(control_stream_bytes(), transport="quic"), Http3Parser)
        assert isinstance(reg.detect(control_stream_bytes(), transport="tls"), _AnyParser)


class TestDefaultRegistry:
    def test_default_registry_restricts_quic(self):
        reg = get_default_registry()
        assert isinstance(reg.detect(control_stream_bytes(), transport="quic"), Http3Parser)
        assert Http2Parser not in reg._candidates_for("quic")
        assert WebSocketParser not in reg._candidates_for("quic")

    def test_default_registry_telegram_pins_intact(self):
        reg = get_default_registry()
        assert reg.pinned_parser_for("mtproto") is not None
        assert reg.pinned_parser_for("telegram_e2e") is not None


class TestPinAndRestrictCoexist:
    """Pinning and restricting one transport are independent settings."""

    def test_pin_then_restrict_keeps_both(self):
        reg = _builtin_registry(restrict_quic=False)
        reg.pin_transport("quic", _AnyParser)
        reg.restrict_transport("quic", {Http3Parser})
        assert reg.pinned_parser_for("quic") is _AnyParser
        assert reg._candidates_for("quic") == [Http3Parser]
        assert isinstance(reg.detect(_H2_PREFACE, transport="quic"), _AnyParser)

    def test_restrict_then_pin_keeps_both(self):
        reg = _builtin_registry()
        reg.pin_transport("quic", _AnyParser)
        assert reg._candidates_for("quic") == [Http3Parser]
        assert reg.pinned_parser_for("quic") is _AnyParser

    def test_empty_or_unknown_transport_has_no_rule(self):
        reg = _builtin_registry()
        assert reg.pinned_parser_for("") is None
        assert reg.pinned_parser_for(None) is None
        assert len(reg._candidates_for("")) == 5
