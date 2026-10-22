"""``reparse_flow`` honours the flow's transport when re-picking its parser.

A non-pinned flow's main parser is re-detected from its first bytes. That
detection must pass ``flow.transport`` so restrictions apply (``quic`` ->
HTTP/3 only): a QUIC flow whose bytes happen to sniff as HTTP/1 must not be
re-parsed with Http1Parser. ``tls`` flows keep pure byte-sniffing.
"""

from friTap.flow.models import Flow, FlowChunk
from friTap.flow.reparse import reparse_flow
from friTap.parsers.http1 import Http1Parser
from friTap.parsers.registry import get_default_registry

_HTTP1_REQUEST = b"GET /next HTTP/1.1\r\nHost: example.com\r\n\r\n"
_HTTP1_RESPONSE = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
_NOISE = b"\xff\xfe\xfd\xfc\xfb\xfa\xf9\xf8"


def _flow(transport, chunks) -> Flow:
    flow = Flow(flow_id="f1", connection_id="c1", transport=transport)
    flow.chunks = [FlowChunk(data=data, direction=direction, timestamp=float(i))
                   for i, (direction, data) in enumerate(chunks)]
    return flow


def _spy_detect_transports(monkeypatch) -> list:
    """Record the ``transport`` of every registry.detect call."""
    # Patch the class, not the singleton: undoing an instance patch would leave
    # a stale bound method shadowing later class-level patches in other tests.
    registry_cls = type(get_default_registry())
    original = registry_cls.detect
    seen: list = []

    def spy(self, data, transport=None):
        seen.append(transport)
        return original(self, data, transport=transport)

    monkeypatch.setattr(registry_cls, "detect", spy)
    return seen


class TestReparseQuicTransport:
    def test_quic_flow_not_reparsed_as_http1(self):
        flow = _flow("quic", [("write", _HTTP1_REQUEST), ("read", _HTTP1_RESPONSE)])
        reparse_flow(flow)
        assert flow.display_protocol != Http1Parser.PROTOCOL
        assert not (flow.request and flow.request.protocol.startswith("HTTP/1"))

    def test_quic_alt_direction_not_reparsed_as_http1(self):
        flow = _flow("quic", [("write", _NOISE), ("read", _HTTP1_RESPONSE)])
        reparse_flow(flow)
        assert not (flow.response and flow.response.protocol.startswith("HTTP/1"))

    def test_detect_receives_flow_transport(self, monkeypatch):
        seen = _spy_detect_transports(monkeypatch)
        reparse_flow(_flow("quic", [("write", _NOISE), ("read", _NOISE)]))
        assert seen and all(t == "quic" for t in seen)


class TestReparseTlsUnchanged:
    def test_tls_flow_still_reparsed_as_http1(self):
        flow = _flow("tls", [("write", _HTTP1_REQUEST), ("read", _HTTP1_RESPONSE)])
        assert reparse_flow(flow) is True
        assert flow.request.protocol.startswith("HTTP/1")
        assert flow.response.protocol.startswith("HTTP/1")

    def test_tls_alt_direction_still_reparsed_as_http1(self):
        flow = _flow("tls", [("write", _NOISE), ("read", _HTTP1_RESPONSE)])
        assert reparse_flow(flow) is True
        assert flow.response.protocol.startswith("HTTP/1")

    def test_none_transport_still_reparsed_as_http1(self):
        flow = _flow(None, [("write", _HTTP1_REQUEST)])
        assert reparse_flow(flow) is True
        assert flow.request.protocol.startswith("HTTP/1")
