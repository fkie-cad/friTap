"""Shared builders and test doubles for the display-filter tests.

Pure Python — no device/Frida.
"""

from __future__ import annotations

from types import SimpleNamespace

from friTap.filter import FilterEngine
from friTap.flow.models import Flow
from friTap.parsers.base import ParseResult
from friTap.schemas.canonical import DataCanonical, Direction, Endpoint


def summary_row(protocols=(), attrs=None, **extra):
    """Duck-typed summary row carrying precomputed filter data."""
    base = dict(
        filter_attrs=attrs or {}, protocols=frozenset(protocols),
        request=None, response=None, detected_protocol="", ssl_session_id="",
        transport="", outer_app_protocol="", inner_e2e_protocol="",
        inner_summary="", flow_method="", process_name="", tls_sni="",
        tls_alpn="", src_addr="", dst_addr="", src_port=0, dst_port=0,
    )
    base.update(extra)
    return SimpleNamespace(**base)


def tg_message(method, body, *, kind="text", peer_id=0, user_id=0, sender="",
               **overrides) -> dict:
    """Message dict in the exact shape ``_parsed_mtproto_to_dicts`` emits."""
    message = {
        "sender": sender, "direction": "read", "timestamp": 1.0, "kind": kind,
        "body": body, "method": method, "attachments": False, "quote": False,
        "reaction": False, "peer_id": peer_id, "user_id": user_id,
    }
    message.update(overrides)
    return message


def http_flow(protocol="HTTP/1.1", method="GET", host="example.com",
              status=200, src="10.0.0.1", dst="1.2.3.4", dport=443,
              *, with_response=True) -> Flow:
    """An HTTP flow with a parsed request (and, by default, a response)."""
    flow = Flow(flow_id="h1", connection_id="c2", src_addr=src, dst_addr=dst,
                src_port=50000, dst_port=dport)
    flow.request = ParseResult(protocol=protocol, method=method, host=host,
                               url="/x", is_request=True)
    if with_response:
        flow.response = ParseResult(protocol=protocol, status_code=status,
                                    is_request=False)
    return flow


def data_event(protocol="ssh", dst_port=443) -> DataCanonical:
    """A headless data event (``DataCanonical``) for *protocol*."""
    return DataCanonical(data=b"x", direction=Direction.READ,
                         src=Endpoint("10.0.0.1", 1234),
                         dst=Endpoint("1.2.3.4", dst_port), protocol=protocol)


class FakeCtx:
    """Evaluation context: returns lowercased content bytes, counts calls."""

    def __init__(self, text: bytes | None):
        self._text = text.lower() if text is not None else None
        self.calls = 0

    def text_for(self, obj):
        self.calls += 1
        return self._text


def match(expr, obj, ctx=None) -> bool:
    return FilterEngine(expr).matches(obj, ctx)
