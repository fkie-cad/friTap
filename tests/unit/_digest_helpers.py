"""Shared synthetic ``.tap`` fixture builders for digest / agent-tool tests.

Flows are built directly from :mod:`friTap.flow.models` and written with the
real :class:`~friTap.flow.tap_writer.TapWriter`, so readers see exactly what a
capture would contain.
"""

from __future__ import annotations

import json

from friTap.flow.layers import SignalLayer
from friTap.flow.models import Flow, FlowChunk, FlowState
from friTap.flow.tap_writer import TapWriter
from friTap.parsers.base import ParseResult

CLIENT_RANDOM = "ab" * 32
MASTER_SECRET = "cd" * 48
KEYLOG_LINE = f"CLIENT_RANDOM {CLIENT_RANDOM} {MASTER_SECRET}"
EMAIL = "alice.secret@example.org"

DEFAULT_SIGNAL_MESSAGES = (
    {"direction": "write", "kind": "text", "body": "hello SECRETBODY"},
)


def http_flow(flow_id, *, host="api.example.com", method="POST", url="/v1/users/42",
              body=b"", content_type="application/json", headers=None,
              protocol="HTTP/1.1", status=200, started=1_700_000_000.0):
    """A complete HTTP flow with a parsed request and response."""
    hdrs = {"host": host, "content-type": content_type}
    hdrs.update(headers or {})
    flow = Flow(flow_id=flow_id, connection_id=flow_id, src_addr="10.0.0.1",
                src_port=50000, dst_addr="93.184.216.34", dst_port=443,
                state=FlowState.COMPLETE, started=started)
    flow.chunks.append(FlowChunk(data=b"x" * 100 + body, direction="write", timestamp=started))
    flow.request = ParseResult(protocol=protocol, method=method, url=url, host=host,
                               headers=hdrs, body=body, content_type=content_type,
                               is_complete=True)
    flow.response = ParseResult(protocol=protocol, status_code=status, is_request=False,
                                is_complete=True)
    return flow


def signal_flow(flow_id, messages=DEFAULT_SIGNAL_MESSAGES):
    """A flow carrying a :class:`SignalLayer` with the given decoded messages."""
    flow = Flow(flow_id=flow_id, connection_id=flow_id, src_addr="10.0.0.1",
                src_port=50001, dst_addr="15.197.251.99", dst_port=443,
                state=FlowState.COMPLETE, started=1_700_000_100.0)
    flow.chunks.append(FlowChunk(data=b"\x00" * 64, direction="write", timestamp=1.7e9))
    layer = SignalLayer()
    layer.messages = [dict(message) for message in messages]
    flow.add_layer(layer)
    return flow


def write_tap(path, flows, *, keylog=True):
    """Write *flows* (plus one keylog line unless ``keylog=False``) to *path*."""
    writer = TapWriter()
    writer.open(str(path), target="test")
    for flow in flows:
        writer.write_flow(flow)
    if keylog:
        writer.write_keylog(KEYLOG_LINE)
    writer.close()
    return path


def json_body(uid=7, *, email=EMAIL, tags=False):
    """A JSON request body holding PII; ``tags=True`` adds a string array."""
    payload = {"email": email, "user": {"id": uid}}
    if tags:
        payload["tags"] = ["a"]
    return json.dumps(payload).encode()
