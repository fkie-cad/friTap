"""``Flow.decode_request_protobuf`` / ``decode_response_protobuf``.

Both delegate to the shared :func:`decode_protobuf_view` after gating on the
body and content type, and return a ``ProtobufView`` (or ``None``).
"""

from __future__ import annotations

import gzip
import struct

import pytest

import friTap.parsers.protobuf.schema as schema_module
from friTap.flow.models import Flow
from friTap.parsers.base import ParseResult
from friTap.parsers.protobuf import ProtobufView

MSG = b"\x08\x96\x01\x12\x03abc"
MSG_TEXT = '1: 150\n2: "abc"'
PLAIN_TEXT = b"hello world, plain text"


def frame(payload: bytes, compressed: int = 0) -> bytes:
    return bytes([compressed]) + struct.pack(">I", len(payload)) + payload


def _flow(request: ParseResult | None = None,
          response: ParseResult | None = None) -> Flow:
    return Flow(flow_id="pb-1", connection_id="c-1", request=request, response=response)


def _message(body: bytes, content_type: str = "", **headers: str) -> ParseResult:
    headers = {k.replace("_", "-"): v for k, v in headers.items()}
    if content_type:
        headers["content-type"] = content_type
    return ParseResult(protocol="HTTP/2", body=body, headers=headers)


class FakeSchemaDecoder:
    """Records ``load_schema`` calls and renders a marker instead of decoding."""

    loaded: list[tuple[str, str]] = []

    def load_schema(self, path, message_type):
        FakeSchemaDecoder.loaded.append((str(path), message_type))

    def load_descriptor(self, path, message_type):  # pragma: no cover - must not be used
        raise AssertionError("load_descriptor must not be called")

    def decode_text(self, data: bytes) -> str:
        return f"schema-decoded {len(data)} bytes"


@pytest.fixture
def fake_schema(monkeypatch):
    FakeSchemaDecoder.loaded = []
    monkeypatch.setattr(schema_module, "SchemaDecoder", FakeSchemaDecoder)
    return FakeSchemaDecoder


def test_grpc_request_body_decodes_to_grpc_view():
    flow = _flow(request=_message(frame(MSG), "application/grpc"))
    view = flow.decode_request_protobuf()
    assert isinstance(view, ProtobufView)
    assert view.ok and view.framing == "grpc" and view.mode == "wire"
    assert view.messages[0].text == MSG_TEXT


def test_compressed_grpc_response_uses_grpc_encoding_header():
    body = frame(gzip.compress(MSG), compressed=1)
    flow = _flow(response=_message(body, "application/grpc", grpc_encoding="gzip"))
    view = flow.decode_response_protobuf()
    assert view is not None and view.framing == "grpc"
    message = view.messages[0]
    assert message.compressed and not message.error
    assert message.text == MSG_TEXT


def test_unrelated_content_type_without_force_returns_none():
    flow = _flow(request=_message(PLAIN_TEXT, "text/plain"))
    assert flow.decode_request_protobuf() is None


def test_force_decodes_regardless_of_content_type():
    flow = _flow(request=_message(MSG, "text/plain"))
    view = flow.decode_request_protobuf(force=True)
    assert view is not None and view.framing == "none"
    assert view.messages[0].text == MSG_TEXT


def test_likely_protobuf_body_decodes_without_content_type():
    view = _flow(response=_message(MSG)).decode_response_protobuf()
    assert view is not None and view.ok


def test_empty_body_returns_none_even_when_forced():
    flow = _flow(request=_message(b"", "application/grpc"))
    assert flow.decode_request_protobuf(force=True) is None
    assert _flow().decode_response_protobuf(force=True) is None


def test_schema_path_without_message_type_notes_and_falls_back_to_wire():
    flow = _flow(request=_message(MSG, "application/x-protobuf"))
    view = flow.decode_request_protobuf(schema_path="api.proto")
    assert view is not None and view.mode == "wire"
    assert any("needs both a schema file and a message type" in n for n in view.notes)
    assert view.messages[0].text == MSG_TEXT


def test_schema_path_and_message_type_reach_the_schema_decoder(fake_schema):
    flow = _flow(response=_message(frame(MSG), "application/grpc"))
    view = flow.decode_response_protobuf(schema_path="api.proto", message_type="demo.Hello")
    assert fake_schema.loaded == [("api.proto", "demo.Hello")]
    assert view is not None and view.mode == "schema"
    assert view.messages[0].text == f"schema-decoded {len(MSG)} bytes"
