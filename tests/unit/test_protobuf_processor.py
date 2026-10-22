"""Characterization tests for ``ProtobufProcessor`` (the BodyPipeline step).

Pins today's behaviour so the shared viewer decoder can evolve without
changing what the body pipeline and analyzers produce.
"""

from __future__ import annotations

import json
import logging
import shutil
import struct

import pytest

from friTap.parsers.protobuf import ProtobufProcessor

MSG = b"\x08\x96\x01\x12\x03abc"


def frame(payload: bytes) -> bytes:
    return b"\x00" + struct.pack(">I", len(payload)) + payload


def test_inactive_for_unrelated_content_type():
    assert ProtobufProcessor().process(MSG, "text/plain", "") == (MSG, "text/plain", "")


def test_inactive_for_empty_body():
    assert ProtobufProcessor(force=True).process(b"", "application/grpc", "") == (
        b"", "application/grpc", "",
    )


def test_protobuf_content_type_is_decoded():
    body, ct, err = ProtobufProcessor().process(MSG, "application/x-protobuf", "")
    assert (body, ct, err) == (b'1: 150\n2: "abc"', "text/x-protobuf-decoded", "")


def test_single_grpc_message_has_no_separator():
    body, _ct, _err = ProtobufProcessor().process(frame(MSG), "application/grpc", "")
    assert body == b'1: 150\n2: "abc"'


def test_multiple_grpc_messages_are_separated():
    body, _ct, err = ProtobufProcessor().process(
        frame(MSG) + frame(b"\x08\x01"), "application/grpc", "",
    )
    assert err == ""
    assert body.decode() == (
        '--- gRPC message 1 ---\n1: 150\n2: "abc"\n'
        "--- gRPC message 2 ---\n1: 1 (signed: -1)"
    )


def test_force_decodes_any_content_type():
    body, ct, _err = ProtobufProcessor(force=True).process(MSG, "application/octet-stream", "")
    assert ct == "text/x-protobuf-decoded" and body.startswith(b"1: 150")


def test_malformed_body_is_returned_with_error():
    body, ct, err = ProtobufProcessor(force=True).process(b"\x08", "application/x-protobuf", "")
    assert (body, ct) == (b"\x08", "application/x-protobuf")
    assert err.startswith("protobuf decode failed: truncated varint")


def test_invalid_grpc_framing_decodes_whole_body():
    body, _ct, err = ProtobufProcessor().process(MSG, "application/grpc", "")
    assert err == "" and body == b'1: 150\n2: "abc"'


def test_unloadable_schema_warns_and_falls_back_to_raw(tmp_path, caplog):
    proc_logger = logging.getLogger("friTap.parsers.protobuf.processor")
    proc_logger.addHandler(caplog.handler)
    try:
        proc = ProtobufProcessor(schema_path=str(tmp_path / "missing.desc"),
                                 message_type="a.B")
    finally:
        proc_logger.removeHandler(caplog.handler)
    assert any("Failed to load protobuf schema" in r.message for r in caplog.records)
    body, _ct, err = proc.process(MSG, "application/x-protobuf", "")
    assert err == "" and body == b'1: 150\n2: "abc"'


class _FakeSchemaDecoder:
    """Stands in for ``SchemaDecoder``: records which loader was used."""

    calls: list[tuple[str, str, str]] = []

    def load_schema(self, path, message_type):
        _FakeSchemaDecoder.calls.append(("load_schema", str(path), message_type))

    def load_descriptor(self, path, message_type):
        _FakeSchemaDecoder.calls.append(("load_descriptor", str(path), message_type))

    def decode(self, data: bytes) -> dict:
        return {"size": len(data)}


def test_schema_is_loaded_via_load_schema_for_proto_sources(monkeypatch):
    import friTap.parsers.protobuf.schema as schema_module

    _FakeSchemaDecoder.calls = []
    monkeypatch.setattr(schema_module, "SchemaDecoder", _FakeSchemaDecoder)
    proc = ProtobufProcessor(schema_path="api.proto", message_type="demo.Hello")
    assert _FakeSchemaDecoder.calls == [("load_schema", "api.proto", "demo.Hello")]
    body, ct, err = proc.process(MSG, "application/x-protobuf", "")
    assert (err, ct) == ("", "text/x-protobuf-decoded")
    assert json.loads(body) == {"size": len(MSG)}


@pytest.mark.skipif(shutil.which("protoc") is None, reason="protoc not on PATH")
def test_real_proto_source_decodes_with_schema(tmp_path):
    pytest.importorskip("google.protobuf")
    from friTap.parsers.protobuf.schema import _compile_proto_cached

    _compile_proto_cached.cache_clear()
    proto = tmp_path / "demo.proto"
    proto.write_text(
        'syntax = "proto3";\npackage demo;\n'
        "message Hello { int32 id = 1; string name = 2; }\n"
    )
    proc = ProtobufProcessor(schema_path=str(proto), message_type="demo.Hello")
    body, ct, err = proc.process(MSG, "application/x-protobuf", "")
    assert (err, ct) == ("", "text/x-protobuf-decoded")
    decoded = json.loads(body)
    assert decoded.get("id") == 150 and decoded.get("name") == "abc"
