"""Tests for the shared viewer decode ``decode_protobuf_view`` and schema helpers.

Schema decoding needs ``google.protobuf`` (``pip install fritap[proto]``) and,
for ``.proto`` sources, ``protoc`` on PATH; those cases skip otherwise.
"""

from __future__ import annotations

import gzip
import importlib.machinery
import json
import random
import shutil
import struct
import subprocess
import sys
import types

import pytest

from friTap.parsers.protobuf import (
    ProtobufView,
    blackbox_available,
    decode_protobuf_view,
)
from friTap.parsers.protobuf.schema import (
    SchemaError,
    _compile_proto_cached,
    compile_proto,
)

MSG = b"\x08\x96\x01\x12\x07[/x] ok"
MSG_TEXT = '1: 150\n2: "[/x] ok"'
HAVE_PROTOC = shutil.which("protoc") is not None
needs_protoc = pytest.mark.skipif(not HAVE_PROTOC, reason="protoc not on PATH")


def frame(payload: bytes, compressed: int = 0) -> bytes:
    return bytes([compressed]) + struct.pack(">I", len(payload)) + payload


@pytest.fixture
def no_blackbox(monkeypatch):
    monkeypatch.setitem(sys.modules, "blackboxprotobuf", None)


@pytest.fixture
def fake_blackbox(monkeypatch):
    module = types.ModuleType("blackboxprotobuf")
    module.__spec__ = importlib.machinery.ModuleSpec("blackboxprotobuf", None)
    module.decode_message = lambda data: ({"1": len(data)}, {"1": {"type": "int"}})
    monkeypatch.setitem(sys.modules, "blackboxprotobuf", module)
    return module


@pytest.fixture
def proto_dir(tmp_path):
    (tmp_path / "common.proto").write_text(
        'syntax = "proto3";\npackage common;\nmessage Meta { string tag = 1; }\n'
    )
    (tmp_path / "demo.proto").write_text(
        'syntax = "proto3";\npackage demo;\nimport "common.proto";\n'
        "message Hello { int32 id = 1; string name = 2; common.Meta meta = 3; }\n"
    )
    _compile_proto_cached.cache_clear()
    return tmp_path


# ── Framing ──────────────────────────────────────────────────────


def test_bare_protobuf():
    view = decode_protobuf_view(MSG)
    assert (view.mode, view.framing, view.notes, view.error) == ("wire", "none", [], "")
    assert view.text() == MSG_TEXT
    assert view.ok


def test_grpc_detected_from_content_type():
    view = decode_protobuf_view(frame(MSG) + frame(b"\x08\x01"),
                                content_type="application/grpc+proto")
    assert view.framing == "grpc"
    assert [m.index for m in view.messages] == [1, 2]
    assert view.text().splitlines()[0] == "--- gRPC message 1 (12 bytes) ---"


def test_grpc_mode_false_overrides_content_type():
    data = frame(MSG)
    view = decode_protobuf_view(data, grpc_mode=False, content_type="application/grpc")
    assert view.framing == "none"


def test_forced_grpc_on_unframed_body_falls_back_to_bare():
    view = decode_protobuf_view(MSG, grpc_mode=True)
    assert view.framing == "grpc-invalid"
    assert "not valid gRPC framing" in view.notes[0]
    assert view.messages[0].text == MSG_TEXT


def test_grpc_is_not_stripped_blindly():
    """The old preview dropped 5 bytes whatever they were."""
    view = decode_protobuf_view(MSG, grpc_mode=True)
    assert '"[/x] ok"' in view.text()


def test_grpc_truncated_last_frame_is_noted_and_partially_decoded():
    data = frame(MSG) + frame(MSG + b"\x18\x05")[:10]
    view = decode_protobuf_view(data, grpc_mode=True)
    assert any("truncated gRPC payload" in n for n in view.notes)
    last = view.messages[-1]
    assert last.truncated and "truncated" in last.header()
    assert last.text == "1: 150"
    assert last.error


def test_grpc_frame_without_payload_bytes():
    view = decode_protobuf_view(frame(MSG) + frame(MSG)[:5], grpc_mode=True)
    assert view.messages[-1].error == "no payload bytes captured"


def test_compressed_grpc_message_is_inflated():
    view = decode_protobuf_view(frame(gzip.compress(MSG), 1), grpc_mode=True,
                                grpc_encoding="gzip")
    message = view.messages[0]
    assert message.compressed and message.text == MSG_TEXT and message.notes == []


def test_compressed_grpc_message_with_unsupported_encoding():
    view = decode_protobuf_view(frame(b"xx", 1), grpc_mode=True, grpc_encoding="snappy")
    message = view.messages[0]
    assert message.text == "" and "unsupported grpc-encoding" in message.error
    assert not view.ok


# ── Input shaping and errors ─────────────────────────────────────


def test_empty_input_is_an_error():
    view = decode_protobuf_view(b"")
    assert view.error == "no data to decode" and view.messages == [] and not view.ok


def test_preview_cap_notes_and_marks_truncation():
    view = decode_protobuf_view(MSG * 10, max_input_bytes=20)
    assert view.notes == ["preview limited to the first 20 of 120 bytes"]
    assert view.messages[0].truncated
    assert view.messages[0].text.startswith("1: 150")


def test_unknown_backend_raises():
    with pytest.raises(ValueError, match="unknown protobuf backend"):
        decode_protobuf_view(MSG, backend="nope")


def test_garbage_reports_error():
    view = decode_protobuf_view(b"\x00\xff\xff")
    assert view.messages[0].error and not view.ok


def test_never_raises_on_random_input():
    rng = random.Random(3)
    for _ in range(1000):
        data = bytes(rng.randrange(256) for _ in range(rng.randrange(60)))
        view = decode_protobuf_view(data, grpc_mode=rng.choice([None, True]),
                                    max_input_bytes=rng.choice([None, 16]))
        assert isinstance(view.text(), str)


def test_text_is_plain_and_kinds_are_tagged():
    view = decode_protobuf_view(MSG, grpc_mode=True)
    kinds = [line.kind for line in view.lines()]
    assert kinds == ["note", "body", "body"]
    assert view.text().startswith("note: not valid gRPC framing")


def test_view_dataclass_defaults():
    assert ProtobufView().text() == ""


# ── blackbox backend (opt-in) ────────────────────────────────────


def test_blackbox_missing_falls_back_to_wire_with_install_hint(no_blackbox):
    assert not blackbox_available()
    view = decode_protobuf_view(MSG, backend="blackbox")
    assert view.mode == "wire"
    assert "pip install fritap[proto]" in view.notes[0]
    assert view.messages[0].text == MSG_TEXT


def test_blackbox_backend_used_when_importable(fake_blackbox):
    assert blackbox_available()
    view = decode_protobuf_view(frame(MSG), grpc_mode=True, backend="blackbox")
    assert view.mode == "blackbox"
    assert json.loads(view.messages[0].text) == {"1": len(MSG)}


def test_blackbox_failure_falls_back_per_message(fake_blackbox):
    def boom(data):
        raise ValueError("bad")
    fake_blackbox.decode_message = boom
    view = decode_protobuf_view(MSG, backend="blackbox")
    assert "blackbox decode failed (bad)" in view.messages[0].notes[0]
    assert view.messages[0].text == MSG_TEXT


def test_wire_backend_ignores_installed_blackbox(fake_blackbox):
    assert decode_protobuf_view(MSG).mode == "wire"


# ── Schema handling ──────────────────────────────────────────────


def test_schema_without_message_type_notes_and_uses_wire():
    view = decode_protobuf_view(MSG, schema_path="/x.proto")
    assert view.mode == "wire" and "needs both" in view.notes[0]


def test_schema_without_protobuf_package_notes_install_hint(monkeypatch):
    monkeypatch.setitem(sys.modules, "google.protobuf", None)
    view = decode_protobuf_view(MSG, schema_path="/x.proto", message_type="a.B")
    assert view.mode == "wire" and "pip install fritap[proto]" in view.notes[0]
    assert view.messages[0].text == MSG_TEXT


@needs_protoc
def test_compile_proto_includes_imports_and_caches(proto_dir):
    raw = compile_proto(proto_dir / "demo.proto")
    assert b"common.proto" in raw and b"demo.proto" in raw
    compile_proto(proto_dir / "demo.proto")
    assert _compile_proto_cached.cache_info().hits == 1


@needs_protoc
def test_compile_proto_recompiles_after_edit(proto_dir):
    path = proto_dir / "demo.proto"
    compile_proto(path)
    path.write_text(path.read_text() + "message Extra { int32 x = 1; }\n")
    assert b"Extra" in compile_proto(path)
    assert _compile_proto_cached.cache_info().misses == 2


@needs_protoc
def test_compile_proto_error_carries_stderr(tmp_path):
    bad = tmp_path / "bad.proto"
    bad.write_text("syntax = \"proto3\"; message {")
    with pytest.raises(SchemaError) as info:
        compile_proto(bad)
    assert info.value.stderr and "bad.proto" in info.value.stderr


@needs_protoc
def test_compile_proto_recompiles_after_import_edit(proto_dir):
    compile_proto(proto_dir / "demo.proto")
    common = proto_dir / "common.proto"
    common.write_text(common.read_text() + "message Imported { int32 x = 1; }\n")
    assert b"Imported" in compile_proto(proto_dir / "demo.proto")
    assert _compile_proto_cached.cache_info().misses == 2


@needs_protoc
def test_compile_proto_import_from_include_path_invalidates(tmp_path):
    lib = tmp_path / "lib"
    lib.mkdir()
    (lib / "dep.proto").write_text('syntax = "proto3";\nmessage Dep { int32 a = 1; }\n')
    main = tmp_path / "main.proto"
    main.write_text('syntax = "proto3";\nimport "dep.proto";\nmessage M { Dep d = 1; }\n')
    _compile_proto_cached.cache_clear()
    compile_proto(main, include_paths=[lib])
    compile_proto(main, include_paths=[lib])
    (lib / "dep.proto").write_text(
        'syntax = "proto3";\nmessage Dep { int32 a = 1; }\nmessage NewDep {}\n')
    assert b"NewDep" in compile_proto(main, include_paths=[lib])
    assert _compile_proto_cached.cache_info()[:2] == (1, 2)


@needs_protoc
def test_compile_proto_failure_is_cached_until_fixed(proto_dir, monkeypatch):
    path = proto_dir / "demo.proto"
    original = path.read_text()
    path.write_text(original + "message {\n")
    runs = []
    real_run = subprocess.run
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: runs.append(1) or real_run(*a, **k))
    errors = []
    for _ in range(3):
        with pytest.raises(SchemaError) as info:
            compile_proto(path)
        errors.append((str(info.value), info.value.stderr))
    assert len(runs) == 1 and errors[0] == errors[1] == errors[2]
    path.write_text(original + "message Fixed {}\n")
    assert b"Fixed" in compile_proto(path)
    assert len(runs) == 2


@needs_protoc
def test_compile_proto_failure_in_import_is_cached_until_import_fixed(proto_dir):
    common = proto_dir / "common.proto"
    good = common.read_text()
    common.write_text('syntax = "proto3";\npackage common;\n')  # Meta removed
    for _ in range(2):
        with pytest.raises(SchemaError):
            compile_proto(proto_dir / "demo.proto")
    assert _compile_proto_cached.cache_info()[:2] == (1, 1)
    common.write_text(good)
    assert b"common.proto" in compile_proto(proto_dir / "demo.proto")


@needs_protoc
def test_compile_proto_missing_import_recovers_when_created(proto_dir):
    common = proto_dir / "common.proto"
    good = common.read_text()
    common.unlink()
    with pytest.raises(SchemaError):
        compile_proto(proto_dir / "demo.proto")
    common.write_text(good)
    assert b"common.proto" in compile_proto(proto_dir / "demo.proto")


def test_compile_proto_without_protoc(proto_dir, monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda name: None)
    with pytest.raises(SchemaError, match="protoc not found"):
        compile_proto(proto_dir / "demo.proto")


def test_compile_proto_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        compile_proto(tmp_path / "missing.proto")


@needs_protoc
def test_schema_decode_with_proto_source(proto_dir):
    pytest.importorskip("google.protobuf")
    data = MSG + b"\x1a\x03\x0a\x01t\x28\x05"  # meta {tag: "t"} + unknown field 5
    view = decode_protobuf_view(data, schema_path=str(proto_dir / "demo.proto"),
                                message_type="demo.Hello")
    assert view.mode == "schema"
    text = view.messages[0].text
    assert 'name: "[/x] ok"' in text and 'tag: "t"' in text
    assert "5: 5" in text  # unknown fields are shown


@needs_protoc
def test_schema_decode_with_descriptor_set(proto_dir):
    pytest.importorskip("google.protobuf")
    desc = proto_dir / "demo.desc"
    desc.write_bytes(compile_proto(proto_dir / "demo.proto"))
    view = decode_protobuf_view(MSG, schema_path=str(desc), message_type="demo.Hello")
    assert view.mode == "schema" and "id: 150" in view.messages[0].text


@needs_protoc
def test_schema_unknown_message_type_falls_back(proto_dir):
    pytest.importorskip("google.protobuf")
    view = decode_protobuf_view(MSG, schema_path=str(proto_dir / "demo.proto"),
                                message_type="demo.Nope")
    assert view.mode == "wire" and "schema not loaded" in view.notes[0]
    assert view.messages[0].text == MSG_TEXT


@needs_protoc
def test_schema_decode_failure_falls_back_per_message(proto_dir):
    pytest.importorskip("google.protobuf")
    view = decode_protobuf_view(b"\x08", schema_path=str(proto_dir / "demo.proto"),
                                message_type="demo.Hello")
    message = view.messages[0]
    assert "schema decode failed" in message.notes[0]
    assert "truncated varint" in message.error


@needs_protoc
def test_schema_skipped_for_truncated_payload(proto_dir):
    pytest.importorskip("google.protobuf")
    view = decode_protobuf_view(MSG * 4, schema_path=str(proto_dir / "demo.proto"),
                                message_type="demo.Hello", max_input_bytes=14)
    assert "message is truncated; schema decode skipped" in view.messages[0].notes[0]
