#!/usr/bin/env python3

"""Unit tests for the remote (-H) chunked agent loader.

A remote frida-server drops the connection on any host->server message above
~128 KiB, so large scripts are staged through a bootstrap script. These tests
pin the package parsing, the wire-size bound, the ack protocol, the message
handler transparency and the backend's routing — with fakes, no frida-server.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import frida
import pytest

from friTap.backends import frida_chunked_loader as loader
from friTap.backends.base import (
    BackendInvalidArgumentError,
    BackendTimedOutError,
)
from friTap.backends.frida_backend import FridaBackend
from friTap.backends.frida_chunked_loader import (
    CHUNK_MAX_ENCODED_BYTES,
    LOADER_MESSAGE_TYPE,
    LOADER_REPLY_MARKER,
    MODE_CLASSIC,
    MODE_ESM,
    ChunkedLoadScript,
    FridaPackageError,
    build_load_plan,
    is_loader_reply,
    needs_chunked_load,
    parse_frida_package,
    split_into_chunks,
)

REPO_ROOT = Path(__file__).resolve().parents[2]


def make_package(modules, aliases=None):
    aliases = aliases or {}
    header = "📦\n"
    for name, code in modules:
        header += f"{len(code.encode('utf-8'))} {name}\n"
        header += "".join(f"↻ {alias}\n" for alias in aliases.get(name, ()))
    return header + "✄\n" + "\n✄\n".join(code for _, code in modules)


# ----------------------------------------------------------------------
# Package parsing
# ----------------------------------------------------------------------

def test_parse_single_module_package():
    modules = parse_frida_package(make_package([("/agent/a.js", "send(1);\n")]))
    assert [(m.name, m.code) for m in modules] == [("/agent/a.js", "send(1);\n")]


def test_parse_multi_module_package_uses_byte_sizes():
    # Non-ASCII code: sizes in the header are UTF-8 bytes, not characters,
    # and a module may itself contain the separator glyph.
    mods = [("/agent/a.js", 'import "./b.js"; // é 📦\n'),
            ("/agent/b.js", "const s = '\n✄\n'; send(s);")]
    modules = parse_frida_package(make_package(mods))
    assert [(m.name, m.code) for m in modules] == mods


def test_parse_aliases_attach_to_preceding_module():
    pkg = make_package([("/agent/a.js", "1"), ("/node_modules/x/index.js", "2")],
                       aliases={"/node_modules/x/index.js": ["x"]})
    modules = parse_frida_package(pkg)
    assert modules[0].aliases == ()
    assert modules[1].aliases == ("x",)


@pytest.mark.parametrize("bad", [
    "📦\n12 /agent/a.js\nsend(1);",              # no header terminator
    "📦\nabc /agent/a.js\n✄\nsend(1);",           # size not a number
    "📦\n↻ alias\n✄\nsend(1);",                  # alias before a module
    "📦\n99 /agent/a.js\n✄\nsend(1);",            # truncated module
    "📦\n2 /agent/a.js\n✄\nabEXTRA",              # trailing data
    "📦\n1 /a.js\n1 /b.js\n✄\naXb",               # missing separator
])
def test_parse_rejects_malformed_packages(bad):
    with pytest.raises(FridaPackageError):
        parse_frida_package(bad)


@pytest.mark.parametrize("bundle", ["fritap_agent.js", "fritap_memscan.js"])
def test_parse_shipped_bundles(bundle):
    path = REPO_ROOT / "friTap" / bundle
    if not path.exists():
        pytest.skip(f"{bundle} not built")
    source = path.read_text(encoding="utf-8")
    modules = parse_frida_package(source)
    assert modules and modules[0].name.startswith("/agent/")
    # The parsed entry is exactly the source after the package header.
    assert modules[0].code == source[source.index("✄") + 2:]


# ----------------------------------------------------------------------
# Load plan and chunking
# ----------------------------------------------------------------------

def test_plain_script_is_loaded_as_classic_script():
    plan = build_load_plan("send('hi');")
    assert plan.mode == MODE_CLASSIC
    assert [m.code for m in plan.modules] == ["send('hi');"]


def test_package_plan_loads_dependencies_first_and_entry_last():
    pkg = make_package([("/agent/entry.js", "e"), ("/agent/b.js", "b"), ("/agent/c.js", "c")])
    plan = build_load_plan(pkg)
    assert plan.mode == MODE_ESM
    assert [m.name for m in plan.modules] == ["/agent/c.js", "/agent/b.js", "/agent/entry.js"]


def test_package_with_aliases_is_refused_with_clear_error():
    pkg = make_package([("/agent/a.js", "1"), ("/x.js", "2")], aliases={"/x.js": ["x"]})
    with pytest.raises(FridaPackageError, match="alias"):
        build_load_plan(pkg)


@pytest.mark.parametrize("code", [
    "a" * 300_000,
    "é" * 100_000,                 # 6 JSON bytes per char
    "📦" * 50_000,                 # 12 JSON bytes per char (surrogate pair)
    ("x\"\\\n" * 40_000) + "é📦",
])
def test_chunks_respect_encoded_limit_and_reassemble(code):
    chunks = split_into_chunks(code)
    assert "".join(chunks) == code
    assert all(len(json.dumps(c)) <= CHUNK_MAX_ENCODED_BYTES for c in chunks)


def test_needs_chunked_load_counts_utf8_bytes():
    assert not needs_chunked_load("a" * 100, threshold=100)
    assert needs_chunked_load("é" * 51, threshold=100)


# ----------------------------------------------------------------------
# Proxy with a fake bootstrap script
# ----------------------------------------------------------------------

class FakeBootstrap:
    """Simulates the bootstrap script's message protocol synchronously."""

    def __init__(self, *, fail_op=None, silent_op=None, early_messages=()):
        self.callbacks = {"message": [], "destroyed": []}
        self.posted = []
        self.loaded = False
        self.unloaded = False
        self.fail_op = fail_op
        self.silent_op = silent_op
        self.early_messages = list(early_messages)
        self.staged = []
        self.exports_sync = MagicMock(name="exports_sync")

    def on(self, signal, callback):
        self.callbacks[signal].append(callback)

    def off(self, signal, callback):
        self.callbacks[signal].remove(callback)

    def load(self):
        self.loaded = True

    def unload(self):
        self.unloaded = True
        for cb in list(self.callbacks["destroyed"]):
            cb()

    def emit(self, message, data=None):
        for cb in list(self.callbacks["message"]):
            cb(message, data)

    def reply(self, seq, op, **extra):
        self.emit({"type": "send", "payload": {LOADER_REPLY_MARKER: {"op": op, "seq": seq, **extra}}})

    def post(self, message, data=None):
        self.posted.append(message)
        if message.get("type") != LOADER_MESSAGE_TYPE:
            return
        op, seq = message["op"], message["seq"]
        if op == self.silent_op:
            return
        if op == self.fail_op:
            self.reply(seq, "failed", error="Error: boom", stack="at /agent/a.js:1")
            return
        if op == "begin":
            self.staged.append([message["name"], ""])
        elif op == "data":
            self.staged[-1][1] += message["data"]
        elif op == "commit":
            for early in self.early_messages:
                self.emit(early)
            self.reply(seq, "loaded")
            return
        self.reply(seq, "ack")


class FakeSession:
    def __init__(self, bootstrap):
        self.bootstrap = bootstrap
        self.created = []

    def create_script(self, source, runtime="qjs"):
        self.created.append((source, runtime))
        return self.bootstrap


def big_package(size=300_000):
    return make_package([("/agent/fritap_agent.js", "send('x');\n" + "/" * size)])


def test_create_stages_every_byte_in_bounded_chunks():
    boot = FakeBootstrap()
    source = big_package()
    ChunkedLoadScript.create(FakeSession(boot), source, runtime="v8")
    assert boot.loaded
    assert boot.staged == [["/agent/fritap_agent.js", source[source.index("✄") + 2:]]]
    assert all(len(json.dumps(m)) <= CHUNK_MAX_ENCODED_BYTES + 200 for m in boot.posted)
    assert not any(m["op"] == "commit" for m in boot.posted)  # waits for load()


def test_bootstrap_is_created_with_callers_runtime():
    boot = FakeBootstrap()
    session = FakeSession(boot)
    ChunkedLoadScript.create(session, big_package(), runtime="v8")
    assert session.created == [(loader.BOOTSTRAP_SOURCE, "v8")]


def test_handler_attached_before_load_sees_early_agent_messages_but_no_acks():
    early = [{"type": "send", "payload": "config_batch"},
             {"type": "send", "payload": {"contentType": "hook_breadcrumb"}}]
    boot = FakeBootstrap(early_messages=early)
    script = ChunkedLoadScript.create(FakeSession(boot), big_package())
    seen = []
    script.on("message", lambda message, data: seen.append(message))
    script.load()
    assert seen == early
    assert boot.posted[-1]["op"] == "commit"
    assert boot.posted[-1]["mode"] == MODE_ESM


def test_agent_messages_after_load_still_reach_handler():
    boot = FakeBootstrap()
    script = ChunkedLoadScript.create(FakeSession(boot), big_package())
    seen = []
    script.on("message", lambda message, data: seen.append((message, data)))
    script.load()
    boot.emit({"type": "send", "payload": {"k": 1}}, b"\x01")
    boot.emit({"type": "error", "description": "agent error"})
    assert seen == [({"type": "send", "payload": {"k": 1}}, b"\x01"),
                    ({"type": "error", "description": "agent error"}, None)]


def test_off_removes_the_wrapped_handler():
    boot = FakeBootstrap()
    script = ChunkedLoadScript.create(FakeSession(boot), big_package())
    seen = []
    handler = lambda message, data: seen.append(message)  # noqa: E731
    script.on("message", handler)
    script.off("message", handler)
    script.load()
    boot.emit({"type": "send", "payload": 1})
    assert seen == []


def test_rpc_post_unload_and_destroyed_delegate_to_the_script():
    boot = FakeBootstrap()
    script = ChunkedLoadScript.create(FakeSession(boot), big_package())
    destroyed = []
    script.on("destroyed", lambda: destroyed.append(True))
    script.load()
    assert script.exports_sync is boot.exports_sync
    script.post({"type": "config", "payload": {"a": 1}})
    assert boot.posted[-1] == {"type": "config", "payload": {"a": 1}}
    script.unload()
    assert boot.unloaded and destroyed == [True]


def test_load_is_idempotent_after_success():
    boot = FakeBootstrap()
    script = ChunkedLoadScript.create(FakeSession(boot), big_package())
    script.load()
    script.load()
    assert [m["op"] for m in boot.posted].count("commit") == 1


def test_failed_agent_evaluation_raises_invalid_argument_with_message():
    boot = FakeBootstrap(fail_op="commit")
    script = ChunkedLoadScript.create(FakeSession(boot), big_package())
    with pytest.raises(frida.InvalidArgumentError, match="chunked agent load failed: Error: boom"):
        script.load()
    with pytest.raises(frida.InvalidOperationError):
        script.load()


def test_commit_without_reply_times_out():
    boot = FakeBootstrap(silent_op="commit")
    script = ChunkedLoadScript.create(FakeSession(boot), big_package(), commit_timeout=0.05)
    with pytest.raises(frida.TimedOutError, match="commit"):
        script.load()


def test_staging_failure_raises_and_unloads_bootstrap():
    boot = FakeBootstrap(silent_op="data")
    with pytest.raises(frida.TimedOutError):
        ChunkedLoadScript.create(FakeSession(boot), big_package(), ack_timeout=0.05)
    assert boot.unloaded


def test_bootstrap_destroyed_during_staging_raises_invalid_operation():
    boot = FakeBootstrap(silent_op="data")
    original_post = boot.post

    def post_then_die(message, data=None):
        original_post(message, data)
        if message.get("op") == "data":
            for cb in boot.callbacks["destroyed"]:
                cb()
    boot.post = post_then_die
    with pytest.raises(frida.InvalidOperationError, match="destroyed"):
        ChunkedLoadScript.create(FakeSession(boot), big_package())


def test_loader_error_message_before_commit_fails_fast():
    boot = FakeBootstrap(silent_op="data")
    original_post = boot.post

    def post_then_error(message, data=None):
        original_post(message, data)
        if message.get("op") == "data":
            boot.emit({"type": "error", "description": "ReferenceError: x"})
    boot.post = post_then_error
    with pytest.raises(frida.InvalidArgumentError, match="ReferenceError"):
        ChunkedLoadScript.create(FakeSession(boot), big_package())


def test_aliased_package_raises_before_creating_anything():
    session = FakeSession(FakeBootstrap())
    pkg = make_package([("/agent/a.js", "1" * 200_000), ("/x.js", "2")], aliases={"/x.js": ["x"]})
    with pytest.raises(frida.InvalidArgumentError, match="alias"):
        ChunkedLoadScript.create(session, pkg)
    assert session.created == []


def test_is_loader_reply_only_matches_marker_sends():
    assert is_loader_reply({"type": "send", "payload": {LOADER_REPLY_MARKER: {}}})
    assert not is_loader_reply({"type": "send", "payload": {"other": 1}})
    assert not is_loader_reply({"type": "send", "payload": "config_batch"})
    assert not is_loader_reply({"type": "error", "description": LOADER_REPLY_MARKER})


# ----------------------------------------------------------------------
# Backend routing
# ----------------------------------------------------------------------

def attached_session(backend, device_type):
    device = MagicMock()
    device.type = device_type
    session = MagicMock(name=f"{device_type}-session")
    device.attach.return_value = session
    assert backend.attach(device, "1234") is session
    return session


def test_remote_session_with_large_script_is_chunk_loaded(monkeypatch):
    backend = FridaBackend()
    session = attached_session(backend, "remote")
    created = MagicMock(name="chunked")
    monkeypatch.setattr(ChunkedLoadScript, "create", MagicMock(return_value=created))
    source = big_package()
    assert backend.create_script(session, source, runtime="v8") is created
    ChunkedLoadScript.create.assert_called_once_with(session, source, runtime="v8")
    session.create_script.assert_not_called()


@pytest.mark.parametrize("device_type", ["local", "usb"])
def test_local_and_usb_sessions_load_directly(device_type, monkeypatch):
    backend = FridaBackend()
    session = attached_session(backend, device_type)
    monkeypatch.setattr(ChunkedLoadScript, "create", MagicMock())
    backend.create_script(session, big_package())
    session.create_script.assert_called_once()
    ChunkedLoadScript.create.assert_not_called()


def test_remote_session_with_small_script_loads_directly(monkeypatch):
    backend = FridaBackend()
    session = attached_session(backend, "remote")
    monkeypatch.setattr(ChunkedLoadScript, "create", MagicMock())
    backend.create_script(session, "send('small');", runtime="qjs")
    session.create_script.assert_called_once_with("send('small');", runtime="qjs")
    ChunkedLoadScript.create.assert_not_called()


def test_spawned_remote_session_is_tracked(monkeypatch):
    backend = FridaBackend()
    device = MagicMock()
    device.type = "remote"
    device.spawn.return_value = 4321
    session = MagicMock(name="spawned")
    device.attach.return_value = session
    backend.spawn(device, "/bin/app")
    monkeypatch.setattr(ChunkedLoadScript, "create", MagicMock())
    backend.create_script(session, big_package())
    ChunkedLoadScript.create.assert_called_once()


def test_backend_without_init_still_creates_directly():
    backend = FridaBackend.__new__(FridaBackend)
    backend._logger = MagicMock()
    session = MagicMock()
    backend.create_script(session, big_package())
    session.create_script.assert_called_once()


def test_chunked_load_errors_are_mapped_by_the_backend():
    backend = FridaBackend()
    session = attached_session(backend, "remote")
    session.create_script.return_value = FakeBootstrap(fail_op="begin")
    with pytest.raises(BackendInvalidArgumentError, match="boom"):
        backend.create_script(session, big_package())


def test_backend_load_script_maps_chunked_timeout():
    backend = FridaBackend()
    boot = FakeBootstrap(silent_op="commit")
    script = ChunkedLoadScript.create(FakeSession(boot), big_package(), commit_timeout=0.05)
    with pytest.raises(BackendTimedOutError):
        backend.load_script(script)
