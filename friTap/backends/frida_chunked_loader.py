#!/usr/bin/env python3

"""Chunked agent loading for remote (``-H``) frida-server sessions.

frida-server's WebSocket transport drops the connection on any single host
message above ~128 KiB (libsoup ``max-incoming-payload-size``; server -> host
is unaffected). ``create_script`` sends the whole agent in one message, so the
2 MB agent cannot be created over a remote device (``TransportError: the
connection is closed``). USB and local transports are unaffected.

1. A tiny bootstrap script is loaded instead of the agent.
2. The agent source is staged into it with ``script.post`` in acknowledged
   pieces whose JSON encoding stays well below the limit.
3. ``load()`` on :class:`ChunkedLoadScript` sends a ``commit``: the bootstrap
   evaluates the agent with ``Script.load(name, code)`` (global eval for a
   non-package script).

The agent runs in the bootstrap's own script runtime, so ``rpc.exports``,
``send``, ``recv``, ``unload`` and ``on('destroyed')`` behave as on a direct
script. The proxy only hides the bootstrap's acknowledgement messages.
"""

from __future__ import annotations

import json
import logging
import queue
from dataclasses import dataclass
from typing import Any, Callable

import frida

logger = logging.getLogger("friTap.backend.frida.chunked_loader")

# create_script sources above this many UTF-8 bytes are chunk-loaded on remote
# sessions. Below libsoup's 128 KiB limit with room for the D-Bus/JSON envelope
# (measured: 130 KB passes, 140 KB fails).
REMOTE_DIRECT_LOAD_MAX_BYTES = 100_000

# Upper bound for the JSON encoding of one staged piece.
CHUNK_MAX_ENCODED_BYTES = 64 * 1024

ACK_TIMEOUT_SECONDS = 30.0
COMMIT_TIMEOUT_SECONDS = 120.0

LOADER_MESSAGE_TYPE = "fritap:chunked-load"
LOADER_REPLY_MARKER = "__fritap_chunked_loader__"

PACKAGE_MAGIC = "\U0001f4e6\n"          # "📦\n"
PACKAGE_SEPARATOR = "\n✄\n"         # "\n✄\n"
PACKAGE_ALIAS_PREFIX = "↻ "        # "↻ "

MODE_ESM = "esm"
MODE_CLASSIC = "classic"

BOOTSTRAP_SOURCE = r"""
(function () {
  'use strict';
  var MARKER = '__fritap_chunked_loader__';
  var TYPE = 'fritap:chunked-load';
  var MISSING_DEPENDENCY = 'could not load module';
  var staged = [];
  var current = null;

  function reply(seq, op, extra) {
    var body = { op: op, seq: seq };
    if (extra) { for (var key in extra) { body[key] = extra[key]; } }
    var payload = {};
    payload[MARKER] = body;
    send(payload);
  }

  function describe(error) {
    return { error: String(error), stack: (error && error.stack) ? String(error.stack) : '' };
  }

  function listen() { recv(TYPE, onMessage); }

  function onMessage(msg) {
    try {
      if (msg.op === 'begin') {
        current = { name: msg.name, parts: [] };
        staged.push(current);
      } else if (msg.op === 'data') {
        current.parts.push(msg.data);
      } else if (msg.op === 'commit') {
        commit(msg);   // no listen(): the loader's recv loop ends here
        return;
      } else {
        throw new Error('unknown chunked-load op: ' + msg.op);
      }
    } catch (e) {
      reply(msg.seq, 'failed', describe(e));
      return;
    }
    reply(msg.seq, 'ack');
    listen();
  }

  function takeStaged() {
    var modules = staged.map(function (m) { return { name: m.name, code: m.parts.join('') }; });
    staged = [];
    current = null;
    return modules;
  }

  function commit(msg) {
    var modules = takeStaged();
    var loaded = function () { reply(msg.seq, 'loaded'); };
    var failed = function (e) { reply(msg.seq, 'failed', describe(e)); };
    if (msg.mode === 'classic') {
      try { (0, eval)(modules[0].code); } catch (e) { failed(e); return; }
      loaded();
      return;
    }
    loadModules(modules, loaded, failed);
  }

  // Script.load evaluates a module right away and resolves its imports only
  // against modules loaded before it; a missing import fails at link time,
  // before any evaluation. So a module whose dependency is not loaded yet is
  // retried in a later round until every module loads or no round progresses.
  function loadModules(pending, done, fail) {
    var deferred = [];
    var progressed = false;
    var lastError = null;
    function step(i) {
      if (i === pending.length) {
        if (deferred.length === 0) { done(); return; }
        if (!progressed) { fail(lastError); return; }
        loadModules(deferred, done, fail);
        return;
      }
      var m = pending[i];
      Script.load(m.name, m.code).then(function () {
        progressed = true;
        step(i + 1);
      }, function (e) {
        if (String(e).indexOf(MISSING_DEPENDENCY) === -1) { fail(e); return; }
        deferred.push(m);
        lastError = e;
        step(i + 1);
      });
    }
    step(0);
  }

  listen();
})();
"""


class FridaPackageError(ValueError):
    """The source starts with the frida package magic but is malformed."""


@dataclass(frozen=True)
class PackageModule:
    name: str
    code: str
    aliases: tuple[str, ...] = ()


@dataclass(frozen=True)
class LoadPlan:
    """What the bootstrap evaluates on commit, in evaluation order."""
    mode: str
    modules: tuple[PackageModule, ...]


# ----------------------------------------------------------------------
# Package format (written by frida's compiler / frida-compile)
#
#   📦\n
#   <utf8-byte-size> <module path>\n      one line per module, entry first
#   ↻ <alias>\n                           optional aliases of the line above
#   ✄\n
#   <module source>[\n✄\n<module source>]...
# ----------------------------------------------------------------------

def is_frida_package(source: str) -> bool:
    return source.startswith(PACKAGE_MAGIC)


def parse_frida_package(source: str) -> list[PackageModule]:
    """Split a frida package into its modules (entry module first)."""
    if not is_frida_package(source):
        raise FridaPackageError("not a frida package (missing package magic)")
    header_end = source.find(PACKAGE_SEPARATOR, len(PACKAGE_MAGIC) - 1)
    if header_end == -1:
        raise FridaPackageError("frida package header is not terminated")
    entries = _parse_package_header(source[len(PACKAGE_MAGIC):header_end])
    body = source[header_end + len(PACKAGE_SEPARATOR):].encode("utf-8")
    return _split_package_body(entries, body)


def _parse_package_header(header: str) -> list[tuple[int, str, list[str]]]:
    entries: list[tuple[int, str, list[str]]] = []
    for line in header.split("\n"):
        if line.startswith(PACKAGE_ALIAS_PREFIX):
            if not entries:
                raise FridaPackageError("frida package alias before any module")
            entries[-1][2].append(line[len(PACKAGE_ALIAS_PREFIX):])
            continue
        size_text, _, name = line.partition(" ")
        if not size_text.isdigit() or not name:
            raise FridaPackageError(f"malformed frida package header line: {line!r}")
        entries.append((int(size_text), name, []))
    if not entries:
        raise FridaPackageError("frida package declares no modules")
    return entries


def _split_package_body(entries, body: bytes) -> list[PackageModule]:
    separator = PACKAGE_SEPARATOR.encode("utf-8")
    modules: list[PackageModule] = []
    offset = 0
    for index, (size, name, aliases) in enumerate(entries):
        if index > 0:
            if body[offset:offset + len(separator)] != separator:
                raise FridaPackageError(f"missing separator before module {name!r}")
            offset += len(separator)
        chunk = body[offset:offset + size]
        if len(chunk) != size:
            raise FridaPackageError(f"module {name!r} is truncated")
        modules.append(PackageModule(name, chunk.decode("utf-8"), tuple(aliases)))
        offset += size
    if body[offset:].strip(b"\n"):
        raise FridaPackageError("trailing data after the last frida package module")
    return modules


def build_load_plan(source: str) -> LoadPlan:
    """Decide how the bootstrap must evaluate ``source``.

    A plain script runs as a classic global script. A package loads
    dependencies first: frida-compile writes the entry module first, so the
    rest go in reverse order and the entry last. The bootstrap's retry loop
    fixes a wrong order.
    """
    if not is_frida_package(source):
        return LoadPlan(MODE_CLASSIC, (PackageModule("/fritap_script.js", source),))
    modules = parse_frida_package(source)
    aliased = [m.name for m in modules if m.aliases]
    if aliased:
        raise FridaPackageError(
            "frida package module aliases cannot be chunk-loaded "
            f"(Script.load registers one name per module): {aliased}"
        )
    entry, dependencies = modules[0], modules[1:]
    return LoadPlan(MODE_ESM, tuple(reversed(dependencies)) + (entry,))


def split_into_chunks(code: str, max_encoded_bytes: int = CHUNK_MAX_ENCODED_BYTES) -> list[str]:
    """Split ``code`` so every piece JSON-encodes to at most ``max_encoded_bytes``.

    frida-python posts JSON with ``ensure_ascii``, where a non-ASCII character
    costs up to 12 bytes, so pieces are measured encoded. A cut never splits
    a surrogate pair because Python strings hold code points.
    """
    chunks: list[str] = []
    start = 0
    while start < len(code):
        length = min(max_encoded_bytes, len(code) - start)
        while len(json.dumps(code[start:start + length])) > max_encoded_bytes:
            length = max(1, length // 2)
        chunks.append(code[start:start + length])
        start += length
    return chunks


def needs_chunked_load(source: str, threshold: int = REMOTE_DIRECT_LOAD_MAX_BYTES) -> bool:
    return len(source.encode("utf-8")) > threshold


# ----------------------------------------------------------------------
# Script proxy
# ----------------------------------------------------------------------

def is_loader_reply(message: Any) -> bool:
    if not isinstance(message, dict) or message.get("type") != "send":
        return False
    payload = message.get("payload")
    return isinstance(payload, dict) and LOADER_REPLY_MARKER in payload


class ChunkedLoadScript:
    """A frida ``Script`` stand-in whose agent is staged through a bootstrap.

    Everything not defined here (``exports_sync``, ``post``, ``unload``, ...)
    is the bootstrap script's attribute, which after ``load()`` is the agent's
    runtime.
    """

    def __init__(self, script: Any, plan: LoadPlan, *,
                 ack_timeout: float = ACK_TIMEOUT_SECONDS,
                 commit_timeout: float = COMMIT_TIMEOUT_SECONDS) -> None:
        self._script = script
        self._plan = plan
        self._ack_timeout = ack_timeout
        self._commit_timeout = commit_timeout
        self._replies: "queue.Queue[tuple[str, Any]]" = queue.Queue()
        self._message_wrappers: dict[Callable, Callable] = {}
        self._seq = 0
        self._committed = False
        self._loaded = False
        script.on("message", self._on_loader_message)
        script.on("destroyed", self._on_loader_destroyed)

    @classmethod
    def create(cls, session: Any, source: str, runtime: str = "qjs", **timeouts: float) -> "ChunkedLoadScript":
        """Create the bootstrap in ``session`` and stage ``source`` into it.

        Staging happens here so transport failures surface from
        ``create_script``; evaluation waits for :meth:`load`, after the caller
        wired its handlers.
        """
        try:
            plan = build_load_plan(source)
        except FridaPackageError as exc:
            raise frida.InvalidArgumentError(f"chunked agent load: {exc}") from exc
        script = session.create_script(BOOTSTRAP_SOURCE, runtime=runtime)
        proxy = cls(script, plan, **timeouts)
        try:
            script.load()
            proxy._stage()
        except BaseException:
            proxy._unload_quietly()
            raise
        return proxy

    # -- frida Script surface -----------------------------------------

    def on(self, signal: str, callback: Callable[..., Any]) -> None:
        if signal == "message":
            wrapper = self._message_wrappers.setdefault(callback, self._hide_loader_replies(callback))
            self._script.on("message", wrapper)
            return
        self._script.on(signal, callback)

    def off(self, signal: str, callback: Callable[..., Any]) -> None:
        if signal == "message":
            self._script.off("message", self._message_wrappers.pop(callback, callback))
            return
        self._script.off(signal, callback)

    def load(self) -> None:
        """Evaluate the staged agent; returns once its top-level code ran."""
        if self._loaded:
            return
        if self._committed:
            raise frida.InvalidOperationError("chunked agent load already attempted")
        self._committed = True
        self._request({"op": "commit", "mode": self._plan.mode}, self._commit_timeout, "loaded")
        self._loaded = True

    def __getattr__(self, name: str) -> Any:
        return getattr(self._script, name)

    def __repr__(self) -> str:
        return f"ChunkedLoadScript({self._script!r})"

    # -- staging ------------------------------------------------------

    def _stage(self) -> None:
        total_chunks = 0
        for module in self._plan.modules:
            self._request({"op": "begin", "name": module.name}, self._ack_timeout, "ack")
            for chunk in split_into_chunks(module.code):
                self._request({"op": "data", "data": chunk}, self._ack_timeout, "ack")
                total_chunks += 1
        logger.debug(
            "remote session: staged %d module(s) in %d chunk(s) through the bootstrap loader",
            len(self._plan.modules), total_chunks,
        )

    def _request(self, fields: dict, timeout: float, expected_op: str) -> None:
        self._seq += 1
        seq = self._seq
        self._script.post({"type": LOADER_MESSAGE_TYPE, "seq": seq, **fields})
        reply = self._await_reply(timeout, fields["op"])
        if reply.get("seq") != seq:
            raise frida.ProtocolError(f"chunked agent load: reply {reply!r} does not answer request {seq}")
        if reply.get("op") == "failed":
            raise frida.InvalidArgumentError(self._failure_text(reply))
        if reply.get("op") != expected_op:
            raise frida.ProtocolError(f"chunked agent load: unexpected reply {reply!r}")

    def _await_reply(self, timeout: float, op: str) -> dict:
        try:
            kind, value = self._replies.get(timeout=timeout)
        except queue.Empty:
            raise frida.TimedOutError(
                f"chunked agent load: no reply to '{op}' within {timeout:.0f}s"
            ) from None
        if kind == "reply":
            return value
        if kind == "destroyed":
            raise frida.InvalidOperationError("chunked agent load: script was destroyed")
        raise frida.InvalidArgumentError(f"chunked agent load: loader script error: {value}")

    @staticmethod
    def _failure_text(reply: dict) -> str:
        text = f"chunked agent load failed: {reply.get('error') or 'unknown error'}"
        stack = reply.get("stack")
        return f"{text}\n{stack}" if stack and stack not in text else text

    # -- signal plumbing ----------------------------------------------

    def _on_loader_message(self, message: Any, data: Any) -> None:
        if is_loader_reply(message):
            self._replies.put(("reply", message["payload"][LOADER_REPLY_MARKER]))
        elif not self._committed and isinstance(message, dict) and message.get("type") == "error":
            # Before commit only the bootstrap runs, so an error is the loader's.
            self._replies.put(("error", message.get("description") or message))

    def _on_loader_destroyed(self, *_args: Any) -> None:
        self._replies.put(("destroyed", None))

    @staticmethod
    def _hide_loader_replies(callback: Callable) -> Callable:
        def forward(message: Any, data: Any) -> None:
            if not is_loader_reply(message):
                callback(message, data)
        return forward

    def _unload_quietly(self) -> None:
        try:
            self._script.unload()
        except Exception:
            logger.debug("chunked loader: bootstrap unload failed", exc_info=True)

