"""Decoder worker body. Runs only inside the spawned worker process.

The parent starts it with ``runpy.run_path`` as the ``multiprocessing``
(spawn) target, so the ``friTap`` package is never imported here: the wire
protocol, the hardening helpers, the decompression engine
(``friTap/parsers/decompress.py``) and the ``qpack_decoder`` kind
(``qpack_kind.py``) are loaded by file path. The worker therefore holds only
the stdlib, zlib/brotli/zstandard/pylsqpack and friTap's in-process decoder
functions -- no Frida, no keys, no session state.

Lifecycle: load modules, warm every decoder (so nothing is imported after
the sandbox closes), harden, send HELLO, then serve requests until the pipe
reaches EOF (parent closed it or died).
"""

import importlib.util
import os
import sys
import time

CONFIG_NAME = "__fritap_worker_config__"
MAX_CONTEXTS = 4096  # default per-worker cap (config 'max_contexts' overrides)

# Context kinds and their per-call op codes (see ContextOp in client.py).
CTX_OP_FEED = 1


def _load_module(name, path):
    """Import the stdlib-only file *path* as module *name* (no package import)."""
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _warm_up_decoders(engine):
    """Run every decoder once, success and failure, before the sandbox closes."""
    import zlib
    gz = zlib.compressobj(wbits=31)
    sample = gz.compress(b"fritap") + gz.flush()
    engine.decompress_body(sample, "gzip", 64)
    engine.decompress_body(b"\x00not-compressed", "deflate", 64)
    engine.inflate_bounded_checked(sample, 64)
    engine._find_gzip_member(b"xx" + sample, 64, 4)
    if engine._brotli:
        engine.decompress_body(engine.brotli.compress(b"fritap"), "br", 64)
        engine.decompress_body(b"\xff\xff", "br", 64)
    if engine._zstd:
        frame = engine.zstandard.ZstdCompressor().compress(b"fritap")
        engine.decompress_body(frame, "zstd", 64)
        engine.decompress_body(b"\xff\xff", "zstd", 64)


class _ZlibStreamContext:
    """``zlib_stream``: a persistent inflater (permessage-deflate takeover)."""

    def __init__(self, engine, protocol, params):
        wbits = protocol.unpack_i64(params)
        if wbits is None:
            raise ValueError("zlib_stream needs an 8-byte wbits parameter")
        import zlib
        self._engine, self._dec, self._poisoned = engine, zlib.decompressobj(wbits), False

    def call(self, op, data, max_out, protocol):
        S = protocol.Status
        if op != CTX_OP_FEED:
            return S.UNSUPPORTED, 0, b"", b"unknown zlib_stream op"
        if self._poisoned:
            return S.CONTEXT_ERROR, 0, b"", b"context poisoned by an earlier failure"
        try:
            return S.OK, 0, self._engine.inflate_stream_bounded(self._dec, data, max_out), b""
        except self._engine.InflateLimitError as exc:
            self._poisoned = True
            return S.LIMIT_ERROR, 0, b"", protocol.encode_text(str(exc))
        except Exception as exc:
            self._poisoned = True
            return S.CONTEXT_ERROR, 0, b"", protocol.encode_text(str(exc))


class _TestEchoStateContext:
    """``test_echo_state`` (test hooks only): returns all data fed so far."""

    def __init__(self, engine, protocol, params):
        self._state = bytearray(params)

    def call(self, op, data, max_out, protocol):
        S = protocol.Status
        if op != CTX_OP_FEED:
            return S.UNSUPPORTED, 0, b"", b"unknown test_echo_state op"
        self._state += data
        if len(self._state) > max_out:
            return S.LIMIT_ERROR, 0, b"", b"state exceeds max_out"
        return S.OK, 0, bytes(self._state), b""


class _TestReplyContext:
    """``test_reply`` (test hooks only): replies with a crafted status/flags/data.

    FEED-independent: any op answers ``data = u16 status | u16 flags | payload``
    verbatim, so tests can hand the parent hostile context replies.
    """

    def __init__(self, engine, protocol, params):
        pass

    def call(self, op, data, max_out, protocol):
        if len(data) < 4:
            return protocol.Status.BAD_REQUEST, 0, b"", b"test_reply needs 4 bytes"
        status, flags = int.from_bytes(data[:2], "big"), int.from_bytes(data[2:4], "big")
        return status, flags, bytes(data[4:]), b""


class Worker:
    """Request loop and op dispatch."""

    def __init__(self, conn, protocol, engine, test_hooks, qpack=None,
                 max_contexts=MAX_CONTEXTS):
        self.conn, self.P, self.engine, self.test_hooks = conn, protocol, engine, test_hooks
        self.contexts = {}
        self.max_contexts = max_contexts
        self.next_handle = 1
        self.report = ""
        self.kinds = {"zlib_stream": _ZlibStreamContext}
        if qpack is not None and qpack.available():
            self.kinds[qpack.KIND] = qpack.QpackDecoderContext
        if test_hooks:
            self.kinds["test_echo_state"] = _TestEchoStateContext
            self.kinds["test_reply"] = _TestReplyContext
        Op = protocol.Op
        self.handlers = {
            Op.PING: self._ping,
            Op.DECOMPRESS_BODY: self._decompress_body,
            Op.FIND_GZIP_MEMBER: self._find_gzip_member,
            Op.INFLATE_CHECKED: self._inflate_checked,
            Op.CTX_CREATE: self._ctx_create,
            Op.CTX_CALL: self._ctx_call,
            Op.CTX_DESTROY: self._ctx_destroy,
            Op.TEST_EXIT: self._test_exit,
            Op.TEST_SEGV: self._test_segv,
            Op.TEST_SLEEP: self._test_sleep,
            Op.TEST_RAW_REPLY: self._test_raw_reply,
            Op.TEST_LIST_MODULES: self._test_list_modules,
            Op.TEST_HARDENING: self._test_hardening,
        }

    def serve(self):
        """Answer requests until EOF on the pipe."""
        while True:
            try:
                message = self.conn.recv_bytes()
            except (EOFError, OSError):
                return
            reply = self.handle(message)
            try:
                self.conn.send_bytes(reply)
            except (EOFError, OSError):
                return

    def handle(self, message):
        """One request frame in, one reply frame out."""
        P = self.P
        try:
            frame = P.decode_frame(message, P.MAX_TEXT_LEN, P.MAX_REQUEST_DATA)
        except P.ProtocolError as exc:
            return P.encode_frame(0, 0, status=P.Status.BAD_REQUEST,
                                  text=P.encode_text(str(exc)))
        handler = self.handlers.get(frame.op)
        if handler is None or (frame.op in P.Op.TEST_OPS and not self.test_hooks):
            return self._reply(frame, P.Status.UNSUPPORTED, text=b"unsupported op")
        try:
            return handler(frame)
        except Exception as exc:  # a bug or MemoryError: report, keep serving
            return self._reply(frame, P.Status.BAD_REQUEST,
                               text=P.encode_text(f"{type(exc).__name__}: {exc}"))

    def _reply(self, frame, status, *, flags=0, handle=None, arg0=0, arg1=0,
               text=b"", data=b""):
        return self.P.encode_frame(
            frame.op, frame.request_id, status=status, flags=flags,
            handle=frame.handle if handle is None else handle,
            arg0=arg0, arg1=arg1, text=text, data=data)

    # --- stateless decoding ----------------------------------------------------

    def _ping(self, frame):
        return self._reply(frame, self.P.Status.OK)

    def _decompress_body(self, frame):
        P = self.P
        self._apply_brotli_override(frame.flags & P.REQ_ALLOW_UNPATCHED_BROTLI)
        encoding = frame.text.decode("ascii", errors="replace")
        out, err = self.engine.decompress_body(frame.data, encoding, frame.arg0)
        if err:
            return self._reply(frame, P.Status.DECODE_ERROR, text=P.encode_text(err))
        return self._reply(frame, P.Status.OK, data=out)

    def _apply_brotli_override(self, allowed):
        """Mirror the parent's FRITAP_ALLOW_UNPATCHED_BROTLI decision."""
        name = self.engine.ALLOW_UNPATCHED_BROTLI_ENV
        if allowed:
            os.environ[name] = "1"
        else:
            os.environ.pop(name, None)

    def _find_gzip_member(self, frame):
        P = self.P
        found = self.engine._find_gzip_member(frame.data, frame.arg0, frame.arg1)
        if found is None:
            return self._reply(frame, P.Status.NOT_FOUND)
        offset, inflated, member_len = found
        return self._reply(frame, P.Status.OK, arg0=offset, arg1=member_len, data=inflated)

    def _inflate_checked(self, frame):
        P = self.P
        try:
            data, complete = self.engine.inflate_bounded_checked(frame.data, frame.arg0)
        except self.engine.InflateLimitError as exc:
            return self._reply(frame, P.Status.LIMIT_ERROR, text=P.encode_text(str(exc)))
        except self.engine.zlib.error as exc:
            return self._reply(frame, P.Status.ZLIB_ERROR, text=P.encode_text(str(exc)))
        flags = P.REPLY_COMPLETE if complete else 0
        return self._reply(frame, P.Status.OK, flags=flags, data=data)

    # --- stateful contexts -----------------------------------------------------

    def _ctx_create(self, frame):
        P = self.P
        factory = self.kinds.get(frame.text.decode("ascii", errors="replace"))
        if factory is None:
            return self._reply(frame, P.Status.UNSUPPORTED, text=b"unknown context kind")
        if len(self.contexts) >= self.max_contexts:
            return self._reply(frame, P.Status.CONTEXT_ERROR, text=b"too many contexts")
        try:
            context = factory(self.engine, P, frame.data)
        except Exception as exc:
            return self._reply(frame, P.Status.CONTEXT_ERROR, text=P.encode_text(str(exc)))
        handle = self.next_handle
        self.next_handle = (self.next_handle % P.U32_MASK) + 1
        self.contexts[handle] = context
        return self._reply(frame, P.Status.OK, handle=handle)

    def _ctx_call(self, frame):
        P = self.P
        context = self.contexts.get(frame.handle)
        if context is None:
            return self._reply(frame, P.Status.HANDLE_LOST)
        status, flags, data, text = context.call(frame.arg1, frame.data, frame.arg0, P)
        return self._reply(frame, status, flags=flags, text=text, data=data)

    def _ctx_destroy(self, frame):
        P = self.P
        if self.contexts.pop(frame.handle, None) is None:
            return self._reply(frame, P.Status.HANDLE_LOST)
        return self._reply(frame, P.Status.OK)

    # --- test hooks (only reachable when started with test_hooks) --------------

    def _test_exit(self, frame):
        os._exit(int(frame.arg0) & 0xFF)

    def _test_segv(self, frame):
        import ctypes
        ctypes.string_at(0)
        return self._reply(frame, self.P.Status.OK)

    def _test_sleep(self, frame):
        time.sleep(frame.arg0 / 1000.0)
        return self._reply(frame, self.P.Status.OK)

    def _test_raw_reply(self, frame):
        return frame.data

    def _test_list_modules(self, frame):
        names = "\n".join(sorted(sys.modules)).encode("ascii", errors="replace")
        return self._reply(frame, self.P.Status.OK, data=names)

    def _test_hardening(self, frame):
        return self._reply(frame, self.P.Status.OK, text=self.P.encode_text(self.report))


def _load_optional_kind(name, path):
    """Load an optional context-kind module by path; None when absent/broken."""
    if not path:
        return None
    try:
        return _load_module(name, path)
    except Exception:
        return None


def main(config):
    """Worker entry: load, warm up, harden, greet, serve, exit."""
    sys.dont_write_bytecode = True
    conn = config["conn"]
    protocol = _load_module("_fritap_decoder_protocol", config["protocol_path"])
    hardening = _load_module("_fritap_decoder_hardening", config["hardening_path"])
    engine = _load_module("_fritap_decoder_engine", config["engine_path"])
    engine._IN_DECODER_WORKER = True
    test_hooks = bool(config.get("test_hooks"))
    if test_hooks:
        import ctypes  # noqa: F401  (TEST_SEGV must not import after the sandbox)
    qpack = _load_optional_kind("_fritap_decoder_qpack", config.get("qpack_kind_path"))
    _warm_up_decoders(engine)
    if qpack is not None:
        qpack.warm_up()
    worker = Worker(conn, protocol, engine, test_hooks, qpack,
                    int(config.get("max_contexts") or MAX_CONTEXTS))
    report = hardening.harden_worker((conn.fileno(),)) if config.get("harden", True) else []
    worker.report = ",".join(report)
    conn.send_bytes(protocol.encode_frame(protocol.Op.HELLO, 0, arg0=os.getpid(),
                                          text=protocol.encode_text(worker.report)))
    worker.serve()
    os._exit(0)


if CONFIG_NAME in globals():
    main(globals()[CONFIG_NAME])
