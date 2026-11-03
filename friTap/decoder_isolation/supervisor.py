"""Parent-side supervision of the decoder worker process.

One persistent worker, started lazily with the ``multiprocessing`` *spawn*
method (never fork: the parent runs Frida threads). Requests are serialised
by a lock, each bounded by a watchdog deadline. Any crash, timeout or
malformed reply kills and reaps the worker, is logged as a possible exploit
attempt, quarantines the input and counts toward a circuit breaker; the next
request starts a fresh worker. Nothing the worker sends is unpickled or
trusted: replies are length-capped binary frames validated field by field.
"""

from __future__ import annotations

import atexit
import contextlib
import logging
import multiprocessing
import os
import runpy
import signal
import sys
import threading
import time
import types
from pathlib import Path
from typing import Callable, NamedTuple

from . import protocol as P
from .breaker import CircuitBreaker
from .quarantine import quarantine_input
from .watchdog import Watchdog

logger = logging.getLogger("friTap.decoder_isolation")

TIMEOUT_ENV = "FRITAP_DECODER_TIMEOUT"
TEST_HOOKS_ENV = "FRITAP_DECODER_WORKER_TEST_HOOKS"
DEFAULT_TIMEOUT = 10.0
STARTUP_TIMEOUT = 30.0
INPUT_BYTES_PER_SECOND = 4 << 20    # timeout grows 1 s per 4 MiB of input ...
OUTPUT_BYTES_PER_SECOND = 64 << 20  # ... and 1 s per 64 MiB of allowed output
REAP_TIMEOUT = 2.0
WORKER_RUN_NAME = "__fritap_decoder_worker__"

_PACKAGE_DIR = Path(__file__).resolve().parent
WORKER_PATH = _PACKAGE_DIR / "worker_main.py"
ENGINE_PATH = _PACKAGE_DIR.parent / "parsers" / "decompress.py"
QPACK_KIND_PATH = _PACKAGE_DIR / "qpack_kind.py"

BREAKER_OPEN_MESSAGE = "decoder worker disabled after repeated crashes"
CONTEXT_LOST_MESSAGE = "decoder context lost (worker restarted)"


class WorkerFailure(NamedTuple):
    """A request that produced no valid reply. *message* is safe to log."""

    kind: str  # "crash" | "timeout" | "protocol" | "start" | "breaker" | "too_large" | "lost"
    message: str


Validator = Callable[[P.Frame], "str | None"]


def _truthy_env(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes")


def default_timeout() -> float:
    """Base per-request timeout (``FRITAP_DECODER_TIMEOUT`` overrides 10 s)."""
    try:
        value = float(os.environ.get(TIMEOUT_ENV, ""))
    except ValueError:
        return DEFAULT_TIMEOUT
    return value if value > 0 else DEFAULT_TIMEOUT


@contextlib.contextmanager
def _main_module_hidden():
    """Hide ``__main__`` while spawning so the child does not re-import it.

    ``multiprocessing`` spawn re-runs the parent's main script in the child
    (for the friTap CLI that imports all of friTap, Frida included). The
    worker needs nothing from it, so a bare stand-in is shown for the
    duration of ``Process.start()``.
    """
    real_main = sys.modules.get("__main__")
    sys.modules["__main__"] = types.ModuleType("__main__")
    try:
        yield
    finally:
        if real_main is not None:
            sys.modules["__main__"] = real_main


def describe_exit(exitcode: int | None) -> str:
    """Human-readable worker exit status."""
    if exitcode is None:
        return "still running"
    if exitcode < 0:
        try:
            return f"killed by {signal.Signals(-exitcode).name}"
        except ValueError:
            return f"killed by signal {-exitcode}"
    return f"exit code {exitcode}"


class DecoderSupervisor:
    """Owns the worker process; :meth:`request` is the only way to talk to it."""

    def __init__(self, *, timeout: float | None = None, test_hooks: bool | None = None,
                 harden: bool = True, breaker: CircuitBreaker | None = None,
                 max_contexts: int | None = None) -> None:
        self.timeout = timeout
        self.max_contexts = max_contexts  # None: the worker's default cap
        self.test_hooks = _truthy_env(TEST_HOOKS_ENV) if test_hooks is None else test_hooks
        self.harden = harden
        self.breaker = breaker or CircuitBreaker()
        self.generation = 0
        self.hello_text = ""
        self.last_startup_seconds: float | None = None
        self._lock = threading.Lock()
        self._process = None
        self._conn = None
        self._request_id = 0
        self._watchdog: Watchdog | None = None

    # --- public ----------------------------------------------------------------

    @property
    def pid(self) -> int | None:
        """PID of the live worker, or None."""
        process = self._process
        return process.pid if process is not None and process.is_alive() else None

    def request(self, op: int, *, data: bytes = b"", text: bytes = b"", flags: int = 0,
                handle: int = 0, arg0: int = 0, arg1: int = 0, max_reply: int = 0,
                label: str = "", output_hint: int = 0,
                validate: Validator | None = None,
                expected_generation: int | None = None) -> P.Frame | WorkerFailure:
        """Send one request; return the validated reply frame or a failure.

        *max_reply* caps the reply data length (the caller's ``max_out``),
        *label* names the input in logs and quarantine files (e.g. the
        encoding), *output_hint* scales the timeout, and *validate* adds
        op-specific checks (a non-None message is a protocol violation).
        With *expected_generation* (context calls) the request is only sent
        to that worker generation; otherwise a ``"lost"`` failure is returned
        without starting a worker. Never raises for worker misbehaviour and never blocks past the timeout.
        """
        reply, _generation = self.request_in_generation(
            op, data=data, text=text, flags=flags, handle=handle, arg0=arg0, arg1=arg1,
            max_reply=max_reply, label=label, output_hint=output_hint, validate=validate,
            expected_generation=expected_generation)
        return reply

    def request_in_generation(self, op: int, *, data: bytes = b"", text: bytes = b"",
                              flags: int = 0, handle: int = 0, arg0: int = 0, arg1: int = 0,
                              max_reply: int = 0, label: str = "", output_hint: int = 0,
                              validate: Validator | None = None,
                              expected_generation: int | None = None,
                              ) -> tuple[P.Frame | WorkerFailure, int]:
        """:meth:`request` plus the worker generation that answered (read under
        the lock, so a context handle is never tagged with a later worker)."""
        if len(data) > P.MAX_REQUEST_DATA:
            return WorkerFailure("too_large", "input too large for decoder worker"), 0
        with self._lock:
            if self.breaker.is_open():
                return WorkerFailure("breaker", BREAKER_OPEN_MESSAGE), 0
            if expected_generation is not None and not self._serves(expected_generation):
                return WorkerFailure("lost", CONTEXT_LOST_MESSAGE), 0
            failure = self._ensure_started()
            if failure is not None:
                return failure, 0
            generation = self.generation
            return self._exchange(op, data, text, flags, handle, arg0, arg1,
                                  max_reply, label, output_hint, validate), generation

    def shutdown(self) -> None:
        """Stop the worker (EOF first, then kill) and the watchdog thread."""
        with self._lock:
            self._stop_worker(graceful=True)
            if self._watchdog is not None:
                self._watchdog.stop()
                self._watchdog = None

    # --- lifecycle -------------------------------------------------------------

    def _serves(self, generation: int) -> bool:
        """True when worker *generation* is the live one (its contexts exist)."""
        alive = self._process is not None and self._process.is_alive()
        return alive and generation == self.generation

    def _ensure_started(self) -> WorkerFailure | None:
        if self._process is not None and self._process.is_alive():
            return None
        self._stop_worker(graceful=False)
        if self._watchdog is None:
            self._watchdog = Watchdog(self._kill_worker)
        started = time.perf_counter()
        try:
            self._spawn()
            self._await_hello()
        except Exception as exc:
            return self._start_failed(exc)
        self.last_startup_seconds = time.perf_counter() - started
        self.generation += 1
        logger.debug("decoder worker %s started in %.0f ms (hardening: %s)",
                     self._process.pid, self.last_startup_seconds * 1000,
                     self.hello_text or "none")
        return None

    def _spawn(self) -> None:
        ctx = multiprocessing.get_context("spawn")
        parent_conn, child_conn = ctx.Pipe(duplex=True)
        config = {"conn": child_conn, "protocol_path": str(_PACKAGE_DIR / "protocol.py"),
                  "hardening_path": str(_PACKAGE_DIR / "hardening.py"),
                  "engine_path": str(ENGINE_PATH), "qpack_kind_path": str(QPACK_KIND_PATH),
                  "test_hooks": self.test_hooks, "harden": self.harden,
                  "max_contexts": self.max_contexts}
        process = ctx.Process(
            target=runpy.run_path, args=(str(WORKER_PATH),),
            kwargs={"init_globals": {"__fritap_worker_config__": config},
                    "run_name": WORKER_RUN_NAME},
            name="fritap-decoder-worker", daemon=True)
        with _main_module_hidden():
            process.start()
        child_conn.close()
        self._process, self._conn = process, parent_conn

    def _await_hello(self) -> None:
        self._watchdog.arm(STARTUP_TIMEOUT)
        try:
            message = self._conn.recv_bytes(P.HEADER_SIZE + P.MAX_TEXT_LEN)
        finally:
            if self._watchdog.disarm():
                raise TimeoutError("no HELLO from worker")
        hello = P.parse_reply(message, op=P.Op.HELLO, request_id=0, max_data=0)
        self.hello_text = P.safe_worker_text(hello.text)

    def _start_failed(self, exc: Exception) -> WorkerFailure:
        exitcode = self._stop_worker(graceful=False)
        self.breaker.record_failure()
        reason = f"decoder worker failed to start ({type(exc).__name__}, {describe_exit(exitcode)})"
        logger.error(reason)
        return WorkerFailure("start", reason)

    def _kill_worker(self) -> None:
        """Watchdog callback: hard-kill the worker (unblocks the pending recv)."""
        process = self._process
        if process is not None and process.is_alive():
            process.kill()

    def _stop_worker(self, *, graceful: bool) -> int | None:
        """Close the pipe, then reap (killing if needed); return the exit code."""
        process, conn = self._process, self._conn
        self._process = self._conn = None
        if conn is not None:
            with contextlib.suppress(Exception):
                conn.close()
        if process is None:
            return None
        process.join(REAP_TIMEOUT if graceful else 0.2)
        if process.is_alive():
            process.kill()
            process.join(REAP_TIMEOUT)
        exitcode = process.exitcode
        with contextlib.suppress(Exception):
            process.close()
        return exitcode

    # --- one exchange ----------------------------------------------------------

    def _next_request_id(self) -> int:
        self._request_id = (self._request_id % P.U32_MASK) + 1
        return self._request_id

    def _request_timeout(self, input_len: int, output_hint: int) -> float:
        base = self.timeout if self.timeout is not None else default_timeout()
        scaled_out = min(output_hint, P.MAX_REPLY_DATA)
        return (base + input_len / INPUT_BYTES_PER_SECOND
                + scaled_out / OUTPUT_BYTES_PER_SECOND)

    def _exchange(self, op, data, text, flags, handle, arg0, arg1, max_reply,
                  label, output_hint, validate) -> P.Frame | WorkerFailure:
        request_id = self._next_request_id()
        frame = P.encode_frame(op, request_id, flags=flags, handle=handle,
                               arg0=arg0, arg1=arg1, text=text, data=data)
        max_reply = max(0, min(max_reply, P.MAX_REPLY_DATA))
        self._watchdog.arm(self._request_timeout(len(data), output_hint))
        try:
            self._conn.send_bytes(frame)
            message = self._conn.recv_bytes(P.HEADER_SIZE + P.MAX_TEXT_LEN + max_reply)
        except (EOFError, OSError, ValueError) as exc:
            return self._io_failure(exc, data, label)
        finally:
            timed_out = self._watchdog.disarm()
        if timed_out:
            return self._fail("timeout", "timed out", data, label)
        return self._validated(message, op, request_id, max_reply, validate, data, label)

    def _io_failure(self, exc: Exception, data: bytes, label: str) -> WorkerFailure:
        """EOF/broken pipe: the watchdog killed it (timeout) or it crashed."""
        if self._watchdog.disarm():
            return self._fail("timeout", "timed out", data, label)
        if isinstance(exc, OSError) and "bad message length" in str(exc):
            return self._fail("protocol", "sent an oversized reply", data, label)
        return self._fail("crash", "crashed", data, label)

    def _validated(self, message, op, request_id, max_reply, validate, data, label):
        try:
            reply = P.parse_reply(message, op=op, request_id=request_id, max_data=max_reply)
            problem = validate(reply) if validate is not None else None
        except P.ProtocolError as exc:
            problem = str(exc)
        if problem:
            return self._fail("protocol", f"sent an invalid reply ({problem})", data, label)
        return reply

    def _fail(self, kind: str, what: str, data: bytes, label: str) -> WorkerFailure:
        """Kill + reap, log loudly, quarantine the input, feed the breaker."""
        pid = self._process.pid if self._process is not None else None
        exitcode = self._stop_worker(graceful=kind == "crash")
        status = describe_exit(exitcode)
        sample = quarantine_input(data, label or "unknown", kind)
        logger.error(
            "Decoder worker %s %s (%s) while decoding %s input of %d bytes -- "
            "possible exploit attempt against a native decoder; input %s",
            pid, what, status, label or "unknown", len(data),
            f"quarantined at {sample}" if sample else "could not be quarantined")
        if self.breaker.record_failure():
            logger.error("Decoder worker failed repeatedly; %s for %.0f s",
                         BREAKER_OPEN_MESSAGE, self.breaker.cooldown)
        return WorkerFailure(kind, f"decoder worker {what} ({status})")


# --- process-wide singleton ---------------------------------------------------

_singleton: DecoderSupervisor | None = None
_singleton_lock = threading.Lock()
_atexit_registered = False


def get_supervisor() -> DecoderSupervisor:
    """The shared supervisor (created on first use; worker starts on first request)."""
    global _singleton, _atexit_registered
    with _singleton_lock:
        if _singleton is None:
            _singleton = DecoderSupervisor()
        if not _atexit_registered:
            atexit.register(shutdown_supervisor)
            _atexit_registered = True
        return _singleton


def shutdown_supervisor() -> None:
    """Stop the shared worker, if any (registered with ``atexit``)."""
    global _singleton
    with _singleton_lock:
        supervisor, _singleton = _singleton, None
    if supervisor is not None:
        supervisor.shutdown()


def set_supervisor(supervisor: DecoderSupervisor | None) -> DecoderSupervisor | None:
    """Swap the shared supervisor (tests); returns the previous one."""
    global _singleton
    with _singleton_lock:
        previous, _singleton = _singleton, supervisor
    return previous
