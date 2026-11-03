#!/usr/bin/env python3

"""Reserve the process's stdout for the ``-j -`` JSONL event stream.

When ``-j -`` / ``--json -`` is given, stdout must carry nothing but JSONL so
scripts and AI agents can parse it line by line. Rather than chase every
``print()``, banner and logging handler, :func:`claim_stdout_for_json_stream`
works at the file-descriptor level:

1. the original stdout fd is duplicated and wrapped as the private JSON stream;
2. fd 1 is then pointed at stderr (``dup2``), so every other write to stdout --
   Python ``print()``, logging handlers bound to ``sys.stdout``, native code and
   a target process spawned afterwards that inherits our stdio -- lands on
   stderr instead.

The claim is process-wide and idempotent: the second caller (e.g. the Windows
LSASS helper session sharing ``-j -``) gets the same stream.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
from typing import IO, Callable, Optional

#: The ``-j``/``--json`` value that selects the stdout JSONL stream.
JSON_STREAM_STDOUT = "-"

#: Schema/version marker carried by every stream line.
STREAM_SCHEMA = "fritap.events/1"

_lock = threading.Lock()
_stream: Optional[IO] = None

#: Exit code reported when friTap fails at runtime (mirrors friTap.exit_codes).
_EXIT_RUNTIME_ERROR = 1

# Run outcome, read once when the stream closes (``stream_end``): the first
# runtime error noted by the CLI, and a callable returning the process's final
# exit status (SSL_Logger's first-non-zero-wins status).
_first_runtime_error: Optional[dict] = None
_exit_status_provider: Optional[Callable[[], Optional[int]]] = None

# Envelope progress of the claimed stream: ``stream_start`` written / the
# closing record (``stream_end`` or ``usage_error``) written. Lets
# :func:`finish_unclosed_stream` complete the envelope for a run that failed
# before (or without) the JSONL output handler ever opening or closing it.
_stream_opened = False
_stream_closed = False


def is_stdout_target(path: Optional[str]) -> bool:
    """True when *path* is the ``-`` placeholder meaning "stdout"."""
    return path == JSON_STREAM_STDOUT


def _flush_python_streams() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.flush()
        except Exception:  # noqa: BLE001 - a closed/odd stream must not block
            pass


def claim_stdout_for_json_stream(stdout_fd: int = 1, stderr_fd: int = 2) -> IO:
    """Return the JSON stream and redirect everything else on stdout to stderr.

    Idempotent; the fds are parameters only so tests can use pipes.
    """
    global _stream
    with _lock:
        if _stream is not None:
            return _stream
        _flush_python_streams()
        json_fd = os.dup(stdout_fd)
        os.dup2(stderr_fd, stdout_fd)
        _stream = os.fdopen(json_fd, "w", buffering=1, encoding="utf-8",
                            errors="replace", closefd=True)
        return _stream


def argv_requests_stdout_stream(argv) -> bool:
    """True when *argv* (without the program name) contains ``-j -``/``--json -``.

    Used before/without argparse (e.g. on a usage error) to know whether stdout
    is promised to be pure JSONL.
    """
    tokens = list(argv)
    for index, token in enumerate(tokens):
        if token in ("-j", "--json") and index + 1 < len(tokens) \
                and is_stdout_target(tokens[index + 1]):
            return True
        if token in ("-j-", "--json=-"):
            return True
    return False


def envelope(kind: str, fields: dict) -> dict:
    """One stream record: the ``schema``/``type``/``timestamp`` envelope + *fields*.

    *fields* win on a key clash (e.g. an event's own ``timestamp``).
    """
    return {"schema": STREAM_SCHEMA, "type": kind, "timestamp": time.time(), **fields}


def write_stream_record(record: dict) -> None:
    """Write *record* (must carry ``type``) to the claimed stream, enveloped.

    No-op when stdout was not claimed.

    The stream is line-buffered (``buffering=1``), so each line is flushed on
    its trailing newline.
    """
    stream = _stream
    if stream is None:
        return
    try:
        stream.write(json.dumps(envelope(record["type"], record), ensure_ascii=False) + "\n")
    except Exception:  # noqa: BLE001 - e.g. the reader closed the pipe
        pass


def note_runtime_error(error_type: str, message: str,
                       hint: Optional[str] = None) -> None:
    """Remember the cause of a runtime failure for the closing ``error`` record.

    Only records; the record itself is written once, when the stream closes,
    so it carries the FINAL exit code. The first noted error wins, like the
    exit status itself.
    """
    global _first_runtime_error
    with _lock:
        if _first_runtime_error is not None:
            return
        _first_runtime_error = {"error_type": error_type or "RuntimeError",
                                "message": message or error_type or "runtime error"}
        if hint:
            _first_runtime_error["hint"] = hint


def register_exit_status_provider(provider: Callable[[], Optional[int]]) -> None:
    """Install the callable that returns the process's final exit status."""
    global _exit_status_provider
    with _lock:
        _exit_status_provider = provider


def final_exit_code() -> Optional[int]:
    """The final exit status, or None when no provider is registered / it fails."""
    provider = _exit_status_provider
    if provider is None:
        return None
    try:
        return provider()
    except Exception:  # noqa: BLE001 - never block the stream's end
        return None


def runtime_error_fields(exit_code: Optional[int]) -> Optional[dict]:
    """Fields of the closing ``error`` record, or None when the run did not fail.

    Written for every non-zero exit that has a noted cause, and for a bare
    runtime-error exit (1) without one, so a consumer always learns why.
    """
    error = _first_runtime_error
    if not exit_code:
        return None
    if error is None:
        if exit_code != _EXIT_RUNTIME_ERROR:
            return None
        error = {"error_type": "RuntimeError",
                 "message": "friTap stopped with a runtime error; see stderr for details."}
    return {**error, "exit_code": exit_code}


def mark_stream_opened() -> None:
    """Record that ``stream_start`` was written to the claimed stream."""
    global _stream_opened
    with _lock:
        _stream_opened = True


def mark_stream_closed() -> None:
    """Record that the stream's closing record was written (nothing may follow)."""
    global _stream_closed
    with _lock:
        _stream_closed = True


def is_stream_closed() -> bool:
    return _stream_closed


def _closing_records(exit_code: Optional[int]) -> list:
    """``error`` (when the run failed) + ``stream_end`` for *exit_code*."""
    records = []
    error = runtime_error_fields(exit_code)
    if error is not None:
        records.append({"type": "error", **error})
    records.append({"type": "stream_end", "exit_code": exit_code})
    return records


def finish_unclosed_stream(exit_code: Optional[int], *,
                           key_material: bool = False) -> bool:
    """Emergency writer: complete the ``-j -`` envelope if nobody else did.

    For failures that happen before the JSONL output handler opened the stream
    (e.g. a refused macOS platform binary, a config error) or where it never
    closed it: writes the missing ``stream_start``, the ``error`` record (cause
    noted via :func:`note_runtime_error`, else the generic "see stderr" text
    for exit 1) and ``stream_end``. No-op when stdout was not claimed or the
    stream is already closed. Returns True when it wrote the closing records.
    """
    if _stream is None or _stream_closed:
        return False
    if not _stream_opened:
        write_stream_record({"type": "stream_start", "key_material": key_material})
        mark_stream_opened()
    for record in _closing_records(exit_code):
        write_stream_record(record)
    mark_stream_closed()
    return True


def _reset_for_tests() -> None:
    """Forget the claimed stream and run outcome (unit tests only; no fd restore)."""
    global _stream, _first_runtime_error, _exit_status_provider
    global _stream_opened, _stream_closed
    with _lock:
        _stream = None
        _first_runtime_error = None
        _exit_status_provider = None
        _stream_opened = False
        _stream_closed = False


__all__ = [
    "JSON_STREAM_STDOUT",
    "STREAM_SCHEMA",
    "argv_requests_stdout_stream",
    "envelope",
    "write_stream_record",
    "claim_stdout_for_json_stream",
    "final_exit_code",
    "finish_unclosed_stream",
    "is_stream_closed",
    "mark_stream_closed",
    "mark_stream_opened",
    "is_stdout_target",
    "note_runtime_error",
    "register_exit_status_provider",
    "runtime_error_fields",
]
