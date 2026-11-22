#!/usr/bin/env python3

"""Reserve the process's stdout for the ``-j -`` JSONL event stream.

stdout must carry nothing but JSONL. :func:`claim_stdout_for_json_stream` works
at the fd level: the original stdout fd is duplicated as the private JSON
stream, then fd 1 is ``dup2``-ed to stderr so every other stdout write (print,
logging, native code, an inheriting spawned target) lands on stderr.

The claim is process-wide and idempotent (the Windows LSASS helper shares the stream).
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
#: Exit code reported when the target exited/detached (mirrors friTap.exit_codes).
_EXIT_TARGET_DETACHED = 3

#: Why the run ended (``stream_end``'s ``ended_by``). Omitted when unknown.
ENDED_BY_DURATION = "duration"
ENDED_BY_STOPPED = "stopped"
ENDED_BY_TARGET_EXITED = "target_exited"
ENDED_BY_ERROR = "error"
_END_REASONS = frozenset({ENDED_BY_DURATION, ENDED_BY_STOPPED,
                          ENDED_BY_TARGET_EXITED, ENDED_BY_ERROR})

# Run outcome read once at ``stream_end``: the first runtime error noted by the CLI, and
# a callable returning the final exit status (first non-zero wins).
_first_runtime_error: Optional[dict] = None
_exit_status_provider: Optional[Callable[[], Optional[int]]] = None
# Why a clean (exit 0) run ended: the CLI's first noted reason (e.g. --duration) wins over the provider.
_noted_end_reason: Optional[str] = None
_end_reason_provider: Optional[Callable[[], Optional[str]]] = None

# Envelope progress, so :func:`finish_unclosed_stream` can complete it when the
# JSONL handler never opened or closed the stream.
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
    """Return the JSON stream and redirect everything else on stdout to stderr (idempotent; fds are parameters for tests)."""
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
    """True when *argv* (without the program name) contains ``-j -``/``--json -`` (usable before argparse)."""
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
    """Write *record* (must carry ``type``) to the claimed stream, enveloped; no-op when unclaimed.

    The stream is line-buffered, so each line flushes on its newline.
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
    """Remember the cause of a runtime failure for the closing ``error`` record (first wins).

    The record is written at close so it carries the final exit code.
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

    Written for a non-zero exit with a noted cause and for a bare exit 1, so a consumer learns why.
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


def note_end_reason(reason: str) -> None:
    """Remember why a clean run is ending (``duration``/``stopped``); first wins; only used for exit 0."""
    global _noted_end_reason
    if reason not in _END_REASONS:
        raise ValueError(f"unknown end reason: {reason!r}")
    with _lock:
        if _noted_end_reason is None:
            _noted_end_reason = reason


def register_end_reason_provider(provider: Callable[[], Optional[str]]) -> None:
    """Install the fallback callable that says why a clean run ended (or None)."""
    global _end_reason_provider
    with _lock:
        _end_reason_provider = provider


def _provided_end_reason() -> Optional[str]:
    provider = _end_reason_provider
    if provider is None:
        return None
    try:
        reason = provider()
    except Exception:  # noqa: BLE001 - never block the stream's end
        return None
    return reason if reason in _END_REASONS else None


def ended_by(exit_code: Optional[int]) -> Optional[str]:
    """``stream_end``'s ``ended_by`` for *exit_code*, or None when unknown.

    A detach (3) and failures speak for themselves; a clean exit reports the
    noted reason, else the provider's. Unknown codes and unexplained clean exits give None.
    """
    if exit_code == _EXIT_TARGET_DETACHED:
        return ENDED_BY_TARGET_EXITED
    if exit_code == 0:
        return _noted_end_reason or _provided_end_reason()
    if runtime_error_fields(exit_code) is not None:
        return ENDED_BY_ERROR
    return None


def stream_end_fields(exit_code: Optional[int]) -> dict:
    """The ``stream_end`` record's fields: ``exit_code`` (+ ``ended_by`` when known)."""
    fields = {"exit_code": exit_code}
    reason = ended_by(exit_code)
    if reason is not None:
        fields["ended_by"] = reason
    return fields


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
    records.append({"type": "stream_end", **stream_end_fields(exit_code)})
    return records


def finish_unclosed_stream(exit_code: Optional[int], *,
                           key_material: bool = False) -> bool:
    """Emergency writer: complete the ``-j -`` envelope if nobody else did.

    For failures before the JSONL handler opened the stream, or that never closed it:
    writes the missing ``stream_start``, ``error`` (cause from :func:`note_runtime_error`,
    else the generic "see stderr" text for exit 1) and ``stream_end``. No-op when unclaimed
    or already closed. Returns True when it wrote the closing records.
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
    global _stream_opened, _stream_closed, _noted_end_reason, _end_reason_provider
    with _lock:
        _stream = None
        _first_runtime_error = None
        _exit_status_provider = None
        _noted_end_reason = None
        _end_reason_provider = None
        _stream_opened = False
        _stream_closed = False


__all__ = [
    "JSON_STREAM_STDOUT",
    "STREAM_SCHEMA",
    "argv_requests_stdout_stream",
    "envelope",
    "write_stream_record",
    "claim_stdout_for_json_stream",
    "ENDED_BY_DURATION",
    "ENDED_BY_ERROR",
    "ENDED_BY_STOPPED",
    "ENDED_BY_TARGET_EXITED",
    "ended_by",
    "final_exit_code",
    "finish_unclosed_stream",
    "is_stream_closed",
    "mark_stream_closed",
    "mark_stream_opened",
    "is_stdout_target",
    "note_end_reason",
    "note_runtime_error",
    "register_end_reason_provider",
    "register_exit_status_provider",
    "runtime_error_fields",
    "stream_end_fields",
]
