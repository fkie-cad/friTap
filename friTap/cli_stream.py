"""'-j -' JSONL stdout stream glue for the capture CLI.

Every helper is a no-op unless the stream is active; see
:mod:`friTap.output.stdout_stream`.
"""

import sys

from .exit_codes import EXIT_OK, EXIT_USAGE_ERROR


def _claim_stdout_for_json_stream(parsed):
    """-j -: reserve stdout for JSONL before any banner/log line is written.

    Everything else that would reach stdout (print, logging, a spawned target's
    output) goes to stderr at the fd level; see :mod:`friTap.output.stdout_stream`.
    """
    from .output.stdout_stream import claim_stdout_for_json_stream, is_stdout_target
    if is_stdout_target(parsed.json):
        claim_stdout_for_json_stream()


def _error_type_name(error):
    """The underlying (e.g. frida) class name, not the backend's wrapper type."""
    return type(getattr(error, "original_exception", None) or error).__name__


def _stream_hint(hint_lines):
    """Hint lines as one string ('-> ' bullets stripped), or None."""
    parts = [line.strip().lstrip("->").strip() for line in hint_lines or ()]
    return " ".join(part for part in parts if part) or None


def _note_stream_runtime_error(error, hint_lines=None):
    """Note *error* as the cause of a failed capture for the '-j -' stream.

    Only records it: the stream writes the ``error`` record when it closes,
    with the final exit code (see JsonlStdoutHandler.close). No-op otherwise.
    """
    from .output.stdout_stream import note_runtime_error
    note_runtime_error(_error_type_name(error), str(error), _stream_hint(hint_lines))


def _register_stream_exit_status(ssl_log):
    """Let the '-j -' stream read *ssl_log*'s final exit status at stream_end."""
    from .output.stdout_stream import register_exit_status_provider
    register_exit_status_provider(
        lambda: getattr(ssl_log, "_exit_status", EXIT_OK))
    _register_stream_end_reason(ssl_log)


def _register_stream_end_reason(ssl_log):
    """Let '-j -''s stream_end say a clean run was stopped by a signal
    (``ended_by: "stopped"``); --duration notes its own reason first."""
    from .output.stdout_stream import ENDED_BY_STOPPED, register_end_reason_provider
    register_end_reason_provider(
        lambda: ENDED_BY_STOPPED if _stop_signal_received(ssl_log) else None)


def _stop_signal_received(ssl_log):
    """True once a Ctrl+C/SIGINT (or a --duration stop) started the teardown."""
    session_manager = getattr(ssl_log, "_session_manager", None)
    return bool(getattr(session_manager, "_exit_signal_received", False))


def _emit_json_stream_usage_error(message):
    """With '-j -' on the command line, keep stdout pure JSONL on a usage error.

    Claims stdout (so the human help text below goes to stderr) and writes one
    ``{"type": "usage_error", ...}`` record for the consuming script/agent.
    """
    from .output.stdout_stream import (
        argv_requests_stdout_stream,
        claim_stdout_for_json_stream,
        write_stream_record,
    )
    if not argv_requests_stdout_stream(sys.argv[1:]):
        return
    from .output.stdout_stream import mark_stream_closed
    claim_stdout_for_json_stream()
    write_stream_record({"type": "usage_error", "error": message,
                         "exit_code": EXIT_USAGE_ERROR})
    mark_stream_closed()  # the usage_error record is the stream's last line


def _split_exit_info(info):
    """A FriTapExit's (possibly multi-line) info as (message, hint lines)."""
    lines = [line for line in (info or "").splitlines() if line.strip()]
    if not lines:
        return None, []
    return lines[0].strip(), lines[1:]


def _finish_json_stream_on_exit(exit_code, info=None, error_type="StartupError"):
    """'-j -': give a run that ends before/without the capture teardown the
    full stream envelope (stream_start, error, stream_end).

    The general net for early failures after argparse (a refused macOS
    platform binary, a rejected --filter, a config error, ...): the cause is
    noted from the exit's own text unless an earlier, more specific one was
    already noted (first wins). No-op without '-j -' or when the stream
    already ended (the normal teardown or a usage_error record).
    """
    from .output.stdout_stream import finish_unclosed_stream, note_runtime_error
    message, hint_lines = _split_exit_info(info)
    if exit_code and message:
        note_runtime_error(error_type, message, _stream_hint(hint_lines))
    finish_unclosed_stream(exit_code)
