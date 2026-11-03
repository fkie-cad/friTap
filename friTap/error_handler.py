#!/usr/bin/env python3

"""
Error handler for friTap Frida script errors.

Handles error reporting, JSON logging, rich console output,
and message formatting for Frida script messages.
"""

import logging
import os
import signal
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from .text_safety import safe_terminal_text

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.text import Text
except ImportError:
    Console = None


# Debug-mode dumps of binary data attached to agent log messages. The agent
# runs inside a possibly hostile target, so the dump directory is dedicated,
# filenames are generated here (never taken from agent data) and both the
# number of files and their total size are capped.
FRIDA_BLOB_SUBDIR = "frida_blobs"
MAX_FRIDA_BLOB_FILES = 100
MAX_FRIDA_BLOB_TOTAL_BYTES = 64 * 1024 * 1024
MAX_FRIDA_BLOB_BYTES = 4 * 1024 * 1024
FRIDA_BLOB_PREFIX = "frida_blob_"
FRIDA_BLOB_SUFFIX = ".bin"


def frida_blob_dir() -> Path:
    """The dedicated directory for debug blob dumps (not created here)."""
    import platformdirs
    return Path(platformdirs.user_log_dir("friTap", appauthor=False)) / FRIDA_BLOB_SUBDIR


class FridaBlobStore:
    """Writes agent-attached debug blobs under count / total-size caps."""

    _lock = threading.Lock()
    _sequence = 0
    _cap_warned = False

    @classmethod
    def save(cls, data, logger) -> "Path | None":
        """Persist (the first MAX_FRIDA_BLOB_BYTES of) *data*; return the path.

        Returns ``None`` -- logging the reason once -- when a cap is reached
        or the write fails.
        """
        blob = bytes(data[:MAX_FRIDA_BLOB_BYTES])
        with cls._lock:
            directory = frida_blob_dir()
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            if not cls._has_room(directory, len(blob)):
                cls._warn_cap_once(logger, directory)
                return None
            path = directory / cls._next_name()
            cls._write_private(path, blob)
            return path

    @staticmethod
    def _existing_blobs(directory: Path) -> list:
        return [p for p in directory.glob(f"{FRIDA_BLOB_PREFIX}*{FRIDA_BLOB_SUFFIX}")
                if p.is_file()]

    @classmethod
    def _has_room(cls, directory: Path, size: int) -> bool:
        existing = cls._existing_blobs(directory)
        if len(existing) >= MAX_FRIDA_BLOB_FILES:
            return False
        total = sum(p.stat().st_size for p in existing)
        return total + size <= MAX_FRIDA_BLOB_TOTAL_BYTES

    @classmethod
    def _next_name(cls) -> str:
        cls._sequence += 1
        stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        return (f"{FRIDA_BLOB_PREFIX}{stamp}_{os.getpid()}_"
                f"{cls._sequence:06d}{FRIDA_BLOB_SUFFIX}")

    @staticmethod
    def _write_private(path: Path, blob: bytes) -> None:
        """Create *path* exclusively with mode 0600 and write *blob*."""
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        fd = os.open(path, flags, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(blob)

    @classmethod
    def _warn_cap_once(cls, logger, directory: Path) -> None:
        if cls._cap_warned:
            return
        cls._cap_warned = True
        logger.warning(
            "Not saving further agent debug blobs: %s already holds the maximum "
            "(%d files / %d MiB).", directory, MAX_FRIDA_BLOB_FILES,
            MAX_FRIDA_BLOB_TOTAL_BYTES // (1024 * 1024))


def _markup_safe(value) -> str:
    """Agent text made safe for both the terminal and Rich markup."""
    text = safe_terminal_text(value)
    try:
        from rich.markup import escape
    except ImportError:
        return text
    return escape(text)


# Non-fatal agent runtime exceptions (e.g. thrown inside a Java.perform /
# setTimeout callback) do not stop the Frida script, so they must not end the
# run either: killing the host makes friTap detach while hooks are still being
# installed, which can crash the target ("attempting to detach while still
# running code"). They are logged, rate-limited per distinct error.
RUNTIME_ERROR_LOG_INTERVAL = 60.0
MAX_TRACKED_RUNTIME_ERRORS = 256
_RUNTIME_ERROR_OVERFLOW_KEY = ("<other agent runtime errors>", "")


class RuntimeErrorLimiter:
    """Decides which repeated agent runtime errors are worth logging.

    The first occurrence of each distinct error is logged; repeats are counted
    and summarised at most once per RUNTIME_ERROR_LOG_INTERVAL. The table is
    bounded so a hostile agent cannot grow it without limit.
    """

    _lock = threading.Lock()
    _entries: dict = {}  # key -> [last_logged_at, suppressed_count]
    _hint_shown = False

    @classmethod
    def reset(cls) -> None:
        with cls._lock:
            cls._entries = {}
            cls._hint_shown = False

    @classmethod
    def check(cls, key, now: float):
        """``None`` to suppress, else the number of repeats suppressed since
        the last time this error was logged."""
        with cls._lock:
            if key not in cls._entries and len(cls._entries) >= MAX_TRACKED_RUNTIME_ERRORS:
                key = _RUNTIME_ERROR_OVERFLOW_KEY
            entry = cls._entries.get(key)
            if entry is None:
                cls._entries[key] = [now, 0]
                return 0
            if now - entry[0] < RUNTIME_ERROR_LOG_INTERVAL:
                entry[1] += 1
                return None
            suppressed, entry[0], entry[1] = entry[1], now, 0
            return suppressed

    @classmethod
    def take_hint(cls) -> bool:
        """True exactly once per process: show the "still running" hint."""
        with cls._lock:
            shown, cls._hint_shown = cls._hint_shown, True
            return not shown


def _runtime_error_key(description: str, stack: str) -> tuple:
    """Identity of a runtime error: its text plus the top stack frame."""
    lines = [ln.strip() for ln in stack.splitlines() if ln.strip()]
    top_frame = lines[1] if len(lines) > 1 else (lines[0] if lines else "")
    return description[:512], top_frame[:512]


def log_runtime_script_error(message, logger, source="Agent"):
    """Log a non-fatal Frida script ``error`` message, rate-limited.

    Returns ``(description, stack)`` (terminal-safe) when the error was
    logged, or ``None`` when it was suppressed as a recent repeat.
    """
    description = safe_terminal_text(message.get("description", "Unknown error"))
    stack = safe_terminal_text(message.get("stack", ""))
    suppressed = RuntimeErrorLimiter.check(
        (source,) + _runtime_error_key(description, stack), time.monotonic())
    if suppressed is None:
        return None
    repeat_note = f" (repeated {suppressed} more time(s))" if suppressed else ""
    logger.error("%s runtime error%s: %s%s", source, repeat_note, description,
                 f"\n{stack}" if stack else "")
    if RuntimeErrorLimiter.take_hint():
        logger.warning(
            "friTap keeps running: an exception in a script callback does not "
            "stop the script, and other hooks keep working. Identical errors are "
            "reported at most once per %d s.", int(RUNTIME_ERROR_LOG_INTERVAL))
    return description, stack


class ScriptErrorHandler:
    """Handles Frida script errors and message formatting."""

    @staticmethod
    def handle(message, event_bus, session_data, session_data_lock,
               json_output, debug_output, logger, fatal=True):
        """Handle a Frida script error message.

        A *fatal* error (raised while the agent was loading / initialising,
        so it cannot work) emits an ErrorEvent, logs to JSON if enabled,
        renders rich output if debug_output is active, and terminates the
        process. A non-fatal runtime exception is delegated to
        :meth:`handle_runtime_error` and the session keeps running.

        Args:
            message: The Frida error message dict.
            event_bus: The EventBus instance for emitting ErrorEvent.
            session_data: Session data dict for JSON error logging.
            session_data_lock: Threading lock for session_data access.
            json_output: JSON output path (truthy if JSON logging enabled).
            debug_output: Whether debug output is active.
            logger: A logging.Logger instance.
            fatal: False for a runtime exception that left the agent working.
        """
        if not fatal:
            ScriptErrorHandler.handle_runtime_error(
                message, event_bus, session_data, session_data_lock,
                json_output, logger)
            return

        from .events import ErrorEvent

        print("\n\n")
        # Every field comes from the (possibly hostile) target: neutralise
        # terminal control sequences before anything is displayed.
        error_msg = safe_terminal_text(message.get("description", "Unknown error"))
        stack = safe_terminal_text(message.get("stack", "No stacktrace provided"))
        file = safe_terminal_text(message.get("fileName", ""))
        line = safe_terminal_text(message.get("lineNumber", ""))
        column = safe_terminal_text(message.get("columnNumber", ""))

        # Emit error event via EventBus
        event_bus.emit(ErrorEvent(
            error=error_msg,
            description=error_msg,
            stack=stack,
            file=str(file),
            line=str(line),
        ))

        ScriptErrorHandler._record_json_error(
            message, session_data, session_data_lock, json_output,
            "frida_script_error")

        if debug_output:
            if Console:
                console = Console()
                header = Text("✖ Frida Script Error", style="bold red")
                body = Text.from_markup(
                    f"[bold]Description:[/bold] {_markup_safe(error_msg)}\n"
                    f"[bold]File:[/bold] {_markup_safe(file)}:{_markup_safe(line)}:"
                    f"{_markup_safe(column)}\n\n"
                    f"[bold]Stacktrace:[/bold]\n{_markup_safe(stack)}"
                )
                panel = Panel(body, title=header, expand=False, border_style="red")
                console.print(panel)
            else:
                logger.error("✖ Frida Script Error:")
                logger.error("Description: %s", error_msg)
                logger.error("File: %s:%s:%s", file, line, column)
                logger.error("Stacktrace:\n%s", stack)
        else:
            logger.error("Error from Frida script: %s", error_msg)

        logger.critical("Exiting due to script error.")
        os.kill(os.getpid(), signal.SIGTERM)

    @staticmethod
    def _record_json_error(message, session_data, session_data_lock,
                           json_output, error_type) -> None:
        """Append the error to the JSON session log, if JSON output is on.

        JSON encoding already neutralises control characters, so the raw
        agent values are kept there.
        """
        if not json_output:
            return
        error_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "type": error_type,
            "description": message.get("description", "Unknown error"),
            "file": message.get("fileName", ""),
            "line": message.get("lineNumber", ""),
            "column": message.get("columnNumber", ""),
            "stack": message.get("stack", "No stacktrace provided"),
        }
        with session_data_lock:
            session_data["errors"].append(error_entry)

    @staticmethod
    def handle_runtime_error(message, event_bus, session_data,
                             session_data_lock, json_output, logger) -> None:
        """Log a non-fatal agent runtime exception; the session continues.

        Identical errors are rate-limited (see :class:`RuntimeErrorLimiter`).
        """
        from .events import ErrorEvent

        logged = log_runtime_script_error(message, logger)
        if logged is None:
            return
        description, stack = logged
        event_bus.emit(ErrorEvent(
            error=description,
            description=description,
            stack=stack,
            file=safe_terminal_text(message.get("fileName", "")),
            line=safe_terminal_text(message.get("lineNumber", "")),
        ))
        ScriptErrorHandler._record_json_error(
            message, session_data, session_data_lock, json_output,
            "frida_script_runtime_error")

    @staticmethod
    def format_fritap_message(message, data, level_map, to_datetime_fn,
                              short_file_fn, logger):
        """Format and log a Frida send/error message.

        Args:
            message: The Frida message dict.
            data: Binary data attached to the message (or None).
            level_map: Dict mapping level strings to logging levels.
            to_datetime_fn: Callable to convert timestamps to datetime.
            short_file_fn: Callable to shorten file paths.
            logger: A logging.Logger instance.
        """
        msg_type = message.get("type")
        if msg_type == "send":
            payload = message.get("payload", {}) or {}
            if not isinstance(payload, dict):
                logger.warning("Received non-dict payload: %s",
                               safe_terminal_text(repr(payload)))
                return

            level = payload.get("level", "info")
            ts = payload.get("time") or payload.get("timestamp")
            text = safe_terminal_text(
                payload.get("message") or payload.get("msg") or "<no message>")
            file = payload.get("file")
            line = payload.get("line")
            func = payload.get("func")

            if text == "<no message>" or len(text) <= 3:
                return

            dt = to_datetime_fn(ts)
            time_str = dt.isoformat(sep=" ") if dt else safe_terminal_text(ts)

            # Build [File: <name:line>] tag
            short = short_file_fn(file)
            short = safe_terminal_text(short) if short else short
            line = safe_terminal_text(line) if line is not None else None
            func = safe_terminal_text(func) if func else func
            file_tag = ""
            if short and line is not None:
                file_tag = f"[File: {short}:{line}]"
            elif short:
                file_tag = f"[File: {short}]"

            # Optional: include function name
            if func:
                file_tag = f"{file_tag[:-1]}, fn={func}]" if file_tag else f"[fn={func}]"

            py_level = level_map.get(str(level).lower(), logging.INFO)

            parts = [f"[{time_str}]"]
            if file_tag:
                parts.append(file_tag)
            parts.append(text)
            log_msg = " ".join(parts)

            logger.log(py_level, log_msg, extra={"_colorize": True})

            if data:
                ScriptErrorHandler._save_attached_blob(data, logger)

        elif msg_type == "error":
            description = safe_terminal_text(message.get("description", "<no desc>"))
            stack = safe_terminal_text(message.get("stack"))
            logger.error("Frida script error: %s\n%s", description, stack)
        else:
            logger.debug("Unhandled message type: %s payload=%s data=%s",
                         safe_terminal_text(msg_type),
                         safe_terminal_text(repr(message.get("payload"))),
                         safe_terminal_text(repr(data)))

    @staticmethod
    def _save_attached_blob(data, logger) -> None:
        """Dump agent-attached *data* into the capped blob directory."""
        try:
            path = FridaBlobStore.save(data, logger)
        except Exception as e:
            logger.exception("Failed to save attached data: %s", e)
            return
        if path is not None:
            logger.info("Saved attached data to %s", path)
