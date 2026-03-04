#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Error handler for friTap Frida script errors.

Handles error reporting, JSON logging, rich console output,
and message formatting for Frida script messages.
"""

import os
import signal
import logging
from datetime import datetime, timezone

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.text import Text
except ImportError:
    Console = None


class ScriptErrorHandler:
    """Handles Frida script errors and message formatting."""

    @staticmethod
    def handle(message, event_bus, session_data, session_data_lock,
               json_output, debug_output, logger):
        """Handle a Frida script error message.

        Emits an ErrorEvent, logs to JSON if enabled, renders rich output
        if debug_output is active, and terminates the process.

        Args:
            message: The Frida error message dict.
            event_bus: The EventBus instance for emitting ErrorEvent.
            session_data: Session data dict for JSON error logging.
            session_data_lock: Threading lock for session_data access.
            json_output: JSON output path (truthy if JSON logging enabled).
            debug_output: Whether debug output is active.
            logger: A logging.Logger instance.
        """
        from .events import ErrorEvent

        print("\n\n")
        error_msg = message.get("description", "Unknown error")
        stack = message.get("stack", "No stacktrace provided")
        file = message.get("fileName", "")
        line = message.get("lineNumber", "")
        column = message.get("columnNumber", "")

        # Emit error event via EventBus
        event_bus.emit(ErrorEvent(
            error=error_msg,
            description=error_msg,
            stack=stack,
            file=str(file),
            line=str(line),
        ))

        # Log error to JSON if enabled
        if json_output:
            error_entry = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "type": "frida_script_error",
                "description": error_msg,
                "file": file,
                "line": line,
                "column": column,
                "stack": stack
            }
            with session_data_lock:
                session_data["errors"].append(error_entry)

        if debug_output:
            if Console:
                console = Console()
                header = Text("✖ Frida Script Error", style="bold red")
                body = Text.from_markup(
                    f"[bold]Description:[/bold] {error_msg}\n"
                    f"[bold]File:[/bold] {file}:{line}:{column}\n\n"
                    f"[bold]Stacktrace:[/bold]\n{stack}"
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
                logger.warning("Received non-dict payload: %r", payload)
                return

            level = payload.get("level", "info")
            ts = payload.get("time") or payload.get("timestamp")
            text = payload.get("message") or payload.get("msg") or "<no message>"
            file = payload.get("file")
            line = payload.get("line")
            func = payload.get("func")

            if text == "<no message>" or len(text) <= 3:
                return

            dt = to_datetime_fn(ts)
            time_str = dt.isoformat(sep=" ") if dt else str(ts)

            # Build [File: <name:line>] tag
            short = short_file_fn(file)
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
                try:
                    fname = f"frida_blob_{int(datetime.utcnow().timestamp())}.bin"
                    with open(fname, "wb") as f:
                        f.write(data)
                    logger.info("Saved attached data to %s", fname)
                except Exception as e:
                    logger.exception("Failed to save attached data: %s", e)

        elif msg_type == "error":
            description = message.get("description", "<no desc>")
            stack = message.get("stack")
            logger.error("Frida script error: %s\n%s", description, stack or "")
        else:
            logger.debug("Unhandled message type: %s payload=%r data=%r",
                         msg_type, message.get("payload"), data)
