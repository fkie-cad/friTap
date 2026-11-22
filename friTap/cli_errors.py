"""User-facing error hints and reporters for the capture CLI.

The hint builders are pure so their wording stays testable. The reporters run
inside ``cli()``'s exception handlers and only log (or raise a FriTapExit).
"""

import sys
import traceback

from .backends import BackendError
from .cli_stream import _error_type_name, _note_stream_runtime_error
from .exit_codes import EXIT_RUNTIME_ERROR
from .fritap_utility import Failure, Success


def _format_seconds(seconds):
    """Render a duration without rounding a sub-second value away to "0.0s".

    "0.0s" would read as *disabled* (0 means that for --script-load-timeout),
    so it must never be printed for a bound that fired.
    """
    return f"{seconds:.3f}s" if 0 < seconds < 1 else f"{seconds:.1f}s"


def _script_load_timeout_hints(elapsed_seconds, breadcrumb, timeout):
    """Return the user-facing message lines for a script-load timeout.

    Pure so the wording stays testable. ``breadcrumb`` is the agent's last
    reported stage (may be empty), the best signal for where the load wedged.
    """
    # timeout is None when the user disabled the bound; breadcrumb may be missing.
    bound = f" (bound: {_format_seconds(timeout)})" if timeout else ""
    breadcrumb = breadcrumb or ""
    lines = [
        f"Agent did not finish loading within {_format_seconds(elapsed_seconds)}{bound}.",
    ]
    # Match the breadcrumb verdicts used by SSL_Logger's crash reporting so
    # both places tell the user the same story about the same marker.
    if breadcrumb.startswith("agent-init"):
        lines.append(
            f"  The agent died before any hook was installed "
            f"(last agent stage: {breadcrumb})."
        )
    elif breadcrumb.startswith("install-phase"):
        lines.append(
            f"  The agent died while installing hooks "
            f"(last agent stage: {breadcrumb})."
        )
    elif breadcrumb:
        lines.append(f"  Last agent stage: {breadcrumb}.")
    else:
        lines.append("  The agent never reported a startup stage.")
    lines.append(
        "  -> Rebuild the agent bundle with ./dev/compile_agent.sh — a stale or "
        "partially-built bundle is a common cause."
    )
    lines.append(
        "  -> Re-run with --probe (if available) to isolate the failing agent stage."
    )
    lines.append(
        "  -> Raise the bound with --script-load-timeout <seconds>, or pass "
        "--script-load-timeout 0 to disable it."
    )
    return lines


def _process_not_responding_hints(message, spawn):
    """Return the user-facing message lines for a not-responding target (pure)."""
    lines = [f"Target process is not responding: {message}"]
    lines.append(
        "  The target did not complete the agent-injection handshake in time."
    )
    if spawn:
        lines.append(
            "  -> Spawn-time injection stalls on targets that do heavy work (or "
            "an integrity check) at startup. Start the app yourself, then ATTACH "
            "friTap (run WITHOUT -s)."
        )
    else:
        lines.append(
            "  -> The process may be suspended, stopped in a debugger, or wedged "
            "in a syscall. Verify it is running and responsive, then retry."
        )
    lines.append(
        "  -> Also confirm the backend server version matches the friTap client."
    )
    return lines


_DEVICE_NOT_FOUND_HINT = (
    "Unable to identify the target device; pass its ID with -m <device-id> "
    "(see `adb devices` or `fritap devices`).")

_REMOTE_SERVER_DOWN_HINT = (
    "Backend server is not running on remote device. Please start frida-server "
    "(e.g. via `afrim` or the TUI's Server Check -> Install) and rerun.")


def _unexpected_error_line(error):
    """The log line for an error the capture's specific handlers did not catch.

    A plain backend error (e.g. frida's ExecutableNotFoundError) is shown as
    "<FridaClass>: <message>"; only a genuinely unexpected exception (a friTap
    bug, category ``backend_bug``) keeps the "Unknown error" wording.
    """
    if isinstance(error, BackendError) and error.category != "backend_bug":
        return f"{_error_type_name(error)}: {error}"
    if "NotSupportedError" in type(error).__name__:
        return f"Backend error: {error}"
    return f"Unknown error: {error}"


def _report_transport_error(fe, ssl_log, logger):
    """Log a mid-session transport error, unless on_detach already explained it."""
    if getattr(ssl_log, "_crash_reported", False):
        pass  # already reported clearly by on_detach
    else:
        logger.error(f"Backend transport error: {fe}")
        # Remote frida-server 17.24.0-17.24.3 closes the link on a > 128 KiB
        # message: say so (once), as the target may not have crashed at all.
        _remote_hint = None
        if ssl_log is not None and not getattr(ssl_log, "_remote_limit_hint_reported", False):
            try:
                _remote_hint = ssl_log.remote_message_limit_hint_for(fe)
            except Exception:  # noqa: BLE001 - a hint must never mask the error
                _remote_hint = None
        if _remote_hint:
            logger.error(_remote_hint)
        crumb = getattr(ssl_log, "_last_hook_breadcrumb", "")
        spawn = getattr(ssl_log, "spawn", False)
        # A plain exit only when the agent fully initialised in attach mode
        # ("agent-init: complete"); an empty/partial crumb (especially in
        # spawn mode) is treated as a possible hook crash.
        if not spawn and crumb == "agent-init: complete":
            logger.error(
                "The target process ended (last agent stage: agent-init: "
                "complete); if this was unexpected, check the debug log.")
        else:
            extra = f" (last instrumented: {crumb})" if crumb else ""
            logger.error(
                f"The target process appears to have terminated unexpectedly"
                f"{extra} — it may have crashed inside an instrumented hook. "
                f"Check the debug log.")


def _report_invalid_argument(e, logger):
    """Log an invalid-argument error, with device-selection help for "device not found"."""
    logger.error(f"Invalid argument: {e}")
    _note_stream_runtime_error(e, [_DEVICE_NOT_FOUND_HINT] if "device not found" in str(e) else None)
    if "device not found" in str(e):
        logger.error("Unable to identify the target device.")
        logger.error("If you have multiple devices connected, please specify the device ID using the `-m` option:")
        logger.error("\t1. Identify the target device ID (e.g., using `adb devices`).")
        logger.error("\t2. Run FriTap with the device ID:")
        logger.error("\t   fritap -m <device-id> <target>")


def _report_unexpected_error(ar, parsed, logger, special_logger):
    """Report an error no specific handler caught. Always raises a FriTapExit.

    Must be called from inside the ``except`` clause: it reads ``sys.exc_info()``.
    """
    ex_type, ex_value, ex_traceback = sys.exc_info()
    trace_back = traceback.extract_tb(ex_traceback)
    stack_trace = [
        "File : %s , Line : %d, Func.Name : %s, Message : %s" % (trace[0], trace[1], trace[2], trace[3])
        for trace in trace_back
    ]
    
    if parsed.debug or parsed.debug_output:
        if "NotSupportedError" in ex_type.__name__:
            logger.error("Backend error:")
        logger.error("Exception type : %s " % ex_type.__name__)
        logger.error("Exception message : %s" %ex_value)
        logger.error("Stack trace : %s" %stack_trace)


    remote_server_down = "unable to connect to remote frida-server: closed" in str(ar)
    if remote_server_down:
        logger.error(_REMOTE_SERVER_DOWN_HINT)
    _note_stream_runtime_error(ar, [_REMOTE_SERVER_DOWN_HINT] if remote_server_down else None)
        
    logger.error(_unexpected_error_line(ar))

    if "unable to access process with pid" in str(ex_value).lower():
        raise Success(logger=special_logger)
    if "not yet supported on this os" in str(ex_value).lower():
        logger.error("This feature is currently not supported on this OS.")
        raise Success(logger=special_logger)

    raise Failure(code=EXIT_RUNTIME_ERROR)
