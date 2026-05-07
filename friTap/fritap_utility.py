#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pathlib import Path
from .backends import get_backend
import atexit
import contextlib
import logging
import os
import platform
import queue
import signal
import sys
import tempfile
import threading
import time
import traceback as _traceback
import warnings
from typing import Iterable, Optional

def find_pid_by_name(proc_name: str) -> int | None:
    """
    Locate the PID of an *already-running* process whose executable name
    matches `proc_name` (case-insensitive).
    
    Parameters
    ----------
    proc_name : str
        e.g. "notepad.exe"  (".exe" optional)

    Returns
    -------
    int | None
        PID of the first match, or None if not found.
    """
    target = proc_name.lower().removesuffix(".exe")
    backend = get_backend()
    dev = backend.get_local_device()
    for p in backend.enumerate_processes(dev):
        name = Path(p.name).stem.lower()
        if name == target:
            return p.pid
    return None


def get_pid_of_lsass() -> int | None:
    """
    Get the PID of the Local Security Authority Subsystem Service (LSASS) process.
    
    Returns
    -------
    int | None
        PID of LSASS or None if not found.
    """
    return find_pid_by_name("lsass")  # LSASS is typically named "lsass.exe" on Windows

def stringify_list(*args):
    """
    Turn a potenially nested list-ish into a string, typically for debug purposes.
    """
    return ' '.join([
        stringify_list(*arg) if isinstance(arg, (list, tuple)) else str(arg) \
        for arg in args
    ])
     
def are_we_running_on_windows() -> bool:
    """
    Pure Python check if the host system is Windows.
    This runs before spawning the target application.
    """
    return platform.system().lower() == "windows"


WINDOWS_LIVE_UNSUPPORTED = (
    "Live Wireshark mode is not supported on Windows. "
    "Named pipes (os.mkfifo) are not available on Windows. "
    "Use -p <file.pcapng> to write a PCAP file instead, "
    "then open it in Wireshark."
)


def find_wireshark_binary() -> str | None:
    """Locate the Wireshark executable on the system.

    Checks PATH first, then falls back to the macOS app bundle location.
    """
    import shutil
    for name in ("wireshark", "Wireshark"):
        path = shutil.which(name)
        if path:
            return path
    # macOS app bundle fallback
    mac_path = "/Applications/Wireshark.app/Contents/MacOS/Wireshark"
    if os.path.isfile(mac_path):
        return mac_path
    return None


def supports_color(stream) -> bool:
    try:
        return (
            hasattr(stream, "isatty") and stream.isatty() and
            os.getenv("NO_COLOR") is None and
            os.getenv("TERM", "") not in ("", "dumb")
        )
    except Exception:
        return False


def setup_fritap_logging(logger_name="friTap", debug=False, debug_output=False):
    """
    Shared logging setup for friTap.

    Creates both the main logger (with CustomFormatter prefix) and
    a special logger for clean messages without prefixes.

    Parameters
    ----------
    logger_name : str
        Base name for the logger (default "friTap").
    debug : bool
        Enable debug-level logging.
    debug_output : bool
        Enable debug-level logging (alternative flag).

    Returns
    -------
    tuple[logging.Logger, logging.Logger]
        (main_logger, special_logger)
    """
    level = logging.DEBUG if (debug or debug_output) else logging.INFO

    logger = logging.getLogger(logger_name)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(CustomFormatter(use_color=supports_color(handler.stream)))
        handler.setLevel(level)
        logger.setLevel(level)
        logger.addHandler(handler)
        logger.propagate = False

    special = logging.getLogger(f"{logger_name}.no_prefix")
    if not special.handlers:
        special.setLevel(level)
        h = logging.StreamHandler()
        h.setFormatter(logging.Formatter("%(message)s"))
        special.addHandler(h)
        special.propagate = False

    return logger, special


class CustomFormatter(logging.Formatter):
    """friTap prefix + optional ANSI colors (only when record._colorize=True)."""

    RESET = "\x1b[0m"
    COLORS = {
        logging.DEBUG:    "\x1b[95m",    # magenta
        logging.INFO:     "\x1b[32m",    # green
        logging.WARNING:  "\x1b[33m",    # yellow
        logging.ERROR:    "\x1b[31m",    # red
        logging.CRITICAL: "\x1b[31;1m",  # bright red
    }

    PREFIXES = {
        logging.INFO:     "[*]",
        logging.DEBUG:    "[!]",
        logging.WARNING:  "[-]",
        logging.ERROR:    "[-]",
        logging.CRITICAL: "[-]",
    }

    def __init__(self, *, use_color: bool = True):
        # we ignore parent fmt; we fully control the line format here
        super().__init__()
        self.use_color = use_color

    def format(self, record: logging.LogRecord) -> str:
        prefix = self.PREFIXES.get(record.levelno, "[*]")
        text = f"{prefix} {record.getMessage()}"
        if self.use_color and getattr(record, "_colorize", False):
            color = self.COLORS.get(record.levelno)
            if color:
                return f"{color}{text}{self.RESET}"
        return text

class FriTapExit(Exception):
    """
    Base exception for controlled friTap exits.

    Subclasses should set `default_code` and `default_info` class attributes,
    and override `_log_level` property if needed.
    """
    default_code: int = 0
    default_info: str = ""

    def __init__(self, info: str = None, logger: logging.Logger = None, code: int = None):
        # Use provided values or fall back to class defaults
        self.info = info if info is not None else self.default_info
        self.logger = logger
        self.code = code if code is not None else self.default_code
        # Call parent Exception with the info message
        super().__init__(self.info)

    @property
    def _log_level(self) -> int:
        return logging.INFO

    def log(self, text: str) -> None:
        if self.logger:
            self.logger.log(self._log_level, text)
        else:
            print(text, file=sys.stderr)

    def exit(self) -> None:
        if self.info:
            self.log(self.info)
        sys.exit(self.code)


class Success(FriTapExit):
    default_code = 0
    default_info = "\n\nThx for using friTap\nHave a great day\n"

    @property
    def _log_level(self) -> int:
        return logging.INFO

class Failure(FriTapExit):
    default_code = 2
    default_info = ""

    @property
    def _log_level(self) -> int:
        return logging.ERROR


# ---------------------------------------------------------------------------
# Debug log subsystem
# ---------------------------------------------------------------------------
# Goal: a single file (``fritap_debug_<ts>_<pid>.log``) that captures ALL of:
#   * Python ``logging`` records from any logger (friTap, frida, scapy, h11,
#     asyncio, urllib3, py.warnings, root),
#   * ``warnings.warn(...)`` calls (via ``logging.captureWarnings(True)``),
#   * uncaught exceptions in main thread, worker threads, and asyncio tasks,
#   * the existing per-event prose blocks emitted by
#     ``CaptureController._setup_debug_log`` (which subscribes to the
#     EventBus and writes formatted DatalogEvent / KeylogEvent / ErrorEvent
#     blocks).
#
# The two writer paths (logging records and EventBus prose) share a single
# ``DebugLogWriter`` whose write method is non-blocking on the calling
# thread: each write enqueues a string on a ``queue.SimpleQueue`` drained
# by a daemon writer thread. This keeps the Frida hook thread free of
# disk I/O even at 5,000+ events/sec, and avoids the self-deadlock that
# a plain ``threading.Lock``-guarded stream would risk under
# ``logging.captureWarnings(True)``.

# Per-logger level overrides applied when the file handler is attached.
# Keeps third-party noise out of the file without forcing the user to
# configure every library separately.
_DEFAULT_LOGGER_LEVELS = {
    "friTap":     logging.DEBUG,
    "py.warnings": logging.WARNING,
    "frida":       logging.INFO,
    "scapy":       logging.WARNING,
    "asyncio":     logging.WARNING,
    "h11":         logging.WARNING,
    "urllib3":     logging.WARNING,
    "watchdog":    logging.WARNING,
    "textual":     logging.WARNING,
}

# Loggers we attach the file handler to. ``""`` is the root logger; we
# also attach explicitly to ``friTap`` because ``setup_fritap_logging``
# sets ``propagate=False`` on it. ``py.warnings`` is intentionally NOT
# listed: it propagates to root and would otherwise log every warning
# twice.
_FILE_HANDLER_TARGET_LOGGERS = ("", "friTap")

# Module-level singletons; populated by open_debug_log() and torn down
# by close_debug_log()/atexit.
_debug_log_writer: Optional["DebugLogWriter"] = None
_debug_log_path: Optional[str] = None
_debug_file_handler: Optional[logging.Handler] = None
_warnings_capture_enabled: bool = False
_excepthook_installed: bool = False
_prior_sys_excepthook = None
_prior_threading_excepthook = None
_signal_handlers_installed: bool = False
_prior_signal_handlers: dict = {}

_DEBUG_LOG_FORMATTER = logging.Formatter(
    fmt="%(asctime)s.%(msecs)03d %(levelname)-5s [%(threadName)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)


class DebugLogWriter:
    """Async, single-consumer debug-log writer.

    Calls to :meth:`write` enqueue the (already-formatted) string and
    return immediately. A daemon thread drains the queue and writes
    line-buffered to the underlying file. ``flush`` and ``close`` are
    blocking — they wait until the queue is drained.

    Thread-safety: any number of producer threads may call ``write``
    concurrently; ordering between producers is best-effort (queue
    ordering). No lock is exposed to producers.
    """

    _SENTINEL = object()

    def __init__(self, fp) -> None:
        self._fp = fp
        self._queue: "queue.SimpleQueue[object]" = queue.SimpleQueue()
        self._closed = threading.Event()
        self._drained = threading.Event()
        self._thread = threading.Thread(
            target=self._run,
            name="friTap-debug-log-writer",
            daemon=True,
        )
        self._thread.start()

    @property
    def stream(self):
        return self._fp

    def write(self, text: str) -> int:
        if self._closed.is_set():
            return 0
        self._queue.put(text)
        return len(text)

    def flush(self) -> None:
        # Insert a synchronisation marker; wait until drained.
        if self._closed.is_set():
            return
        evt = threading.Event()
        self._queue.put(("flush", evt))
        evt.wait(timeout=2.0)

    def close(self, timeout: float = 2.0) -> None:
        if self._closed.is_set():
            return
        self._closed.set()
        self._queue.put(self._SENTINEL)
        self._thread.join(timeout=timeout)
        try:
            self._fp.flush()
        except Exception:
            pass
        try:
            self._fp.close()
        except Exception:
            pass

    def _run(self) -> None:
        while True:
            item = self._queue.get()
            if item is self._SENTINEL:
                self._drained.set()
                return
            if isinstance(item, tuple) and len(item) == 2 and item[0] == "flush":
                try:
                    self._fp.flush()
                except Exception:
                    pass
                item[1].set()
                continue
            try:
                self._fp.write(item)
            except Exception:
                # Writer thread must never die: a broken pipe / disk-full
                # error must not silently lose the rest of the log.
                try:
                    sys.__stderr__.write(
                        f"friTap debug log write failed: {item[:80]}...\n"
                    )
                except Exception:
                    pass


class _DebugLogStreamProxy:
    """Stream-like adapter handed to ``logging.StreamHandler``.

    Delegates write/flush to the active ``DebugLogWriter`` if one is
    open; silently no-ops otherwise. Exists so the FileHandler installed
    early in main() does not break when the writer is later torn down.
    """

    def write(self, s: str) -> int:
        w = _debug_log_writer
        if w is None:
            return 0
        return w.write(s)

    def flush(self) -> None:
        w = _debug_log_writer
        if w is not None:
            w.flush()


def _resolve_debug_log_path(override: Optional[str] = None) -> str:
    """Pick an absolute, writable path for the debug log."""
    if override:
        return os.path.abspath(os.path.expanduser(override))
    env = os.environ.get("FRITAP_DEBUG_LOG")
    if env:
        return os.path.abspath(os.path.expanduser(env))
    ts = time.strftime("%Y%m%d_%H%M%S")
    name = f"fritap_debug_{ts}_{os.getpid()}.log"
    # Prefer cwd; fall back to tempdir if cwd is not writable.
    cwd = os.getcwd()
    candidate = os.path.join(cwd, name)
    try:
        # Cheap writability probe via os.access; opening for read+write
        # is more authoritative but creates the file even on failure.
        if os.access(cwd, os.W_OK):
            return candidate
    except Exception:
        pass
    return os.path.join(tempfile.gettempdir(), name)


def _format_debug_log_header() -> str:
    from importlib.metadata import PackageNotFoundError, version as _pkg_version
    parts = [
        f"# friTap debug log — started {time.strftime('%Y-%m-%d %H:%M:%S')}\n",
    ]
    try:
        from friTap.about import __version__ as fritap_ver
    except Exception:
        fritap_ver = "?"
    py_ver = sys.version.split()[0]
    plat = sys.platform
    argv = " ".join(sys.argv)
    parts.append(
        f"# friTap={fritap_ver} python={py_ver} platform={plat} argv={argv}\n"
    )
    # importlib.metadata reads the dist-info METADATA without importing
    # the package, so heavyweight modules (frida, scapy) are not loaded
    # purely to print their version.
    versions = []
    for pkg in ("frida", "scapy", "h11", "textual"):
        try:
            versions.append(f"{pkg}={_pkg_version(pkg)}")
        except PackageNotFoundError:
            continue
        except Exception:
            continue
    if versions:
        parts.append("# " + " ".join(versions) + "\n")
    parts.append("\n")
    return "".join(parts)


def get_debug_log_path() -> Optional[str]:
    """Return the absolute path of the active debug log, or None."""
    return _debug_log_path


def get_debug_log_writer() -> Optional[DebugLogWriter]:
    """Return the active :class:`DebugLogWriter`, or None if not open."""
    return _debug_log_writer


def open_debug_log(path_override: Optional[str] = None) -> str:
    """Open the shared debug-log file and start the writer thread.

    Idempotent: if a log is already open at the same effective path,
    returns the existing path unchanged. Returns the absolute path.

    The header line and a metadata line (versions, argv, platform) are
    written immediately. Subsequent writes — both ``logging`` records
    and EventBus prose blocks — go through the same writer thread and
    interleave at line boundaries.
    """
    global _debug_log_writer, _debug_log_path
    if _debug_log_writer is not None:
        return _debug_log_path  # type: ignore[return-value]
    target = _resolve_debug_log_path(path_override)
    # Open binary-text with line buffering; the writer thread is the
    # sole consumer so additional locking is unnecessary.
    fp = open(target, "w", buffering=1, encoding="utf-8", errors="replace")
    _debug_log_writer = DebugLogWriter(fp)
    _debug_log_path = target
    _debug_log_writer.write(_format_debug_log_header())
    return target


def close_debug_log() -> None:
    """Drain and close the debug log. Safe to call multiple times."""
    global _debug_log_writer, _debug_log_path, _debug_file_handler
    handler = _debug_file_handler
    if handler is not None:
        for name in _FILE_HANDLER_TARGET_LOGGERS:
            try:
                logging.getLogger(name).removeHandler(handler)
            except Exception:
                pass
        try:
            handler.close()
        except Exception:
            pass
        _debug_file_handler = None
    writer = _debug_log_writer
    if writer is not None:
        try:
            writer.write(
                f"\n# friTap debug log — closed {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
            )
        except Exception:
            pass
        writer.close()
    _debug_log_writer = None
    _debug_log_path = None


def attach_file_handlers(
    level: int = logging.DEBUG,
    targets: Iterable[str] = _FILE_HANDLER_TARGET_LOGGERS,
    logger_levels: Optional[dict] = None,
) -> Optional[logging.Handler]:
    """Install a single ``StreamHandler`` writing to the debug log.

    The handler is attached to each logger named in *targets*. Per-logger
    level overrides are applied from *logger_levels* (defaults sized to
    keep third-party libraries from drowning the file). Returns the
    installed handler, or ``None`` if no debug log is open yet.
    """
    global _debug_file_handler
    if _debug_log_writer is None:
        return None
    if _debug_file_handler is not None:
        return _debug_file_handler
    handler = logging.StreamHandler(_DebugLogStreamProxy())
    handler.setLevel(level)
    handler.setFormatter(_DEBUG_LOG_FORMATTER)
    # Stop the friTap logger propagating to root before we attach the same
    # handler to both — otherwise every friTap.* record would be written
    # twice (once via friTap's handler, once via root's). setup_fritap_logging
    # also sets this, but may run after attach_file_handlers, so enforce it
    # here unconditionally.
    logging.getLogger("friTap").propagate = False
    for name in targets:
        lg = logging.getLogger(name)
        if handler not in lg.handlers:
            lg.addHandler(handler)
    overrides = dict(_DEFAULT_LOGGER_LEVELS)
    if logger_levels:
        overrides.update(logger_levels)
    for name, lvl in overrides.items():
        logging.getLogger(name).setLevel(lvl)
    _debug_file_handler = handler
    return handler


def enable_warning_capture() -> None:
    """Route ``warnings.warn(...)`` through the ``py.warnings`` logger."""
    global _warnings_capture_enabled
    if _warnings_capture_enabled:
        return
    logging.captureWarnings(True)
    _warnings_capture_enabled = True


def install_global_excepthook() -> None:
    """Install chained ``sys.excepthook`` and ``threading.excepthook``.

    Each hook logs via ``logger.exception`` (-> debug log file) and then
    calls the prior hook. Idempotent.
    """
    global _excepthook_installed, _prior_sys_excepthook, _prior_threading_excepthook
    if _excepthook_installed:
        return
    crash_logger = logging.getLogger("friTap.uncaught")

    _prior_sys_excepthook = sys.excepthook

    def _sys_hook(exc_type, exc, tb):
        try:
            crash_logger.error(
                "Uncaught exception in main thread",
                exc_info=(exc_type, exc, tb),
            )
        except Exception:
            pass
        if _prior_sys_excepthook is not None and _prior_sys_excepthook is not _sys_hook:
            try:
                _prior_sys_excepthook(exc_type, exc, tb)
            except Exception:
                pass

    sys.excepthook = _sys_hook

    if hasattr(threading, "excepthook"):
        _prior_threading_excepthook = threading.excepthook

        def _thread_hook(args):
            try:
                crash_logger.error(
                    "Uncaught exception in thread %s",
                    args.thread.name if args.thread else "?",
                    exc_info=(args.exc_type, args.exc_value, args.exc_traceback),
                )
            except Exception:
                pass
            if (_prior_threading_excepthook is not None
                    and _prior_threading_excepthook is not _thread_hook):
                try:
                    _prior_threading_excepthook(args)
                except Exception:
                    pass

        threading.excepthook = _thread_hook

    _excepthook_installed = True


def install_signal_handlers() -> None:
    """Best-effort SIGINT/SIGTERM handlers that drain the debug log.

    Idempotent. Only registers handlers in the main thread (as required
    by ``signal.signal``); silently no-ops elsewhere. The prior handler
    is preserved and re-invoked after the drain.
    """
    global _signal_handlers_installed
    if _signal_handlers_installed:
        return
    if threading.current_thread() is not threading.main_thread():
        return
    for sig_name in ("SIGINT", "SIGTERM"):
        sig = getattr(signal, sig_name, None)
        if sig is None:
            continue
        try:
            prior = signal.getsignal(sig)
        except Exception:
            continue
        _prior_signal_handlers[sig] = prior

        def _handler(signum, frame, _prior=prior):
            try:
                w = _debug_log_writer
                if w is not None:
                    w.flush()
            except Exception:
                pass
            if callable(_prior) and _prior not in (signal.SIG_DFL, signal.SIG_IGN):
                try:
                    _prior(signum, frame)
                except Exception:
                    pass
            elif _prior == signal.SIG_DFL:
                # Re-raise default behavior by restoring and re-raising.
                signal.signal(signum, signal.SIG_DFL)
                os.kill(os.getpid(), signum)

        try:
            signal.signal(sig, _handler)
        except Exception:
            continue
    _signal_handlers_installed = True


@contextlib.contextmanager
def mute_console_handlers(logger_names: Iterable[str] = ("friTap", "friTap.no_prefix", "")):
    """Context manager that mutes stdout/stderr StreamHandlers on entry.

    On exit, prior levels are restored. Used while the Textual TUI is
    running to prevent log records from corrupting the screen. The
    debug-log file handler is unaffected.
    """
    saved: list = []
    for name in logger_names:
        log = logging.getLogger(name)
        for h in list(log.handlers):
            # Identify *console* StreamHandlers — those whose stream is
            # stdout or stderr — and exclude our own DebugLogStreamProxy.
            stream = getattr(h, "stream", None)
            if isinstance(h, logging.StreamHandler) and stream in (sys.stdout, sys.stderr):
                saved.append((h, h.level))
                h.setLevel(logging.CRITICAL + 1)
    try:
        yield
    finally:
        for h, lvl in saved:
            try:
                h.setLevel(lvl)
            except Exception:
                pass


def _atexit_drain() -> None:
    """Final flush at interpreter shutdown. Errors are swallowed."""
    try:
        close_debug_log()
    except Exception:
        pass


atexit.register(_atexit_drain)


def prime_debug_log(path_override: Optional[str] = None) -> Optional[str]:
    """Open the debug log and install all log capture mechanisms.

    Idempotent — calling twice is safe (each underlying primitive is
    individually idempotent). Returns the absolute log path on success
    or None on failure (errors are swallowed so callers cannot
    accidentally block startup on a debug-log issue).
    """
    try:
        path = open_debug_log(path_override)
        attach_file_handlers()
        enable_warning_capture()
        install_global_excepthook()
        install_signal_handlers()
        return path
    except Exception:
        return None
