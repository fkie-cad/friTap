#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
GDB instrumentation backend for friTap.

Uses GDB's Python API for breakpoint-based hooking. Useful for
debugging, CI/CD testing, or environments where Frida can't run.

The ``gdb`` Python module is available only inside GDB's embedded
Python interpreter. Run friTap from within GDB::

    gdb -x your_script.py -p <pid>

Or use ``gdb -batch -x`` for non-interactive extraction.
"""

from __future__ import annotations

import logging
import struct
from typing import Any, Callable

from .base import (
    Backend,
    BackendError,
    BackendProcessNotFoundError,
    ThreadInfo,
)
from .debugger_script import DebuggerScript

# Optional import — gdb module only available inside GDB's Python
try:
    import gdb as _gdb_module
except ImportError:
    _gdb_module = None

_INSTALL_HINT = (
    "GDB Python module not found. The 'gdb' module is only available "
    "inside GDB's embedded Python interpreter.\n"
    "  Usage:  gdb -x your_script.py -p <pid>\n"
    "  Or:     gdb -batch -x extract_keys.py -p <pid>\n"
    "  Linux:  apt install gdb python3-gdb  (if not already installed)"
)


def _ensure_gdb() -> None:
    """Raise BackendError if the gdb module is unavailable."""
    if _gdb_module is None:
        raise BackendError(_INSTALL_HINT)


class GDBScript(DebuggerScript):
    """Frida-style script using GDB breakpoints.

    Each function name is translated to a ``gdb.Breakpoint`` with
    a ``stop()`` callback that invokes the registered message handler.
    """

    def load(self) -> None:
        """Create GDB breakpoints for all function names."""
        _ensure_gdb()

        for fn in self._function_names:
            try:
                bp = _FriTapBreakpoint(fn, self._callback)
                self._breakpoints[fn] = bp
            except Exception as e:
                logging.getLogger("friTap.backend.gdb").warning(
                    "Could not set breakpoint on '%s': %s", fn, e
                )
        self._loaded = True

    def unload(self) -> None:
        """Delete all GDB breakpoints."""
        for bp in self._breakpoints.values():
            try:
                bp.delete()
            except Exception:
                pass
        self._breakpoints.clear()
        self._loaded = False

    def set_message_callback(self, callback: Callable) -> None:
        super().set_message_callback(callback)
        # Also update existing breakpoints' callback references
        for bp in self._breakpoints.values():
            if isinstance(bp, _FriTapBreakpoint):
                bp._callback = callback


# Conditional class — only defined when gdb is available
if _gdb_module is not None:
    class _FriTapBreakpoint(_gdb_module.Breakpoint):
        """GDB Breakpoint subclass that invokes a callback on hit."""

        def __init__(self, function_name: str, callback: Callable | None = None):
            super().__init__(function_name, _gdb_module.BP_BREAKPOINT)
            self._fn_name = function_name
            self._callback = callback

        def stop(self) -> bool:
            """Called by GDB when breakpoint is hit. Returns False to continue."""
            if self._callback:
                try:
                    frame = _gdb_module.selected_frame()
                    message = {
                        "type": "send",
                        "payload": {
                            "contentType": "breakpoint_hit",
                            "function": self._fn_name,
                            "pc": str(frame.pc()),
                        }
                    }
                    self._callback(message, None)
                except Exception:
                    pass
            return False  # Don't stop — continue execution
else:
    class _FriTapBreakpoint:
        """Placeholder when gdb module is not available."""
        def __init__(self, *args, **kwargs):
            raise BackendError(_INSTALL_HINT)


class GDBBackend(Backend):
    """
    GDB-based backend using breakpoints for function hooking.

    Requires GDB's Python API (``gdb`` module), which is only
    available inside GDB's embedded Python interpreter.
    """

    def __init__(self) -> None:
        self._logger = logging.getLogger("friTap.backend.gdb")
        self._gdb = _gdb_module
        self._cached_ptr_size: int | None = None
        self._init_detach_callbacks()

        if self._gdb is not None:
            self._logger.info("GDB backend initialized (version: %s)", self.version)
        else:
            self._logger.warning("GDB backend created but gdb module not available")

    # ------------------------------------------------------------------
    # Device
    # ------------------------------------------------------------------

    def get_device(self, mobile: bool | str = False, host: str | None = None) -> Any:
        if mobile:
            raise NotImplementedError("GDB backend does not support mobile devices")
        if host:
            # GDB supports remote targets via gdbserver
            _ensure_gdb()
            self._gdb.execute(f"target remote {host}")
            return host
        return "local"

    # ------------------------------------------------------------------
    # Attach / Spawn
    # ------------------------------------------------------------------

    def attach(self, device: Any, target: str) -> Any:
        _ensure_gdb()
        try:
            pid = int(target)
            self._gdb.execute(f"attach {pid}")
        except ValueError:
            # Attach by name — need to find PID first
            self._gdb.execute(f"attach {target}")

        inferior = self._gdb.selected_inferior()
        if not inferior or not inferior.is_valid():
            raise BackendProcessNotFoundError(f"GDB could not attach to '{target}'")

        self._logger.info("Attached to process: %s (PID %d)", target, inferior.pid)
        return inferior

    def spawn(self, device: Any, target: str, env: dict | None = None) -> tuple[Any, int]:
        _ensure_gdb()
        self._gdb.execute(f"file {target}")

        if env:
            for key, val in env.items():
                self._gdb.execute(f"set environment {key}={val}")

        # Start but stop at entry
        self._gdb.execute("starti")
        inferior = self._gdb.selected_inferior()
        return inferior, inferior.pid

    def spawn_raw(self, device: Any, target, env: dict | None = None) -> int:
        _ensure_gdb()
        exe = target[0] if isinstance(target, list) else str(target)
        args = " ".join(target[1:]) if isinstance(target, list) and len(target) > 1 else ""

        self._gdb.execute(f"file {exe}")
        if args:
            self._gdb.execute(f"set args {args}")

        if env:
            for key, val in env.items():
                self._gdb.execute(f"set environment {key}={val}")

        self._gdb.execute("starti")
        return self._gdb.selected_inferior().pid

    def resume(self, device: Any, pid: int) -> None:
        _ensure_gdb()
        self._gdb.execute("continue &")  # Async continue

    # ------------------------------------------------------------------
    # Script
    # ------------------------------------------------------------------

    def create_script(self, process: Any, script_source: str, runtime: str = "qjs") -> Any:
        _ensure_gdb()
        fn_names = self._extract_function_names(script_source)
        return GDBScript(fn_names)

    def load_script(self, script: Any) -> None:
        if isinstance(script, GDBScript):
            script.load()

    def unload_script(self, script: Any) -> None:
        try:
            if isinstance(script, GDBScript):
                script.unload()
        except Exception:
            pass

    def on_message(self, script: Any, callback: Callable) -> None:
        if isinstance(script, GDBScript):
            script.set_message_callback(callback)

    def post_message(self, script: Any, msg_type: str, payload: Any) -> None:
        # GDB scripts don't receive messages like Frida
        pass

    # ------------------------------------------------------------------
    # Process management
    # ------------------------------------------------------------------

    def detach(self, process: Any) -> None:
        if self._gdb is None:
            return
        try:
            self._gdb.execute("detach")
            self._fire_detach_callbacks(process)
        except Exception as e:
            self._logger.warning("GDB detach warning: %s", e)

    def on_detached(self, process: Any, callback: Callable) -> None:
        pid = self._get_process_pid(process)
        self._detach_callbacks.setdefault(pid, []).append(callback)

    # ------------------------------------------------------------------
    # Debugger
    # ------------------------------------------------------------------

    def enable_debugger(self, script: Any, port: int) -> None:
        self._logger.info("GDB is already a debugger — no separate debugger port needed")

    # ------------------------------------------------------------------
    # Threads
    # ------------------------------------------------------------------

    def enumerate_threads(self, process: Any) -> list[ThreadInfo]:
        _ensure_gdb()
        threads = []
        inferior = process if hasattr(process, 'threads') else self._gdb.selected_inferior()
        for thread in inferior.threads():
            threads.append(ThreadInfo(
                id=thread.global_num,
                name=thread.name or f"Thread-{thread.num}",
                index=thread.num,
                is_stopped=thread.is_stopped(),
            ))
        return threads

    def suspend_thread(self, process: Any, thread_id: int) -> None:
        _ensure_gdb()
        self._gdb.execute(f"thread {thread_id}")
        self._gdb.execute("interrupt")

    def resume_thread(self, process: Any, thread_id: int) -> None:
        _ensure_gdb()
        self._gdb.execute(f"thread {thread_id}")
        self._gdb.execute("continue &")

    # ------------------------------------------------------------------
    # Device enumeration
    # ------------------------------------------------------------------

    def enumerate_devices(self) -> list:
        return [{"id": "local", "name": "Local System (GDB)", "type": "local"}]

    def get_local_device(self) -> Any:
        return "local"

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "gdb"

    @property
    def version(self) -> str:
        if self._gdb is None:
            return "0.0.0-unavailable"
        try:
            return self._gdb.VERSION
        except AttributeError:
            return "0.0.0"

    # ------------------------------------------------------------------
    # Memory helpers (for SSH/IPSec key extraction)
    # ------------------------------------------------------------------

    def read_memory(self, target, addr: int, size: int) -> bytes:
        """Read raw bytes from inferior memory."""
        _ensure_gdb()
        return target.read_memory(addr, size).tobytes()

    def read_pointer(self, target, addr: int) -> int:
        """Read a pointer-sized value with cached architecture detection."""
        if self._cached_ptr_size is None:
            ptr_size = 8
            try:
                arch = _gdb_module.selected_frame().architecture().name()
                if "i386" in arch or ("arm" in arch and "aarch64" not in arch):
                    ptr_size = 4
            except Exception:
                pass
            self._cached_ptr_size = ptr_size
        raw = self.read_memory(target, addr, self._cached_ptr_size)
        fmt = "<Q" if self._cached_ptr_size == 8 else "<I"
        return struct.unpack(fmt, raw)[0]
