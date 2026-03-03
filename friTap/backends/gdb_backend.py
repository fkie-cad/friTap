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
import re
import struct
from typing import Any, Callable

from .base import (
    Backend,
    BackendError,
    BackendProcessNotFoundError,
    BackendInvalidOperationError,
)

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


class GDBScript:
    """Simulates a Frida-style script using GDB breakpoints.

    Each function name is translated to a ``gdb.Breakpoint`` with
    a ``stop()`` callback that invokes the registered message handler.
    """

    def __init__(self, function_names: list[str], message_callback: Callable | None = None):
        self._function_names = function_names
        self._callback = message_callback
        self._breakpoints: dict[str, Any] = {}
        self._loaded = False

    def load(self) -> None:
        """Create GDB breakpoints for all function names."""
        if _gdb_module is None:
            raise BackendError(_INSTALL_HINT)

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

    @property
    def is_loaded(self) -> bool:
        return self._loaded

    def set_message_callback(self, callback: Callable) -> None:
        self._callback = callback
        # Update existing breakpoints
        for bp in self._breakpoints.values():
            if isinstance(bp, _FriTapBreakpoint):
                bp._callback = callback

    def post(self, message: dict) -> None:
        """Simulate posting a message to the script (no-op for GDB)."""
        pass

    @property
    def exports_sync(self):
        raise BackendInvalidOperationError(
            "GDB backend does not support script RPC exports."
        )


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
        self._detach_callbacks: dict[int, list[Callable]] = {}

        if self._gdb is not None:
            self._logger.info("GDB backend initialized (version: %s)", self.version)
        else:
            self._logger.warning("GDB backend created but gdb module not available")

    def _require_gdb(self) -> None:
        """Raise BackendError if gdb is not available."""
        if self._gdb is None:
            raise BackendError(_INSTALL_HINT)

    # ------------------------------------------------------------------
    # Device
    # ------------------------------------------------------------------

    def get_device(self, mobile: bool | str = False, host: str | None = None) -> Any:
        if mobile:
            raise NotImplementedError("GDB backend does not support mobile devices")
        if host:
            # GDB supports remote targets via gdbserver
            self._require_gdb()
            self._gdb.execute(f"target remote {host}")
            return host
        return "local"

    # ------------------------------------------------------------------
    # Attach / Spawn
    # ------------------------------------------------------------------

    def attach(self, device: Any, target: str) -> Any:
        self._require_gdb()
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
        self._require_gdb()
        self._gdb.execute(f"file {target}")

        if env:
            for key, val in env.items():
                self._gdb.execute(f"set environment {key}={val}")

        # Start but stop at entry
        self._gdb.execute("starti")
        inferior = self._gdb.selected_inferior()
        return inferior, inferior.pid

    def spawn_raw(self, device: Any, target, env: dict | None = None) -> int:
        self._require_gdb()
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
        self._require_gdb()
        self._gdb.execute("continue &")  # Async continue

    # ------------------------------------------------------------------
    # Script
    # ------------------------------------------------------------------

    def create_script(self, process: Any, script_source: str, runtime: str = "qjs") -> Any:
        self._require_gdb()
        fn_names = re.findall(
            r'(?:Module\.findExportByName|BreakpointCreateByName)\s*\(\s*["\']([^"\']+)',
            script_source
        )
        fn_names += re.findall(
            r'hookFunction\s*\(\s*["\']([^"\']+)',
            script_source
        )
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
            pid = process.pid if hasattr(process, 'pid') else 0
            self._gdb.execute("detach")
            for cb in self._detach_callbacks.get(pid, []):
                try:
                    cb("user-requested")
                except Exception:
                    pass
        except Exception as e:
            self._logger.warning("GDB detach warning: %s", e)

    def on_detached(self, process: Any, callback: Callable) -> None:
        pid = process.pid if hasattr(process, 'pid') else 0
        self._detach_callbacks.setdefault(pid, []).append(callback)

    # ------------------------------------------------------------------
    # Gating (not supported)
    # ------------------------------------------------------------------

    def enable_child_gating(self, process: Any) -> None:
        # GDB has follow-fork-mode but it's not the same as Frida's gating
        raise NotImplementedError("GDB backend does not support child gating")

    def enable_spawn_gating(self, device: Any) -> None:
        raise NotImplementedError("GDB backend does not support spawn gating")

    def on_child_added(self, device: Any, callback: Callable) -> None:
        raise NotImplementedError("GDB backend does not support child events")

    def on_spawn_added(self, device: Any, callback: Callable) -> None:
        raise NotImplementedError("GDB backend does not support spawn events")

    # ------------------------------------------------------------------
    # Debugger
    # ------------------------------------------------------------------

    def enable_debugger(self, script: Any, port: int) -> None:
        self._logger.info("GDB is already a debugger — no separate debugger port needed")

    # ------------------------------------------------------------------
    # Threads
    # ------------------------------------------------------------------

    def enumerate_threads(self, process: Any) -> list:
        self._require_gdb()
        threads = []
        inferior = process if hasattr(process, 'threads') else self._gdb.selected_inferior()
        for thread in inferior.threads():
            threads.append({
                "id": thread.global_num,
                "index": thread.num,
                "name": thread.name or f"Thread-{thread.num}",
                "is_stopped": thread.is_stopped(),
            })
        return threads

    def suspend_thread(self, process: Any, thread_id: int) -> None:
        self._require_gdb()
        self._gdb.execute(f"thread {thread_id}")
        self._gdb.execute("interrupt")

    def resume_thread(self, process: Any, thread_id: int) -> None:
        self._require_gdb()
        self._gdb.execute(f"thread {thread_id}")
        self._gdb.execute("continue &")

    # ------------------------------------------------------------------
    # Device enumeration
    # ------------------------------------------------------------------

    def enumerate_devices(self) -> list:
        return [{"id": "local", "name": "Local System (GDB)", "type": "local"}]

    def get_device_manager(self) -> Any:
        raise NotImplementedError("GDB backend does not have a device manager")

    def get_local_device(self) -> Any:
        return "local"

    def get_usb_device(self) -> Any:
        raise NotImplementedError("GDB backend does not support USB devices")

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

    @staticmethod
    def read_memory(inferior, addr: int, size: int) -> bytes:
        """Read raw bytes from inferior memory."""
        if _gdb_module is None:
            raise BackendError(_INSTALL_HINT)
        return inferior.read_memory(addr, size).tobytes()

    @staticmethod
    def read_pointer(inferior, addr: int) -> int:
        """Read a pointer-sized value from inferior memory."""
        if _gdb_module is None:
            raise BackendError(_INSTALL_HINT)
        ptr_size = 8  # Default to 64-bit; GDB API doesn't expose this easily
        try:
            arch = _gdb_module.selected_frame().architecture().name()
            if "i386" in arch or ("arm" in arch and "aarch64" not in arch):
                ptr_size = 4
        except Exception:
            pass
        data = inferior.read_memory(addr, ptr_size).tobytes()
        fmt = "<Q" if ptr_size == 8 else "<I"
        return struct.unpack(fmt, data)[0]

    @staticmethod
    def read_uint32(inferior, addr: int) -> int:
        """Read a 32-bit unsigned integer from inferior memory."""
        if _gdb_module is None:
            raise BackendError(_INSTALL_HINT)
        data = inferior.read_memory(addr, 4).tobytes()
        return struct.unpack("<I", data)[0]

    @staticmethod
    def read_string(inferior, addr: int, max_len: int = 256) -> str:
        """Read a null-terminated string from inferior memory."""
        if _gdb_module is None:
            raise BackendError(_INSTALL_HINT)
        data = inferior.read_memory(addr, max_len).tobytes()
        null_idx = data.find(b'\x00')
        if null_idx >= 0:
            data = data[:null_idx]
        return data.decode('utf-8', errors='replace')
