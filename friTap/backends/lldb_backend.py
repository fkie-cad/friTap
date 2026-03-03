#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
LLDB instrumentation backend for friTap.

Uses LLDB's Python API for breakpoint-based key extraction.
Particularly useful on macOS where LLDB is readily available via Xcode,
and for SSH/IPSec key extraction via the keys-in-flux approach.

The ``lldb`` Python module is NOT a pip dependency. It ships with
LLDB itself (Xcode on macOS, ``apt install python3-lldb`` on Linux).
If unavailable, all methods raise BackendError with installation instructions.
"""

from __future__ import annotations

import logging
import re
import struct
from typing import Any, Callable

from .base import (
    Backend,
    BackendError,
    BackendInvalidOperationError,
    BackendProcessNotFoundError,
)

# Optional import — LLDB is not a pip package
try:
    import lldb as _lldb_module
except ImportError:
    _lldb_module = None

_INSTALL_HINT = (
    "LLDB Python module not found. Install LLDB and ensure its Python bindings "
    "are on your PYTHONPATH.\n"
    "  macOS:  Install Xcode Command Line Tools (xcode-select --install)\n"
    "  Linux:  apt install python3-lldb  (or equivalent for your distro)\n"
    "  Manual: export PYTHONPATH=/path/to/lldb/python/site-packages"
)


class LLDBScript:
    """Simulates a Frida-style script using LLDB breakpoints.

    Each 'function name' in the script source is translated to a
    breakpoint. When hit, the registered callback is invoked with
    a Frida-compatible message dict.
    """

    def __init__(self, target, function_names: list[str], message_callback: Callable | None = None):
        self._target = target
        self._function_names = function_names
        self._callback = message_callback
        self._breakpoints: dict[str, Any] = {}
        self._loaded = False

    def load(self) -> None:
        """Create breakpoints for all function names."""
        if _lldb_module is None:
            raise BackendError(_INSTALL_HINT)
        for fn in self._function_names:
            bp = self._target.BreakpointCreateByName(fn)
            if bp.IsValid():
                self._breakpoints[fn] = bp
                if self._callback:
                    bp.SetScriptCallbackBody(
                        f'frame = frame\n'
                        f'# Breakpoint hit for {fn}\n'
                        f'return False  # Do not stop'
                    )
        self._loaded = True

    def unload(self) -> None:
        """Remove all breakpoints."""
        if self._target and self._loaded:
            for bp in self._breakpoints.values():
                try:
                    self._target.BreakpointDelete(bp.GetID())
                except Exception:
                    pass
            self._breakpoints.clear()
            self._loaded = False

    @property
    def is_loaded(self) -> bool:
        return self._loaded

    def set_message_callback(self, callback: Callable) -> None:
        self._callback = callback

    def post(self, message: dict) -> None:
        """Simulate posting a message to the script (no-op for LLDB)."""
        pass

    @property
    def exports_sync(self):
        """Not supported for LLDB scripts."""
        raise BackendInvalidOperationError(
            "LLDB backend does not support script RPC exports. "
            "Use breakpoint-based extraction instead."
        )


class LLDBBackend(Backend):
    """
    LLDB-based backend using breakpoints for function hooking.

    Translates the Frida-centric Backend interface into LLDB Python
    API calls. Useful for debugger-based key extraction (SSH, IPSec)
    where Frida cannot be used.
    """

    def __init__(self) -> None:
        self._logger = logging.getLogger("friTap.backend.lldb")
        self._lldb = _lldb_module
        self._debugger = None
        self._detach_callbacks: dict[int, list[Callable]] = {}

        if self._lldb is not None:
            self._debugger = self._lldb.SBDebugger.Create()
            self._debugger.SetAsync(True)
            self._logger.info("LLDB backend initialized (version: %s)", self.version)
        else:
            self._logger.warning("LLDB backend created but lldb module not available")

    def _require_lldb(self) -> None:
        """Raise BackendError if lldb is not available."""
        if self._lldb is None:
            raise BackendError(_INSTALL_HINT)

    # ------------------------------------------------------------------
    # Device
    # ------------------------------------------------------------------

    def get_device(self, mobile: bool | str = False, host: str | None = None) -> Any:
        if mobile:
            raise NotImplementedError(
                "LLDB backend does not support mobile devices. "
                "Use Frida backend for Android/iOS."
            )
        if host:
            raise NotImplementedError(
                "LLDB backend does not support remote devices. "
                "Use 'lldb-server' for remote debugging separately."
            )
        return "local"

    # ------------------------------------------------------------------
    # Attach / Spawn
    # ------------------------------------------------------------------

    def attach(self, device: Any, target: str) -> Any:
        self._require_lldb()

        lldb_target = self._debugger.CreateTarget("")
        if not lldb_target.IsValid():
            raise BackendError("Failed to create LLDB target")

        error = self._lldb.SBError()
        listener = self._lldb.SBListener()

        if target.isnumeric():
            process = lldb_target.AttachToProcessWithID(listener, int(target), error)
        else:
            process = lldb_target.AttachToProcessWithName(listener, target, False, error)

        if error.Fail():
            raise BackendProcessNotFoundError(
                f"LLDB attach failed for '{target}': {error.GetCString()}"
            )
        if not process.IsValid():
            raise BackendProcessNotFoundError(
                f"LLDB could not attach to '{target}'"
            )

        self._logger.info("Attached to process: %s (PID %d)", target, process.GetProcessID())
        return process

    def spawn(self, device: Any, target: str, env: dict | None = None) -> tuple[Any, int]:
        self._require_lldb()

        lldb_target = self._debugger.CreateTarget(target)
        if not lldb_target.IsValid():
            raise BackendError(f"Failed to create LLDB target for '{target}'")

        error = self._lldb.SBError()
        launch_info = self._lldb.SBLaunchInfo(None)
        launch_info.SetLaunchFlags(
            self._lldb.eLaunchFlagStopAtEntry
        )

        if env:
            env_list = [f"{k}={v}" for k, v in env.items()]
            launch_info.SetEnvironmentEntries(env_list, True)

        process = lldb_target.Launch(launch_info, error)

        if error.Fail():
            raise BackendError(
                f"LLDB spawn failed for '{target}': {error.GetCString()}"
            )

        pid = process.GetProcessID()
        self._logger.info("Spawned process: %s (PID %d)", target, pid)
        return process, pid

    def spawn_raw(self, device: Any, target, env: dict | None = None) -> int:
        self._require_lldb()
        if isinstance(target, list):
            exe = target[0]
            args = target[1:] if len(target) > 1 else None
        else:
            exe = str(target)
            args = None

        lldb_target = self._debugger.CreateTarget(exe)
        if not lldb_target.IsValid():
            raise BackendError(f"Failed to create LLDB target for '{exe}'")

        error = self._lldb.SBError()
        launch_info = self._lldb.SBLaunchInfo(args)
        launch_info.SetLaunchFlags(self._lldb.eLaunchFlagStopAtEntry)

        if env:
            env_list = [f"{k}={v}" for k, v in env.items()]
            launch_info.SetEnvironmentEntries(env_list, True)

        process = lldb_target.Launch(launch_info, error)

        if error.Fail():
            raise BackendError(f"LLDB spawn_raw failed: {error.GetCString()}")

        return process.GetProcessID()

    def resume(self, device: Any, pid: int) -> None:
        self._require_lldb()
        # Find process by iterating targets
        for i in range(self._debugger.GetNumTargets()):
            target = self._debugger.GetTargetAtIndex(i)
            process = target.GetProcess()
            if process.IsValid() and process.GetProcessID() == pid:
                error = process.Continue()
                if error and hasattr(error, 'Fail') and error.Fail():
                    raise BackendError(f"LLDB resume failed: {error.GetCString()}")
                return
        raise BackendProcessNotFoundError(f"No LLDB process with PID {pid}")

    # ------------------------------------------------------------------
    # Script
    # ------------------------------------------------------------------

    def create_script(self, process: Any, script_source: str, runtime: str = "qjs") -> Any:
        self._require_lldb()
        fn_names = re.findall(
            r'(?:Module\.findExportByName|BreakpointCreateByName)\s*\(\s*["\']([^"\']+)',
            script_source
        )
        # Also handle simple function name lists
        fn_names += re.findall(
            r'hookFunction\s*\(\s*["\']([^"\']+)',
            script_source
        )

        target = process.GetTarget() if hasattr(process, 'GetTarget') else None
        return LLDBScript(target, fn_names)

    def load_script(self, script: Any) -> None:
        if isinstance(script, LLDBScript):
            script.load()

    def unload_script(self, script: Any) -> None:
        try:
            if isinstance(script, LLDBScript):
                script.unload()
        except Exception:
            pass

    def on_message(self, script: Any, callback: Callable) -> None:
        if isinstance(script, LLDBScript):
            script.set_message_callback(callback)

    def post_message(self, script: Any, msg_type: str, payload: Any) -> None:
        # LLDB scripts don't receive messages like Frida
        # No-op: config handshake is Frida-specific
        pass

    # ------------------------------------------------------------------
    # Process management
    # ------------------------------------------------------------------

    def detach(self, process: Any) -> None:
        if process is None:
            return
        self._require_lldb()
        try:
            pid = process.GetProcessID() if hasattr(process, 'GetProcessID') else 0
            error = process.Detach()
            if error and hasattr(error, 'Fail') and error.Fail():
                self._logger.warning("LLDB detach warning: %s", error.GetCString())
            # Fire detach callbacks
            for cb in self._detach_callbacks.get(pid, []):
                try:
                    cb("user-requested")
                except Exception:
                    pass
        except Exception as e:
            self._logger.warning("LLDB detach error: %s", e)

    def on_detached(self, process: Any, callback: Callable) -> None:
        pid = process.GetProcessID() if hasattr(process, 'GetProcessID') else 0
        self._detach_callbacks.setdefault(pid, []).append(callback)

    # ------------------------------------------------------------------
    # Gating (not supported)
    # ------------------------------------------------------------------

    def enable_child_gating(self, process: Any) -> None:
        raise NotImplementedError("LLDB backend does not support child gating")

    def enable_spawn_gating(self, device: Any) -> None:
        raise NotImplementedError("LLDB backend does not support spawn gating")

    def on_child_added(self, device: Any, callback: Callable) -> None:
        raise NotImplementedError("LLDB backend does not support child events")

    def on_spawn_added(self, device: Any, callback: Callable) -> None:
        raise NotImplementedError("LLDB backend does not support spawn events")

    # ------------------------------------------------------------------
    # Debugger
    # ------------------------------------------------------------------

    def enable_debugger(self, script: Any, port: int) -> None:
        self._logger.info("LLDB is already a debugger — no separate debugger port needed")

    # ------------------------------------------------------------------
    # Threads
    # ------------------------------------------------------------------

    def enumerate_threads(self, process: Any) -> list:
        self._require_lldb()
        threads = []
        for i in range(process.GetNumThreads()):
            thread = process.GetThreadAtIndex(i)
            threads.append({
                "id": thread.GetThreadID(),
                "index": thread.GetIndexID(),
                "name": thread.GetName() or f"Thread-{thread.GetIndexID()}",
                "state": str(thread.GetStopReason()),
            })
        return threads

    def _find_thread(self, process: Any, thread_id: int) -> Any:
        for i in range(process.GetNumThreads()):
            thread = process.GetThreadAtIndex(i)
            if thread.GetThreadID() == thread_id:
                return thread
        raise BackendError(f"Thread {thread_id} not found")

    def suspend_thread(self, process: Any, thread_id: int) -> None:
        self._require_lldb()
        self._find_thread(process, thread_id).Suspend()

    def resume_thread(self, process: Any, thread_id: int) -> None:
        self._require_lldb()
        self._find_thread(process, thread_id).Resume()

    # ------------------------------------------------------------------
    # Device enumeration
    # ------------------------------------------------------------------

    def enumerate_devices(self) -> list:
        return [{"id": "local", "name": "Local System", "type": "local"}]

    def get_device_manager(self) -> Any:
        raise NotImplementedError("LLDB backend does not have a device manager")

    def get_local_device(self) -> Any:
        return "local"

    def get_usb_device(self) -> Any:
        raise NotImplementedError("LLDB backend does not support USB devices")

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "lldb"

    @property
    def version(self) -> str:
        if self._lldb is None:
            return "0.0.0-unavailable"
        try:
            version_string = self._lldb.SBDebugger.GetVersionString()
            if not version_string:
                return "0.0.0"
            return version_string.split()[1]
        except (IndexError, AttributeError):
            return "0.0.0"

    # ------------------------------------------------------------------
    # Memory helpers (for SSH/IPSec key extraction)
    # ------------------------------------------------------------------

    @staticmethod
    def read_memory(process, addr: int, size: int) -> bytes:
        """Read raw bytes from process memory."""
        error = _lldb_module.SBError()
        data = process.ReadMemory(addr, size, error)
        if error.Fail():
            raise BackendError(f"Memory read failed at 0x{addr:x}: {error.GetCString()}")
        return data

    @staticmethod
    def read_pointer(process, addr: int) -> int:
        """Read a pointer-sized value from process memory."""
        ptr_size = process.GetAddressByteSize()
        error = _lldb_module.SBError()
        data = process.ReadMemory(addr, ptr_size, error)
        if error.Fail():
            raise BackendError(f"Pointer read failed at 0x{addr:x}: {error.GetCString()}")
        fmt = "<Q" if ptr_size == 8 else "<I"
        return struct.unpack(fmt, data)[0]

    @staticmethod
    def read_uint32(process, addr: int) -> int:
        """Read a 32-bit unsigned integer from process memory."""
        error = _lldb_module.SBError()
        data = process.ReadMemory(addr, 4, error)
        if error.Fail():
            raise BackendError(f"uint32 read failed at 0x{addr:x}: {error.GetCString()}")
        return struct.unpack("<I", data)[0]

    @staticmethod
    def read_string(process, addr: int, max_len: int = 256) -> str:
        """Read a null-terminated string from process memory."""
        error = _lldb_module.SBError()
        data = process.ReadMemory(addr, max_len, error)
        if error.Fail():
            raise BackendError(f"String read failed at 0x{addr:x}: {error.GetCString()}")
        null_idx = data.find(b'\x00')
        if null_idx >= 0:
            data = data[:null_idx]
        return data.decode('utf-8', errors='replace')
