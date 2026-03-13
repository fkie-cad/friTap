#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Abstract base class for instrumentation backends.

friTap supports multiple backends for dynamic instrumentation:
- Frida (default): Cross-platform, full-featured
- eBPF (future): Linux-only, kernel-level, read-only
- GDB (future): Debugger-based, single-threaded
- LLDB (future): Debugger-based, single-threaded
- Other backends may be added in the future (e.g. DynamoRIO, PIN, x64dbg, etc.)
"""

from __future__ import annotations
import functools
import re
import struct
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable


# ---------------------------------------------------------------------------
# Backend exception hierarchy
# ---------------------------------------------------------------------------

class BackendError(Exception):
    """Base exception for all backend errors."""


class BackendNotRunningError(BackendError):
    """The instrumentation server is not running on the target device."""


class BackendInvalidArgumentError(BackendError):
    """An invalid argument was passed to the backend."""


class BackendTransportError(BackendError):
    """Communication with the target device failed."""


class BackendTimedOutError(BackendError):
    """The operation timed out."""


class BackendProcessNotFoundError(BackendError):
    """The target process was not found."""


class BackendPermissionDeniedError(BackendError):
    """Permission denied for the requested operation."""


class BackendInvalidOperationError(BackendError):
    """The requested operation is invalid in the current state."""


# ---------------------------------------------------------------------------
# Type-safe enums
# ---------------------------------------------------------------------------

class BackendName(str, Enum):
    """Validated backend identifiers.

    Inherits ``str`` so that ``BackendName.FRIDA == "frida"`` is True,
    making migration from bare string literals safe and incremental.
    """
    FRIDA = "frida"
    GDB = "gdb"
    LLDB = "lldb"
    EBPF = "ebpf"


class ScriptRuntime(str, Enum):
    """JavaScript runtime for Frida-based script execution.

    Inherits ``str`` so that ``ScriptRuntime.QJS == "qjs"`` is True.
    GDB/LLDB backends ignore this parameter.
    """
    QJS = "qjs"
    V8 = "v8"


# ---------------------------------------------------------------------------
# Shared data types
# ---------------------------------------------------------------------------

@dataclass
class ThreadInfo:
    """Backend-agnostic thread descriptor."""
    id: int
    name: str
    index: int = 0
    entrypoint: int | None = None
    is_stopped: bool = False


@dataclass
class ProcessInfo:
    """Backend-agnostic process descriptor."""
    pid: int
    name: str


class Backend(ABC):
    """
    Abstract interface for an instrumentation backend.

    All backend-specific calls (device discovery, process attach/spawn,
    script injection, messaging) go through this interface so that the
    core SSL_Logger / FriTap API remains backend-agnostic.
    """

    @abstractmethod
    def get_device(self, mobile: bool | str = False, host: str | None = None) -> Any:
        """
        Obtain a handle to the target device.

        Parameters
        ----------
        mobile : bool | str
            True for default USB device, or a device-ID string.
        host : str | None
            Remote device address (ip:port).

        Returns
        -------
        device
            Backend-specific device handle.
        """
        ...

    @abstractmethod
    def attach(self, device: Any, target: str) -> Any:
        """
        Attach to a running process on *device*.

        Parameters
        ----------
        device
            Device handle from :meth:`get_device`.
        target : str
            Process name or PID (as string).

        Returns
        -------
        process
            Backend-specific process/session handle.
        """
        ...

    @abstractmethod
    def spawn(self, device: Any, target: str, env: dict | None = None) -> tuple[Any, int]:
        """
        Spawn a new process on *device*.

        Returns
        -------
        (process, pid)
            Backend-specific process handle and the PID.
        """
        ...

    @abstractmethod
    def resume(self, device: Any, pid: int) -> None:
        """Resume a spawned (suspended) process."""
        ...

    @abstractmethod
    def create_script(self, process: Any, script_source: str, runtime: str = "qjs") -> Any:
        """
        Create an instrumentation script on the given process.

        Returns
        -------
        script
            Backend-specific script handle.
        """
        ...

    @abstractmethod
    def load_script(self, script: Any) -> None:
        """Load/inject the script into the target process."""
        ...

    @abstractmethod
    def unload_script(self, script: Any) -> None:
        """Unload the script from the target process."""
        ...

    @abstractmethod
    def on_message(self, script: Any, callback: Callable) -> None:
        """Register a message callback on the script."""
        ...

    @abstractmethod
    def post_message(self, script: Any, msg_type: str, payload: Any) -> None:
        """Send a message to the injected script."""
        ...

    @abstractmethod
    def detach(self, process: Any) -> None:
        """Detach from the target process."""
        ...

    def enable_child_gating(self, process: Any) -> None:
        """Enable child process gating on the process."""
        raise NotImplementedError(f"{self.name} backend does not support child gating")

    def enable_spawn_gating(self, device: Any) -> None:
        """Enable spawn gating on the device."""
        raise NotImplementedError(f"{self.name} backend does not support spawn gating")

    def on_child_added(self, device: Any, callback: Callable) -> None:
        """Register a callback for child process events."""
        raise NotImplementedError(f"{self.name} backend does not support child events")

    def on_spawn_added(self, device: Any, callback: Callable) -> None:
        """Register a callback for spawn events."""
        raise NotImplementedError(f"{self.name} backend does not support spawn events")

    def enable_debugger(self, script: Any, port: int) -> None:
        """Enable script debugger on the given port."""
        raise NotImplementedError(f"{self.name} backend does not support script debugging")

    @abstractmethod
    def enumerate_threads(self, process: Any) -> list[ThreadInfo]:
        """List threads in the target process."""
        ...

    @abstractmethod
    def suspend_thread(self, process: Any, thread_id: int) -> None:
        """Suspend a specific thread."""
        ...

    @abstractmethod
    def resume_thread(self, process: Any, thread_id: int) -> None:
        """Resume a specific thread."""
        ...

    @abstractmethod
    def enumerate_devices(self) -> list:
        """List all available devices."""
        ...

    def query_system_parameters(self, device: Any) -> dict:
        """Query system parameters from the target device.

        Returns a dict with keys like 'os', 'arch', 'platform', etc.
        Default returns empty dict for backends that don't support this.
        """
        return {}

    def enumerate_processes(self, device: Any) -> list[ProcessInfo]:
        """List running processes on the target device."""
        raise NotImplementedError(f"{self.name} backend does not support process enumeration")

    def check_connectivity(self, device: Any) -> bool:
        """Test whether *device* is reachable without materializing full process list.

        Default implementation calls ``enumerate_processes()``; subclasses
        may provide a lighter-weight check.
        """
        try:
            self.enumerate_processes(device)
            return True
        except Exception:
            return False

    def get_device_manager(self) -> Any:
        """Return the underlying device manager object."""
        raise NotImplementedError(f"{self.name} backend does not support device manager")

    @abstractmethod
    def get_local_device(self) -> Any:
        """Return the local device handle."""
        ...

    def get_usb_device(self) -> Any:
        """Return the default USB device handle."""
        raise NotImplementedError(f"{self.name} backend does not support USB devices")

    @abstractmethod
    def spawn_raw(self, device: Any, target, env: dict | None = None) -> int:
        """Spawn a process on device and return its PID (without attaching)."""
        ...

    @abstractmethod
    def on_detached(self, process: Any, callback: Callable) -> None:
        """Register a callback for process detach events."""
        ...

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable backend name."""
        ...

    @property
    @abstractmethod
    def version(self) -> str:
        """Backend/framework version string."""
        ...

    def version_at_least(self, major: int, minor: int = 0) -> bool:
        """Check if the backend version is at least major.minor."""
        return self._parsed_version >= (major, minor)

    @functools.cached_property
    def _parsed_version(self) -> tuple:
        """Parse and cache the version string as a comparable tuple."""
        try:
            raw_parts = self.version.split(".")[:2]
            return tuple(int(p) for p in raw_parts if p.isdigit())
        except (AttributeError, ValueError):
            return (0, 0)

    # ------------------------------------------------------------------
    # Detach callback helpers (shared by GDB / LLDB backends)
    # ------------------------------------------------------------------

    def _init_detach_callbacks(self) -> None:
        """Initialize the detach callback registry."""
        self._detach_callbacks: dict[int, list[Callable]] = {}

    def _get_process_pid(self, process: Any) -> int:
        """Extract PID from a backend-specific process handle.

        Subclasses override for their own handle types.
        """
        return getattr(process, 'pid', 0)

    def _fire_detach_callbacks(self, process: Any, reason: str = "user-requested") -> None:
        """Invoke and remove all detach callbacks for *process*."""
        pid = self._get_process_pid(process)
        for cb in self._detach_callbacks.get(pid, []):
            try:
                cb(reason)
            except Exception:
                pass
        self._detach_callbacks.pop(pid, None)

    # ------------------------------------------------------------------
    # Memory helpers (shared by GDB / LLDB backends)
    # ------------------------------------------------------------------

    def read_pointer(self, target, addr: int) -> int:
        """Read a pointer-sized value from target memory.

        Uses ``read_memory()`` (implemented by each backend) as the
        underlying primitive.  GDB overrides this with cached arch
        detection because GDB targets lack ``GetAddressByteSize()``.
        """
        ptr_size = getattr(target, 'GetAddressByteSize', lambda: 8)()
        if ptr_size not in (4, 8):
            ptr_size = 8
        raw = self.read_memory(target, addr, ptr_size)
        fmt = "<Q" if ptr_size == 8 else "<I"
        return struct.unpack(fmt, raw)[0]

    def read_uint32(self, target, addr: int) -> int:
        """Read a 32-bit unsigned integer from target memory."""
        raw = self.read_memory(target, addr, 4)
        return struct.unpack("<I", raw)[0]

    def read_string(self, target, addr: int, max_len: int = 256) -> str:
        """Read a null-terminated string from target memory."""
        raw = self.read_memory(target, addr, max_len)
        null_idx = raw.find(b'\x00')
        if null_idx >= 0:
            raw = raw[:null_idx]
        return raw.decode('utf-8', errors='replace')

    @staticmethod
    def _extract_function_names(script_source: str) -> list[str]:
        """Extract function names from a Frida-style script source.

        Shared by GDB and LLDB backends for ``create_script()``.
        """
        fn_names = re.findall(
            r'(?:Module\.findExportByName|BreakpointCreateByName)\s*\(\s*["\']([^"\']+)',
            script_source
        )
        fn_names += re.findall(
            r'hookFunction\s*\(\s*["\']([^"\']+)',
            script_source
        )
        return fn_names
