#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Abstract base class for instrumentation backends.

friTap supports multiple backends for dynamic instrumentation:
- Frida (default): Cross-platform, full-featured
- eBPF (future): Linux-only, kernel-level, read-only
- GDB (future): Debugger-based, single-threaded
"""

from __future__ import annotations
import functools
from abc import ABC, abstractmethod
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

    @abstractmethod
    def enable_child_gating(self, process: Any) -> None:
        """Enable child process gating on the process."""
        ...

    @abstractmethod
    def enable_spawn_gating(self, device: Any) -> None:
        """Enable spawn gating on the device."""
        ...

    @abstractmethod
    def on_child_added(self, device: Any, callback: Callable) -> None:
        """Register a callback for child process events."""
        ...

    @abstractmethod
    def on_spawn_added(self, device: Any, callback: Callable) -> None:
        """Register a callback for spawn events."""
        ...

    @abstractmethod
    def enable_debugger(self, script: Any, port: int) -> None:
        """Enable script debugger on the given port."""
        ...

    @abstractmethod
    def enumerate_threads(self, process: Any) -> list:
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

    @abstractmethod
    def get_device_manager(self) -> Any:
        """Return the underlying device manager object."""
        ...

    @abstractmethod
    def get_local_device(self) -> Any:
        """Return the local device handle."""
        ...

    @abstractmethod
    def get_usb_device(self) -> Any:
        """Return the default USB device handle."""
        ...

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
