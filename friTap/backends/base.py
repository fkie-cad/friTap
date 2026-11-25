#!/usr/bin/env python3

"""Abstract base class for instrumentation backends.

Frida is the default and full-featured backend. GDB and LLDB are
debugger-based and single-threaded; eBPF is a Linux-only, read-only stub.
"""

from __future__ import annotations

import functools
import re
import struct
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, Optional


@dataclass
class BackendErrorContext:
    """Cheap, best-effort diagnostic snapshot taken at error time.

    Fields are ``None``/sentinel when not sampled. Safe to log: holds no
    secrets or stack traces (those go to the debug log file).
    """
    euid: int = -1
    platform: str = ""
    sip_enabled: Optional[bool] = None        # macOS only; None elsewhere
    target_alive: Optional[bool] = None
    server_reachable: Optional[bool] = None
    # ``query_system_parameters()["access"]`` ("full" / "jailed"). With no
    # frida-server on a USB Android device, frida 17 still answers via an
    # ADB-only fallback as "jailed", so this tells a real server apart.
    server_access: Optional[str] = None
    # macOS target binary probes (PID target, ``codesign``/``ps`` present).
    target_path: Optional[str] = None
    target_hardened_runtime: Optional[bool] = None
    target_library_validation_disabled: Optional[bool] = None
    target_get_task_allow: Optional[bool] = None
    extra: Dict[str, str] = field(default_factory=dict)


class BackendError(Exception):
    """Base exception for all backend errors.

    Carries the original exception, a category and a context so callers and
    the TUI can tell *backend-said-no* from *environment-said-no*.
    ``BackendError("msg")`` is valid.
    """

    def __init__(
        self,
        message: str,
        *,
        original_exception: Optional[BaseException] = None,
        category: str = "backend_error",
        context: Optional[BackendErrorContext] = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.original_exception = original_exception
        self.category = category
        self.context = context if context is not None else BackendErrorContext()

    def diagnostic_summary(self) -> str:
        """Return a multi-line, user-facing summary of the error."""
        lines = [self.message]
        orig = self.original_exception
        if orig is not None:
            # The original class tells "frida said no" apart from a backend bug.
            cls = type(orig).__name__
            if str(orig) and str(orig) != self.message:
                lines.append(f"  ↳ {cls}: {orig}")
            else:
                lines.append(f"  ↳ {cls}")
        if self.category == "backend_bug":
            lines.append(
                "This is a friTap bug, not your environment. Please file an issue."
            )
        elif self.category == "script_load_timeout":
            # Elapsed time and breadcrumb are the only clues to where the agent wedged.
            lines.append(
                f"  ↳ agent did not finish loading within "
                f"{getattr(self, 'elapsed_seconds', 0.0):.1f}s"
            )
            crumb = getattr(self, "breadcrumb", "")
            if crumb:
                lines.append(f"  ↳ last agent stage: {crumb}")
        elif self.category.startswith("frida_"):
            ctx = self.context
            bits = [f"euid={ctx.euid}"]
            if ctx.sip_enabled is not None:
                bits.append(f"SIP={'on' if ctx.sip_enabled else 'off'}")
            if ctx.target_alive is not None:
                bits.append(f"target_alive={ctx.target_alive}")
            if ctx.server_reachable is not None:
                bits.append(f"server_reachable={ctx.server_reachable}")
            if ctx.server_access is not None:
                bits.append(f"server_access={ctx.server_access}")
            for k, v in ctx.extra.items():
                bits.append(f"{k}={v}")
            lines.append("  context: " + ", ".join(bits))
            # Own line: likeliest culprits when the basic context looks fine.
            tgt_bits = []
            if ctx.target_path:
                tgt_bits.append(f"path={ctx.target_path}")
            if ctx.target_hardened_runtime is not None:
                tgt_bits.append(
                    f"hardened_runtime={'on' if ctx.target_hardened_runtime else 'off'}"
                )
            if ctx.target_library_validation_disabled is not None:
                tgt_bits.append(
                    f"library_validation_disabled={ctx.target_library_validation_disabled}"
                )
            if ctx.target_get_task_allow is not None:
                tgt_bits.append(
                    f"get_task_allow={ctx.target_get_task_allow}"
                )
            if tgt_bits:
                lines.append("  target: " + ", ".join(tgt_bits))
        return "\n".join(lines)


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


class BackendProcessNotRespondingError(BackendError):
    """The target process did not complete the Frida injection handshake in time."""


class BackendPermissionDeniedError(BackendError):
    """Permission denied for the requested operation."""


class BackendInvalidOperationError(BackendError):
    """The requested operation is invalid in the current state."""


class BackendScriptLoadTimeout(BackendError):
    """``load_script()`` did not return within the allotted time.

    Frida's ``script.load()`` blocks until the agent's top-level code ends,
    and the agent waits there for the host's startup handshake, so a wedged
    agent hangs the session silently. The bound turns that into this error.
    """

    def __init__(
        self,
        message: str,
        *,
        elapsed_seconds: float = 0.0,
        bound_seconds: float = 0.0,
        breadcrumb: str = "",
        original_exception: Optional[BaseException] = None,
        context: Optional[BackendErrorContext] = None,
    ) -> None:
        super().__init__(
            message,
            original_exception=original_exception,
            category="script_load_timeout",
            context=context,
        )
        self.elapsed_seconds = elapsed_seconds
        # The effective bound (tripled for scan-heavy configs); the CLI only
        # knows the raw --script-load-timeout and would misreport it.
        self.bound_seconds = bound_seconds
        # Set by SSL_Logger, which owns the breadcrumb trail.
        self.breadcrumb = breadcrumb


class BackendName(str, Enum):
    """Validated backend identifiers; ``BackendName.FRIDA == "frida"`` is True."""
    FRIDA = "frida"
    GDB = "gdb"
    LLDB = "lldb"
    EBPF = "ebpf"


class ScriptRuntime(str, Enum):
    """JavaScript runtime for Frida scripts (GDB/LLDB ignore it)."""
    QJS = "qjs"
    V8 = "v8"


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
    """Abstract instrumentation backend.

    All device, attach/spawn, script and messaging calls go through this
    interface so SSL_Logger / the FriTap API stay backend-agnostic.
    """

    @abstractmethod
    def get_device(self, mobile: bool | str = False, host: str | None = None) -> Any:
        """Return a backend-specific device handle.

        *mobile*: True for the default USB device, or a device-ID string.
        *host*: remote device address (ip:port).
        """
        ...

    @abstractmethod
    def attach(self, device: Any, target: str) -> Any:
        """Attach to a running process; *target* is a name or a PID string.

        Returns a backend-specific process/session handle.
        """
        ...

    @abstractmethod
    def spawn(self, device: Any, target: str, env: dict | None = None) -> tuple[Any, int]:
        """Spawn a process; returns ``(process handle, pid)``."""
        ...

    @abstractmethod
    def resume(self, device: Any, pid: int) -> None:
        """Resume a spawned (suspended) process."""
        ...

    @abstractmethod
    def create_script(self, process: Any, script_source: str, runtime: str = "qjs") -> Any:
        """Create an instrumentation script; returns a backend-specific handle."""
        ...

    @abstractmethod
    def load_script(self, script: Any, *, timeout: float | None = None) -> None:
        """Load/inject the script into the target process.

        *timeout* bounds the (potentially blocking) load in seconds; ``None``
        or ``0`` loads inline on the calling thread. Cheap synchronous
        backends may ignore it; one that exceeds it raises
        :class:`BackendScriptLoadTimeout`.
        """
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

    def disable_spawn_gating(self, device: Any) -> None:
        """Disable spawn gating on the device."""
        raise NotImplementedError(f"{self.name} backend does not support spawn gating")

    def enumerate_pending_spawn(self, device: Any) -> list:
        """Spawns the device holds for this client's spawn gating (each has ``.pid``)."""
        return []

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
        """Return a dict of device parameters ('os', 'arch', ...); empty if unsupported."""
        return {}

    def enumerate_processes(self, device: Any) -> list[ProcessInfo]:
        """List running processes on the target device."""
        raise NotImplementedError(f"{self.name} backend does not support process enumeration")

    def process_paths(self, device: Any, pids: list[int]) -> dict[int, str]:
        """Return ``{pid: executable path}`` for those of *pids* still running.

        Cheap per-pid lookup used to notice an exec() of an instrumented process
        (its path changes). Backends without it raise NotImplementedError.
        """
        raise NotImplementedError(f"{self.name} backend does not support process paths")

    def process_name(self, device: Any, pid: int) -> str | None:
        """Best display name for *pid* (an Android package id if known), else ``None``.

        Used after attaching by numeric PID so flow classification sees a
        real name. Default: unsupported.
        """
        return None

    def check_connectivity(self, device: Any) -> bool:
        """True if *device* is reachable. Default calls ``enumerate_processes()``;
        subclasses may override with a lighter check."""
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
    def spawn_raw(self, device: Any, target, env: dict | None = None,
                  aux: dict | None = None) -> int:
        """Spawn a process on device and return its PID (without attaching).

        ``aux`` carries backend-specific auxiliary spawn options. The Frida
        backend forwards them to ``device.spawn`` (e.g. Android activity
        selection: ``{"activity": ".SomeActivity"}``); backends that spawn a
        local binary ignore it.
        """
        ...

    @abstractmethod
    def on_detached(self, process: Any, callback: Callable) -> None:
        """Register a callback for process detach events."""
        ...

    def on_process_crashed(self, device: Any, callback: Callable) -> None:
        """Register a device-level process-crashed callback (carries a native
        crash report). No-op on backends without the concept."""
        return None

    def off_process_crashed(self, device: Any, callback: Callable) -> None:
        """Unregister a process-crashed callback. No-op by default."""
        return None

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
        """True if the backend version is at least major.minor."""
        return self._parsed_version >= (major, minor)

    @functools.cached_property
    def _parsed_version(self) -> tuple:
        """Parse and cache the version string as a comparable tuple."""
        try:
            raw_parts = self.version.split(".")[:2]
            return tuple(int(p) for p in raw_parts if p.isdigit())
        except (AttributeError, ValueError):
            return (0, 0)

    def _init_detach_callbacks(self) -> None:
        """Create the detach callback registry."""
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

    def read_pointer(self, target, addr: int) -> int:
        """Read a pointer-sized value via ``read_memory()``.

        GDB overrides this because its targets lack ``GetAddressByteSize()``.
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
        """Function names in a Frida-style script source (GDB/LLDB ``create_script``)."""
        fn_names = re.findall(
            r'(?:Module\.findExportByName|BreakpointCreateByName)\s*\(\s*["\']([^"\']+)',
            script_source
        )
        fn_names += re.findall(
            r'hookFunction\s*\(\s*["\']([^"\']+)',
            script_source
        )
        return fn_names
