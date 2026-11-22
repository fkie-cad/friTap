#!/usr/bin/env python3

"""Backend abstraction layer for friTap."""

from .base import (
    Backend,
    BackendError,
    BackendInvalidArgumentError,
    BackendInvalidOperationError,
    BackendName,
    BackendNotRunningError,
    BackendPermissionDeniedError,
    BackendProcessNotFoundError,
    BackendProcessNotRespondingError,
    BackendScriptLoadTimeout,
    BackendTimedOutError,
    BackendTransportError,
    ProcessInfo,
    ScriptRuntime,
    ThreadInfo,
)

_backend_instances: dict[str, Backend] = {}


def get_backend(name: str = BackendName.FRIDA) -> Backend:
    """Return the cached backend (frida, gdb, lldb, ebpf) for *name*.

    An unknown name raises ``ValueError`` via :class:`BackendName`.
    """
    validated = BackendName(name)

    if validated in _backend_instances:
        return _backend_instances[validated]

    if validated == BackendName.FRIDA:
        from .frida_backend import FridaBackend
        instance = FridaBackend()
    elif validated == BackendName.GDB:
        from .gdb_backend import GDBBackend
        instance = GDBBackend()
    elif validated == BackendName.LLDB:
        from .lldb_backend import LLDBBackend
        instance = LLDBBackend()
    elif validated == BackendName.EBPF:
        from .ebpf_backend import EBPFBackend
        instance = EBPFBackend()

    _backend_instances[validated] = instance
    return instance


def reset_backends() -> None:
    """Clear the backend instance cache (useful for testing)."""
    _backend_instances.clear()


__all__ = [
    "Backend",
    "BackendError",
    "BackendInvalidArgumentError",
    "BackendInvalidOperationError",
    "BackendName",
    "BackendNotRunningError",
    "BackendPermissionDeniedError",
    "BackendProcessNotFoundError",
    "BackendProcessNotRespondingError",
    "BackendScriptLoadTimeout",
    "BackendTimedOutError",
    "BackendTransportError",
    "ProcessInfo",
    "ScriptRuntime",
    "ThreadInfo",
    "get_backend",
    "reset_backends",
]
