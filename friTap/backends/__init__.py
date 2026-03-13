#!/usr/bin/env python3
# -*- coding: utf-8 -*-

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
    BackendTimedOutError,
    BackendTransportError,
    ProcessInfo,
    ScriptRuntime,
    ThreadInfo,
)


_backend_instances: dict[str, Backend] = {}


def get_backend(name: str = BackendName.FRIDA) -> Backend:
    """Return a cached backend instance for the given name.

    Supported backends: frida, gdb, lldb, ebpf.
    Instances are cached per name so repeated calls return the same object.

    *name* is validated via :class:`BackendName`; passing an unknown
    string raises ``ValueError``.
    """
    # Validate (BackendName("frida") is idempotent for str-enum values)
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
    "BackendTimedOutError",
    "BackendTransportError",
    "ProcessInfo",
    "ScriptRuntime",
    "ThreadInfo",
    "get_backend",
    "reset_backends",
]
