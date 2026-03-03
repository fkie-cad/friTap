#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Backend abstraction layer for friTap."""

from .base import (
    Backend,
    BackendError,
    BackendInvalidArgumentError,
    BackendInvalidOperationError,
    BackendNotRunningError,
    BackendPermissionDeniedError,
    BackendProcessNotFoundError,
    BackendTimedOutError,
    BackendTransportError,
)
from .frida_backend import FridaBackend


_backend_instances: dict[str, Backend] = {}


def get_backend(name: str = "frida") -> Backend:
    """Return a cached backend instance for the given name.

    Supported backends: frida, gdb, lldb, ebpf.
    Instances are cached per name so repeated calls return the same object.
    """
    if name in _backend_instances:
        return _backend_instances[name]

    if name == "frida":
        from .frida_backend import FridaBackend
        instance = FridaBackend()
    elif name == "gdb":
        from .gdb_backend import GDBBackend
        instance = GDBBackend()
    elif name == "lldb":
        from .lldb_backend import LLDBBackend
        instance = LLDBBackend()
    elif name == "ebpf":
        from .ebpf_backend import EBPFBackend
        instance = EBPFBackend()
    else:
        raise ValueError(
            f"Unknown backend: {name!r}. Choose from: frida, gdb, lldb, ebpf"
        )

    _backend_instances[name] = instance
    return instance


def reset_backends() -> None:
    """Clear the backend instance cache (useful for testing)."""
    _backend_instances.clear()


__all__ = [
    "Backend",
    "BackendError",
    "BackendInvalidArgumentError",
    "BackendInvalidOperationError",
    "BackendNotRunningError",
    "BackendPermissionDeniedError",
    "BackendProcessNotFoundError",
    "BackendTimedOutError",
    "BackendTransportError",
    "FridaBackend",
    "get_backend",
    "reset_backends",
]
