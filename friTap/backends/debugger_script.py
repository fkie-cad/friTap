#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DebuggerScript — abstract base for GDB/LLDB script wrappers.

Both GDBScript and LLDBScript simulate a Frida-style script using
debugger breakpoints. This ABC captures the 95% shared logic;
subclasses override only ``load()`` and ``unload()``.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Callable

from .base import BackendInvalidOperationError


class DebuggerScript(ABC):
    """Abstract Frida-style script backed by debugger breakpoints."""

    def __init__(self, function_names: list[str], message_callback: Callable | None = None):
        self._function_names = function_names
        self._callback = message_callback
        self._breakpoints: dict[str, Any] = {}
        self._loaded = False

    @abstractmethod
    def load(self) -> None:
        """Create breakpoints for all function names."""
        ...

    @abstractmethod
    def unload(self) -> None:
        """Remove all breakpoints."""
        ...

    @property
    def is_loaded(self) -> bool:
        return self._loaded

    def set_message_callback(self, callback: Callable) -> None:
        self._callback = callback

    def post(self, message: dict) -> None:
        """Simulate posting a message to the script (no-op for debuggers)."""
        pass

    @property
    def exports_sync(self):
        raise BackendInvalidOperationError(
            "Debugger backends do not support script RPC exports."
        )
