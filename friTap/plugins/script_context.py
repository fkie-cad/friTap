#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ScriptContext — frozen dataclass encapsulating everything a ScriptPlugin needs.

Passed to ScriptPlugin.on_instrument() and on_detach_process() so that
plugins can create/load scripts without reaching into SSL_Logger internals.
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ..backends.base import Backend
    from ..events import EventBus
    from ..session import Session


@dataclass(frozen=True)
class ScriptContext:
    """Immutable snapshot of the instrumentation environment.

    Attributes
    ----------
    backend : Backend
        Backend ABC instance (e.g. FridaBackend).
    process : Any
        Backend-specific process/session handle.
    device : Any
        Backend-specific device handle (may be None for local).
    runtime : str
        JavaScript runtime — ``"qjs"`` or ``"v8"``.
    event_bus : EventBus
        Shared event bus for emitting events.
    backend_name : str
        Short backend identifier (``"frida"``, ``"ebpf"``, ``"gdb"``).
    debug : bool
        True when debug mode (Chrome Inspector) is active.
    debug_output : bool
        True when verbose debug logging is active.
    """

    backend: "Backend"
    process: Any
    device: Any
    runtime: str
    event_bus: "EventBus"
    backend_name: str
    debug: bool = False
    debug_output: bool = False
    session: Optional["Session"] = None
