#!/usr/bin/env python3

"""Frozen ScriptContext passed to ScriptPlugin.on_instrument() / on_detach_process()."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Optional

if TYPE_CHECKING:
    from ..backends.base import Backend
    from ..events import EventBus
    from ..session import Session


@dataclass(frozen=True)
class ScriptContext:
    """Immutable snapshot of the instrumentation environment.

    ``process`` and ``device`` are backend-specific handles (``device`` may be
    None for local). ``runtime`` is ``"qjs"`` or ``"v8"``; ``backend_name`` is
    ``"frida"``, ``"ebpf"`` or ``"gdb"``; ``debug`` means Chrome Inspector.
    ``script_load_timeout`` bounds a plugin's ``load_script()`` in seconds
    (see :func:`friTap.config.effective_script_load_timeout`); None means no
    bound (``--script-load-timeout 0`` or none supplied).
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
    script_load_timeout: Optional[float] = None
