#!/usr/bin/env python3

"""MemoryScanScriptPlugin — thin plugin adapter over :class:`MemoryScanEngine`.

Memory scanning is a first-class friTap capability driven directly by the core
(see :mod:`friTap.memory_scanning.engine`), **not** a plugin. This adapter exists
so the *plugin system* can still reach the engine: a third-party plugin (or a
user dropping this into their plugin directory) can drive the exact same heap
secret-scanner through the standard :class:`~friTap.plugins.script_plugin.ScriptPlugin`
lifecycle. The core does **not** register this adapter — it constructs a
``MemoryScanEngine`` directly.

The adapter is deliberately thin: it forwards each lifecycle callback to a
wrapped ``MemoryScanEngine``. The engine owns script injection and message
routing, so the adapter never calls ``super().on_instrument`` — there is a
single injection path, inside the engine.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, List, Optional

from ..plugins.script_plugin import ScriptLoadOrder, ScriptPlugin
from .engine import MemoryScanEngine

if TYPE_CHECKING:
    from ..plugins.script_context import ScriptContext


class MemoryScanScriptPlugin(ScriptPlugin):
    """Expose :class:`MemoryScanEngine` through the friTap plugin system."""

    def __init__(
        self,
        patterns_path: Optional[str] = None,
        interval: float = 2.0,
        profile_id: Optional[str] = None,
        protocols: Optional[List[str]] = None,
        install_lsass_hook: bool = True,
        unpaired_path: Optional[str] = None,
        rc4_path: Optional[str] = None,
        rc4_known_plaintext: Optional[str] = None,
        rc4_ciphertext: Optional[str] = None,
        engine: Optional[MemoryScanEngine] = None,
    ) -> None:
        super().__init__()
        # Accept a prebuilt engine (e.g. from build_memory_scan_engine) or build
        # one from the same parameters the engine takes.
        self._engine = engine or MemoryScanEngine(
            patterns_path=patterns_path,
            interval=interval,
            profile_id=profile_id,
            protocols=protocols,
            install_lsass_hook=install_lsass_hook,
            unpaired_path=unpaired_path,
            rc4_path=rc4_path,
            rc4_known_plaintext=rc4_known_plaintext,
            rc4_ciphertext=rc4_ciphertext,
        )

    @property
    def engine(self) -> MemoryScanEngine:
        """The wrapped engine (so callers can inspect / reuse it)."""
        return self._engine

    @property
    def name(self) -> str:
        return self._engine.name

    @property
    def version(self) -> str:
        return self._engine.version

    @property
    def description(self) -> str:
        return self._engine.description

    @property
    def load_order(self) -> ScriptLoadOrder:
        # AFTER_MAIN: when combined with the main agent, let it install its hooks
        # first; the scan loop is independent and starts once its own script is up.
        return ScriptLoadOrder.AFTER_MAIN

    @property
    def supported_backends(self) -> List[str]:
        return list(self._engine.supported_backends)

    def get_script_source(self, context: "ScriptContext") -> str:
        # The engine injects its own script(s); the base injection path is unused.
        return ""

    def on_instrument(self, context: "ScriptContext") -> None:
        self._engine.start(context)

    def on_detach_process(self, context: "ScriptContext") -> None:
        self._engine.stop(context)

    def on_unload(self, session: Any) -> None:
        self._engine.close()
