#!/usr/bin/env python3

"""MemoryScanScriptPlugin — thin plugin adapter over :class:`MemoryScanEngine`.

Lets the plugin system drive the heap scanner through the standard
``ScriptPlugin`` lifecycle. The core does not register this adapter; it builds
a ``MemoryScanEngine`` directly.

Each lifecycle callback is forwarded to the wrapped engine. The engine owns
script injection, so the adapter never calls ``super().on_instrument``.
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
        # The main agent installs its hooks first; the scan loop is independent.
        return ScriptLoadOrder.AFTER_MAIN

    @property
    def supported_backends(self) -> List[str]:
        return list(self._engine.supported_backends)

    def get_script_source(self, context: "ScriptContext") -> str:
        return ""

    def on_instrument(self, context: "ScriptContext") -> None:
        self._engine.start(context)

    def on_detach_process(self, context: "ScriptContext") -> None:
        self._engine.stop(context)

    def on_unload(self, session: Any) -> None:
        self._engine.close()
