#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ScriptPlugin — abstract base for plugins that inject Frida scripts.

Extends FriTapPlugin with a two-phase lifecycle:
  Phase 1 (on_load): subscribe to EventBus — no backend access yet.
  Phase 2 (on_instrument): receive ScriptContext, inject scripts.
"""

from __future__ import annotations
import logging
from abc import abstractmethod
from enum import Enum
from typing import Any, List, Optional, TYPE_CHECKING

from .base import FriTapPlugin

if TYPE_CHECKING:
    from .script_context import ScriptContext

logger = logging.getLogger("friTap.plugins.script")


class ScriptLoadOrder(Enum):
    """When the plugin's script should be loaded relative to friTap's main script."""
    BEFORE_MAIN = "before"
    AFTER_MAIN = "after"


class ScriptPlugin(FriTapPlugin):
    """Abstract base for plugins that inject instrumentation scripts.

    Subclasses **must** implement:
        - ``name`` (property)
        - ``version`` (property)
        - ``get_script_source(context)``

    Subclasses **may** override:
        - ``load_order`` — default ``AFTER_MAIN``
        - ``supported_backends`` — default ``[]`` (all backends)
        - ``on_script_message(message, data)``
    """

    def __init__(self) -> None:
        self._scripts: List[Any] = []
        self._context: Optional["ScriptContext"] = None

    # ------------------------------------------------------------------
    # Configuration hooks (override in subclasses)
    # ------------------------------------------------------------------

    @property
    def load_order(self) -> ScriptLoadOrder:
        """When this plugin's script loads relative to the main friTap script."""
        return ScriptLoadOrder.AFTER_MAIN

    @property
    def supported_backends(self) -> List[str]:
        """Backend names this plugin supports. Empty list means all."""
        return []

    def is_compatible_with(self, backend_name: str) -> bool:
        """Check if this plugin is compatible with the given backend."""
        return not self.supported_backends or backend_name in self.supported_backends

    # ------------------------------------------------------------------
    # Abstract: subclass must provide script source
    # ------------------------------------------------------------------

    @abstractmethod
    def get_script_source(self, context: "ScriptContext") -> str:
        """Return the JavaScript source to inject.

        Return an empty string to skip injection for this invocation.
        """
        ...

    # ------------------------------------------------------------------
    # Lifecycle: called by PluginLoader / SSL_Logger
    # ------------------------------------------------------------------

    def on_instrument(self, context: "ScriptContext") -> None:
        """Create, register, and load the plugin's script.

        Called by ``PluginLoader.instrument_all()``.  The default
        implementation checks backend compatibility, obtains the script
        source, creates the script via the backend, wires up
        ``_route_message``, and loads it.
        """
        # Check backend compatibility
        if not self.is_compatible_with(context.backend_name):
            logger.warning(
                "Plugin %s skipped: backend %s not in %s",
                self.name, context.backend_name, self.supported_backends,
            )
            return

        self._context = context

        source = self.get_script_source(context)
        if not source:
            logger.debug("Plugin %s returned empty script source — skipping", self.name)
            return

        script = context.backend.create_script(context.process, source, runtime=context.runtime)
        context.backend.on_message(script, self._route_message)
        context.backend.load_script(script)
        self._scripts.append(script)
        logger.info("Plugin %s: script loaded (order=%s)", self.name, self.load_order.value)

    def on_script_message(self, message: dict, data: Any) -> None:
        """Handle messages from the injected script.

        Override in subclasses for custom message handling.
        The default logs errors at ERROR level and payloads at DEBUG.
        """
        if message.get("type") == "error":
            logger.error("Plugin %s script error: %s", self.name, message)
        elif logger.isEnabledFor(logging.DEBUG):
            logger.debug("Plugin %s message: %s", self.name, message)

    def on_detach_process(self, context: "ScriptContext") -> None:
        """Called when the target process detaches.

        Default: unloads all scripts created by this plugin.
        """
        self._unload_scripts(context)

    def on_unload(self) -> None:
        """Final cleanup — unloads all remaining scripts."""
        if self._context is not None:
            self._unload_scripts(self._context)
        self._scripts.clear()
        self._context = None

    # ------------------------------------------------------------------
    # Bidirectional messaging
    # ------------------------------------------------------------------

    def post_to_script(self, msg_type: str, payload: Any, script_index: int = 0) -> None:
        """Send a message to the injected script.

        Parameters
        ----------
        msg_type : str
            Message type identifier.
        payload : Any
            Message payload (will be JSON-serialized by the backend).
        script_index : int
            Index into ``self._scripts`` (default 0 = first script).
        """
        if self._context is None or not self._scripts:
            return
        if script_index < 0 or script_index >= len(self._scripts):
            logger.warning("Plugin %s: invalid script_index %d", self.name, script_index)
            return
        self._context.backend.post_message(self._scripts[script_index], msg_type, payload)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _route_message(self, message: dict, data: Any) -> None:
        """Trampoline: routes backend messages to on_script_message with error guard."""
        try:
            self.on_script_message(message, data)
        except Exception:
            logger.exception("Plugin %s: on_script_message raised", self.name)

    def _unload_scripts(self, context: "ScriptContext") -> None:
        """Unload all tracked scripts via the backend."""
        for script in self._scripts:
            try:
                context.backend.unload_script(script)
            except Exception:
                logger.debug("Plugin %s: failed to unload script", self.name, exc_info=True)
        self._scripts.clear()
