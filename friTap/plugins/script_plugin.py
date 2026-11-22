#!/usr/bin/env python3

"""ScriptPlugin: base for plugins that inject Frida scripts.

Two-phase lifecycle: on_load subscribes to the EventBus (no backend access
yet); on_instrument receives a ScriptContext and injects scripts.
"""

from __future__ import annotations

import logging
from abc import abstractmethod
from enum import Enum
from typing import TYPE_CHECKING, Any, List, Optional

from ..backends.base import BackendScriptLoadTimeout
from .base import FriTapPlugin

if TYPE_CHECKING:
    from ..session import Session
    from .script_context import ScriptContext

logger = logging.getLogger("friTap.plugins.script")


class ScriptLoadOrder(Enum):
    """Load position relative to friTap's main script."""
    BEFORE_MAIN = "before"
    AFTER_MAIN = "after"


class ScriptPlugin(FriTapPlugin):
    """Abstract base for plugins that inject instrumentation scripts.

    Must implement ``name``, ``version`` and ``get_script_source(context)``.
    May override ``load_order`` (default ``AFTER_MAIN``), ``supported_backends``
    (default ``[]`` = all) and ``on_script_message(message, data)``.
    """

    def __init__(self) -> None:
        self._scripts: List[Any] = []
        self._context: Optional["ScriptContext"] = None

    @property
    def session(self) -> "Optional[Session]":
        """The Session, if instrumented."""
        if self._context is not None:
            return self._context.session
        return None

    @property
    def load_order(self) -> ScriptLoadOrder:
        """Load position of this plugin's script."""
        return ScriptLoadOrder.AFTER_MAIN

    @property
    def supported_backends(self) -> List[str]:
        """Supported backend names; empty means all."""
        return []

    def is_compatible_with(self, backend_name: str) -> bool:
        """True if ``backend_name`` is supported."""
        return not self.supported_backends or backend_name in self.supported_backends

    @abstractmethod
    def get_script_source(self, context: "ScriptContext") -> str:
        """Return the JavaScript to inject; an empty string skips injection."""
        ...

    def on_instrument(self, context: "ScriptContext") -> None:
        """Create, wire up and load the plugin's script (called by ``PluginLoader.instrument_all()``).

        Skips with a warning when the backend is unsupported.
        """
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
        self._load_script_bounded(context, script)
        self._scripts.append(script)
        logger.info("Plugin %s: script loaded (order=%s)", self.name, self.load_order.value)

    def on_script_message(self, message: dict, data: Any) -> None:
        """Handle a message from the injected script (default: log errors, debug payloads)."""
        if message.get("type") == "error":
            logger.error("Plugin %s script error: %s", self.name, message)
        elif logger.isEnabledFor(logging.DEBUG):
            logger.debug("Plugin %s message: %s", self.name, message)

    def on_detach_process(self, context: "ScriptContext") -> None:
        """Called when the target process detaches; default unloads this plugin's scripts."""
        self._unload_scripts(context)

    def on_unload(self, session: "Session") -> None:
        """Unload all remaining scripts."""
        if self._context is not None:
            self._unload_scripts(self._context)
        self._scripts.clear()
        self._context = None

    def post_to_script(self, msg_type: str, payload: Any, script_index: int = 0) -> None:
        """Post a JSON-serialized message to ``self._scripts[script_index]``."""
        if self._context is None or not self._scripts:
            return
        if script_index < 0 or script_index >= len(self._scripts):
            logger.warning("Plugin %s: invalid script_index %d", self.name, script_index)
            return
        self._context.backend.post_message(self._scripts[script_index], msg_type, payload)

    def _load_script_bounded(self, context: "ScriptContext", script: Any) -> None:
        """Load *script* under ``context.script_load_timeout``.

        Plugin JavaScript is user-supplied and Frida's ``script.load()`` is not
        cancellable, so an unbounded wedge would hang friTap silently. On
        timeout the plugin name is attached as the breadcrumb and
        ``PluginLoader.instrument_all()`` logs it and carries on.
        """
        try:
            context.backend.load_script(script, timeout=context.script_load_timeout)
        except BackendScriptLoadTimeout as exc:
            if not exc.breadcrumb:
                exc.breadcrumb = f"plugin:{self.name}"
            raise

    def _route_message(self, message: dict, data: Any) -> None:
        """Route backend messages to on_script_message, logging exceptions."""
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
