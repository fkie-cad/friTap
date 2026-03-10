#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ModuleLoggerPlugin — example ScriptPlugin that enumerates process modules.

Demonstrates the full ScriptPlugin API:
- Inline Frida JavaScript for module enumeration
- EventBus subscription in on_load()
- Bidirectional script communication via post_to_script()
"""

from __future__ import annotations
import logging
from typing import Any, TYPE_CHECKING

from ..script_plugin import ScriptPlugin, ScriptLoadOrder

if TYPE_CHECKING:
    from ...events import LibraryDetectedEvent
    from ...session import Session
    from ..script_context import ScriptContext

logger = logging.getLogger("friTap.plugins.examples.module_logger")

_MODULE_LOGGER_JS = """
'use strict';

// Enumerate loaded modules and send back to Python
recv('enumerate', function () {
    var modules = Process.enumerateModules();
    var names = modules.map(function (m) {
        return { name: m.name, base: m.base.toString(), size: m.size, path: m.path };
    });
    send({ type: 'modules', payload: names });
});
"""


class ModuleLoggerPlugin(ScriptPlugin):
    """Example plugin that enumerates process modules on library detection."""

    @property
    def name(self) -> str:
        return "module-logger"

    @property
    def version(self) -> str:
        return "0.1.0"

    @property
    def description(self) -> str:
        return "Enumerates and logs loaded process modules"

    @property
    def load_order(self) -> ScriptLoadOrder:
        return ScriptLoadOrder.AFTER_MAIN

    @property
    def supported_backends(self) -> list[str]:
        return ["frida"]

    def on_load(self, session: "Session") -> None:
        """Subscribe to LibraryDetectedEvent to trigger module enumeration."""
        from ...events import LibraryDetectedEvent
        session.lifecycle_bus.subscribe(LibraryDetectedEvent, self._on_library_detected)

    def get_script_source(self, context: "ScriptContext") -> str:
        return _MODULE_LOGGER_JS

    def on_script_message(self, message: dict, data: Any) -> None:
        """Process module enumeration results."""
        payload = message.get("payload", {})
        if isinstance(payload, dict) and payload.get("type") == "modules":
            modules = payload.get("payload", [])
            logger.info("Enumerated %d modules", len(modules))
            for mod in modules[:10]:  # Log first 10
                logger.debug("  %s @ %s (%d bytes)", mod["name"], mod["base"], mod["size"])
        else:
            super().on_script_message(message, data)

    def _on_library_detected(self, event: "LibraryDetectedEvent") -> None:
        """Trigger module enumeration when a TLS library is detected."""
        if self._scripts:
            logger.debug("Library detected (%s), requesting module enumeration", event.library)
            self.post_to_script("enumerate", {})
