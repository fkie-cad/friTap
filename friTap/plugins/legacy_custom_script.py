#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
LegacyCustomScriptPlugin — wraps the --custom_script CLI flag as a ScriptPlugin.

Provides exact backward-compatible behavior for users who pass a custom
Frida JS script via the command line.
"""

from __future__ import annotations
import logging
import os
import pprint
import signal
from typing import Any, List, Optional, TYPE_CHECKING

from .script_plugin import ScriptPlugin, ScriptLoadOrder

if TYPE_CHECKING:
    from .script_context import ScriptContext

logger = logging.getLogger("friTap.plugins.legacy_custom_script")

# Directory where friTap package lives (for resolving relative script paths)
_here = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))


class LegacyCustomScriptPlugin(ScriptPlugin):
    """Wraps ``--custom_script`` as a ScriptPlugin with exact legacy behavior.

    - Load order: BEFORE_MAIN (matches original instrument() order).
    - On error messages: pprint + SIGTERM (matches original on_custom_hook_message).
    - On "custom" payloads: log as info.
    """

    def __init__(self, script_path: str) -> None:
        super().__init__()
        self._script_path = script_path
        self._source_cache: Optional[str] = None

    @property
    def name(self) -> str:
        return "legacy-custom-script"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def description(self) -> str:
        return f"Legacy --custom_script wrapper ({self._script_path})"

    @property
    def load_order(self) -> ScriptLoadOrder:
        return ScriptLoadOrder.BEFORE_MAIN

    @property
    def supported_backends(self) -> List[str]:
        return ["frida"]

    def get_script_source(self, context: "ScriptContext") -> str:
        """Read the custom Frida script from disk (cached after first read)."""
        if self._source_cache is not None:
            return self._source_cache
        path = os.path.join(_here, self._script_path)
        try:
            with open(path, encoding="utf-8", newline="\n") as f:
                self._source_cache = f.read()
                return self._source_cache
        except FileNotFoundError:
            logger.error("Custom script not found: %s", path)
            return ""

    def on_script_message(self, message: dict, data: Any) -> None:
        """Reproduce original on_custom_hook_message() behavior exactly."""
        if message.get("type") == "error":
            pprint.pprint(message)
            os.kill(os.getpid(), signal.SIGTERM)
            return

        payload = message.get("payload", {})
        if not isinstance(payload, dict) or "custom" not in payload:
            return

        logger.info("custom hook: %s", payload["custom"])
