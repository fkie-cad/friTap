#!/usr/bin/env python3

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
import time
from typing import TYPE_CHECKING, Any, List, Optional

from ..error_handler import log_runtime_script_error
from .script_plugin import ScriptLoadOrder, ScriptPlugin

if TYPE_CHECKING:
    from .script_context import ScriptContext

logger = logging.getLogger("friTap.plugins.legacy_custom_script")

# Directory where friTap package lives (for resolving relative script paths)
_here = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))

# Frida may deliver an error thrown by the script's top-level code just after
# script.load() returns; errors this soon after the load still count as
# load-time (fatal) errors.
LOAD_ERROR_GRACE_SECONDS = 1.0


class LegacyCustomScriptPlugin(ScriptPlugin):
    """Wraps ``--custom_script`` as a ScriptPlugin with exact legacy behavior.

    - Load order: BEFORE_MAIN (matches original instrument() order).
    - On load-time error messages: pprint + SIGTERM (original behavior).
    - On later runtime errors (an exception in a deferred callback, which
      does not stop the script): log, rate-limited, and keep running --
      killing the host then would detach while hooks may still be running.
    - On "custom" payloads: log as info.
    """

    def __init__(self, script_path: str) -> None:
        super().__init__()
        self._script_path = script_path
        self._source_cache: Optional[str] = None
        self._loading = False
        self._loaded_at: Optional[float] = None

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

    def on_instrument(self, context: "ScriptContext") -> None:
        """Load the script, remembering when loading finished (see
        :meth:`_is_load_time_error`)."""
        self._loading = True
        try:
            super().on_instrument(context)
        finally:
            self._loading = False
            self._loaded_at = time.monotonic()

    def _is_load_time_error(self) -> bool:
        if self._loading or self._loaded_at is None:
            return True
        return time.monotonic() - self._loaded_at < LOAD_ERROR_GRACE_SECONDS

    def on_script_message(self, message: dict, data: Any) -> None:
        """Original on_custom_hook_message() behavior, except that a runtime
        error after a successful load no longer ends the run."""
        if message.get("type") == "error":
            if self._is_load_time_error():
                # pprint uses repr(), so control characters are shown escaped.
                pprint.pprint(message)
                os.kill(os.getpid(), signal.SIGTERM)
            else:
                log_runtime_script_error(message, logger, source="Custom script")
            return

        payload = message.get("payload", {})
        if not isinstance(payload, dict) or "custom" not in payload:
            return

        logger.info("custom hook: %s", payload["custom"])
