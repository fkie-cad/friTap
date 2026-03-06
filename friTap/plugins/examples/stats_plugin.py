#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Example stats plugin — counts captured events and prints a summary on exit.

To use: copy this file to your platform's plugin directory and run friTap.
Find the path with: python -c "from friTap.plugins.loader import PLUGIN_DIR; print(PLUGIN_DIR)"
"""

import logging
from friTap.plugins.base import FriTapPlugin
from friTap.events import KeylogEvent, DatalogEvent, ConsoleEvent, ErrorEvent

logger = logging.getLogger("friTap.plugins.stats")


class Plugin(FriTapPlugin):
    """Counts captured events and prints a summary on unload."""

    @property
    def name(self) -> str:
        return "stats"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def description(self) -> str:
        return "Counts captured events and prints summary on exit"

    def on_load(self, event_bus) -> None:
        self._counts = {"keylog": 0, "data": 0, "console": 0, "error": 0}
        self._event_bus = event_bus
        event_bus.subscribe(KeylogEvent, self._on_keylog)
        event_bus.subscribe(DatalogEvent, self._on_data)
        event_bus.subscribe(ConsoleEvent, self._on_console)
        event_bus.subscribe(ErrorEvent, self._on_error)

    def _on_keylog(self, event) -> None:
        self._counts["keylog"] += 1

    def _on_data(self, event) -> None:
        self._counts["data"] += 1

    def _on_console(self, event) -> None:
        self._counts["console"] += 1

    def _on_error(self, event) -> None:
        self._counts["error"] += 1

    def on_unload(self) -> None:
        total = sum(self._counts.values())
        logger.info(
            "[stats] Session summary: %d events "
            "(%d keys, %d data, %d console, %d errors)",
            total,
            self._counts["keylog"],
            self._counts["data"],
            self._counts["console"],
            self._counts["error"],
        )
