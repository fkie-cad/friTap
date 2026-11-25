#!/usr/bin/env python3

"""Verbose console output handler."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from ..events import MAIN_PROCESS_ROLE
from ..text_safety import visible_controls
from .base import OutputHandler
from .dedup import KeyDeduplicator
from .formatters import format_data_header, format_hexdump

if TYPE_CHECKING:
    from ..events import ConsoleEvent, DatalogEvent, EventBus, KeylogEvent


def origin_prefix(event) -> str:
    """``"[<pid> <process>] "`` for an event from a process other than the main target, else ``""``.

    Single-process captures (and events without an origin) print exactly as before.
    """
    origin = getattr(event, "process_origin", None)
    if not origin or origin.get("role") == MAIN_PROCESS_ROLE:
        return ""
    parts = (origin.get("pid"), origin.get("process"))
    who = " ".join(visible_controls(part) for part in parts if part)
    return f"[{who}] " if who else ""


class ConsoleOutputHandler(OutputHandler):
    """Prints decrypted data and key material to the console."""

    def __init__(self, verbose: bool = False) -> None:
        self._verbose = verbose
        self._dedup = KeyDeduplicator()
        self._logger = logging.getLogger("friTap")

    def setup(self, event_bus: "EventBus") -> None:
        from ..events import ConsoleEvent, DatalogEvent, KeylogEvent
        if self._verbose:
            event_bus.subscribe(KeylogEvent, self.on_keylog)
            event_bus.subscribe(DatalogEvent, self.on_data)
        event_bus.subscribe(ConsoleEvent, self.on_console)

    def on_keylog(self, event: "KeylogEvent") -> None:
        if event.cancelled:
            return
        if event.key_data and self._dedup.is_new(event.key_data):
            self._logger.info(origin_prefix(event) + event.key_data)

    def on_data(self, event: "DatalogEvent") -> None:
        if event.cancelled:
            return
        if not event.data:
            return
        self._logger.info(
            origin_prefix(event)
            + format_data_header(event.function, event.src_addr, event.src_port,
                                 event.dst_addr, event.dst_port)
        )
        self._logger.info(format_hexdump(event.data))

    def on_console(self, event: "ConsoleEvent") -> None:
        msg = event.message.removeprefix("[*] ")
        level = event.level
        if level == "debug":
            self._logger.debug(msg)
        elif level == "error":
            self._logger.error(msg)
        elif level in ("warn", "warning"):
            self._logger.warning(msg)
        else:
            self._logger.info(msg)

    def close(self) -> None:
        pass
