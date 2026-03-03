#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Verbose console output handler."""

from __future__ import annotations
import logging
from typing import Set, TYPE_CHECKING

from .base import OutputHandler

if TYPE_CHECKING:
    from ..events import EventBus, KeylogEvent, DatalogEvent, ConsoleEvent

try:
    import hexdump as hexdump_mod
except ImportError:
    hexdump_mod = None


class ConsoleOutputHandler(OutputHandler):
    """Prints decrypted data and key material to the console."""

    def __init__(self, verbose: bool = False) -> None:
        self._verbose = verbose
        self._seen_keys: Set[str] = set()
        self._logger = logging.getLogger("friTap")

    def setup(self, event_bus: "EventBus") -> None:
        from ..events import KeylogEvent, DatalogEvent, ConsoleEvent
        if self._verbose:
            event_bus.subscribe(KeylogEvent, self.on_keylog)
            event_bus.subscribe(DatalogEvent, self.on_data)
        event_bus.subscribe(ConsoleEvent, self.on_console)

    def on_keylog(self, event: "KeylogEvent") -> None:
        if event.cancelled:
            return
        if event.key_data and event.key_data not in self._seen_keys:
            self._seen_keys.add(event.key_data)
            self._logger.info(event.key_data)

    def on_data(self, event: "DatalogEvent") -> None:
        if event.cancelled:
            return
        if not event.data:
            return
        self._logger.info(
            "[%s] %s:%d --> %s:%d",
            event.function,
            event.src_addr,
            event.src_port,
            event.dst_addr,
            event.dst_port,
        )
        if hexdump_mod:
            hexdump_mod.hexdump(event.data)
        else:
            self._logger.info("Data: %s", event.data.hex())

    def on_console(self, event: "ConsoleEvent") -> None:
        msg = event.message
        if msg.startswith("[*]"):
            msg = msg.replace("[*] ", "")
        self._logger.info(msg)

    def close(self) -> None:
        pass
