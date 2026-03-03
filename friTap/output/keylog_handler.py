#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""SSLKEYLOGFILE output handler."""

from __future__ import annotations
import logging
from typing import IO, Optional, Set, TYPE_CHECKING

from .base import OutputHandler

if TYPE_CHECKING:
    from ..events import EventBus, KeylogEvent


class KeylogOutputHandler(OutputHandler):
    """Writes TLS key material in NSS Key Log format."""

    def __init__(self, keylog_path: str, protocol_handler=None) -> None:
        self._path = keylog_path
        self._file: Optional[IO] = None
        self._seen: Set[str] = set()
        self._logger = logging.getLogger("friTap.output.keylog")
        self._protocol_handler = protocol_handler

    def setup(self, event_bus: "EventBus") -> None:
        from ..events import KeylogEvent
        self._file = open(self._path, "w")
        event_bus.subscribe(KeylogEvent, self.on_keylog)

    def on_keylog(self, event: "KeylogEvent") -> None:
        if not self._file or not event.key_data:
            return
        if event.key_data not in self._seen:
            self._seen.add(event.key_data)
            try:
                formatted = (
                    self._protocol_handler.format_key_for_wireshark(event.key_data)
                    if self._protocol_handler is not None
                    else event.key_data
                )
                self._file.write(formatted + "\n")
                self._file.flush()
            except OSError as e:
                self._logger.warning("Failed to write keylog data: %s", e)

    def close(self) -> None:
        if self._file:
            try:
                self._file.close()
            except Exception:
                pass
            self._file = None
