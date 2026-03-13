#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""SSLKEYLOGFILE output handler."""

from __future__ import annotations
import logging
from typing import IO, Optional, TYPE_CHECKING

from .base import OutputHandler
from .dedup import KeyDeduplicator
from .formatters import write_keylog_line

if TYPE_CHECKING:
    from ..events import EventBus, KeylogEvent


class KeylogOutputHandler(OutputHandler):
    """Writes TLS key material in NSS Key Log format."""

    def __init__(self, keylog_path: str, protocol_handler=None) -> None:
        self._path = keylog_path
        self._file: Optional[IO] = None
        self._dedup = KeyDeduplicator()
        self._logger = logging.getLogger("friTap.output.keylog")
        self._protocol_handler = protocol_handler

    def setup(self, event_bus: "EventBus") -> None:
        from ..events import KeylogEvent
        self._file = open(self._path, "w")
        event_bus.subscribe(KeylogEvent, self.on_keylog)

    def on_keylog(self, event: "KeylogEvent") -> None:
        if not self._file or not event.key_data:
            return
        if self._dedup.is_new(event.key_data):
            try:
                formatted = (
                    self._protocol_handler.format_key_for_wireshark(event.key_data)
                    if self._protocol_handler is not None
                    else event.key_data
                )
                write_keylog_line(self._file, formatted)
            except OSError as e:
                self._logger.warning("Failed to write keylog data: %s", e)

    def close(self) -> None:
        if self._file:
            try:
                self._file.close()
            except Exception:
                pass
            self._file = None
