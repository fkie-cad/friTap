#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Generic keylog output handler.

One instance per active protocol. The bound :class:`KeylogFormatter`
both selects which :class:`KeylogEvent` instances this handler cares
about (via ``event.protocol == formatter.protocol``) and translates
each event into Wireshark-loadable line(s).

The file is opened lazily on the first matching event so that runs with
``--protocol all`` against a target that never emits SSH (for example)
don't leave a confusing empty ``mykeys.ssh.log`` on disk.
"""

from __future__ import annotations
import logging
from typing import IO, Optional, TYPE_CHECKING

from .base import OutputHandler
from .dedup import KeyDeduplicator
from .keylog_format import KeylogFormatter

if TYPE_CHECKING:
    from ..events import EventBus, KeylogEvent


class KeylogOutputHandler(OutputHandler):
    """Writes per-protocol Wireshark-loadable key material to a file."""

    def __init__(self, keylog_path: str, formatter: KeylogFormatter) -> None:
        self._path = keylog_path
        self._formatter = formatter
        self._file: Optional[IO] = None
        self._dedup = KeyDeduplicator()
        self._logger = logging.getLogger("friTap.output.keylog")

    def setup(self, event_bus: "EventBus") -> None:
        from ..events import KeylogEvent
        # Lazy open — file is created on first matching event in on_keylog().
        event_bus.subscribe(KeylogEvent, self.on_keylog)

    def _open_lazy(self) -> bool:
        if self._file is not None:
            return True
        try:
            self._file = open(self._path, "w")
        except OSError as e:
            self._logger.error("Failed to open keylog %s: %s", self._path, e)
            self._file = None
            return False
        header = self._formatter.header_comment()
        if header:
            try:
                self._file.write(header + "\n")
                self._file.flush()
            except OSError as e:
                self._logger.warning("Failed to write keylog header: %s", e)
        self._logger.info(
            "keylog: opened %s (%s)", self._path, self._formatter.protocol
        )
        return True

    def on_keylog(self, event: "KeylogEvent") -> None:
        if event.protocol != self._formatter.protocol:
            return
        lines = self._formatter.format(event)
        if not lines:
            return
        key = self._formatter.dedup_key(event)
        if not self._dedup.is_new(key):
            return
        if not self._open_lazy():
            return
        try:
            for line in lines:
                self._file.write(line + "\n")
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
