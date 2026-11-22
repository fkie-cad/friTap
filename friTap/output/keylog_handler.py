#!/usr/bin/env python3

"""Generic keylog output handler, one instance per active protocol.

The bound :class:`KeylogFormatter` selects the :class:`KeylogEvent`\ s (via
``event.protocol == formatter.protocol``) and formats them into keylog lines.
The file opens lazily on the first matching event, so e.g. ``--protocol all``
leaves no empty ``mykeys.ssh.log`` when the target never emits SSH.
"""

from __future__ import annotations

import logging
import threading
from typing import IO, TYPE_CHECKING, Optional

from .base import OutputHandler
from .dedup import KeyDeduplicator
from .keylog_format import KeylogFormatter
from .shared_keylog_writer import (
    SharedKeylogWriter,
    acquire_keylog_writer,
    release_keylog_writer,
)

if TYPE_CHECKING:
    from ..events import EventBus, KeylogEvent


class KeylogOutputHandler(OutputHandler):
    """Writes per-protocol Wireshark-loadable key material to a file.

    The file handle is process-wide (:mod:`friTap.output.shared_keylog_writer`), so another
    handler on the same path (e.g. the LSASS session on the shared ``-k``) reuses it.
    """

    def __init__(self, keylog_path: str, formatter: KeylogFormatter) -> None:
        self._path = keylog_path
        self._formatter = formatter
        self._writer: Optional[SharedKeylogWriter] = None
        # Set by close(): a late event must not lazily re-open the path with "w"
        # (it would truncate a finished keylog or recreate one the SChannel relabel renamed to <stem>.raw).
        self._closed = False
        # True once a writer was acquired. A never-opened non-tls split (rc4/memscan, whose async scan
        # can land its first key after teardown) may still open after close(); one that already wrote must not.
        self._ever_opened = False
        self._state_lock = threading.Lock()
        self._dedup = KeyDeduplicator()
        self._logger = logging.getLogger("friTap.output.keylog")

    @property
    def _file(self) -> Optional[IO]:
        """The open keylog handle, or ``None`` before the first key / after close."""
        return self._writer.file if self._writer is not None else None

    def setup(self, event_bus: "EventBus") -> None:
        from ..events import KeylogEvent
        # Lazy open on the first matching event. priority=10 (console is 0) opens the file and logs
        # "keylog: opened" BEFORE the verbose console echo; higher priority runs first (friTap/events.py).
        event_bus.subscribe(KeylogEvent, self.on_keylog, priority=10)

    def _is_relabel_subject(self) -> bool:
        """Whether the SChannel relabel may rename this handler's file.

        It only touches the base ``-k`` keylog and the ``tls`` split
        (``SSL_Logger._schannel_keylog_candidates``). A TLS handler must therefore never
        re-open after close, or a late key would recreate the file renamed to ``<stem>.raw``.
        """
        return self._formatter.protocol == "tls"

    def _open_lazy(self) -> Optional[SharedKeylogWriter]:
        with self._state_lock:
            if self._writer is not None:
                return self._writer
            # Drop a late key only when reopening is harmful (a relabel subject, or a handler that
            # already wrote); a never-opened non-tls split may still open for the first time.
            if self._closed and (self._is_relabel_subject() or self._ever_opened):
                self._logger.debug("keylog: dropping late key for closed %s", self._path)
                return None
            try:
                writer, created = acquire_keylog_writer(self._path)
            except OSError as e:
                self._logger.error("Failed to open keylog %s: %s", self._path, e)
                return None
            self._writer = writer
            self._ever_opened = True
        self._write_header(writer)
        if created:
            self._logger.info(
                "keylog: opened %s (%s)", self._path, self._formatter.protocol
            )
        else:
            self._logger.debug(
                "keylog: sharing already-open %s (%s)", self._path,
                self._formatter.protocol,
            )
        return writer

    def _write_header(self, writer: SharedKeylogWriter) -> None:
        header = self._formatter.header_comment()
        if not header:
            return
        try:
            writer.write_header_once(header)
        except OSError as e:
            self._logger.warning("Failed to write keylog header: %s", e)

    def on_keylog(self, event: "KeylogEvent") -> None:
        if event.protocol != self._formatter.protocol:
            return
        lines = self._formatter.format(event)
        if not lines:
            return
        key = self._formatter.dedup_key(event)
        if not self._dedup.is_new(key):
            return
        writer = self._open_lazy()
        if writer is None:
            return
        try:
            writer.write_lines(lines)
        except OSError as e:
            self._logger.warning("Failed to write keylog data: %s", e)

    def close(self) -> None:
        with self._state_lock:
            self._closed = True
            writer, self._writer = self._writer, None
        if writer is not None:
            try:
                release_keylog_writer(writer)
            except Exception:  # noqa: BLE001 - closing must never raise
                pass
