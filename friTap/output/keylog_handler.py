#!/usr/bin/env python3

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

    The file handle itself is process-wide (see
    :mod:`friTap.output.shared_keylog_writer`): another handler on the same
    path — e.g. the LSASS session's handler on the shared ``-k`` file — reuses
    it instead of truncating it again.
    """

    def __init__(self, keylog_path: str, formatter: KeylogFormatter) -> None:
        self._path = keylog_path
        self._formatter = formatter
        self._writer: Optional[SharedKeylogWriter] = None
        # Set by close(): a late event must never lazily re-open the path with
        # "w" (that would truncate a finished keylog, or recreate one the
        # SChannel relabel just renamed to <stem>.raw).
        self._closed = False
        # True once a writer was ever acquired for this handler. A never-opened
        # NON-tls split handler (e.g. rc4/memscan, whose async scan can land its
        # FIRST key after main-session teardown) may still lazily open after
        # close(); a handler that already wrote keys must not (its file is
        # finished — reopening with "w" would truncate it).
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
        # Lazy open — file is created on first matching event in on_keylog().
        # priority=10 (vs. ConsoleOutputHandler's default 0) ensures the file
        # is opened — and "keylog: opened …" is logged — BEFORE the verbose
        # console echo prints the first key. EventBus dispatches in
        # descending-priority order (see friTap/events.py:260, 302), so a
        # higher numeric priority runs first.
        event_bus.subscribe(KeylogEvent, self.on_keylog, priority=10)

    def _is_relabel_subject(self) -> bool:
        """Whether the SChannel relabel may rename this handler's file.

        The relabel only ever touches the base ``-k`` keylog and the ``tls``
        split (see ``SSL_Logger._schannel_keylog_candidates``: "Non-TLS split
        files (rc4, ssh, ...) are never candidates"). A TLS handler must
        therefore never lazily re-open after close — a late key would recreate
        the file the relabel just renamed to ``<stem>.raw``.
        """
        return self._formatter.protocol == "tls"

    def _open_lazy(self) -> Optional[SharedKeylogWriter]:
        with self._state_lock:
            if self._writer is not None:
                return self._writer
            # Drop a late key only when reopening would be harmful: a relabel
            # subject (tls) could recreate the renamed file, and a handler that
            # already wrote keys would truncate its finished file. A
            # never-opened non-tls split (e.g. an async rc4/memscan key that
            # lands after teardown) is still allowed to open for the first time.
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
