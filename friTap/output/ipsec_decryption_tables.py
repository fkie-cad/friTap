#!/usr/bin/env python3

"""Wireshark IPsec decryption-table writer.

IPsec's Wireshark output is not an NSS keylog but two CSV UAT tables,
``ikev2_decryption_table`` and ``esp_sa``. This handler turns the structured
``KeylogEvent``s from :class:`~friTap.message_router.MessageRouter` into rows via
:class:`~friTap.protocols.ipsec_handler.IPsecKeylogFormatter`, de-duplicates them
(an SA may be reported more than once) and appends them to the files in the ``-k``
directory, in strongSwan's save-keys format so tshark loads them unchanged.
"""

from __future__ import annotations

import logging
import os
import threading
from typing import IO, TYPE_CHECKING, Dict, Optional, Set

from .base import OutputHandler
from .keylog_format import KeylogFormatter, is_safe_keylog_line

if TYPE_CHECKING:
    from ..events import EventBus, KeylogEvent


class IPsecDecryptionTableHandler(OutputHandler):
    """Writes the ``ikev2_decryption_table`` / ``esp_sa`` UAT files, one instance per run.

    Files open lazily on the first matching row (an IKE-only capture leaves no empty
    ``esp_sa``), are truncated on first write, then appended and flushed. De-duplication is per table, in memory.
    """

    def __init__(self, keylog_path: str, formatter: KeylogFormatter) -> None:
        self._formatter = formatter
        # Tables sit next to the -k keylog (``/p/keys.log`` -> ``/p/esp_sa``); a bare filename uses the cwd.
        self._dir = os.path.dirname(keylog_path) or "."
        self._files: Dict[str, IO] = {}
        self._seen: Dict[str, Set[str]] = {}
        self._closed = False
        self._lock = threading.Lock()
        self._logger = logging.getLogger("friTap.output.ipsec")

    def table_path(self, table_name: str) -> str:
        """Absolute-or-relative path this handler writes *table_name* to."""
        return os.path.join(self._dir, table_name)

    def setup(self, event_bus: "EventBus") -> None:
        from ..events import KeylogEvent
        # priority=10 as KeylogOutputHandler: the "opened" log precedes any verbose console echo.
        event_bus.subscribe(KeylogEvent, self.on_keylog, priority=10)

    def on_keylog(self, event: "KeylogEvent") -> None:
        if event.protocol != self._formatter.protocol:
            return
        for table_name, row in self._formatter.format_rows(event):
            self._write_row(table_name, row)

    def _write_row(self, table_name: str, row: str) -> None:
        # Built from untrusted agent data: the last defence against a row injecting a second UAT line.
        if not is_safe_keylog_line(row):
            return
        with self._lock:
            if self._closed:
                return
            seen = self._seen.setdefault(table_name, set())
            if row in seen:
                return
            file = self._file_for(table_name)
            if file is None:
                return
            seen.add(row)
            try:
                file.write(row + "\n")
                file.flush()
            except OSError as e:
                self._logger.warning("Failed to write %s: %s", table_name, e)

    def _file_for(self, table_name: str) -> Optional[IO]:
        """The open handle for *table_name*, opening (and truncating) it once."""
        file = self._files.get(table_name)
        if file is not None:
            return file
        path = self.table_path(table_name)
        try:
            file = open(path, "w")
        except OSError as e:
            self._logger.error("Failed to open %s: %s", path, e)
            return None
        self._files[table_name] = file
        self._logger.info("ipsec: opened %s", path)
        return file

    def close(self) -> None:
        with self._lock:
            self._closed = True
            files = list(self._files.values())
            self._files.clear()
        for file in files:
            try:
                file.close()
            except Exception:  # noqa: BLE001 - closing must never raise
                pass
