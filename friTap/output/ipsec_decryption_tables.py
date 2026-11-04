#!/usr/bin/env python3

"""Wireshark IPsec decryption-table writer.

IPsec is the one protocol whose Wireshark-loadable output is NOT an NSS-style
keylog file but two CSV UAT tables, ``ikev2_decryption_table`` and ``esp_sa``
(Wireshark's canonical file names). This handler receives the structured
``KeylogEvent``s the :class:`~friTap.message_router.MessageRouter` builds for
IPsec, asks the :class:`~friTap.protocols.ipsec_handler.IPsecKeylogFormatter`
for the row(s), de-duplicates identical rows (an SA may be reported more than
once) and appends them to the two files in the directory of the ``-k`` keylog
path. Rows are written exactly as strongSwan's save-keys plugin writes them so
tshark loads them unchanged.
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
    """Writes the ``ikev2_decryption_table`` / ``esp_sa`` Wireshark UAT files.

    One instance per run. Files are opened lazily on the first matching row, so
    an IKE-only capture never leaves an empty ``esp_sa`` behind (and vice versa).
    Each file is truncated on first write — a fresh capture starts fresh tables,
    matching friTap's keylog convention — and rows are appended and flushed as
    SAs are discovered. Row de-duplication is per-table and in-memory.
    """

    def __init__(self, keylog_path: str, formatter: KeylogFormatter) -> None:
        self._formatter = formatter
        # Co-locate the UAT files with the -k keylog: given ``/p/keys.log`` the
        # tables land at ``/p/ikev2_decryption_table`` and ``/p/esp_sa``. A bare
        # filename (no directory) writes them to the current directory.
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
        # priority=10 matches KeylogOutputHandler so the "opened" log line
        # precedes any verbose console echo of the same key.
        event_bus.subscribe(KeylogEvent, self.on_keylog, priority=10)

    def on_keylog(self, event: "KeylogEvent") -> None:
        if event.protocol != self._formatter.protocol:
            return
        for table_name, row in self._formatter.format_rows(event):
            self._write_row(table_name, row)

    def _write_row(self, table_name: str, row: str) -> None:
        # The row is built from untrusted agent data; the formatter already vets
        # every field, but this is the last line of defence against a row that
        # could inject a second line into the UAT file.
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
