#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Keylog file sink for friTap pipeline."""

from __future__ import annotations
import logging
from typing import TYPE_CHECKING

from ..output.dedup import KeyDeduplicator
from ..output.formatters import write_keylog_line

if TYPE_CHECKING:
    from ..schemas.canonical import KeylogCanonical, DataCanonical, MetaCanonical


class KeylogFileSink:
    """Writes TLS key material to an SSLKEYLOGFILE.

    Implements the Sink protocol for keylog file output.
    """

    def __init__(self, path: str) -> None:
        self._path = path
        self._file = None
        self._dedup = KeyDeduplicator()
        self._logger = logging.getLogger("friTap.sinks.keylog")

    def open(self) -> None:
        self._file = open(self._path, "a")
        self._logger.debug("Opened keylog file: %s", self._path)

    def on_keylog(self, event: "KeylogCanonical") -> None:
        if not self._file:
            return
        if event.key_data and self._dedup.is_new(event.key_data):
            write_keylog_line(self._file, event.key_data)

    def on_data(self, event: "DataCanonical") -> None:
        pass

    def on_meta(self, event: "MetaCanonical") -> None:
        pass

    def flush(self) -> None:
        if self._file:
            self._file.flush()

    def close(self) -> None:
        if self._file:
            self._file.close()
            self._file = None
            self._dedup.clear()
            self._logger.debug("Closed keylog file: %s", self._path)
