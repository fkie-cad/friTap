#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Console output sink for friTap pipeline."""

from __future__ import annotations
import logging
from typing import TYPE_CHECKING

from ..constants import PROTOCOL_QUIC_UNPROCESSED
from ..output.dedup import KeyDeduplicator
from ..output.formatters import format_hexdump, format_data_header

if TYPE_CHECKING:
    from ..schemas.canonical import KeylogCanonical, DataCanonical, MetaCanonical


class ConsoleSink:
    """Prints decrypted data and key material to the console.

    Implements the Sink protocol for terminal/console output.
    """

    def __init__(self, verbose: bool = False) -> None:
        self._verbose = verbose
        self._dedup = KeyDeduplicator()
        self._logger = logging.getLogger("friTap")
        self._quic_info_shown: bool = False

    def open(self) -> None:
        pass

    def on_keylog(self, event: "KeylogCanonical") -> None:
        if not self._verbose:
            return
        if event.key_data and self._dedup.is_new(event.key_data):
            self._logger.info(event.key_data)

    def on_data(self, event: "DataCanonical") -> None:
        if not self._verbose:
            return
        if not event.data:
            return

        # One-time info banner for QUIC/HTTP/3 raw traffic
        if event.protocol == PROTOCOL_QUIC_UNPROCESSED:
            if not self._quic_info_shown:
                self._logger.info(
                    "[INFO] Detected HTTP/3/QUIC traffic -- full parsing "
                    "requires QUIC stream hooks (not yet supported). "
                    "Showing raw data."
                )
                self._quic_info_shown = True

        self._logger.info(
            format_data_header(event.direction.value, event.src.addr,
                               event.src.port, event.dst.addr, event.dst.port)
        )
        self._logger.info(format_hexdump(event.data))

    def on_meta(self, event: "MetaCanonical") -> None:
        msg = event.message
        if msg.startswith("[*]"):
            msg = msg.replace("[*] ", "")
        level = event.level
        if level in ("debug",):
            self._logger.debug(msg)
        elif level in ("warn", "warning"):
            self._logger.warning(msg)
        elif level in ("error",):
            self._logger.error(msg)
        else:
            self._logger.info(msg)

    def flush(self) -> None:
        pass

    def close(self) -> None:
        self._dedup.clear()
