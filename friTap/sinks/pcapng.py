#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""PCAPNG output sink with Decryption Secrets Block (DSB).

Self-contained PCAPNG writer that produces files Wireshark can
auto-decrypt without a separate keylog file.
"""

from __future__ import annotations
import logging
import struct
from typing import Callable, IO, List, Optional, TYPE_CHECKING

from ..output.dedup import KeyDeduplicator

if TYPE_CHECKING:
    from ..schemas.canonical import KeylogCanonical, DataCanonical, MetaCanonical

# PCAPNG block types
BT_SHB = 0x0A0D0D0A   # Section Header Block
BT_IDB = 0x00000001   # Interface Description Block
BT_EPB = 0x00000006   # Enhanced Packet Block
BT_DSB = 0x0000000A   # Decryption Secrets Block

# Secrets types
TLS_KEY_LOG = 0x544C534B   # "TLSK" - TLS Key Log

# Link types
LINKTYPE_RAW = 101


def _pad4(n: int) -> int:
    """Round up to next multiple of 4."""
    return (n + 3) & ~3


class PcapngSink:
    """Writes PCAPNG with embedded Decryption Secrets Blocks.

    Implements the Sink protocol. Uses event.timestamp for accurate
    packet timestamps instead of time.time() at write time.
    """

    def __init__(
        self,
        output_path: str,
        key_formatter: Optional[Callable[[str], str]] = None,
    ) -> None:
        self._path = output_path
        self._file: Optional[IO] = None
        self._logger = logging.getLogger("friTap.sinks.pcapng")
        self._dedup = KeyDeduplicator()
        self._pending_keys: List[str] = []
        self._key_formatter = key_formatter

    def open(self) -> None:
        self._file = open(self._path, "wb")
        self._write_shb()
        self._write_idb()

    def on_keylog(self, event: "KeylogCanonical") -> None:
        if event.key_data and self._dedup.is_new(event.key_data):
            self._pending_keys.append(event.key_data)
            self._flush_dsb()

    def on_data(self, event: "DataCanonical") -> None:
        if not self._file or not event.data:
            return
        self._flush_dsb()
        self._write_epb(event)

    def on_meta(self, event: "MetaCanonical") -> None:
        pass

    def flush(self) -> None:
        if self._file:
            self._flush_dsb()
            self._file.flush()

    def close(self) -> None:
        if self._file:
            try:
                self._flush_dsb()
            except OSError as e:
                self._logger.warning("Failed to flush DSB on close: %s", e)
            try:
                self._file.close()
                self._logger.info("PCAPNG output saved to %s", self._path)
            except Exception as e:
                self._logger.error("Error closing PCAPNG: %s", e)
            self._file = None
            self._dedup.clear()

    def _write_shb(self) -> None:
        """Write Section Header Block."""
        if not self._file:
            return
        body = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
        block_len = 12 + len(body)
        self._file.write(
            struct.pack("<II", BT_SHB, block_len) + body + struct.pack("<I", block_len)
        )

    def _write_idb(self) -> None:
        """Write Interface Description Block."""
        if not self._file:
            return
        body = struct.pack("<HHI", LINKTYPE_RAW, 0, 65535)
        padded_len = _pad4(len(body))
        block_len = 12 + padded_len
        padding = b"\x00" * (padded_len - len(body))
        self._file.write(
            struct.pack("<II", BT_IDB, block_len) + body + padding + struct.pack("<I", block_len)
        )

    def _flush_dsb(self) -> None:
        """Write pending key material as a Decryption Secrets Block."""
        if not self._file or not self._pending_keys:
            return
        formatted = (
            [self._key_formatter(k) for k in self._pending_keys]
            if self._key_formatter is not None
            else self._pending_keys
        )
        secrets_data = "\n".join(formatted).encode("utf-8") + b"\n"
        self._pending_keys.clear()
        body = struct.pack("<II", TLS_KEY_LOG, len(secrets_data)) + secrets_data
        padded_len = _pad4(len(body))
        block_len = 12 + padded_len
        padding = b"\x00" * (padded_len - len(body))
        self._file.write(
            struct.pack("<II", BT_DSB, block_len) + body + padding + struct.pack("<I", block_len)
        )
        self._file.flush()

    def _write_epb(self, event: "DataCanonical") -> None:
        """Write Enhanced Packet Block using event.timestamp."""
        if not self._file:
            return
        t_us = int(event.timestamp * 1_000_000)
        ts_high = (t_us >> 32) & 0xFFFFFFFF
        ts_low = t_us & 0xFFFFFFFF
        captured_len = len(event.data)
        body = struct.pack("<IIIII", 0, ts_high, ts_low, captured_len, captured_len) + event.data
        padded_len = _pad4(len(body))
        block_len = 12 + padded_len
        padding = b"\x00" * (padded_len - len(body))
        self._file.write(
            struct.pack("<II", BT_EPB, block_len) + body + padding + struct.pack("<I", block_len)
        )
