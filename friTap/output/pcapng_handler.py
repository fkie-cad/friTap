#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
PCAPNG output handler with Decryption Secrets Block (DSB).

Produces self-contained PCAPNG files that embed TLS key material
directly, allowing Wireshark to auto-decrypt without a separate
keylog file.
"""

from __future__ import annotations
import logging
import struct
import time
from typing import IO, List, Optional, TYPE_CHECKING

from .base import OutputHandler

if TYPE_CHECKING:
    from ..events import EventBus, KeylogEvent, DatalogEvent

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


class PcapngOutputHandler(OutputHandler):
    """Writes PCAPNG with embedded Decryption Secrets Blocks."""

    def __init__(self, output_path: str, protocol_handler=None) -> None:
        self._path = output_path
        self._file: Optional[IO] = None
        self._logger = logging.getLogger("friTap.output.pcapng")
        self._pending_keys: List[str] = []
        self._protocol_handler = protocol_handler

    def setup(self, event_bus: "EventBus") -> None:
        self.setup_with_file(open(self._path, "wb"), event_bus)

    def setup_with_file(self, file_obj: IO, event_bus: "EventBus") -> None:
        """Set up with an already-open file handle (used by LivePcapngHandler)."""
        from ..events import KeylogEvent, DatalogEvent
        self._file = file_obj
        self._write_shb()
        self._write_idb()
        event_bus.subscribe(KeylogEvent, self.on_keylog)
        event_bus.subscribe(DatalogEvent, self.on_data)

    def on_keylog(self, event: "KeylogEvent") -> None:
        if event.key_data:
            self._pending_keys.append(event.key_data)
            self._flush_dsb()

    def on_data(self, event: "DatalogEvent") -> None:
        if not self._file or not event.data:
            return
        # Flush any pending keys as DSB before the packet
        self._flush_dsb()
        self._write_epb(event)

    def _write_shb(self) -> None:
        """Write Section Header Block."""
        if not self._file:
            return
        # SHB body: byte order magic + major + minor version
        body = struct.pack("<I", 0x1A2B3C4D)  # Byte-Order Magic
        body += struct.pack("<HH", 1, 0)       # Version 1.0
        body += struct.pack("<q", -1)           # Section Length (unspecified)
        block_len = 12 + len(body)
        self._file.write(struct.pack("<I", BT_SHB))
        self._file.write(struct.pack("<I", block_len))
        self._file.write(body)
        self._file.write(struct.pack("<I", block_len))

    def _write_idb(self) -> None:
        """Write Interface Description Block."""
        if not self._file:
            return
        body = struct.pack("<HH", LINKTYPE_RAW, 0)  # LinkType + Reserved
        body += struct.pack("<I", 65535)              # SnapLen
        block_len = 12 + _pad4(len(body))
        self._file.write(struct.pack("<I", BT_IDB))
        self._file.write(struct.pack("<I", block_len))
        self._file.write(body)
        # Pad to 4-byte boundary
        self._file.write(b"\x00" * (_pad4(len(body)) - len(body)))
        self._file.write(struct.pack("<I", block_len))

    def _flush_dsb(self) -> None:
        """Write pending key material as a Decryption Secrets Block."""
        if not self._file or not self._pending_keys:
            return
        formatted = (
            [self._protocol_handler.format_key_for_wireshark(k) for k in self._pending_keys]
            if self._protocol_handler is not None
            else self._pending_keys
        )
        secrets_data = "\n".join(formatted).encode("utf-8") + b"\n"
        self._pending_keys.clear()
        body = struct.pack("<I", TLS_KEY_LOG)
        body += struct.pack("<I", len(secrets_data))
        body += secrets_data
        padded_len = _pad4(len(body))
        block_len = 12 + padded_len
        self._file.write(struct.pack("<I", BT_DSB))
        self._file.write(struct.pack("<I", block_len))
        self._file.write(body)
        self._file.write(b"\x00" * (padded_len - len(body)))
        self._file.write(struct.pack("<I", block_len))
        self._file.flush()

    def _write_epb(self, event: "DatalogEvent") -> None:
        """Write Enhanced Packet Block."""
        if not self._file or not event.data:
            return
        t_us = int(time.time() * 1_000_000)
        ts_high = (t_us >> 32) & 0xFFFFFFFF
        ts_low = t_us & 0xFFFFFFFF
        captured_len = len(event.data)
        original_len = captured_len
        body = struct.pack("<I", 0)  # Interface ID
        body += struct.pack("<II", ts_high, ts_low)
        body += struct.pack("<II", captured_len, original_len)
        body += event.data
        padded_len = _pad4(len(body))
        block_len = 12 + padded_len
        self._file.write(struct.pack("<I", BT_EPB))
        self._file.write(struct.pack("<I", block_len))
        self._file.write(body)
        self._file.write(b"\x00" * (padded_len - len(body)))
        self._file.write(struct.pack("<I", block_len))
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
