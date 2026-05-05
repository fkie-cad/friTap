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
import time
from typing import IO, List, Optional, TYPE_CHECKING

from .base import OutputHandler
from .dedup import KeyDeduplicator
from .pcapng_blocks import build_shb, build_idb, build_dsb, build_epb, EPB_FLUSH_INTERVAL
from ..constants import SSL_READ
from ..sinks.tcp_state import TcpSessionTracker, build_framed_packet_from_fields

if TYPE_CHECKING:
    from ..events import EventBus, KeylogEvent, DatalogEvent


class PcapngOutputHandler(OutputHandler):
    """Writes PCAPNG with embedded Decryption Secrets Blocks."""

    def __init__(self, output_path: str, protocol_handler=None) -> None:
        self._path = output_path
        self._file: Optional[IO] = None
        self._logger = logging.getLogger("friTap.output.pcapng")
        self._pending_keys: List[str] = []
        self._protocol_handler = protocol_handler
        self._tracker = TcpSessionTracker()
        self._dedup = KeyDeduplicator()
        self._epb_count = 0

    def setup(self, event_bus: "EventBus") -> None:
        self.setup_with_file(open(self._path, "wb"), event_bus)

    def setup_with_file(self, file_obj: IO, event_bus: "EventBus") -> None:
        """Set up with an already-open file handle (used by LivePcapngHandler)."""
        from ..events import KeylogEvent, DatalogEvent
        self._file = file_obj
        self._file.write(build_shb())
        self._file.write(build_idb())
        event_bus.subscribe(KeylogEvent, self.on_keylog)
        event_bus.subscribe(DatalogEvent, self.on_data)

    def on_keylog(self, event: "KeylogEvent") -> None:
        if event.key_data and self._dedup.is_new(event.key_data):
            self._pending_keys.append(event.key_data)
            self._flush_dsb()

    def on_data(self, event: "DatalogEvent") -> None:
        if not self._file or not event.data:
            return
        self._flush_dsb()
        self._write_epb(event)

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
        block = build_dsb(secrets_data)
        try:
            self._file.write(block)
            self._file.flush()
        except OSError:
            self._dedup.unmark(self._pending_keys)
            raise
        self._pending_keys.clear()

    def _write_epb(self, event: "DatalogEvent") -> None:
        """Write Enhanced Packet Block with IP+TCP framing."""
        if not self._file or not event.data:
            return

        packet = build_framed_packet_from_fields(
            ss_family=event.ss_family,
            src_addr=event.src_addr_raw,
            src_port=event.src_port,
            dst_addr=event.dst_addr_raw,
            dst_port=event.dst_port,
            is_read=event.function in SSL_READ,
            data=event.data,
            tracker=self._tracker,
        )

        t_us = int(time.time() * 1_000_000)
        self._file.write(build_epb(packet, t_us))
        self._epb_count += 1
        if self._epb_count % EPB_FLUSH_INTERVAL == 0:
            self._file.flush()

    def close(self) -> None:
        if self._file:
            self._tracker.clear()
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
