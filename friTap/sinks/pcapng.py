#!/usr/bin/env python3

"""PCAPNG output sink with Decryption Secrets Block (DSB).

Self-contained PCAPNG writer that produces files Wireshark can
auto-decrypt without a separate keylog file.
"""

from __future__ import annotations

import logging
from typing import IO, TYPE_CHECKING, Callable, List, Optional

from ..output.dedup import KeyDeduplicator
from ..output.pcapng_blocks import (
    EPB_FLUSH_INTERVAL,
    build_dsb,
    build_epb,
    build_idb,
    build_shb,
)
from .tcp_state import TcpSessionTracker, build_framed_packets

if TYPE_CHECKING:
    from ..schemas.canonical import DataCanonical, KeylogCanonical, MetaCanonical


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
        self._tracker = TcpSessionTracker()
        self._epb_count = 0

    def open(self) -> None:
        self._file = open(self._path, "wb")
        self._file.write(build_shb())
        self._file.write(build_idb())

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
            self._tracker.clear()

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
        block = build_dsb(secrets_data)
        try:
            self._file.write(block)
            self._file.flush()
        except OSError:
            self._dedup.unmark(self._pending_keys)
            raise
        self._pending_keys.clear()

    def _write_epb(self, event: "DataCanonical") -> None:
        """Write Enhanced Packet Block using event.timestamp."""
        if not self._file:
            return
        # One EPB per segment: oversized records are split to fit an IP packet,
        # and an invalid record yields no packets (nothing is written).
        t_us = int(event.timestamp * 1_000_000)
        for packet in build_framed_packets(event, self._tracker):
            self._write_packet_block(packet, t_us)

    def _write_packet_block(self, packet: bytes, t_us: int) -> None:
        """Append one Enhanced Packet Block, flushing periodically."""
        self._file.write(build_epb(packet, t_us))
        self._epb_count += 1
        if self._epb_count % EPB_FLUSH_INTERVAL == 0:
            self._file.flush()
