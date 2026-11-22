#!/usr/bin/env python3

"""
PCAPNG output handler with Decryption Secrets Block (DSB).

Produces self-contained PCAPNG files that embed TLS key material
directly, allowing Wireshark to auto-decrypt without a separate
keylog file.
"""

from __future__ import annotations

import logging
import time
from typing import IO, TYPE_CHECKING, List, Optional

from ..constants import DIRECTION_READ, direction_for_function
from ..sinks.tcp_state import (
    TcpSessionTracker,
    build_framed_packets_from_fields,
)
from .base import OutputHandler
from .dedup import KeyDeduplicator
from .pcapng_blocks import (
    EPB_FLUSH_INTERVAL,
    build_dsb,
    build_epb,
    build_idb,
    build_shb,
)
from .provisional_endpoint_hold import ProvisionalEndpointHold
from .quic_pcap_bridge import QuicPcapBridge

if TYPE_CHECKING:
    from ..events import DatalogEvent, EventBus, KeylogEvent


class PcapngOutputHandler(OutputHandler):
    """Writes PCAPNG with embedded Decryption Secrets Blocks."""

    consumes_plaintext = True

    def __init__(self, output_path: str, protocol_handler=None) -> None:
        self._path = output_path
        self._file: Optional[IO] = None
        self._logger = logging.getLogger("friTap.output.pcapng")
        self._pending_keys: List[str] = []
        self._protocol_handler = protocol_handler
        self._tracker = TcpSessionTracker()
        self._dedup = KeyDeduplicator()
        self._epb_count = 0
        # Keeps guessed QUIC tuples out of the file as a separate fake conversation.
        self._provisional_hold = ProvisionalEndpointHold()
        self._quic_bridge = QuicPcapBridge(notice=self._logger.info)

    def setup(self, event_bus: "EventBus") -> None:
        # Shared per path: the Windows LSASS session writes the same -p file.
        # Only the first opener writes the SHB+IDB; every block is one write.
        from .shared_output_file import open_shared_output_file
        file_obj, _created = open_shared_output_file(
            self._path, "wb", initializer=self._write_section_header)
        self._attach(file_obj, event_bus)

    def setup_with_file(self, file_obj: IO, event_bus: "EventBus") -> None:
        """Set up with an already-open file handle (used by LivePcapngHandler)."""
        self._write_section_header(file_obj)
        self._attach(file_obj, event_bus)

    @staticmethod
    def _write_section_header(file_obj: IO) -> None:
        file_obj.write(build_shb())
        file_obj.write(build_idb())

    def _attach(self, file_obj: IO, event_bus: "EventBus") -> None:
        from ..events import DatalogEvent, KeylogEvent, SessionEvent
        self._file = file_obj
        event_bus.subscribe(KeylogEvent, self.on_keylog)
        event_bus.subscribe(DatalogEvent, self.on_data)
        event_bus.subscribe(SessionEvent, self.on_session)

    def on_keylog(self, event: "KeylogEvent") -> None:
        if event.key_data and self._dedup.is_new(event.key_data):
            self._pending_keys.append(event.key_data)
            self._flush_dsb()

    def on_data(self, event: "DatalogEvent") -> None:
        if not self._file or not self._quic_bridge.should_write(event):
            return
        self._flush_dsb()
        for record in self._provisional_hold.admit(event):
            self._write_record(record)

    def on_session(self, event) -> None:
        if self._file:
            self._quic_bridge.close_on_destroyed(event, self._write_epb, self._write_secrets)

    def _write_record(self, event: "DatalogEvent") -> None:
        self._quic_bridge.route(event, self._write_epb, self._write_secrets)

    def _write_secrets(self, lines) -> None:
        # Straight to the file: these are not -k keys (no dedup, no formatter).
        self._file.write(build_dsb("".join(line + "\n" for line in lines).encode("utf-8")))
        self._file.flush()

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

    def _write_epb(self, event: "DatalogEvent", timestamp: Optional[float] = None) -> None:
        """Write Enhanced Packet Block with IP+TCP framing."""
        if not self._file or not event.data:
            return

        # One EPB per segment: oversized records are split to fit an IP packet,
        # and an invalid record yields no packets (nothing is written).
        packets = build_framed_packets_from_fields(
            ss_family=event.ss_family,
            src_addr=event.src_addr_raw,
            src_port=event.src_port,
            dst_addr=event.dst_addr_raw,
            dst_port=event.dst_port,
            is_read=direction_for_function(event.function, event.direction) == DIRECTION_READ,
            data=event.data,
            tracker=self._tracker,
            transport=event.transport,
        )

        t_us = int((time.time() if timestamp is None else timestamp) * 1_000_000)
        for packet in packets:
            self._write_packet_block(packet, t_us)

    def _write_packet_block(self, packet: bytes, t_us: int) -> None:
        """Append one Enhanced Packet Block, flushing periodically."""
        self._file.write(build_epb(packet, t_us))
        self._epb_count += 1
        if self._epb_count % EPB_FLUSH_INTERVAL == 0:
            self._file.flush()

    def _release_held_records(self) -> None:
        """Write records whose real tuple never appeared, with their guessed tuple."""
        for record in self._provisional_hold.drain():
            # Per record: one failed write must not drop the rest.
            try:
                self._write_record(record)
            except (OSError, ValueError) as e:
                self._logger.warning("Failed to write a held record on close: %s", e)
        try:
            self._quic_bridge.close_all(self._write_epb, self._write_secrets)
        except (OSError, ValueError) as e:
            self._logger.warning("Failed to close synthetic QUIC connections: %s", e)

    def close(self) -> None:
        if self._file:
            self._release_held_records()
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
