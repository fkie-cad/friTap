#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Live Wireshark named-pipe output handler."""

from __future__ import annotations
import logging
import os
import tempfile
from typing import Optional, TYPE_CHECKING

from .base import OutputHandler

if TYPE_CHECKING:
    from ..events import EventBus, DatalogEvent
    from ..pcap import PCAP


class LiveWiresharkHandler(OutputHandler):
    """Streams decrypted packets to Wireshark via a named FIFO pipe."""

    def __init__(self) -> None:
        self._tmpdir: Optional[str] = None
        self._fifo_path: Optional[str] = None
        self._pcap: Optional["PCAP"] = None
        self._logger = logging.getLogger("friTap.output.wireshark")

    @property
    def fifo_path(self) -> Optional[str]:
        return self._fifo_path

    @property
    def tmpdir(self) -> Optional[str]:
        return self._tmpdir

    def create_fifo(self) -> str:
        """Create the named pipe and return its path."""
        self._tmpdir = tempfile.mkdtemp()
        self._fifo_path = os.path.join(self._tmpdir, "fritap_sharkfin")
        os.mkfifo(self._fifo_path)
        return self._fifo_path

    def set_pcap(self, pcap_obj: "PCAP") -> None:
        """Set the PCAP writer that writes to the FIFO."""
        self._pcap = pcap_obj

    def connect(self, timeout: float = 30.0) -> bool:
        """Open the FIFO for writing (blocks until Wireshark connects or timeout)."""
        import threading

        file_obj = [None]
        error = [None]

        def _open_fifo():
            try:
                file_obj[0] = open(self._fifo_path, "wb", 0)
            except Exception as e:
                error[0] = e

        opener = threading.Thread(target=_open_fifo, daemon=True)
        opener.start()
        opener.join(timeout=timeout)

        if opener.is_alive():
            self._logger.error("Wireshark did not connect within %ds", int(timeout))
            return False

        if error[0] is not None:
            self._logger.error("Failed to open FIFO: %s", error[0])
            return False

        # Create PCAP writer with the already-opened file handle.
        # We bypass PCAP.__init__() because it calls open() internally
        # which would deadlock on the FIFO.
        from ..pcap import PCAP
        from ..constants import SSL_READ, SSL_WRITE
        pcap = PCAP.__new__(PCAP)
        pcap.SSL_READ = SSL_READ
        pcap.SSL_WRITE = SSL_WRITE
        pcap.ssl_sessions = {}
        pcap.pkt = {}
        pcap.pcap_file_name = self._fifo_path
        pcap.pcap_file = file_obj[0]
        pcap.write_pcap_header(pcap.pcap_file)
        self._pcap = pcap

        self._logger.info("Wireshark connected to FIFO — streaming plaintext")
        return True

    def setup(self, event_bus: "EventBus") -> None:
        from ..events import DatalogEvent
        event_bus.subscribe(DatalogEvent, self.on_data)

    def on_data(self, event: "DatalogEvent") -> None:
        if not self._pcap or not event.data:
            return
        try:
            self._pcap.log_plaintext_payload(
                event.ss_family,
                event.function,
                event.src_addr_raw,
                event.src_port,
                event.dst_addr_raw,
                event.dst_port,
                event.data,
            )
        except OSError as e:
            self._logger.error("Wireshark pipe broken: %s", e)

    def close(self) -> None:
        if self._pcap and hasattr(self._pcap, 'pcap_file') and self._pcap.pcap_file:
            try:
                self._pcap.pcap_file.close()
            except OSError:
                pass
        if self._fifo_path and os.path.exists(self._fifo_path):
            try:
                os.unlink(self._fifo_path)
            except OSError:
                pass
        if self._tmpdir and os.path.exists(self._tmpdir):
            try:
                os.rmdir(self._tmpdir)
            except OSError:
                pass
