#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Live Wireshark PCAPNG output handler with Decryption Secrets Block (DSB).

Streams self-decrypting PCAPNG to a named FIFO so Wireshark can
auto-decrypt without a separate keylog file.

The setup/connect split prevents the classic FIFO deadlock:
- setup() is non-blocking: subscribes to events and buffers them
- connect() blocks until a reader (Wireshark) opens the FIFO
"""

from __future__ import annotations
import logging
import os
import tempfile
import threading
from typing import Optional, TYPE_CHECKING

from .base import OutputHandler

if TYPE_CHECKING:
    from ..events import EventBus, FriTapEvent


class LivePcapngHandler(OutputHandler):
    """PCAPNG with DSB to named FIFO — Wireshark auto-decrypts."""

    def __init__(self) -> None:
        self._tmpdir: Optional[str] = None
        self._fifo_path: Optional[str] = None
        self._pcapng_handler = None
        self._logger = logging.getLogger("friTap.output.live_pcapng")
        self._event_bus: Optional["EventBus"] = None
        self._buffer: list[tuple[str, "FriTapEvent"]] = []
        self._buffer_lock = threading.Lock()
        self._connected = False

    @property
    def fifo_path(self) -> Optional[str]:
        return self._fifo_path

    @property
    def tmpdir(self) -> Optional[str]:
        return self._tmpdir

    def create_fifo(self) -> str:
        """Create the named pipe and return its path."""
        self._tmpdir = tempfile.mkdtemp()
        self._fifo_path = os.path.join(self._tmpdir, "fritap_sharkfin.pcapng")
        os.mkfifo(self._fifo_path)
        return self._fifo_path

    def setup(self, event_bus: "EventBus") -> None:
        """Non-blocking setup: subscribe to events and buffer them.

        Call connect() after Wireshark has been launched to open the FIFO.
        """
        if not self._fifo_path:
            raise RuntimeError("Call create_fifo() before setup()")
        from ..events import KeylogEvent, DatalogEvent
        self._event_bus = event_bus
        event_bus.subscribe(KeylogEvent, self._on_buffered_event)
        event_bus.subscribe(DatalogEvent, self._on_buffered_event)

    def _on_buffered_event(self, event: "FriTapEvent") -> None:
        """Buffer or forward events depending on connection state."""
        with self._buffer_lock:
            if self._connected and self._pcapng_handler:
                self._dispatch_event(event)
            else:
                self._buffer.append(event)

    def _dispatch_event(self, event: "FriTapEvent") -> None:
        """Forward a single event to the inner PCAPNG handler."""
        from ..events import KeylogEvent
        if isinstance(event, KeylogEvent):
            self._pcapng_handler.on_keylog(event)
        else:
            self._pcapng_handler.on_data(event)

    def connect(self, timeout: float = 30.0) -> bool:
        """Open the FIFO for writing (blocks until reader connects or timeout).

        Returns True if connected, False on timeout.
        """
        if not self._fifo_path or not self._event_bus:
            raise RuntimeError("Call create_fifo() and setup() before connect()")

        file_obj = [None]
        error = [None]

        def _open_fifo():
            try:
                file_obj[0] = open(self._fifo_path, "wb")
            except Exception as e:
                error[0] = e

        opener = threading.Thread(target=_open_fifo, daemon=True)
        opener.start()
        opener.join(timeout=timeout)

        if opener.is_alive():
            self._logger.error(
                "Wireshark did not connect within %ds — live view disabled", int(timeout)
            )
            return False

        if error[0] is not None:
            self._logger.error("Failed to open FIFO: %s", error[0])
            return False

        # Create PcapngOutputHandler with the pre-opened file
        from .pcapng_handler import PcapngOutputHandler
        self._pcapng_handler = PcapngOutputHandler(self._fifo_path)
        self._pcapng_handler.setup_with_file(file_obj[0], self._event_bus)

        # Replay buffered events under the lock, then mark connected
        with self._buffer_lock:
            for event in self._buffer:
                self._dispatch_event(event)
            self._buffer.clear()
            self._connected = True

        self._logger.info("Wireshark connected to FIFO — streaming PCAPNG")
        return True

    def close(self) -> None:
        """Clean up the internal PCAPNG handler and FIFO."""
        if self._pcapng_handler:
            try:
                self._pcapng_handler.close()
            except (BrokenPipeError, OSError) as e:
                self._logger.debug("FIFO close error (expected): %s", e)
            self._pcapng_handler = None

        # Unsubscribe buffering callback
        if self._event_bus:
            from ..events import KeylogEvent, DatalogEvent
            self._event_bus.unsubscribe(KeylogEvent, self._on_buffered_event)
            self._event_bus.unsubscribe(DatalogEvent, self._on_buffered_event)

        from ..sinks.live_pcapng import _cleanup_fifo
        _cleanup_fifo(self._fifo_path, self._tmpdir)
