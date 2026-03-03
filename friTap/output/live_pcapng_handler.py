#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Live Wireshark PCAPNG output handler with Decryption Secrets Block (DSB).

Streams self-decrypting PCAPNG to a named FIFO so Wireshark can
auto-decrypt without a separate keylog file.
"""

from __future__ import annotations
import logging
import os
import tempfile
from typing import Optional, TYPE_CHECKING

from .base import OutputHandler

if TYPE_CHECKING:
    from ..events import EventBus


class LivePcapngHandler(OutputHandler):
    """PCAPNG with DSB to named FIFO — Wireshark auto-decrypts."""

    def __init__(self) -> None:
        self._tmpdir: Optional[str] = None
        self._fifo_path: Optional[str] = None
        self._pcapng_handler = None
        self._logger = logging.getLogger("friTap.output.live_pcapng")

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
        """Create a PcapngOutputHandler that writes to the FIFO."""
        if not self._fifo_path:
            raise RuntimeError("Call create_fifo() before setup()")
        from .pcapng_handler import PcapngOutputHandler
        self._pcapng_handler = PcapngOutputHandler(self._fifo_path)
        self._pcapng_handler.setup(event_bus)

    def close(self) -> None:
        """Clean up the internal PCAPNG handler and FIFO."""
        if self._pcapng_handler:
            try:
                self._pcapng_handler.close()
            except (BrokenPipeError, OSError) as e:
                self._logger.debug("FIFO close error (expected): %s", e)
            self._pcapng_handler = None

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
