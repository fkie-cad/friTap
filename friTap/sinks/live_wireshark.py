#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Live Wireshark PCAP sink streaming to a named FIFO."""

from __future__ import annotations
import logging
import os
import tempfile
from typing import Optional, TYPE_CHECKING

from .pcap import PcapSink
from .live_pcapng import _cleanup_fifo

if TYPE_CHECKING:
    from ..pcap import PCAP
    from ..schemas.canonical import KeylogCanonical, DataCanonical, MetaCanonical


class LiveWiresharkSink:
    """Streams decrypted packets to Wireshark via a named FIFO pipe.

    Implements the Sink protocol. Creates a FIFO and delegates all
    writing to an inner PcapSink.
    """

    def __init__(self, pcap_obj: "PCAP") -> None:
        self._pcap = pcap_obj
        self._tmpdir: Optional[str] = None
        self._fifo_path: Optional[str] = None
        self._inner: Optional[PcapSink] = None
        self._logger = logging.getLogger("friTap.sinks.live_wireshark")

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

    def open(self) -> None:
        if not self._fifo_path:
            raise RuntimeError("Call create_fifo() before open()")
        self._inner = PcapSink(self._pcap)
        self._inner.open()

    def on_keylog(self, event: "KeylogCanonical") -> None:
        pass

    def on_data(self, event: "DataCanonical") -> None:
        if self._inner:
            self._inner.on_data(event)

    def on_meta(self, event: "MetaCanonical") -> None:
        pass

    def flush(self) -> None:
        pass

    def close(self) -> None:
        if self._inner:
            try:
                self._inner.close()
            except (BrokenPipeError, OSError) as e:
                self._logger.debug("FIFO close error (expected): %s", e)
            self._inner = None

        _cleanup_fifo(self._fifo_path, self._tmpdir)
