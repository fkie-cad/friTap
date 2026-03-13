#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Live PCAPNG sink streaming to a named FIFO for Wireshark auto-decrypt."""

from __future__ import annotations
import logging
import os
import tempfile
from typing import Callable, Optional, TYPE_CHECKING

from .pcapng import PcapngSink

if TYPE_CHECKING:
    from ..schemas.canonical import KeylogCanonical, DataCanonical, MetaCanonical


def _cleanup_fifo(fifo_path: Optional[str], tmpdir: Optional[str]) -> None:
    """Remove a FIFO and its temporary directory, ignoring missing files."""
    if fifo_path:
        try:
            os.unlink(fifo_path)
        except FileNotFoundError:
            pass
    if tmpdir:
        try:
            os.rmdir(tmpdir)
        except OSError:
            pass


class LivePcapngSink:
    """Streams self-decrypting PCAPNG to a named FIFO pipe.

    Implements the Sink protocol. Creates a FIFO and delegates all
    writing to an inner PcapngSink.
    """

    def __init__(
        self,
        key_formatter: Optional[Callable[[str], str]] = None,
    ) -> None:
        self._key_formatter = key_formatter
        self._tmpdir: Optional[str] = None
        self._fifo_path: Optional[str] = None
        self._inner: Optional[PcapngSink] = None
        self._logger = logging.getLogger("friTap.sinks.live_pcapng")

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

    def open(self) -> None:
        if not self._fifo_path:
            raise RuntimeError("Call create_fifo() before open()")
        self._inner = PcapngSink(self._fifo_path, key_formatter=self._key_formatter)
        self._inner.open()

    def on_keylog(self, event: "KeylogCanonical") -> None:
        if self._inner:
            self._inner.on_keylog(event)

    def on_data(self, event: "DataCanonical") -> None:
        if self._inner:
            self._inner.on_data(event)

    def on_meta(self, event: "MetaCanonical") -> None:
        pass

    def flush(self) -> None:
        if self._inner:
            self._inner.flush()

    def close(self) -> None:
        if self._inner:
            try:
                self._inner.close()
            except (BrokenPipeError, OSError) as e:
                self._logger.debug("FIFO close error (expected): %s", e)
            self._inner = None

        _cleanup_fifo(self._fifo_path, self._tmpdir)
