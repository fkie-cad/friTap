#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""PCAP output handler wrapping the existing PCAP class."""

from __future__ import annotations
import logging
from typing import TYPE_CHECKING

from .base import OutputHandler

if TYPE_CHECKING:
    from ..events import EventBus, DatalogEvent
    from ..pcap import PCAP


class PcapOutputHandler(OutputHandler):
    """Writes decrypted traffic to a PCAP file."""

    def __init__(self, pcap_obj: "PCAP") -> None:
        self._pcap = pcap_obj
        self._logger = logging.getLogger("friTap.output.pcap")

    def setup(self, event_bus: "EventBus") -> None:
        from ..events import DatalogEvent
        event_bus.subscribe(DatalogEvent, self.on_data)

    def on_data(self, event: "DatalogEvent") -> None:
        if event.data:
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
                self._logger.error("PCAP write error: %s", e)

    def close(self) -> None:
        if hasattr(self._pcap, "pcap_file") and self._pcap.pcap_file:
            try:
                self._pcap.pcap_file.close()
            except Exception:
                pass
