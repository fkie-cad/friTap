#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""PCAP output sink wrapping the existing PCAP class."""

from __future__ import annotations
import logging
from typing import TYPE_CHECKING

from ..schemas.canonical import Direction

if TYPE_CHECKING:
    from ..pcap import PCAP
    from ..schemas.canonical import KeylogCanonical, DataCanonical, MetaCanonical


class PcapSink:
    """Writes decrypted traffic to a PCAP file via the existing PCAP class.

    Implements the Sink protocol. Translates canonical Direction enum
    to function strings expected by PCAP.log_plaintext_payload().
    """

    _DIRECTION_MAP = {
        Direction.READ: "SSL_read",
        Direction.WRITE: "SSL_write",
    }

    def __init__(self, pcap_obj: "PCAP") -> None:
        self._pcap = pcap_obj
        self._logger = logging.getLogger("friTap.sinks.pcap")

    def open(self) -> None:
        pass

    def on_keylog(self, event: "KeylogCanonical") -> None:
        pass

    def on_data(self, event: "DataCanonical") -> None:
        if not event.data:
            return
        function_str = self._DIRECTION_MAP[event.direction]
        try:
            self._pcap.log_plaintext_payload(
                event.ss_family.value,
                function_str,
                event.src_addr_raw,
                event.src.port,
                event.dst_addr_raw,
                event.dst.port,
                event.data,
            )
        except OSError as e:
            self._logger.error("PCAP write error: %s", e)

    def on_meta(self, event: "MetaCanonical") -> None:
        pass

    def flush(self) -> None:
        pass

    def close(self) -> None:
        pcap_file = getattr(self._pcap, "pcap_file", None)
        if pcap_file:
            try:
                pcap_file.close()
            except Exception:
                pass
