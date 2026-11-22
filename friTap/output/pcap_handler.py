#!/usr/bin/env python3

"""PCAP output handler wrapping the existing PCAP class."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from ..constants import direction_label
from .base import OutputHandler
from .provisional_endpoint_hold import ProvisionalEndpointHold
from .quic_pcap_bridge import QuicPcapBridge

#: Sidecar suffix for the synthetic QUIC connections' TLS secrets (classic pcap has no DSB).
QUIC_SYNTHETIC_KEYLOG_SUFFIX = ".quic-synthetic.keylog"

if TYPE_CHECKING:
    from ..events import DatalogEvent, EventBus
    from ..pcap import PCAP


class PcapOutputHandler(OutputHandler):
    """Writes decrypted traffic to a PCAP file."""

    consumes_plaintext = True

    def __init__(self, pcap_obj: "PCAP") -> None:
        self._pcap = pcap_obj
        self._logger = logging.getLogger("friTap.output.pcap")
        # Keeps guessed QUIC tuples out of the file as a separate fake conversation.
        self._provisional_hold = ProvisionalEndpointHold()
        self._quic_bridge = QuicPcapBridge(notice=self._logger.info)
        self._quic_keylog_file = None
        self._quic_keylog_path = None

    def setup(self, event_bus: "EventBus") -> None:
        from ..events import DatalogEvent, SessionEvent
        event_bus.subscribe(DatalogEvent, self.on_data)
        event_bus.subscribe(SessionEvent, self.on_session)

    def on_data(self, event: "DatalogEvent") -> None:
        if self._quic_bridge.should_write(event):
            for record in self._provisional_hold.admit(event):
                self._write(record)

    def on_session(self, event) -> None:
        self._quic_bridge.close_on_destroyed(event, self._write_record, self._append_quic_keylog)

    def _write(self, event: "DatalogEvent") -> None:
        self._quic_bridge.route(event, self._write_record, self._append_quic_keylog)

    def _append_quic_keylog(self, lines) -> None:
        if not lines:
            return
        try:
            if self._quic_keylog_file is None:
                self._open_quic_keylog()
            self._quic_keylog_file.write("".join(line + "\n" for line in lines))
            self._quic_keylog_file.flush()
        except OSError as e:
            self._logger.error("QUIC synthetic keylog write error: %s", e)

    def _open_quic_keylog(self) -> None:
        # Never the user's -k file: these secrets belong to synthetic connections only.
        path = str(self._pcap.pcap_file_name) + QUIC_SYNTHETIC_KEYLOG_SUFFIX
        self._quic_keylog_file = open(path, "w", encoding="utf-8")
        self._quic_keylog_path = path
        register = getattr(self._pcap, "set_quic_synthetic_keylog_path", None)
        if callable(register):
            register(path)

    def _close_quic_keylog(self) -> None:
        if self._quic_keylog_file is None:
            return
        try:
            self._quic_keylog_file.close()
        except OSError:
            pass
        self._quic_keylog_file = None
        self._logger.info("HTTP/3 in %s: open with Wireshark, TLS keylog file %s",
                          self._pcap.pcap_file_name, self._quic_keylog_path)

    def _write_record(self, event: "DatalogEvent", timestamp=None) -> None:
        try:
            self._pcap.log_plaintext_payload(
                event.ss_family,
                direction_label(event.function, event.direction),
                event.src_addr_raw,
                event.src_port,
                event.dst_addr_raw,
                event.dst_port,
                event.data,
                transport=event.transport,
                timestamp=timestamp,
            )
        except OSError as e:
            self._logger.error("PCAP write error: %s", e)

    def close(self) -> None:
        # Records whose real tuple never appeared keep their guessed tuple.
        for record in self._provisional_hold.drain():
            # Per record: one failed write must not drop the rest.
            try:
                self._write(record)
            except Exception:  # noqa: BLE001 - the file may already be closed at teardown
                self._logger.debug("could not write a held record on close", exc_info=True)
        self._close_quic_connections()
        if hasattr(self._pcap, "pcap_file") and self._pcap.pcap_file:
            try:
                self._pcap.pcap_file.close()
            except Exception:
                pass
        self._close_quic_keylog()

    def _close_quic_connections(self) -> None:
        try:
            self._quic_bridge.close_all(self._write_record, self._append_quic_keylog)
        except Exception:  # noqa: BLE001 - the file may already be closed at teardown
            self._logger.debug("could not close synthetic QUIC connections", exc_info=True)
