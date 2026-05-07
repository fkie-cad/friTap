#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""In-memory TLS key collector for later DSB injection.

Used by the full-capture path when output is pcapng: keys are buffered
during the session and embedded as a Decryption Secrets Block when the
final pcapng is written. This makes the resulting capture self-decrypting
in Wireshark with no separate keylog file required.

Unlike PcapngOutputHandler._pending_keys (which clears after every flush
because that handler streams DSBs as they arrive), this collector retains
all keys for the single end-of-session flush in pcap.py.
"""

from __future__ import annotations
import logging
from typing import List, TYPE_CHECKING

from .base import OutputHandler
from .dedup import KeyDeduplicator

if TYPE_CHECKING:
    from ..events import EventBus, KeylogEvent


class KeyCollectorHandler(OutputHandler):
    """Buffers TLS key material in memory for later DSB injection."""

    def __init__(self, protocol_handler=None) -> None:
        self._keys: List[str] = []
        self._dedup = KeyDeduplicator()
        self._protocol_handler = protocol_handler
        self._logger = logging.getLogger("friTap.output.key_collector")

    def setup(self, event_bus: "EventBus") -> None:
        from ..events import KeylogEvent
        event_bus.subscribe(KeylogEvent, self.on_keylog)

    def on_keylog(self, event: "KeylogEvent") -> None:
        if not event.key_data or not self._dedup.is_new(event.key_data):
            return
        formatted = (
            self._protocol_handler.format_key_for_wireshark(event.key_data)
            if self._protocol_handler is not None
            else event.key_data
        )
        self._keys.append(formatted)

    def get_collected_keys(self) -> List[str]:
        """Return all collected keys (already formatted via the protocol handler)."""
        return self._keys

    def close(self) -> None:
        return
