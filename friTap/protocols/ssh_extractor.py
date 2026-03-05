#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SSH key processor.

Handles formatting and processing of SSH key data received from
any backend (Frida, GDB, LLDB). Hooking logic lives in the
per-backend agent directories (agent_gdb/, agent_lldb/).
"""

from __future__ import annotations

import logging
from typing import Optional

from ..events import KeylogEvent
from .base import BaseKeyProcessor

logger = logging.getLogger("friTap.protocols.ssh_extractor")


class SSHKeyProcessor(BaseKeyProcessor):
    """Process SSH key events from any backend.

    Receives key data events and formats them for output
    (Wireshark keylog format, event bus emission, etc.).
    """

    def process_key_event(self, event: dict) -> Optional[dict]:
        """Process an incoming SSH key event from any backend.

        Parameters
        ----------
        event
            Dict with keys: direction, cipher, key_len, iv_len,
            key_data (hex), iv_data (hex).

        Returns
        -------
        dict or None
            The stored record, or None if invalid.
        """
        direction = event.get("direction", "unknown")
        record = {
            "direction": direction,
            "cipher": event.get("cipher", ""),
            "key_len": event.get("key_len", 0),
            "iv_len": event.get("iv_len", 0),
        }

        if "key_data" in event:
            record["key_data"] = event["key_data"]
            logger.info(
                "SSH %s key: cipher=%s, len=%d",
                direction, record["cipher"], record["key_len"],
            )

        if "iv_data" in event:
            record["iv_data"] = event["iv_data"]
            logger.info(
                "SSH %s IV: cipher=%s, len=%d",
                direction, record["cipher"], record["iv_len"],
            )

        self._extracted_keys.append(record)

        # Emit event if event bus is available
        if self._event_bus and "key_data" in record:
            key_line = f"SSH_ENC_KEY_{direction.upper()} {record['key_data']}"
            self._event_bus.emit(KeylogEvent(key_data=key_line))

        return record

    def format_keylog(self) -> str:
        """Format all extracted keys as a keylog string."""
        lines = []
        for record in self._extracted_keys:
            direction = record.get("direction", "unknown")
            if "key_data" in record:
                lines.append(f"SSH_ENC_KEY_{direction.upper()} {record['key_data']}")
            if "iv_data" in record:
                lines.append(f"SSH_IV_{direction.upper()} {record['iv_data']}")
        return "\n".join(lines)


# Backward compatibility alias
SSHKeyExtractor = SSHKeyProcessor
