#!/usr/bin/env python3

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
from ..output.keylog_format import (
    is_hex_field,
    is_safe_keylog_line,
    warn_dropped_keylog_line,
)
from .base import BaseKeyProcessor

logger = logging.getLogger("friTap.protocols.ssh_extractor")

# Directions an SSH backend reports (compared case-insensitively). The value
# becomes part of a keylog label (``SSH_ENC_KEY_<DIR>``), so it is whitelisted.
ALLOWED_SSH_DIRECTIONS = frozenset({
    "c2s", "s2c", "client", "server", "client_to_server", "server_to_client",
    "in", "out", "unknown",
})
# Bound on retained key records (a hostile agent could otherwise grow it forever).
MAX_EXTRACTED_SSH_KEYS = 10_000


def _whitelisted_direction(value) -> Optional[str]:
    """*value* (case kept) when it is a whitelisted direction, else ``None``."""
    if not isinstance(value, str):
        return None
    return value if value.lower() in ALLOWED_SSH_DIRECTIONS else None


def _safe_text(value) -> str:
    """*value* when it is a single safe line, else ``""`` (for log/record fields)."""
    return value if is_safe_keylog_line(value) else ""


def _safe_int(value) -> int:
    """*value* as a non-negative ``int`` (``bool``/garbage -> 0)."""
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    return 0


def _has_valid_hex_fields(event: dict) -> bool:
    """Every present ``key_data``/``iv_data`` field is an even-length hex string."""
    return all(
        is_hex_field(event[field]) for field in ("key_data", "iv_data") if field in event
    )


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
            The stored record, or None if invalid. The event comes from an
            untrusted agent: a non-whitelisted direction or a non-hex
            ``key_data``/``iv_data`` drops the event (rate-limited warning),
            and at most :data:`MAX_EXTRACTED_SSH_KEYS` records are retained.
        """
        record = self._validated_record(event)
        if record is None:
            return None
        direction = record["direction"]

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

        self._retain(record)

        # Emit event if event bus is available
        if self._event_bus and "key_data" in record:
            key_line = f"SSH_ENC_KEY_{direction.upper()} {record['key_data']}"
            self._event_bus.emit(KeylogEvent(key_data=key_line))

        return record

    @staticmethod
    def _validated_record(event) -> Optional[dict]:
        """The base record for *event*, or ``None`` when it is malformed."""
        if not isinstance(event, dict):
            warn_dropped_keylog_line("ssh: non-dict key event")
            return None
        direction = _whitelisted_direction(event.get("direction", "unknown"))
        if direction is None:
            warn_dropped_keylog_line("ssh: unknown direction")
            return None
        if not _has_valid_hex_fields(event):
            warn_dropped_keylog_line("ssh: non-hex key material")
            return None
        return {
            "direction": direction,
            "cipher": _safe_text(event.get("cipher", "")),
            "key_len": _safe_int(event.get("key_len", 0)),
            "iv_len": _safe_int(event.get("iv_len", 0)),
        }

    def _retain(self, record: dict) -> None:
        """Store *record* unless :data:`MAX_EXTRACTED_SSH_KEYS` is reached."""
        if len(self._extracted_keys) >= MAX_EXTRACTED_SSH_KEYS:
            warn_dropped_keylog_line("ssh: extracted key cap reached")
            return
        self._extracted_keys.append(record)

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
