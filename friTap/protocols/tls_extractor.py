#!/usr/bin/env python3

"""TLS key processor stub; non-Frida TLS extraction is not implemented."""

from __future__ import annotations

import logging
from typing import Optional

from .base import BaseKeyProcessor

logger = logging.getLogger("friTap.protocols.tls_extractor")


class TLSKeyProcessor(BaseKeyProcessor):
    """No-op processor; TLS keys come from the Frida agent.

    Exists so the registry returns a processor for every protocol.
    """

    def process_key_event(self, event: dict) -> Optional[dict]:
        """Process a TLS key event (stub — returns None)."""
        logger.debug("TLSKeyProcessor.process_key_event called (stub)")
        return None

    def format_keylog(self) -> str:
        """Format keys (stub — returns empty string)."""
        return ""
