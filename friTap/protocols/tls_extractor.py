#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
TLS key processor stub.

Exists for routing completeness. TLS key extraction from non-Frida
backends is not yet implemented (planned: HKDF/PRF hooking).
"""

from __future__ import annotations

import logging
from typing import Optional

from .base import BaseKeyProcessor

logger = logging.getLogger("friTap.protocols.tls_extractor")


class TLSKeyProcessor(BaseKeyProcessor):
    """Stub processor for TLS key events from non-Frida backends.

    Currently a no-op — TLS key extraction is handled entirely by
    the Frida agent. This stub exists so the registry can return
    a processor for every protocol uniformly.
    """

    def process_key_event(self, event: dict) -> Optional[dict]:
        """Process a TLS key event (stub — returns None)."""
        logger.debug("TLSKeyProcessor.process_key_event called (stub)")
        return None

    def format_keylog(self) -> str:
        """Format keys (stub — returns empty string)."""
        return ""
