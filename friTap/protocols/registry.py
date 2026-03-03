#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Protocol handler registry."""

from __future__ import annotations
import logging
from typing import Dict, List, Optional

from .base import ProtocolHandler


class ProtocolRegistry:
    """Registry of all available protocol handlers."""

    def __init__(self) -> None:
        self._handlers: Dict[str, ProtocolHandler] = {}
        self._logger = logging.getLogger("friTap.protocols")

    def register(self, handler: ProtocolHandler) -> None:
        self._handlers[handler.name] = handler
        self._logger.debug("Registered protocol handler: %s", handler.name)

    def get(self, protocol: str) -> Optional[ProtocolHandler]:
        return self._handlers.get(protocol)

    def get_all(self) -> List[ProtocolHandler]:
        return list(self._handlers.values())

    def auto_detect(self, detected_libraries: List[str]) -> List[ProtocolHandler]:
        """Given detected libraries, return matching protocol handlers."""
        matched = [
            handler for handler in self._handlers.values()
            if handler.matches_libraries(detected_libraries)
        ]
        if matched:
            return matched
        fallback = self._handlers.get("tls") or next(iter(self._handlers.values()))
        return [fallback]

    def list_protocols(self) -> List[str]:
        return list(self._handlers.keys())


def create_default_registry() -> ProtocolRegistry:
    """Create a registry with all built-in protocol handlers."""
    from .tls_handler import TLSHandler
    from .ipsec_handler import IPSecHandler
    from .ssh_handler import SSHHandler

    registry = ProtocolRegistry()
    registry.register(TLSHandler())
    registry.register(IPSecHandler())
    registry.register(SSHHandler())
    return registry
