#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Abstract base class for protocol handlers."""

from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Any, List, Optional


class BackendSupport:
    """Support level constants for protocol-backend combinations."""
    FULL = "full"
    STUB = "stub"
    UNSUPPORTED = "unsupported"


class ProtocolHandler(ABC):
    """
    Python-side protocol handler. Processes events from the agent
    and routes them to appropriate output handlers.
    """

    library_patterns: List[str] = []

    @property
    @abstractmethod
    def name(self) -> str:
        """Protocol identifier (e.g., 'tls', 'ipsec', 'ssh')."""
        ...

    @property
    @abstractmethod
    def display_name(self) -> str:
        """Human-readable name (e.g., 'TLS/SSL', 'IPSec')."""
        ...

    @abstractmethod
    def get_keylog_format(self) -> str:
        """Return the keylog format description."""
        ...

    def format_key_for_wireshark(self, key_data: str) -> str:
        """Format key material for Wireshark. Override if needed."""
        return key_data

    @abstractmethod
    def get_wireshark_protocol_preference(self) -> str:
        """Return Wireshark protocol preference path."""
        ...

    def get_pcap_dlt(self) -> int:
        """Return PCAP Data Link Type. Default: DLT_EN10MB."""
        return 1

    def get_display_filter_template(self) -> str:
        """Return Wireshark display filter template."""
        return ""

    def matches_libraries(self, detected_libraries: List[str]) -> bool:
        """Check if detected libraries match this protocol."""
        return any(
            pattern in lib.lower()
            for lib in detected_libraries
            for pattern in self.library_patterns
        )

    @property
    def supported_backends(self) -> dict[str, str]:
        """Map of backend name to support level. Override in subclasses."""
        return {"frida": BackendSupport.FULL}

    def is_backend_supported(self, backend_name: str) -> bool:
        """Check if a backend has FULL support for this protocol."""
        return self.supported_backends.get(backend_name) == BackendSupport.FULL

    def get_backend_support_level(self, backend_name: str) -> str:
        """Return the support level for a given backend."""
        return self.supported_backends.get(backend_name, BackendSupport.UNSUPPORTED)


class BaseKeyProcessor:
    """Base class for protocol-specific key processors.

    Provides shared constructor, extracted-keys storage, and
    ``format_keylog()`` template.  Subclasses override
    ``process_key_event()`` and optionally ``format_keylog()``.
    """

    def __init__(self, event_bus: Any = None) -> None:
        self._event_bus = event_bus
        self._extracted_keys: list[dict] = []

    @property
    def extracted_keys(self) -> list[dict]:
        """Return all extracted key records."""
        return list(self._extracted_keys)

    def process_key_event(self, event: dict) -> Optional[dict]:
        """Process an incoming key event. Override in subclasses."""
        return None

    def format_keylog(self) -> str:
        """Format extracted keys as a keylog string. Override in subclasses."""
        return ""
