#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Abstract base class for protocol handlers."""

from __future__ import annotations
from abc import ABC, abstractmethod
from typing import List


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
