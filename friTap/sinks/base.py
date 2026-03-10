#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Base Sink protocol for friTap pipeline output.

A Sink is a write-only terminal destination where processed data flows out.
Sinks never modify, route, or transform events - they only write them.
"""

from __future__ import annotations
from typing import Protocol, runtime_checkable, TYPE_CHECKING

if TYPE_CHECKING:
    from ..schemas.canonical import KeylogCanonical, DataCanonical, MetaCanonical


@runtime_checkable
class Sink(Protocol):
    """Protocol for pipeline output sinks."""

    def open(self) -> None:
        """Open the sink for writing."""
        ...

    def on_keylog(self, event: "KeylogCanonical") -> None:
        """Handle processed key material."""
        ...

    def on_data(self, event: "DataCanonical") -> None:
        """Handle processed decrypted data."""
        ...

    def on_meta(self, event: "MetaCanonical") -> None:
        """Handle processed metadata."""
        ...

    def flush(self) -> None:
        """Flush any buffered data."""
        ...

    def close(self) -> None:
        """Close the sink and release resources."""
        ...
