#!/usr/bin/env python3

"""
Abstract base class for output handlers.

Each output handler subscribes to relevant events on the EventBus
and writes output in its specific format.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..events import (
        ConsoleEvent,
        DatalogEvent,
        ErrorEvent,
        EventBus,
        KeylogEvent,
        SessionEvent,
    )


class OutputHandler(ABC):
    """Abstract output handler that subscribes to EventBus events."""

    #: True for handlers that need the decrypted read/write data events, i.e.
    #: the agent's plaintext hooks (wire key ``pcap_enabled``). The factory ORs
    #: this over the handlers a config selects (see
    #: :meth:`OutputHandlerFactory.plaintext_hooks_needed`).
    consumes_plaintext: bool = False

    @abstractmethod
    def setup(self, event_bus: "EventBus") -> None:
        """Subscribe to relevant events on the bus."""
        ...

    @abstractmethod
    def close(self) -> None:
        """Flush buffers and release resources."""
        ...

    def on_keylog(self, event: "KeylogEvent") -> None:
        """Handle key material extraction. Override in subclasses."""
        pass

    def on_data(self, event: "DatalogEvent") -> None:
        """Handle decrypted data capture. Override in subclasses."""
        pass

    def on_session(self, event: "SessionEvent") -> None:
        """Handle session lifecycle events. Override in subclasses."""
        pass

    def on_console(self, event: "ConsoleEvent") -> None:
        """Handle console messages. Override in subclasses."""
        pass

    def on_error(self, event: "ErrorEvent") -> None:
        """Handle error events. Override in subclasses."""
        pass
