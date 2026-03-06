#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Base class for friTap plugins.

Plugins extend friTap with custom functionality like:
- Additional protocol handlers
- Custom output formats
- Integration bridges
- Pattern generators
"""

from __future__ import annotations
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..events import EventBus, FriTapEvent


class FriTapPlugin(ABC):
    """
    Abstract base class for friTap plugins.

    Plugins are discovered from:
    - Platform-native plugin directory (auto-created on first run):
        - Linux:   ~/.local/share/friTap/plugins/
        - macOS:   ~/Library/Application Support/friTap/plugins/
        - Windows: C:\\Users\\<user>\\AppData\\Local\\friTap\\plugins\\
      Run ``python -c "from friTap.plugins.loader import PLUGIN_DIR; print(PLUGIN_DIR)"``
      to find the actual path on your system.
    - Legacy ~/.fritap/plugins/ directory (used if it exists and the native path doesn't)
    - Python entry points (fritap.plugins group)

    Event cancellation
    ------------------
    Plugins that want to take over display of SSL buffers (e.g. show
    only ASCII, parse HTTP, decompress gzip) can *cancel* events so
    that built-in console output is suppressed::

        from friTap.events import DatalogEvent, EventBus

        class MyPlugin(FriTapPlugin):
            def on_load(self, event_bus: EventBus) -> None:
                event_bus.subscribe(
                    DatalogEvent,
                    self._handle_data,
                    priority=EventBus.PLUGIN_PRIORITY,
                )

            def _handle_data(self, event: DatalogEvent) -> None:
                # Custom display logic
                print(event.data.decode("utf-8", errors="replace"))
                event.cancel()  # suppress default hexdump

    Cancellation is advisory — file-based handlers (PCAP, keylog, JSON)
    always record data regardless.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique plugin identifier."""
        ...

    @property
    @abstractmethod
    def version(self) -> str:
        """Plugin version string."""
        ...

    @property
    def description(self) -> str:
        """Human-readable plugin description."""
        return ""

    def on_load(self, event_bus: "EventBus") -> None:
        """Called when the plugin is loaded. Subscribe to events here."""
        pass

    def on_event(self, event: "FriTapEvent") -> None:
        """Called for every event (catch-all handler)."""
        pass

    def on_unload(self) -> None:
        """Called when the plugin is unloaded. Release resources here."""
        pass
