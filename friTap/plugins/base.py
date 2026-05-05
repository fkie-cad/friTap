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

from typing import Protocol, runtime_checkable

if TYPE_CHECKING:
    from ..events import FriTapEvent
    from ..flow.models import Flow
    from ..session import Session


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
            def on_load(self, session) -> None:
                session.lifecycle_bus.subscribe(
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

    Flow events
    -----------
    Plugins can subscribe to FlowEvent to receive parsed HTTP flows
    in both TUI and CLI modes::

        from friTap.events import FlowEvent

        class MyFlowPlugin(FriTapPlugin):
            def on_load(self, session) -> None:
                session.lifecycle_bus.subscribe(
                    FlowEvent,
                    self._on_flow,
                    priority=EventBus.PLUGIN_PRIORITY,
                )

            def _on_flow(self, event: FlowEvent) -> None:
                if event.flow_event_type == "completed":
                    flow = event.flow
                    if flow.request:
                        print(f"{flow.request.method} {flow.request.url}")

    Custom protocol parsers
    -----------------------
    Plugins can register custom protocol parsers to extend flow detection
    with additional protocols (e.g., gRPC, MQTT, custom binary protocols)::

        from friTap.parsers.base import BaseParser

        class MqttParser(BaseParser):
            def can_parse(self, data: bytes) -> bool:
                return len(data) >= 2 and (data[0] >> 4) in range(1, 15)

            def parse(self, data: bytes, direction: str) -> dict:
                ...  # parse MQTT packet

        class MqttPlugin(FriTapPlugin):
            name = "mqtt"
            version = "1.0.0"

            def on_load(self, session) -> None:
                session.register_parser(MqttParser, priority=75)
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

    def on_load(self, session: "Session") -> None:
        """Called when the plugin is loaded. Subscribe to events here."""
        pass

    def on_event(self, event: "FriTapEvent") -> None:
        """Called for every event (catch-all handler)."""
        pass

    def on_unload(self, session: "Session") -> None:
        """Called when the plugin is unloaded. Release resources here."""
        pass


@runtime_checkable
class ColumnProvider(Protocol):
    """Plugin-provided column for FlowListWidget.

    Plugins implement this protocol and register via session.register_column()
    to add custom columns to the flow list table.
    """
    name: str       # Column header text
    width: int      # Character width hint
    key: str        # Unique column key

    def value(self, flow: "Flow") -> str:
        """Return cell value for this flow.

        This method is called on every flow update in the TUI flow list.
        Keep it lightweight — avoid expensive computation, network calls,
        or heavy string formatting. Prefer caching derived values inside
        the provider rather than recomputing on each call.
        """
        ...

    def style(self, flow: "Flow") -> str:
        """Return Rich style for this cell (optional, defaults to empty)."""
        ...


@runtime_checkable
class TabProvider(Protocol):
    """Plugin-provided tab for FlowDetailWidget.

    Plugins implement this protocol and register via session.register_tab()
    to add custom tabs to the flow detail view.
    """
    title: str      # Tab title displayed in tab bar
    tab_id: str     # Unique tab identifier

    def render(self, flow: "Flow") -> str:
        """Return text content to display for this flow."""
        ...
