#!/usr/bin/env python3

"""Base class and viewer protocols for friTap plugins."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from ..events import FriTapEvent
    from ..flow.models import Flow, FlowSummary
    from ..session import Session


class FriTapPlugin(ABC):
    """Abstract base class for friTap plugins.

    Plugins are discovered from:
    - The platform plugin directory (created on first run):
        - Linux:   ~/.local/share/friTap/plugins/
        - macOS:   ~/Library/Application Support/friTap/plugins/
        - Windows: C:\\Users\\<user>\\AppData\\Local\\friTap\\plugins\\
      ``python -c "from friTap.plugins.loader import _get_plugin_dir; print(_get_plugin_dir())"``
      prints the actual path.
    - ~/.fritap/plugins/ (used if it exists and the native path does not)
    - Python entry points (fritap.plugins group)

    Event cancellation
    ------------------
    Plugins that take over display of SSL buffers can *cancel* events to
    suppress built-in console output::

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

    Cancellation is advisory: file-based handlers (PCAP, keylog, JSON) always
    record data.

    Flow events
    -----------
    Subscribe to FlowEvent to receive parsed HTTP flows (TUI and CLI)::

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
    Register parsers to extend flow detection (gRPC, MQTT, custom binary)::

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

    def register_analyzers(self) -> list:
        """Return the BaseAnalyzer instances this plugin provides (default: none).

        Called by analyzer discovery outside the on_load/Session lifecycle, so
        analyzers work offline, for --list-analyzers, and in the TUI.
        """
        return []


@runtime_checkable
class ColumnProvider(Protocol):
    """Plugin-provided column for FlowListWidget.

    Internal to friTap's TUI (``FlowListWidget.register_column`` in
    friTap/tui/widgets/flow_list.py); plugins are not wired to it.
    Third-party code should use ``FlowColumnSpec`` / ``register_flow_column``
    in ``friTap.ui.extensions`` (see docs/api/embedding.md).
    """
    name: str       # Column header text
    width: int      # Character width hint
    key: str        # Unique column key

    def value(self, flow: "FlowSummary") -> str:
        """Return cell value for this flow's summary row.

        ``flow`` is the displayed ``FlowSummary`` (not the raw ``Flow``).
        Called on every flow update: keep it cheap and cache derived values.
        """
        ...

    def style(self, flow: "FlowSummary") -> str:
        """Return Rich style for this cell (optional, defaults to empty)."""
        ...


@runtime_checkable
class TabProvider(Protocol):
    """Plugin-provided tab for FlowDetailWidget.

    Internal to friTap's TUI (``FlowDetailWidget.register_tab`` in the
    friTap/tui/widgets/flow_detail/ package, e.g. the OHTTP tab in
    friTap/tui/capture_controller.py); plugins are not wired to it.
    Third-party code should use ``DetailTabSpec`` / ``register_detail_tab``
    in ``friTap.ui.extensions`` (see docs/api/embedding.md).
    """
    title: str      # Tab title displayed in tab bar
    tab_id: str     # Unique tab identifier

    def render(self, flow: "Flow") -> str:
        """Return text content to display for this flow."""
        ...
