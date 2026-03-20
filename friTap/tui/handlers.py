#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
TUI output handler bridging EventBus events to the Textual UI thread.

Uses ``app.call_from_thread()`` to safely dispatch from Frida's
callback thread to Textual's event loop.
"""

from __future__ import annotations

import subprocess
from typing import TYPE_CHECKING

from textual.css.query import NoMatches

from ..output.base import OutputHandler
from ..fritap_utility import find_wireshark_binary
from ..events import (
    DatalogEvent,
    KeylogEvent,
    ConsoleEvent,
    ErrorEvent,
    LibraryDetectedEvent,
    SessionEvent,
    DetachEvent,
    LiveReadyEvent,
    WiresharkConnectedEvent,
    LiveConnectionFailedEvent,
)

if TYPE_CHECKING:
    from ..events import EventBus
    from .app import FriTapApp


class TuiOutputHandler(OutputHandler):
    """Bridge EventBus events to the Textual UI thread."""

    def __init__(self, app: "FriTapApp") -> None:
        self._app = app
        self.key_count: int = 0

    def setup(self, event_bus: "EventBus") -> None:
        self._event_bus = event_bus
        event_bus.subscribe(DatalogEvent, self._on_data)
        event_bus.subscribe(KeylogEvent, self._on_keylog)
        event_bus.subscribe(ConsoleEvent, self._on_console)
        event_bus.subscribe(ErrorEvent, self._on_error)
        event_bus.subscribe(LibraryDetectedEvent, self._on_library)
        event_bus.subscribe(SessionEvent, self._on_session)
        event_bus.subscribe(DetachEvent, self._on_detach)
        event_bus.subscribe(LiveReadyEvent, self._on_live_ready)
        event_bus.subscribe(WiresharkConnectedEvent, self._on_wireshark_connected)
        event_bus.subscribe(LiveConnectionFailedEvent, self._on_live_connection_failed)

    # ------------------------------------------------------------------
    # Frida-thread callbacks -> bridge to Textual thread
    # ------------------------------------------------------------------

    def _on_data(self, event: DatalogEvent) -> None:
        self._app.call_from_thread(self._update_data_ui, event)

    def _on_keylog(self, event: KeylogEvent) -> None:
        self.key_count += 1
        self._app.call_from_thread(self._update_keylog_ui, event)

    def _on_console(self, event: ConsoleEvent) -> None:
        self._app.call_from_thread(self._update_console_ui, event)

    def _on_error(self, event: ErrorEvent) -> None:
        self._app.call_from_thread(self._update_error_ui, event)

    def _on_library(self, event: LibraryDetectedEvent) -> None:
        self._app.call_from_thread(self._update_library_ui, event)

    def _on_session(self, event: SessionEvent) -> None:
        self._app.call_from_thread(self._update_session_ui, event)

    def _on_detach(self, event: DetachEvent) -> None:
        self._app.call_from_thread(self._update_detach_ui, event)

    def _on_live_ready(self, event: LiveReadyEvent) -> None:
        self._app.call_from_thread(self._update_live_ready_ui, event)

    def _on_wireshark_connected(self, event: WiresharkConnectedEvent) -> None:
        self._app.call_from_thread(self._update_wireshark_connected_ui, event)

    def _on_live_connection_failed(self, event: LiveConnectionFailedEvent) -> None:
        self._app.call_from_thread(self._update_live_connection_failed_ui, event)

    # ------------------------------------------------------------------
    # Textual-thread UI updates -> route to ActivityLog
    # ------------------------------------------------------------------

    def _update_data_ui(self, event: DatalogEvent) -> None:
        log = self._get_activity_log()
        if log:
            log.log_data(
                function=event.function,
                src=f"{event.src_addr}:{event.src_port}",
                dst=f"{event.dst_addr}:{event.dst_port}",
                size=str(len(event.data)),
            )

    def _update_keylog_ui(self, event: KeylogEvent) -> None:
        log = self._get_activity_log()
        if log:
            preview = event.key_data[:60]
            log.log_key(f"{preview}...")

    def _update_console_ui(self, event: ConsoleEvent) -> None:
        log = self._get_activity_log()
        if log:
            log.log_info(event.message)

    def _update_error_ui(self, event: ErrorEvent) -> None:
        log = self._get_activity_log()
        if log:
            log.log_error(event.error)

    def _update_library_ui(self, event: LibraryDetectedEvent) -> None:
        log = self._get_activity_log()
        if log:
            log.log_library(event.library, event.path)

    def _update_session_ui(self, event: SessionEvent) -> None:
        log = self._get_activity_log()
        if log:
            log.log_session(event.event_type)

    def _update_detach_ui(self, event: DetachEvent) -> None:
        log = self._get_activity_log()
        if log:
            log.log_detach(event.reason)
        status = self._get_widget("#status-bar")
        if status:
            status.update_capture("STOPPED")

    def _update_live_ready_ui(self, event: LiveReadyEvent) -> None:
        log = self._get_activity_log()
        if log:
            log.log_live(f"Named pipe ready: {event.fifo_path}")
            log.log_info("Launching Wireshark...")

            wireshark_path = find_wireshark_binary()
            launched = False
            if wireshark_path:
                try:
                    subprocess.Popen(
                        [wireshark_path, "-k", "-i", event.fifo_path],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        start_new_session=True,
                    )
                    log.log_success("Wireshark launched — waiting for connection...")
                    launched = True
                except OSError as e:
                    log.log_warning(f"Failed to launch Wireshark: {e}")
            else:
                log.log_warning("Wireshark not found in PATH")

            if not launched:
                log.log_info(f"Run manually: wireshark -k -i {event.fifo_path}")

    def _update_wireshark_connected_ui(self, event: WiresharkConnectedEvent) -> None:
        log = self._get_activity_log()
        if log:
            log.log_success("Wireshark connected — starting capture")

    def _update_live_connection_failed_ui(self, event: LiveConnectionFailedEvent) -> None:
        log = self._get_activity_log()
        if log:
            log.log_error(f"Live view failed: {event.reason}")
            log.log_info(
                "Capture will continue without live view. "
                f"To retry: wireshark -k -i {event.fifo_path}"
            )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _get_widget(self, widget_id: str):
        """Return a widget by CSS ID from the current screen stack."""
        for screen in self._app.screen_stack:
            try:
                return screen.query_one(widget_id)
            except NoMatches:
                continue
        return None

    def _get_activity_log(self):
        """Return the ActivityLog widget from the current screen stack."""
        return self._get_widget("#activity-log")

    def close(self) -> None:
        """Required by OutputHandler — delegates to teardown."""
        self.teardown()

    def teardown(self) -> None:
        """Unsubscribe from all EventBus events."""
        bus = getattr(self, "_event_bus", None)
        if bus is None:
            return
        bus.unsubscribe(DatalogEvent, self._on_data)
        bus.unsubscribe(KeylogEvent, self._on_keylog)
        bus.unsubscribe(ConsoleEvent, self._on_console)
        bus.unsubscribe(ErrorEvent, self._on_error)
        bus.unsubscribe(LibraryDetectedEvent, self._on_library)
        bus.unsubscribe(SessionEvent, self._on_session)
        bus.unsubscribe(DetachEvent, self._on_detach)
        bus.unsubscribe(LiveReadyEvent, self._on_live_ready)
        bus.unsubscribe(WiresharkConnectedEvent, self._on_wireshark_connected)
        bus.unsubscribe(LiveConnectionFailedEvent, self._on_live_connection_failed)
        self._event_bus = None
