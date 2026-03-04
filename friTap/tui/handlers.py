#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
TUI output handler bridging EventBus events to the Textual UI thread.

Uses ``app.call_from_thread()`` to safely dispatch from Frida's
callback thread to Textual's event loop.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..output.base import OutputHandler
from ..events import (
    DatalogEvent,
    KeylogEvent,
    ConsoleEvent,
    ErrorEvent,
    LibraryDetectedEvent,
    SessionEvent,
    DetachEvent,
)

if TYPE_CHECKING:
    from ..events import EventBus
    from .app import FriTapApp


class TuiOutputHandler(OutputHandler):
    """Bridge EventBus events to the Textual UI thread."""

    def __init__(self, app: "FriTapApp") -> None:
        self._app = app

    def setup(self, event_bus: "EventBus") -> None:
        self._event_bus = event_bus
        event_bus.subscribe(DatalogEvent, self._on_data)
        event_bus.subscribe(KeylogEvent, self._on_keylog)
        event_bus.subscribe(ConsoleEvent, self._on_console)
        event_bus.subscribe(ErrorEvent, self._on_error)
        event_bus.subscribe(LibraryDetectedEvent, self._on_library)
        event_bus.subscribe(SessionEvent, self._on_session)
        event_bus.subscribe(DetachEvent, self._on_detach)

    # ------------------------------------------------------------------
    # Frida-thread callbacks -> bridge to Textual thread
    # ------------------------------------------------------------------

    def _on_data(self, event: DatalogEvent) -> None:
        self._app.call_from_thread(self._update_data_ui, event)

    def _on_keylog(self, event: KeylogEvent) -> None:
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

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _get_widget(self, widget_id: str):
        """Return a widget by CSS ID from the current screen stack."""
        for screen in self._app.screen_stack:
            try:
                return screen.query_one(widget_id)
            except Exception:
                continue
        return None

    def _get_activity_log(self):
        """Return the ActivityLog widget from the current screen stack."""
        return self._get_widget("#activity-log")

    def close(self) -> None:
        """TUI cleanup handled by MainScreen lifecycle."""
        pass
