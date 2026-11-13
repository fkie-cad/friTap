#!/usr/bin/env python3

"""``--tap <file>``: write a ``.tap`` capture straight from a CLI session.

Reuses the TUI's live-save wiring (``friTap/tui/capture_controller.py``): a
:class:`~friTap.flow.collector.FlowCollector` turns the decrypted
``DatalogEvent`` stream into flows and a
:class:`~friTap.flow.tap_writer.TapWriter` persists each completed flow. On
:meth:`close` the collector is flushed, every flow not yet written is written,
and the writer appends the index + footer.

``close()`` is reached on every CLI stop path because ``SSL_Logger.cleanup()``
always calls ``close_output_handlers()``: Ctrl+C / SIGINT, ``--duration``,
a normal return, and the target-detach path (exit code 3).
"""

from __future__ import annotations

import logging
import threading
from typing import TYPE_CHECKING, Callable, Optional

from .base import OutputHandler

if TYPE_CHECKING:
    from ..events import EventBus


class TapOutputHandler(OutputHandler):
    """Collect flows from the event bus and stream them into a ``.tap`` file."""

    consumes_plaintext = True

    def __init__(self, tap_path: str, target: str = "",
                 collector_factory: Optional[Callable] = None,
                 writer_factory: Optional[Callable] = None) -> None:
        self._path = tap_path
        self._target = target
        self._collector_factory = collector_factory
        self._writer_factory = writer_factory
        self._collector = None
        self._writer = None
        self._close_lock = threading.Lock()
        self._logger = logging.getLogger("friTap.output.tap")

    @property
    def path(self) -> str:
        return self._writer.path if self._writer is not None else self._path

    def setup(self, event_bus: "EventBus") -> None:
        self._collector = self._new_collector()
        self._writer = self._new_writer()
        self._writer.open(self._path, target=self._target)
        self._collector.subscribe(self._writer.on_flow_event)
        self._collector.set_request_context_sink(self._writer.write_request_context)
        self._collector.subscribe_to(event_bus)
        self._logger.info("Writing .tap capture to %s", self._writer.path)

    def _new_collector(self):
        if self._collector_factory is not None:
            return self._collector_factory()
        from ..flow.collector import FlowCollector
        # Headless: nothing browses completed flows, so release each one once
        # the writer (subscribed first, in setup) has persisted it.
        collector = FlowCollector(retain_completed=False)
        collector.set_capture_target(self._target)
        return collector

    def set_process_name(self, process_name: str) -> None:
        """Re-target the collector with the name resolved after a PID attach."""
        if self._collector is not None:
            self._collector.set_capture_target(self._target, process_name=process_name)

    def _new_writer(self):
        if self._writer_factory is not None:
            return self._writer_factory()
        from ..flow.tap_writer import TapWriter
        return TapWriter()

    def _write_remaining_flows(self, writer) -> None:
        """flush() completes active flows without notifying; persist the rest."""
        self._collector.flush()
        written = writer.written_flow_ids
        for flow in self._collector.get_flows():
            if flow.flow_id not in written:
                writer.write_flow(flow)

    def close(self) -> None:
        """Finalize the ``.tap`` (index + footer). Idempotent, never raises."""
        with self._close_lock:
            writer, self._writer = self._writer, None
        if writer is None:
            return
        try:
            if self._collector is not None:
                self._write_remaining_flows(writer)
        except Exception as e:  # noqa: BLE001 - still finalize the file below
            self._logger.error("Error collecting remaining flows for .tap: %s", e)
        finally:
            try:
                writer.close()
                self._logger.info("Capture saved: %s (%d flows)",
                                  writer.path, writer.flow_count)
            except Exception as e:  # noqa: BLE001
                self._logger.error("Error finalizing .tap file: %s", e)
