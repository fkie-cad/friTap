#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Session: first-class capture instance for friTap.

A Session represents one running capture:
- Attach/spawn one target process
- Load the agent
- Run with one frozen config snapshot
- Produce artifacts (keys.log, PCAP, JSONL, etc.)
- Stop and finalize all outputs

All mutable state lives here. No globals, no singletons.
"""

from __future__ import annotations

import asyncio
import enum
import logging
import threading
import uuid
from typing import TYPE_CHECKING, Optional

from .config import FriTapConfig
from .connection_index import ConnectionIndex
from .events import EventBus, SessionEvent

if TYPE_CHECKING:
    from .backends.base import Backend
    from .pipeline import MessagePipeline
    from .plugins.loader import PluginLoader
    from .protocols.registry import ProtocolRegistry
    from .sinks.base import Sink


class SessionState(enum.Enum):
    """Lifecycle states for a capture session."""
    CREATED = "created"
    ATTACHING = "attaching"
    RUNNING = "running"
    STOPPING = "stopping"
    STOPPED = "stopped"


class Session:
    """One capture instance. All mutable state lives here.

    Usage:
        session = controller.create_session(config)
        session.start()   # attach, load agent, open sinks
        session.wait()    # block until session ends
        session.stop()    # detach, drain pipeline, close sinks
    """

    def __init__(
        self,
        config: FriTapConfig,
        backend: "Backend",
        protocol_registry: "ProtocolRegistry",
        plugin_loader: "PluginLoader",
        pipeline: "MessagePipeline",
        logger: Optional[logging.Logger] = None,
    ) -> None:
        self.id: str = str(uuid.uuid4())
        self.config: FriTapConfig = config
        self.state: SessionState = SessionState.CREATED
        self.pipeline: "MessagePipeline" = pipeline
        self.connection_index: ConnectionIndex = ConnectionIndex()
        self.lifecycle_bus: EventBus = EventBus()

        self._backend = backend
        self._protocol_registry = protocol_registry
        self._plugin_loader = plugin_loader
        self._logger = logger or logging.getLogger("friTap.session")
        self._done_event = threading.Event()
        self._device = None
        self._process = None
        self._script = None
        self._lock = threading.Lock()

    @property
    def sinks(self) -> list["Sink"]:
        """Return the list of active sinks."""
        return self.pipeline.sinks

    def register_sink(self, sink: "Sink") -> None:
        """Register an additional sink (e.g., from a plugin)."""
        self.pipeline.add_sink(sink)

    def start(self) -> None:
        """Start the capture session.

        Transitions: CREATED -> ATTACHING -> RUNNING
        """
        with self._lock:
            if self.state != SessionState.CREATED:
                raise RuntimeError(
                    f"Cannot start session in state {self.state.value}"
                )
            self.state = SessionState.ATTACHING

        self._logger.info("Session %s starting for target: %s", self.id[:8], self.config.target)

        # Open all sinks
        for sink in self.pipeline.sinks:
            try:
                sink.open()
            except Exception:
                self._logger.exception("Failed to open sink %s", type(sink).__name__)

        # Load plugins with session context
        self._plugin_loader.load_all(self)

        # Emit session started event
        self.lifecycle_bus.emit(SessionEvent(
            event_type="started",
            session_id=self.id,
        ))

        with self._lock:
            self.state = SessionState.RUNNING

    def stop(self) -> None:
        """Stop the capture session.

        Transitions: RUNNING -> STOPPING -> STOPPED
        """
        with self._lock:
            if self.state not in (SessionState.RUNNING, SessionState.ATTACHING):
                self._logger.debug("Session already in state %s, skip stop", self.state.value)
                return
            self.state = SessionState.STOPPING

        self._logger.info("Session %s stopping", self.id[:8])

        # Unload plugins (before pipeline close so final events reach sinks)
        self._plugin_loader.unload_all(self)

        # Flush and close pipeline sinks
        self.pipeline.flush_all()
        self.pipeline.close_all()

        # Emit session stopped event
        self.lifecycle_bus.emit(SessionEvent(
            event_type="stopped",
            session_id=self.id,
        ))

        with self._lock:
            self.state = SessionState.STOPPED

        self._done_event.set()

    def wait(self) -> None:
        """Block until the session ends."""
        self._done_event.wait()

    def wait_timeout(self, timeout: float) -> bool:
        """Block until the session ends or timeout. Returns True if done."""
        return self._done_event.wait(timeout=timeout)

    @property
    def is_running(self) -> bool:
        """Return whether the session is currently running."""
        return self.state == SessionState.RUNNING

    def push_message(self, payload: dict, data: bytes | None = None) -> None:
        """Push a raw agent message into the pipeline.

        Called by the message handler when an agent message arrives.
        """
        self.pipeline.push(payload, data)

    # ------------------------------------------------------------------
    # Async API (wraps sync methods via asyncio.to_thread)
    # ------------------------------------------------------------------

    async def astart(self) -> None:
        """Async version of start(). Runs blocking operations in a thread."""
        await asyncio.to_thread(self.start)

    async def astop(self) -> None:
        """Async version of stop()."""
        await asyncio.to_thread(self.stop)

    async def await_done(self) -> None:
        """Async version of wait(). Non-blocking wait for session end."""
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self._done_event.wait)
