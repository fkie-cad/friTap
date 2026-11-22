#!/usr/bin/env python3

"""Session: first-class capture instance for friTap.

One running capture: attach/spawn a target, load the agent, run with one frozen
config, produce artifacts (keys.log, PCAP, JSONL), stop and finalize outputs.
All mutable state lives here; no globals or singletons.
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
    from .parsers.base import BaseParser
    from .parsers.registry import ParserRegistry
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
    """One capture instance; all mutable state lives here.

    ``start()`` attaches, loads the agent and opens sinks; ``wait()`` blocks;
    ``stop()`` detaches, drains the pipeline and closes sinks.
    """

    def __init__(
        self,
        config: FriTapConfig,
        backend: "Backend",
        protocol_registry: "ProtocolRegistry",
        plugin_loader: "PluginLoader",
        pipeline: "MessagePipeline",
        parser_registry: Optional["ParserRegistry"] = None,
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
        self._parser_registry = parser_registry
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

    def register_parser(
        self,
        parser_cls: type["BaseParser"],
        priority: int = 50,
    ) -> None:
        """Register a custom parser for flow detection (call from a plugin's ``on_load()``).

        *parser_cls* is a :class:`~friTap.parsers.base.BaseParser` subclass; higher
        *priority* (default 50) is tried first in ``can_parse()``.
        Raises ``RuntimeError`` if the session has no parser registry.
        """
        if self._parser_registry is None:
            from .parsers.registry import get_default_registry
            self._parser_registry = get_default_registry()
        self._parser_registry.register(parser_cls, priority)
        self._logger.debug(
            "Plugin registered parser %s at priority %d",
            parser_cls.__name__,
            priority,
        )

    def start(self) -> None:
        """Start the capture: CREATED -> ATTACHING -> RUNNING."""
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
        """Stop the capture: RUNNING -> STOPPING -> STOPPED."""
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
        """Push a raw agent message into the pipeline (called by the message handler)."""
        self.pipeline.push(payload, data)


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
