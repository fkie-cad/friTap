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
from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable, Optional, Protocol

from .config import FriTapConfig
from .connection_index import ConnectionIndex
from .events import ErrorEvent, EventBus, FriTapEvent

if TYPE_CHECKING:
    from .backends.base import Backend
    from .message_router import MessageRouter
    from .parsers.base import BaseParser
    from .parsers.registry import ParserRegistry
    from .pipeline import MessagePipeline
    from .plugins.loader import PluginLoader
    from .protocols.registry import ProtocolRegistry
    from .sinks.base import Sink


class CaptureProducer(Protocol):
    """Session-owned source of normalized capture records.

    start returns after startup is confirmed. stop drains queued records and
    is also safe after partial startup or from the producer's completion callback.
    The producer serializes record delivery, including records drained at stop.
    It reports detected loss with a capture_loss record containing a count.
    """

    def start(
        self,
        emit: Callable[[dict, bytes | None], None],
        finished: Callable[[Exception | None], None],
    ) -> None: ...

    def stop(self) -> None: ...


CAPTURE_STARTED = "started"
CAPTURE_STOPPED = "stopped"


@dataclass
class CaptureLifecycleEvent(FriTapEvent):
    """The capture coordinator itself started or stopped.

    Distinct from :class:`~friTap.events.SessionEvent`, which describes a
    TLS session of the target: output handlers count those, not this.
    """
    session_id: str = ""
    event_type: str = ""  # CAPTURE_STARTED or CAPTURE_STOPPED


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
        backend: Optional["Backend"],
        protocol_registry: "ProtocolRegistry",
        plugin_loader: "PluginLoader",
        pipeline: "MessagePipeline",
        parser_registry: Optional["ParserRegistry"] = None,
        logger: Optional[logging.Logger] = None,
        producer: CaptureProducer | None = None,
        manage_capture_resources: bool = True,
    ) -> None:
        self.id: str = str(uuid.uuid4())
        self.config: FriTapConfig = config
        self.state: SessionState = SessionState.CREATED
        self.pipeline: "MessagePipeline" = pipeline
        self.connection_index: ConnectionIndex = ConnectionIndex()
        self.lifecycle_bus: EventBus = EventBus()
        self._router: "MessageRouter | None" = None

        self._backend = backend
        self._protocol_registry = protocol_registry
        self._plugin_loader = plugin_loader
        self._parser_registry = parser_registry
        self._logger = logger or logging.getLogger("friTap.session")
        self._done_event = threading.Event()
        self._producer = producer
        self._manage_capture_resources = manage_capture_resources
        # Undo actions for acquired resources, run in reverse by _finalize.
        self._cleanups: list[Callable[[], None]] = []
        # stop() during the "started" announcement defers teardown to start().
        self._announcing_start = False
        self.failure: Exception | None = None
        self.dropped_records = 0
        self._lock = threading.Lock()
        self._delivery = threading.local()

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

        try:
            if self._manage_capture_resources:
                self._open_capture_resources()
            if self._producer is not None:
                self._start_producer()
            if not self._announce_running():
                self._finalize()
        except Exception as exc:
            with self._lock:
                self.failure = exc
                self.state = SessionState.STOPPING
            self._finalize()
            raise

    def _ensure_router(self) -> "MessageRouter":
        if self._router is None:
            from .message_router import MessageRouter

            self._router = MessageRouter(self.lifecycle_bus, active_protocol=self.config.protocols)
        return self._router

    def _open_capture_resources(self) -> None:
        """Display filter, producer outputs, sinks and plugins; each pushes its undo."""
        self._ensure_router().install_display_filter(self.config.output.filter_expression, self._logger)
        self._cleanups += [self.pipeline.close_all, self.pipeline.flush_all]  # pops flush, then close
        if self._producer is not None:
            self._setup_producer_handlers()
        for sink in self.pipeline.sinks:
            try:
                sink.open()
            except Exception:
                self._logger.exception("Failed to open sink %s", type(sink).__name__)
        # Pushed first: a partial load_all still unloads what it loaded.
        self._cleanups.append(lambda: self._plugin_loader.unload_all(self))
        self._plugin_loader.load_all(self)

    def _setup_producer_handlers(self) -> None:
        from .output.factory import OutputHandlerFactory

        handlers = OutputHandlerFactory.create_producer_handlers(
            self.config, {"session_info": {"backend": self.config.backend}},
            self._logger, self._protocol_registry,
        )
        for handler in handlers:
            self._cleanups.append(handler.close)
            handler.setup(self.lifecycle_bus)

    def _start_producer(self) -> None:
        self._ensure_router()
        # Pushed first: stop() must also be safe after a partial start.
        self._cleanups.append(self._producer.stop)
        self._producer.start(self._receive_capture_record, self._producer_finished)

    def _announce_running(self) -> bool:
        """ATTACHING -> RUNNING plus the start event; False when stop() intervened."""
        with self._lock:
            if self.state != SessionState.ATTACHING:
                return False
            self.state = SessionState.RUNNING
            self._announcing_start = True
        self._emit_lifecycle(CAPTURE_STARTED)
        with self._lock:
            self._announcing_start = False
            return self.state == SessionState.RUNNING

    def _emit_lifecycle(self, event_type: str) -> None:
        self.lifecycle_bus.emit(CaptureLifecycleEvent(event_type=event_type, session_id=self.id))

    def _producer_finished(self, error: Exception | None) -> None:
        if error is not None:
            with self._lock:
                if self.failure is None:
                    self.failure = error
        self.stop()

    def stop(self) -> None:
        """Stop the producer and finalize outputs, or let startup unwind."""
        with self._lock:
            if self.state == SessionState.ATTACHING or self._announcing_start:
                self.state = SessionState.STOPPING
                return
            if self.state != SessionState.RUNNING:
                return
            self.state = SessionState.STOPPING
        if getattr(self._delivery, "active", False):
            # The producer needs this callback to return before it can drain.
            threading.Thread(target=self._finalize, name="fritap-capture-stop", daemon=True).start()
        else:
            self._finalize()

    def _finalize(self) -> None:
        """Undo acquired resources in reverse; announce the stop, then release waiters."""
        while self._cleanups:
            action = self._cleanups.pop()
            try:
                action()
            except Exception as exc:
                if self.failure is None:
                    self.failure = exc
                self._logger.exception("Capture cleanup failed")
        with self._lock:
            self.state = SessionState.STOPPED
        try:
            # Stop subscribers see the event before wait() returns.
            self._emit_lifecycle(CAPTURE_STOPPED)
        finally:
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

    def _receive_capture_record(self, payload: dict, data: bytes | None = None) -> None:
        self._delivery.active = True
        try:
            self._route_capture_record(payload, data)
        finally:
            self._delivery.active = False

    def _route_capture_record(self, payload: dict, data: bytes | None) -> None:
        if (not isinstance(payload, dict) or not isinstance(payload.get("contentType"), str)
                or (data is not None and not isinstance(data, bytes))):
            self.dropped_records += 1
            self._logger.warning("Dropping malformed capture record")
            return
        if payload["contentType"] == "capture_loss":
            count = payload.get("count")
            if type(count) is int and count > 0:
                self.dropped_records += count
                detail = f"Incomplete capture: producer dropped {count} records"
                self._logger.warning(detail)
                self.lifecycle_bus.emit(ErrorEvent(error="capture_loss", description=detail))
                return
            self.dropped_records += 1
            self._logger.warning("Dropping malformed capture loss record")
            return
        try:
            self._router.route(payload, data or b"")
            self.push_message(payload, data)
        except (ValueError, TypeError, OverflowError):
            self.dropped_records += 1
            self._logger.warning("Dropping malformed capture record")

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
