#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Event bus system for friTap.

Replaces the monolithic on_fritap_message() if/elif chain with a
publish-subscribe event system. Output handlers, the TUI, and
external integrations subscribe to typed events.
"""

from __future__ import annotations
import logging
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple, Type


# ---------------------------------------------------------------------------
# Base event
# ---------------------------------------------------------------------------

@dataclass
class FriTapEvent:
    """Base class for all friTap events."""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    protocol: str = "tls"
    _cancelled: bool = field(default=False, init=False, repr=False, compare=False)

    def cancel(self) -> None:
        """Mark this event as cancelled.

        Cancelled events are still delivered to all subscribers, but
        handlers that check ``event.cancelled`` (e.g. ConsoleOutputHandler)
        can choose to skip processing.  This follows the DOM
        ``preventDefault()`` pattern — advisory, not enforced.
        """
        self._cancelled = True

    @property
    def cancelled(self) -> bool:
        """Return whether this event has been cancelled."""
        return self._cancelled


# ---------------------------------------------------------------------------
# Concrete events
# ---------------------------------------------------------------------------

@dataclass
class KeylogEvent(FriTapEvent):
    """Emitted when TLS/SSL key material is extracted."""
    key_data: str = ""


@dataclass
class DatalogEvent(FriTapEvent):
    """Emitted when decrypted application data is captured."""
    data: bytes = b""
    function: str = ""
    direction: str = ""  # "read" or "write"
    src_addr: str = ""
    src_port: int = 0
    dst_addr: str = ""
    dst_port: int = 0
    src_addr_raw: Any = 0       # Raw (int for IPv4, hex str for IPv6, for PCAP)
    dst_addr_raw: Any = 0       # Raw (int for IPv4, hex str for IPv6, for PCAP)
    ss_family: str = "AF_INET"
    ssl_session_id: str = ""


@dataclass
class LibraryDetectedEvent(FriTapEvent):
    """Emitted when a TLS/SSL library is detected in the target process."""
    library: str = ""
    module: str = ""
    path: str = ""


@dataclass
class SessionEvent(FriTapEvent):
    """Emitted for SSL/TLS session lifecycle events."""
    session_id: str = ""
    event_type: str = ""  # "started", "resumed", "ended"
    cipher_suite: str = ""
    protocol_version: str = ""
    server_name: str = ""


@dataclass
class ConsoleEvent(FriTapEvent):
    """Emitted for console log messages from the agent."""
    message: str = ""
    level: str = "info"


@dataclass
class ErrorEvent(FriTapEvent):
    """Emitted when an error occurs in the agent or hooking pipeline."""
    error: str = ""
    description: str = ""
    stack: str = ""
    file: str = ""
    line: str = ""


@dataclass
class SocketTraceEvent(FriTapEvent):
    """Emitted when socket information is traced."""
    src_addr: str = ""
    src_port: int = 0
    dst_addr: str = ""
    dst_port: int = 0
    ss_family: str = "AF_INET"


@dataclass
class DetachEvent(FriTapEvent):
    """Emitted when the target process detaches."""
    reason: str = ""


@dataclass
class InstrumentEvent(FriTapEvent):
    """Emitted when a process is instrumented."""
    process_id: str = ""
    target: str = ""
    backend: str = ""


@dataclass
class ScriptLoadedEvent(FriTapEvent):
    """Emitted when a script is loaded into the target process."""
    script_name: str = ""
    plugin_name: str = ""
    load_order: str = ""


# ---------------------------------------------------------------------------
# Event Bus
# ---------------------------------------------------------------------------

class EventBus:
    """
    Simple thread-safe publish-subscribe event bus.

    Usage:
        bus = EventBus()
        bus.subscribe(KeylogEvent, my_handler)
        bus.emit(KeylogEvent(key_data="CLIENT_RANDOM ..."))

    Subscribers can specify a *priority* (higher runs first).  Plugins
    should use ``EventBus.PLUGIN_PRIORITY`` so they execute before the
    built-in output handlers.
    """

    MAX_HANDLER_FAILURES = 10
    PLUGIN_PRIORITY = 100

    def __init__(self, on_handler_error: Optional[Callable] = None) -> None:
        self._subscribers: Dict[Type[FriTapEvent], List[Tuple[int, Callable]]] = {}
        self._lock = threading.Lock()
        self._logger = logging.getLogger("friTap.events")
        self._failure_counts: Dict[str, int] = {}
        self._on_handler_error = on_handler_error

    def subscribe(self, event_type: Type[FriTapEvent], callback: Callable, *, priority: int = 0) -> None:
        """Register *callback* to be called whenever *event_type* is emitted.

        Higher *priority* values run first.  The default is 0; plugins
        should use ``EventBus.PLUGIN_PRIORITY`` (100).
        """
        with self._lock:
            subs = self._subscribers.setdefault(event_type, [])
            subs.append((priority, callback))
            subs.sort(key=lambda t: t[0], reverse=True)

    def unsubscribe(self, event_type: Type[FriTapEvent], callback: Callable) -> None:
        """Remove a previously registered callback."""
        with self._lock:
            subs = self._subscribers.get(event_type, [])
            for i, (_, cb) in enumerate(subs):
                if cb == callback:
                    subs.pop(i)
                    break

    def emit(self, event: FriTapEvent) -> None:
        """
        Dispatch *event* to all subscribers registered for its type.

        Also dispatches to subscribers of the base ``FriTapEvent`` type,
        allowing catch-all handlers.  The merged list is sorted by
        descending priority so higher-priority subscribers run first.
        """
        with self._lock:
            specific = self._subscribers.get(type(event), [])
            if type(event) is not FriTapEvent:
                catch_all = self._subscribers.get(FriTapEvent, [])
                # Merge two pre-sorted (descending priority) lists
                handlers = []
                i, j = 0, 0
                while i < len(specific) and j < len(catch_all):
                    if specific[i][0] >= catch_all[j][0]:
                        handlers.append(specific[i])
                        i += 1
                    else:
                        handlers.append(catch_all[j])
                        j += 1
                handlers.extend(specific[i:])
                handlers.extend(catch_all[j:])
            else:
                handlers = list(specific)

        for _prio, cb in handlers:
            try:
                cb(event)
            except Exception as exc:
                handler_name = getattr(cb, "__qualname__", repr(cb))
                self._logger.exception(
                    "Error in event subscriber %s for %s",
                    handler_name,
                    type(event).__name__,
                )

                # Track failure count
                count = self._failure_counts.get(handler_name, 0) + 1
                self._failure_counts[handler_name] = count

                # Invoke optional error callback
                if self._on_handler_error is not None:
                    try:
                        self._on_handler_error(cb, event, exc)
                    except Exception:
                        pass

                # Emit ErrorEvent for handler failures (guard against recursion)
                if not isinstance(event, ErrorEvent):
                    try:
                        self.emit(ErrorEvent(
                            error=f"Handler {handler_name} failed",
                            description=str(exc),
                        ))
                    except Exception:
                        pass

                # Auto-unsubscribe after too many failures
                if count >= self.MAX_HANDLER_FAILURES:
                    self._logger.warning(
                        "Auto-unsubscribing handler %s after %d failures",
                        handler_name, count,
                    )
                    self._remove_handler(cb)

    def _remove_handler(self, cb: Callable) -> None:
        """Remove *cb* from all event-type subscriber lists."""
        with self._lock:
            for subs in self._subscribers.values():
                for i, (_p, c) in enumerate(subs):
                    if c is cb:
                        subs.pop(i)
                        break

    @property
    def handler_failures(self) -> Dict[str, int]:
        """Return a copy of the handler failure counts."""
        return dict(self._failure_counts)

    def clear(self) -> None:
        """Remove all subscribers."""
        with self._lock:
            self._subscribers.clear()
