#!/usr/bin/env python3

"""
Typed events and the thread-safe publish-subscribe EventBus.

Output handlers, the TUI and external integrations subscribe to event classes.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple, Type


@dataclass
class FriTapEvent:
    """Base class for all friTap events."""
    timestamp: float = field(default_factory=time.time)
    protocol: str = "tls"
    _cancelled: bool = field(default=False, init=False, repr=False, compare=False)

    def cancel(self) -> None:
        """Mark this event cancelled. Advisory: still delivered, handlers may skip it (like ``preventDefault()``)."""
        self._cancelled = True

    @property
    def cancelled(self) -> bool:
        """Whether :meth:`cancel` was called."""
        return self._cancelled


@dataclass
class KeylogEvent(FriTapEvent):
    """Key material extracted for any protocol.

    Carries a keylog line (``key_data``) or a structured ``payload`` that a
    :class:`KeylogFormatter` turns into Wireshark lines.

    Examples: TLS ``key_data = "CLIENT_RANDOM <hex> <hex>"``; SSH KEX
    ``payload = {"cookie": ..., "shared_secret": ...}``.
    """
    key_data: str = ""
    payload: Optional[Dict[str, Any]] = None


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
    src_addr_raw: Any = 0       # int for IPv4, hex str for IPv6 (for PCAP)
    dst_addr_raw: Any = 0
    ss_family: str = "AF_INET"
    ssl_session_id: str = ""
    client_random: str = ""
    transport: str = "tcp"  # "tcp" or "udp" — controls pcap framing (QUIC=udp)
    http3_headers: Optional[list] = None  # decoded [[name, value], ...]
    stream_id: Optional[int] = None
    quic_scid: str = ""
    quic_dcid: str = ""
    quic_stream_type: str = ""
    # "stream" (raw HTTP/3 stream bytes) | "body" (de-framed DATA payload) | "" (not QUIC).
    quic_payload: str = ""
    # Connection predates the capture: control and QPACK streams were never seen.
    quic_midstream: bool = False
    # STREAM chunk offset and FIN, so a writer can rebuild the STREAM frame.
    stream_offset: Optional[int] = None
    fin: bool = False
    library: str = ""  # module that produced the record (e.g. libssl.so)
    # Arrival time when ``timestamp`` is back-dated (held record); packet writers use it.
    received_at: Optional[float] = None
    # The endpoints above are a synthetic 198.18.0.0/15 pin for an fd-less
    # connection (see friTap.endpoint_pinner). observed_* hold the real tuple
    # when this record had one but the connection stays pinned.
    endpoints_synthetic: bool = False
    observed_src_addr: str = ""
    observed_src_port: int = 0
    observed_dst_addr: str = ""
    observed_dst_port: int = 0
    observed_ss_family: str = ""


@dataclass
class LibraryDetectedEvent(FriTapEvent):
    """Emitted when a TLS/SSL library is detected in the target process."""
    library: str = ""
    module: str = ""
    path: str = ""


@dataclass
class AntiTamperDetectedEvent(FriTapEvent):
    """An anti-tamper runtime (e.g. Google PairIP) was detected in the target.

    ``skipped_loader_hook`` is True when the inline android_dlopen_ext hook was skipped to avoid a SIGSEGV.
    """
    library: str = ""
    name: str = ""
    skipped_loader_hook: bool = False


# Heap memory-scan findings have no dedicated event: they are KeylogEvents tagged
# ``protocol="memscan"`` (label/client_random/secret/tier/source in ``payload``).

SESSION_STARTED = "started"
SESSION_RESUMED = "resumed"
SESSION_ENDED = "ended"
SESSION_DESTROYED = "destroyed"


@dataclass
class SessionEvent(FriTapEvent):
    """Emitted for SSL/TLS session lifecycle events."""
    session_id: str = ""
    event_type: str = ""  # SESSION_STARTED, SESSION_RESUMED, SESSION_ENDED, SESSION_DESTROYED
    cipher_suite: str = ""
    protocol_version: str = ""  # TLS version, e.g. "TLS 1.3"
    server_name: str = ""
    alpn: str = ""  # negotiated ALPN protocol ("h2", "http/1.1", ...)
    quic_version: str = ""  # QUIC only ("1", "2", ...)
    client_random: str = ""
    connection_id: str = ""
    src_addr: str = ""
    src_port: int = 0
    dst_addr: str = ""
    dst_port: int = 0

    @property
    def cipher(self) -> str:
        """Read-only alias for ``cipher_suite``."""
        return self.cipher_suite


@dataclass
class CallerStackEvent(FriTapEvent):
    """A connection's calling-thread backtrace, with its SDK when one matched (``--attribute-sdk``).

    The :class:`~friTap.flow.collector.FlowCollector` joins it onto the flow by
    ``client_random``, then the 4-tuple, then a real ``ssl_session_id``, and
    sets ``flow.sdk`` only when ``sdk`` is set. ``sdk`` is the trusted
    ``{"sdk", "vendor", "category"}`` dict from the bundled signature table
    (:mod:`friTap.analysis.attribution.sdk`), else ``None``.

    Frame strings come from the target (untrusted): they travel only under
    ``untrusted`` (``native_frames[:16]`` as ``{module, symbol}``,
    ``java_frames[:16]``) and as ``thread_name`` / ``transport_module``, escaped
    and capped at 120 characters. No key material or plaintext.
    """
    ssl_session_id: str = ""
    src_addr: str = ""
    src_port: int = 0
    dst_addr: str = ""
    dst_port: int = 0
    sdk: Optional[Dict[str, Any]] = None
    # Empty/0 when the agent could not read it. client_random is the join key.
    client_random: str = ""
    tid: int = 0
    thread_name: str = ""
    pid: int = 0
    transport_module: str = ""
    # Escaped, capped target strings (see friTap.caller_stack_shapes).
    untrusted: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RequestContextEvent(FriTapEvent):
    """One lifecycle point of a Java-level HTTP request (``--attribute-sdk``).

    ``timestamp`` is the host receive time (what the join compares); ``t_ms`` is the agent's
    clock, used only for ordering. Strings are escaped and capped by the router.
    """
    event: str = ""
    req_id: str = ""
    stack_kind: str = ""
    url: str = ""
    method: str = ""
    frames: List[str] = field(default_factory=list)
    thread: str = ""
    tid: Optional[int] = None
    t_ms: Optional[float] = None
    status: Optional[int] = None
    negotiated_protocol: str = ""
    cached: Optional[bool] = None
    error: str = ""
    webview_id: str = ""
    main_frame: Optional[bool] = None


@dataclass
class ConsoleEvent(FriTapEvent):
    """Console log message from the agent.

    ``origin`` is :data:`AGENT_DEV_ORIGIN` for developer diagnostics
    (``console_dev``, ``devlog_*``), which belong in debug output only.
    """
    message: str = ""
    level: str = "info"
    origin: str = ""


#: ConsoleEvent.origin of agent developer diagnostics (devlog / console_dev).
AGENT_DEV_ORIGIN = "agent_dev"


def is_agent_dev_console(event: FriTapEvent) -> bool:
    """True for a ConsoleEvent carrying an agent developer diagnostic."""
    return isinstance(event, ConsoleEvent) and event.origin == AGENT_DEV_ORIGIN


@dataclass
class HookBreadcrumbEvent(FriTapEvent):
    """Entry of a crash-prone hook walk; kept in memory so ``on_detach`` can name the last hook if the target dies.

    Best-effort: an in-flight breadcrumb may be lost on a hard crash.
    """
    marker: str = ""


@dataclass
class PlatformReportEvent(FriTapEvent):
    """Emitted once after the agent picked its platform branch (shows how far it got if the target dies).

    ``platform`` is the human label ("MacOS", "iOS"), ``target`` the internal
    kind ("macos", "ios"), ``probe`` echoes ``--probe`` (tells probe-aware
    bundles from old ones), ``abi`` is ``AGENT_ABI_VERSION``.
    """
    platform: str = ""
    target: str = ""
    probe: bool = False
    abi: int = 0


# ErrorEvent severities: control TUI modal vs activity-log routing.
ERROR_SEVERITY_INFO = "info"
ERROR_SEVERITY_WARNING = "warning"
ERROR_SEVERITY_ERROR = "error"
ERROR_SEVERITY_FATAL = "fatal"
ERROR_SEVERITIES = (
    ERROR_SEVERITY_INFO,
    ERROR_SEVERITY_WARNING,
    ERROR_SEVERITY_ERROR,
    ERROR_SEVERITY_FATAL,
)


@dataclass
class ErrorEvent(FriTapEvent):
    """Error in the agent or hooking pipeline.

    The TUI shows a blocking AlertModal for ``"error"``/``"fatal"`` and only logs
    ``"info"``/``"warning"``. Recovered parser failures are ``"warning"``,
    uncaught session exceptions ``"fatal"``.
    """
    error: str = ""
    description: str = ""
    stack: str = ""
    file: str = ""
    line: str = ""
    severity: str = ERROR_SEVERITY_WARNING


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
class DetachReportEvent(FriTapEvent):
    """The agent's graceful-detach report, emitted once just before outputs close.

    *report* is the DetachReport dict, or None (old bundle, dead target, failed
    RPC); *status* then says why (``timeout`` / ``failed`` / ``skipped``).
    """
    report: Optional[dict] = None
    status: Optional[str] = None


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


@dataclass
class LiveReadyEvent(FriTapEvent):
    """Emitted when live Wireshark FIFO is ready."""
    fifo_path: str = ""


@dataclass
class WiresharkConnectedEvent(FriTapEvent):
    """Emitted when Wireshark connects to the FIFO."""
    fifo_path: str = ""


@dataclass
class LiveConnectionFailedEvent(FriTapEvent):
    """Emitted when Wireshark fails to connect within the timeout."""
    fifo_path: str = ""
    reason: str = ""


@dataclass
class FlowEvent(FriTapEvent):
    """A flow was created, updated or completed (``flow_event_type`` is a :class:`~friTap.flow.models.FlowEventType` value)."""
    flow: Any = None  # friTap.flow.models.Flow
    flow_event_type: str = ""


@dataclass
class OhttpEvent(FriTapEvent):
    """Decrypted OHTTP bhttp payload from NSS HPKE hooks."""
    data: bytes = b""
    direction: str = ""  # "request" | "response"
    source: str = ""


@dataclass
class MessageEvent(FriTapEvent):
    """One fully decrypted and parsed chat message, live.

    The fields are a union of ``friTap.offline.signal.records.DecryptedMessage``,
    the ``SignalLayer`` per-message dict and ``...content.ParsedContent``.
    ``protocol`` is ``"signal"`` live; Telegram/MTProto is offline-only
    (``friTap.offline.pcap_to_tap.convert_pcap_to_tap``).
    """
    direction: str = ""          # "read" (server->client) | "write" (client->server)
    src_addr: str = ""
    src_port: int = 0
    dst_addr: str = ""
    dst_port: int = 0
    ss_family: str = "AF_INET"
    chat_type: str = ""          # "one_to_one" | "group" (Signal)
    identifier: str = ""         # eph_pub (1:1) or auth_tag (group) hex that decrypted it
    sender: str = ""             # sender UUID/E164 (1:1 best-effort), else ""
    kind: str = ""               # "data" | "receipt" | "typing" | "sync" | "unparsed"
    body: str = ""               # decoded chat text, else ""
    timestamp: int = 0           # DataMessage timestamp (ms), else 0
    has_attachments: bool = False
    has_quote: bool = False
    has_reaction: bool = False
    raw: bytes = b""             # inner Content protobuf bytes (padding stripped)


class EventBus:
    """Thread-safe publish-subscribe event bus.

    ``bus.subscribe(KeylogEvent, handler)`` / ``bus.emit(KeylogEvent(...))``.
    Higher *priority* runs first; plugins use ``PLUGIN_PRIORITY`` to run before built-in outputs.
    """

    MAX_HANDLER_FAILURES = 10
    PLUGIN_PRIORITY = 100

    def __init__(self, on_handler_error: Optional[Callable] = None) -> None:
        self._subscribers: Dict[Type[FriTapEvent], List[Tuple[int, Callable]]] = {}
        self._lock = threading.RLock()
        self._logger = logging.getLogger("friTap.events")
        self._failure_counts: Dict[str, int] = {}
        self._on_handler_error = on_handler_error

    def subscribe(self, event_type: Type[FriTapEvent], callback: Callable, *, priority: int = 0) -> None:
        """Call *callback* whenever *event_type* is emitted; higher *priority* (default 0) runs first."""
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
        """Dispatch *event* to its type's subscribers and to ``FriTapEvent`` catch-alls, by descending priority."""
        with self._lock:
            specific = self._subscribers.get(type(event), [])
            if type(event) is not FriTapEvent:
                catch_all = self._subscribers.get(FriTapEvent, [])
                if not catch_all:
                    # fast path
                    handlers = list(specific)
                else:
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

                count = self._failure_counts.get(handler_name, 0) + 1
                self._failure_counts[handler_name] = count

                if self._on_handler_error is not None:
                    try:
                        self._on_handler_error(cb, event, exc)
                    except Exception:
                        pass

                # Guard against recursion on ErrorEvent handlers.
                if not isinstance(event, ErrorEvent):
                    try:
                        self.emit(ErrorEvent(
                            error=f"Handler {handler_name} failed",
                            description=str(exc),
                            severity=ERROR_SEVERITY_ERROR,
                        ))
                    except Exception:
                        pass

                if count >= self.MAX_HANDLER_FAILURES:
                    self._logger.warning(
                        "Auto-unsubscribing handler %s after %d failures",
                        handler_name, count,
                    )
                    self._remove_handler(cb)

    def _remove_handler(self, cb: Callable) -> None:
        """Remove *cb* from every subscriber list."""
        with self._lock:
            for subs in self._subscribers.values():
                for i, (_p, c) in enumerate(subs):
                    if c is cb:
                        subs.pop(i)
                        break

    @property
    def handler_failures(self) -> Dict[str, int]:
        """Copy of the handler failure counts."""
        return dict(self._failure_counts)

    def clear(self) -> None:
        """Remove all subscribers."""
        with self._lock:
            self._subscribers.clear()
