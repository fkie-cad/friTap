"""Agent message intake for :class:`SSL_Logger`: the bounded Frida message queue,
the on_message wrapper, the consumer thread, routing and the event-bus callbacks.

The host class owns the state. Names tests patch on ``ssl_logger_core`` are read
through ``_core()`` at call time so the patches take effect.
"""

import os
import queue
import tempfile
import threading
import time
from collections import deque
from datetime import datetime

from ..agent_socket_fields import FILTERABLE_SS_FAMILIES, coerce_port, get_addr_string, resolve_ss_family
from ..events import AntiTamperDetectedEvent, HookBreadcrumbEvent, PlatformReportEvent, SocketTraceEvent
from ..text_safety import safe_terminal_text

# Breadcrumb the agent sends after its synchronous top-level init succeeded.
AGENT_INIT_COMPLETE_BREADCRUMB = "agent-init: complete"

# Frida message queue bounds. The count cap alone lets a hostile or runaway
# agent park MESSAGE_QUEUE_MAX_MESSAGES x payload size in this process, so
# queued payload bytes are budgeted too. Both caps drop and count instead of
# blocking: the Frida callback must never stall the target.
MESSAGE_QUEUE_MAX_MESSAGES = 10000
MESSAGE_QUEUE_MAX_BYTES = 256 * 1024 * 1024
MESSAGE_QUEUE_DROP_LOG_INTERVAL = 10.0


def _queued_message_size(item) -> int:
    """Approximate bytes of a queued ``(message, data)`` pair (shallow, so O(fields))."""
    message, data = item
    size = len(data) if isinstance(data, (bytes, bytearray, memoryview)) else 0
    payload = message.get("payload") if isinstance(message, dict) else None
    values = payload.values() if isinstance(payload, dict) else (payload,)
    for value in values:
        if isinstance(value, (str, bytes, bytearray)):
            size += len(value)
    return size


class ByteBudgetQueue(queue.Queue):
    """A :class:`queue.Queue` that also caps the total queued payload bytes.

    ``put`` raises :class:`queue.Full` at once when over budget, whatever ``block`` says:
    waiting would hold up Frida's message thread. The size recorded at enqueue is the one
    released at dequeue, so the total never drifts. Concurrent producers may overshoot by
    one message each.
    """

    def __init__(self, maxsize: int = 0, max_bytes: int = MESSAGE_QUEUE_MAX_BYTES):
        super().__init__(maxsize)
        self.max_bytes = max_bytes
        self.queued_bytes = 0
        self._item_sizes: deque = deque()

    def put(self, item, block=True, timeout=None):
        size = _queued_message_size(item)
        with self.mutex:
            over_budget = self.queued_bytes + size > self.max_bytes
        if over_budget:
            raise queue.Full
        super().put(item, block, timeout)

    # _put / _get run under self.mutex (queue.Queue contract).
    def _put(self, item):
        size = _queued_message_size(item)
        super()._put(item)
        self._item_sizes.append(size)
        self.queued_bytes += size

    def _get(self):
        item = super()._get()
        self.queued_bytes -= self._item_sizes.popleft()
        return item


class AgentMessagesMixin:
    """Frida message intake, the consumer thread and agent-message routing."""

    def _on_library_detected(self, event):
        """Track detected libraries (for the exit hint); under ``--protocol auto`` switch the
        protocol handler to the first non-TLS match so key formatting and PCAP DLT fit."""
        lib_name = event.library
        if lib_name and lib_name not in self._detected_libraries:
            self._detected_libraries.add(lib_name)
            self.logger.debug("Library detected — %s (protocol=%s, path=%s)", lib_name, event.protocol,
                              getattr(event, "path", "") or "-")

            # Only switch protocol handler when in auto-detect / install-everything mode
            if self._config.protocol in ("auto", "all"):
                matched = self._protocol_registry.auto_detect(list(self._detected_libraries))
                if matched and matched[0].name != self._protocol_handler.name:
                    self._protocol_handler = matched[0]
                    self.logger.info("Auto-detect: switched protocol handler to %s", self._protocol_handler.name)

    def _on_keylog_captured(self, event):
        """Note that a key was captured (any source).

        Suppresses the misleading "No <PROTO> libraries were detected" exit hint for paths
        that emit no LibraryDetectedEvent (Java Secret-Chat/E2E hooks, the memory-scan engine).
        """
        self._captured_any_secret = True

    _captured_any_data = False

    def _on_traffic_captured(self, event):
        """Note that plaintext was captured."""
        self._captured_any_data = True

    def _capture_produced_output(self) -> bool:
        """True once the capture produced keys or plaintext, so a target ending now did its work."""
        return self.capture_started() and (
            getattr(self, "_captured_any_secret", False) or self._captured_any_data)

    def _on_hook_breadcrumb(self, event: "HookBreadcrumbEvent") -> None:
        """Remember the last hook the agent reported entering (crash attribution)."""
        if event.marker:
            self._last_hook_breadcrumb = event.marker
            if event.marker == AGENT_INIT_COMPLETE_BREADCRUMB:
                self._agent_init_complete = True

    def _on_platform_report(self, event: "PlatformReportEvent") -> None:
        """Log the platform branch the agent selected and ack it for probe mode.

        Logged at INFO regardless of -v/--debugoutput: which platform path ran is the first
        question in any instrumentation-crash report.
        """
        self._platform_report = event
        self.logger.info(
            "Agent platform report: %s (target=%s, agent ABI %s)",
            event.platform or "unknown platform",
            event.target or "unknown",
            event.abi,
        )
        self._platform_report_received.set()

    def wait_for_platform_report(self, timeout: float = 3.0) -> bool:
        """Block up to *timeout* seconds; True when the report arrived (possibly earlier), False on timeout.

        The report is routed on the consumer thread, so one sent during ``script.load()``
        may land slightly after instrumentation returns.
        """
        return self._platform_report_received.wait(timeout)

    def _on_anti_tamper_detected(self, event: "AntiTamperDetectedEvent") -> None:
        """Remember a detected anti-tamper runtime so a later process-terminated crash can be attributed to it."""
        self._anti_tamper_seen = event.name or event.library or "anti-tamper protection"

    def _to_datetime(self, ts):
        # Accepts epoch seconds, epoch milliseconds (> 1e12) or an ISO string.
        if ts is None:
            return None
        try:
            if isinstance(ts, (int, float)):
                if ts > 1e12:
                    return datetime.fromtimestamp(ts / 1000.0)
                if ts > 1e9:
                    return datetime.fromtimestamp(ts)
            return datetime.fromisoformat(str(ts))
        except Exception:
            return None

    def _short_file(self, path: str | None) -> str | None:
        if not path:
            return None
        p = str(path)
        # Frida sometimes reports URL-style paths.
        for pref in ("frida://", "file://"):
            if p.startswith(pref):
                p = p[len(pref):]
        return os.path.basename(p) or p

    def print_fritap_message(self, message: dict, data: bytes):
        from ..error_handler import ScriptErrorHandler
        ScriptErrorHandler.format_fritap_message(
            message, data, self.LEVEL_MAP,
            self._to_datetime, self._short_file, self.logger
        )

    def handle_frida_script_error(self, message: dict):
        from ..error_handler import ScriptErrorHandler
        ScriptErrorHandler.handle(
            message, self._event_bus, self.session_data,
            self._session_data_lock, self.json_output, self.debug_output, self.logger,
            fatal=self._is_fatal_script_error(message),
        )

    def _is_fatal_script_error(self, message: dict) -> bool:
        """Does this Frida ``error`` message leave the agent unable to work?

        Fatal: an error before init finished (handshake open or no ``agent-init: complete``
        breadcrumb; a fatal init stage rethrows to the top level) or one flagged ``fatal``.
        After init, errors come from deferred callbacks (Java.perform, setTimeout, hooks) and
        the script keeps running; ending the run would detach mid-hook-install and risk
        crashing the target.
        """
        if message.get("fatal") is True:
            return True
        if getattr(self, "startup", False):
            return True
        return not getattr(self, "_agent_init_complete", False)

    def temp_fifo(self):
        self.tmpdir = tempfile.mkdtemp()
        self.filename = os.path.join(self.tmpdir, 'fritap_sharkfin')
        try:
            os.mkfifo(self.filename)
        except OSError as e:
            self.logger.error(f'Failed to create FIFO: {e}')
            return None
        return self.filename

    # Agent payload fields the console handlers (EventBus sink, legacy handler) print verbatim.
    _AGENT_CONSOLE_FIELDS = ("console", "console_dev")

    @classmethod
    def _neutralize_console_text(cls, payload: dict) -> None:
        """Escape terminal control sequences in agent console text in place (untrusted agent output)."""
        for field in cls._AGENT_CONSOLE_FIELDS:
            if field in payload:
                payload[field] = safe_terminal_text(payload[field])

    @staticmethod
    def _validated_socket_fields(payload: dict):
        """Validated ``(src, src_port, dst, dst_port, family)``; ``None`` for non-IP families
        (e.g. AF_UNIX) or a missing/malformed address, which must not become filter hosts."""
        family, addr_family = resolve_ss_family(payload.get("ss_family"))
        if addr_family not in FILTERABLE_SS_FAMILIES:
            return None
        src_addr = get_addr_string(payload.get("src_addr"), family)
        dst_addr = get_addr_string(payload.get("dst_addr"), family)
        if not src_addr or not dst_addr:
            return None
        return (src_addr, coerce_port(payload.get("src_port")),
                dst_addr, coerce_port(payload.get("dst_port")), family)

    def _track_traced_socket(self, payload: dict) -> None:
        """Record a socket for --socket_tracing / --full_capture (cleanup() builds BPF and display filters from them)."""
        fields = self._validated_socket_fields(payload)
        if fields is None:
            return
        src_addr, src_port, dst_addr, dst_port, family = fields
        host_pair = frozenset({
            "src_addr": src_addr, "dst_addr": dst_addr, "ss_family": family
        }.items())
        if self.full_capture:
            self.traced_scapy_socket_Set.add(host_pair)
        if self.socket_trace:
            self._event_bus.emit(SocketTraceEvent(
                src_addr=src_addr,
                src_port=src_port,
                dst_addr=dst_addr,
                dst_port=dst_port,
                ss_family=family,
            ))
            self.traced_Socket_Set.add(frozenset({
                "src_addr": src_addr, "dst_addr": dst_addr,
                "src_port": src_port, "dst_port": dst_port,
                "ss_family": family
            }.items()))
            self.traced_scapy_socket_Set.add(host_pair)

    def on_fritap_message(self, job, message, data):
        """Handle an error or message sent by the injected agent script.

        See https://www.frida.re/docs/messages/. ``data`` is the captured plaintext or key
        bytes. Also the entry point for AndroidFridaManager's JobManager (``job``).
        """

        """
        This offers the possibility to work with the JobManger() from the AndroidFridaManager project.
        """
        if self.script is None and job is not None:
            self.script = job.script

        msg_type = message.get('type')

        if msg_type == 'error':
            self.handle_frida_script_error(message)
            return

        if msg_type != 'send':
            return

        payload = message.get('payload')

        # Startup handshake: the agent blocks in recv().wait() until answered.
        # Normally answered on the Frida callback thread (_internal_callback_wrapper);
        # this path serves AndroidFridaManager, whose own_message_handler forwards here.
        if isinstance(payload, str):
            if self._answer_startup_handshake(payload, getattr(job, 'script', None)):
                return

        if not isinstance(payload, dict) or "contentType" not in payload:
            return

        self._neutralize_console_text(payload)

        self._emit_event_from_payload(payload, data)

        if self._handlers_active:
            if (self.socket_trace or self.full_capture) and "src_addr" in payload:
                self._track_traced_socket(payload)
            return  # Output handlers process events via EventBus

        # Legacy path: inline output handling
        from .message_handler import handle_message_legacy
        handle_message_legacy(self, payload, data, message)

    def _emit_event_from_payload(self, payload: dict, data: bytes) -> None:
        """Parse an agent message payload and emit the corresponding event."""
        self._message_router.route(payload, data)

    def _start_consumer_thread(self):
        """Start background thread that drains the message queue."""
        if self._consumer_thread is not None:
            return
        self._consumer_stop.clear()
        self._consumer_thread = threading.Thread(
            target=self._consume_messages, daemon=True, name="fritap-msg-consumer"
        )
        self._consumer_thread.start()

    def _emit_router_error(self, exc: Exception, where: str) -> None:
        """Emit an ErrorEvent for a routing error so the TUI activity log and other subscribers see it; never raises."""
        try:
            import traceback as _tb

            from friTap.events import ERROR_SEVERITY_ERROR, ErrorEvent
            self._event_bus.emit(ErrorEvent(
                error=f"{type(exc).__name__} in message router ({where})",
                description=str(exc),
                stack="".join(_tb.format_exception(type(exc), exc, exc.__traceback__)),
                severity=ERROR_SEVERITY_ERROR,
            ))
        except Exception:
            self.logger.debug("Failed to emit router ErrorEvent", exc_info=True)

    def _consume_messages(self):
        """Process queued Frida messages on a dedicated thread.

        Keeps the Frida callback thread free (instant put_nowait); the 0.1 s timeout gives the TUI thread fair GIL access.
        """
        while not self._consumer_stop.is_set():
            try:
                message, data = self._message_queue.get(timeout=0.1)
            except queue.Empty:
                continue
            try:
                self.on_fritap_message(None, message, data)
            except Exception as exc:
                # logger.exception keeps the traceback in the debug log; the
                # ErrorEvent surfaces the failure in the TUI activity log.
                self.logger.exception("Error processing queued frida message")
                self._emit_router_error(exc, "consume")

    def _drain_message_queue(self):
        """Process all remaining queued messages before PCAP is closed."""
        drained = 0
        while True:
            try:
                message, data = self._message_queue.get_nowait()
            except queue.Empty:
                break
            try:
                self.on_fritap_message(None, message, data)
                drained += 1
            except Exception as exc:
                self.logger.exception("Error draining queued frida message")
                self._emit_router_error(exc, "drain")
        if drained and (self.debug_output or self.debug):
            self.logger.debug("Drained %d queued messages before cleanup", drained)
        if self._queue_drop_count:
            self.logger.warning(
                "Message queue overflow: %d messages dropped during capture",
                self._queue_drop_count,
            )

    def _stop_consumer_thread(self):
        """Signal the consumer thread to stop and wait for it."""
        self._consumer_stop.set()
        if self._consumer_thread is not None:
            self._consumer_thread.join(timeout=5)
            self._consumer_thread = None
        self._drain_message_queue()

    def _provide_custom_hooking_handler(self, handler):
        return handler

    def _internal_callback_wrapper(self, script=None):
        """Build the Frida on_message handler for ``script``.

        ``script`` is captured so a handshake is answered on the script that asked; a child
        agent is never ``self.script`` (the main target's).
        """
        def wrapped_handler(message, data):
            # Answer the startup handshake here on the Frida callback thread, never
            # via the queue. The agent blocks in recv().wait() inside script.load(),
            # so queueing would deadlock when the load() thread is the one draining
            # the queue, and the reply would be dropped if the queue were full.
            if isinstance(message, dict) and message.get('type') == 'send':
                payload = message.get('payload')
                if isinstance(payload, str):
                    try:
                        if self._answer_startup_handshake(payload, script):
                            return
                    except Exception:
                        # A dead script or closed session must not kill Frida's
                        # callback thread; the load times out and is reported.
                        self.logger.exception("Failed to answer startup handshake")
                        return

            # Everything else is only enqueued: return from the callback thread
            # fast to avoid GIL contention that starves the TUI thread.
            try:
                self._message_queue.put_nowait((message, data))
            except queue.Full:
                self._record_queue_drop()

        return wrapped_handler

    def _record_queue_drop(self) -> None:
        """Count a message dropped at the full queue and log the total at most once per MESSAGE_QUEUE_DROP_LOG_INTERVAL.

        Runs on Frida's callback thread: no blocking, no Frida calls.
        """
        self._queue_drop_count += 1
        now = time.monotonic()
        last = getattr(self, "_queue_drop_logged_at", 0.0)
        if last and now - last < MESSAGE_QUEUE_DROP_LOG_INTERVAL:
            return
        self._queue_drop_logged_at = now
        reported = getattr(self, "_queue_drops_reported", 0)
        self._queue_drops_reported = self._queue_drop_count
        self.logger.warning(
            "Agent message queue full (%d messages / %d MiB cap): dropped %d "
            "message(s) since the last report, %d in total.",
            MESSAGE_QUEUE_MAX_MESSAGES, MESSAGE_QUEUE_MAX_BYTES // (1024 * 1024),
            self._queue_drop_count - reported, self._queue_drop_count)
