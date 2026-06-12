#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from ..backends.base import BackendName, ScriptRuntime
import tempfile
import os
import struct
import socket
import time
import json
import threading
import queue
import logging
from datetime import datetime, timezone
from ..pcap import PCAP
from ..fritap_utility import setup_fritap_logging
from ..about import __version__
from ..events import (
    EventBus,
    SessionEvent,
    SocketTraceEvent,
    DetachEvent,
    LibraryDetectedEvent,
    InstrumentEvent,
    ScriptLoadedEvent,
    HookBreadcrumbEvent,
)
from ..config import FriTapConfig
from ..constants import SSL_READ, SSL_WRITE
from dataclasses import dataclass
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


@dataclass(slots=True)
class _ChildAddedSentinel:
    """Internal sentinel queued by on_child_added for the consumer thread."""
    child: object


try:
    import hexdump  # pylint: disable=g-import-not-at-top
except ImportError:
    # Will be handled by logger later
    hexdump = None

# here - where we are.
here = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

class SSL_Logger():

    LEVEL_MAP = {
        "debug": logging.DEBUG,
        "info": logging.INFO,
        "warn": logging.WARNING,
        "warning": logging.WARNING,
        "error": logging.ERROR,
        "critical": logging.CRITICAL,
        # fallback
        "trace": logging.DEBUG,
    }

    def __init__(self, app=None, pcap_name=None, verbose=False, spawn=False, keylog=False, enable_spawn_gating=False, spawn_gating_all=False, enable_child_gating=False, mobile=False, live=False, environment_file=None, debug_mode=False,full_capture=False, socket_trace=False, host=False, offsets=None, debug_output=False, experimental=False, anti_root=False, payload_modification=False,enable_default_fd=False, patterns=None, custom_hook_script=None, json_output=None, install_lsass_hook=True, timeout=None, config: "FriTapConfig | None" = None):
        # Build or accept a FriTapConfig
        if config is not None:
            self._config = config
        elif app is not None:
            self._config = FriTapConfig.from_legacy_params(
                app=app, pcap_name=pcap_name, verbose=verbose, spawn=spawn,
                keylog=keylog, enable_spawn_gating=enable_spawn_gating,
                spawn_gating_all=spawn_gating_all, enable_child_gating=enable_child_gating,
                mobile=mobile, live=live, environment_file=environment_file,
                debug_mode=debug_mode, full_capture=full_capture, socket_trace=socket_trace,
                host=host, offsets=offsets, debug_output=debug_output,
                experimental=experimental, anti_root=anti_root,
                payload_modification=payload_modification, enable_default_fd=enable_default_fd,
                patterns=patterns, custom_hook_script=custom_hook_script,
                json_output=json_output, install_lsass_hook=install_lsass_hook,
                timeout=timeout,
            )
        else:
            raise ValueError("Either 'app' or 'config' must be provided")

        self._cleanup_done = False
        self._tui_mode = False

        # Set up logging (shared helper fixes bug where special_logger was hardcoded to INFO)
        self.logger, self.special_logger = setup_fritap_logging(
            debug=self._config.debug, debug_output=self._config.debug_output
        )

        # Check for hexdump availability
        if hexdump is None:
            self.logger.warning("Unable to import hexdump module! Hexdump functionality will be disabled.")

        # Runtime state (mutable, not config)
        self.pcap_obj = None
        self.script = None
        self.own_message_handler = None
        self.running = True
        self._done_event = threading.Event()

        # Message queue: decouples Frida callback from processing to prevent
        # GIL contention that freezes the TUI under high message rates.
        self._message_queue: queue.Queue = queue.Queue(maxsize=10000)
        self._consumer_stop = threading.Event()
        self._consumer_thread: threading.Thread | None = None
        self._queue_drop_count = 0
        self.target_threads = None
        self.tmpdir = None
        self.filename = ""
        self.startup = True
        self.process = None
        self.device = None
        self.keylog_file = None
        self.json_file = None
        self.offsets_data = None
        self.pattern_data = None
        self.scan_results_data = None
        self._observer = None
        self._proxy_redirector = None
        self._last_runtime = ScriptRuntime.QJS
        self._session_data_lock = threading.Lock()
        self.keydump_Set = set()
        self.traced_Socket_Set = set()
        self.traced_scapy_socket_Set = set()
        self._live_handler = None

        # Event bus for decoupled event handling
        self._event_bus = EventBus()
        self._output_handlers = []
        self._handlers_active = False
        from ..backends import get_backend
        self._backend = get_backend(self._config.backend)

        # Protocol registry and handler. ``auto`` keeps every built-in
        # registered so the agent can swap on LibraryDetectedEvent; an
        # explicit selection narrows the registry to just that handler so
        # we don't load hooks the user didn't ask for.
        from ..protocols.registry import create_default_registry
        # "all" and "auto" are UX twins per the CLI: same hooks installed,
        # only the user-confirmation differs. Both build the full registry
        # so any subsequent LibraryDetectedEvent can swap the active handler.
        if self._config.protocol in ("auto", "all"):
            self._protocol_registry = create_default_registry()
            self._detected_libraries = set()  # tracks libraries detected by agent
            # Start with TLS as default; will be refined via LibraryDetectedEvent
            self._protocol_handler = self._protocol_registry.get("tls") \
                or next(iter(self._protocol_registry.get_all()), None)
        else:
            self._protocol_registry = create_default_registry([self._config.protocol])
            self._detected_libraries = set()
            self._protocol_handler = self._protocol_registry.get(self._config.protocol)
            if self._protocol_handler is None:
                raise RuntimeError(
                    f"Protocol '{self._config.protocol}' is not registered; "
                    "available: " + ", ".join(self._protocol_registry.list_protocols())
                )

        # Validate protocol-backend compatibility
        self._config.validate_protocol_backend(self._protocol_handler)

        # Session manager (extracted for file length management)
        from .session_manager import SessionManager
        self._session_manager = SessionManager(self)

        # Message router (extracted for file length management)
        from ..message_router import MessageRouter
        self._message_router = MessageRouter(self._event_bus)

        # Wire display filter if configured
        if self._config.output.filter_expression:
            try:
                from ..filter import FilterEngine
                self._message_router.set_filter(
                    FilterEngine(self._config.output.filter_expression)
                )
                self.logger.info(
                    "Display filter active: %s",
                    self._config.output.filter_expression,
                )
            except Exception as e:
                self.logger.warning("Invalid filter expression: %s", e)

        # Always track detected libraries (needed for exit hint message)
        self._event_bus.subscribe(LibraryDetectedEvent, self._on_library_detected)

        # Crash attribution: remember the last hook the agent reported entering,
        # so on_detach can name it if the target dies inside a hook. Stored in
        # memory only — never printed (works regardless of -v).
        self._last_hook_breadcrumb = ""
        self._crash_reported = False
        self._event_bus.subscribe(HookBreadcrumbEvent, self._on_hook_breadcrumb)

        # FlowCollector created lazily — only when a plugin or TUI accesses it.
        # The TUI creates its own FlowCollector in capture_controller.py.
        self._flow_collector = None

        # Live passive-analysis ("scan") state. Populated by _setup_live_scan()
        # only when --scan is requested. Completed flows are enqueued onto a
        # bounded queue and drained by a daemon worker thread so analyzers never
        # run on the Frida callback thread.
        self._scan_plugins = []
        self._scan_queue = None
        self._scan_thread = None
        self._scan_stop = threading.Event()
        self._scan_drop_count = 0

        # JSON session data
        self.session_data = {
            "friTap_version": __version__,
            "session_info": {
                "start_time": datetime.now(timezone.utc).isoformat(),
                "target_app": self._config.target,
                "mobile": self._config.device.mobile,
                "spawn": self._config.device.spawn,
                "verbose": self._config.output.verbose,
                "live": self._config.output.live,
                "debug": self._config.debug
            },
            "ssl_sessions": [],
            "connections": [],
            "key_extractions": [],
            "errors": [],
            "statistics": {
                "total_sessions": 0,
                "total_connections": 0,
                "total_bytes_captured": 0,
                "libraries_detected": []
            }
        }

        self.init_fritap()

    # ---------------------------------------------------------------
    # Config property accessors (backward-compatible attribute access)
    # ---------------------------------------------------------------

    @property
    def debug(self) -> bool:
        return self._config.debug

    @property
    def debug_output(self) -> bool:
        return self._config.debug_output

    @property
    def anti_root(self) -> bool:
        return self._config.hooking.anti_root

    @property
    def pcap_name(self):
        return self._config.output.pcap

    @property
    def device_id(self):
        return self._config.device.device_id

    @property
    def mobile(self):
        return self._config.device.mobile

    @property
    def full_capture(self) -> bool:
        return self._config.output.full_capture

    @property
    def target_app(self) -> str:
        return self._config.target

    @property
    def verbose(self) -> bool:
        return self._config.output.verbose

    @property
    def spawn(self) -> bool:
        return self._config.device.spawn

    @property
    def socket_trace(self):
        return self._config.output.socket_trace

    @property
    def keylog(self):
        return self._config.output.keylog

    @property
    def offsets(self):
        return self._config.hooking.offsets

    @property
    def environment_file(self):
        return self._config.environment_file

    @property
    def host(self):
        return self._config.device.host or False

    @property
    def enable_spawn_gating(self) -> bool:
        return self._config.device.enable_spawn_gating

    @property
    def spawn_gating_all(self) -> bool:
        return self._config.device.spawn_gating_all

    @property
    def enable_child_gating(self) -> bool:
        return self._config.device.enable_child_gating

    @property
    def live(self) -> bool:
        return self._config.output.live

    @property
    def payload_modification(self) -> bool:
        return self._config.hooking.payload_modification

    @property
    def enable_default_fd(self) -> bool:
        return self._config.hooking.enable_default_fd

    @property
    def experimental(self) -> bool:
        return self._config.hooking.experimental

    @property
    def custom_hook_script(self):
        return self._config.custom_hook_script

    @property
    def json_output(self):
        return self._config.output.json_output

    @property
    def install_lsass_hook(self) -> bool:
        return self._config.install_lsass_hook

    @property
    def timeout(self):
        return self._config.device.timeout

    @property
    def protocol(self) -> str:
        return self._config.protocol

    @property
    def patterns(self):
        return self._config.hooking.patterns

    def _on_library_detected(self, event):
        """Handle library detection events.

        Always tracks detected libraries (for exit hint). When
        ``--protocol auto`` is active, the first non-TLS protocol
        detected (e.g. IPSec, SSH) causes the protocol handler to be
        switched so that key formatting and PCAP DLT are appropriate.
        """
        lib_name = event.library
        if lib_name and lib_name not in self._detected_libraries:
            self._detected_libraries.add(lib_name)
            self.logger.debug("Library detected — %s (protocol=%s)", lib_name, event.protocol)

            # Only switch protocol handler when in auto-detect / install-everything mode
            if self._config.protocol in ("auto", "all"):
                matched = self._protocol_registry.auto_detect(list(self._detected_libraries))
                if matched and matched[0].name != self._protocol_handler.name:
                    self._protocol_handler = matched[0]
                    self.logger.info("Auto-detect: switched protocol handler to %s", self._protocol_handler.name)



    def init_fritap(self):
        self.agent_script = "fritap_agent.js"

        if self.pcap_name:
            self.pcap_obj =  PCAP(self.pcap_name,SSL_READ,SSL_WRITE,self.full_capture, self.mobile,self.debug_output)

        if self.offsets is not None:
            try:
                with open(self.offsets, "r") as offset_file:
                    self.offsets_data = offset_file.read()
            except FileNotFoundError:
                try:
                    json.loads(self.offsets)
                    self.offsets_data = self.offsets
                except ValueError as e:
                    self.logger.error(f"Log error, defaulting to auto-detection: {e}")

        self.load_patterns()

        if self._config.hooking.library_scan:
            if self._config.device.spawn:
                self.logger.info("Library scan skipped in spawn mode (process not yet running)")
            else:
                from ..inspector import LibraryInspector
                scan_results = LibraryInspector.scan_to_dicts(self._config, self.logger)
                if scan_results:
                    self._apply_sibling_coverage_suppression(scan_results)
                    self.scan_results_data = json.dumps(scan_results)
                    self.logger.info("Library scanner found %d TLS libraries", len(scan_results))
                    for lib in scan_results:
                        self.logger.info("  [%s] %s (%s)", lib["library_type"], lib["name"],
                                         lib.get("detected_version") or "unknown version")

        # Resolve protocol processor and agent script for non-Frida backends
        self._processor = None
        self._agent_script_path = None
        if self._config.backend != BackendName.FRIDA:
            processor_cls = self._protocol_registry.get_processor(self._config.protocol)
            if processor_cls is not None:
                self._processor = processor_cls(event_bus=self._event_bus)
            self._agent_script_path = self._protocol_registry.get_agent_script_path(
                self._config.protocol, self._config.backend
            )

        # Set up output handlers (new modular path)
        self._setup_output_handlers()
        self._handlers_active = True

    def _setup_output_handlers(self):
        """Create and register output handlers based on config."""
        from ..output.factory import OutputHandlerFactory
        self._output_handlers, live_info = OutputHandlerFactory.create_handlers(
            self._config, self.pcap_obj, self._protocol_handler,
            self.session_data, self.logger,
            protocol_registry=self._protocol_registry,
        )
        if live_info:
            self.tmpdir = live_info.get('tmpdir')
            self.filename = live_info.get('filename')

        # Setup handlers on event bus (non-blocking for live handler)
        from ..output import KeylogOutputHandler
        from ..output.live_pcapng_handler import LivePcapngHandler
        from ..output.live_autodecrypt_handler import LiveAutoDecryptHandler
        from ..output.live_wireshark_handler import LiveWiresharkHandler
        for handler in self._output_handlers:
            handler.setup(self._event_bus)
            if isinstance(handler, KeylogOutputHandler):
                self.keylog_file = handler._file
                # Propagate the keylog file path into the pcap object so the
                # capture manifest ('keylog' branch in PCAP._write_capture_manifest)
                # is actually populated; PCAP.keylog_path is otherwise never set.
                if self.pcap_obj is not None:
                    self.pcap_obj.keylog_path = handler._path
            if isinstance(handler, (LivePcapngHandler, LiveAutoDecryptHandler, LiveWiresharkHandler)):
                self._live_handler = handler

        # Load plugins
        from ..plugins.loader import PluginLoader
        self._plugin_loader = PluginLoader()
        self._plugin_shim = _PluginSessionShim(self._event_bus)
        self._plugin_loader.load_all(self._plugin_shim)

        # Register legacy --custom_script as a ScriptPlugin
        if self.custom_hook_script is not None:
            from ..plugins.legacy_custom_script import LegacyCustomScriptPlugin
            legacy_plugin = LegacyCustomScriptPlugin(self.custom_hook_script)
            self._plugin_loader.register_builtin(legacy_plugin, self._plugin_shim)


    def _on_hook_breadcrumb(self, event: "HookBreadcrumbEvent") -> None:
        """Remember the last hook the agent reported entering (crash attribution)."""
        if event.marker:
            self._last_hook_breadcrumb = event.marker

    def _report_target_crash(self, reason: str) -> None:
        """Surface an unexpected target-process death clearly to the user.

        A crash inside an instrumented hook (native SIGSEGV) reaches us as a
        detach with reason ``process-terminated`` and otherwise only as a
        cryptic "Backend transport error: the connection is closed". Make it
        explicit, attribute it to the last hook breadcrumb when known, and point
        at the debug log. Sets a flag so the synchronous transport-error handler
        does not also print the cryptic line.
        """
        self._crash_reported = True
        crumb = self._last_hook_breadcrumb
        msg = "Target process terminated unexpectedly — it most likely crashed " \
              "inside an instrumented hook"
        if crumb:
            msg += f" (last hook entered: {crumb})"
        self.logger.error(msg)
        try:
            from ..fritap_utility import get_debug_log_path
            log_path = get_debug_log_path()
            if log_path:
                self.logger.error(f"See the debug log for the last hook activity: {log_path}")
        except Exception:
            pass
        try:
            from ..events import ErrorEvent, ERROR_SEVERITY_FATAL
            self._event_bus.emit(ErrorEvent(
                error="Target process crashed",
                description=msg,
                severity=ERROR_SEVERITY_FATAL,
            ))
        except Exception:
            pass

    def on_detach(self, reason):
        if not self.running:
            return

        if reason == "application-requested":
            return

        # A native crash inside a hook arrives as 'process-terminated'. Make it
        # explicit instead of letting it surface only as a transport error.
        if reason == "process-terminated":
            self._report_target_crash(reason)

        self._event_bus.emit(DetachEvent(reason=reason))

        # Notify script plugins of detach
        if hasattr(self, '_plugin_loader') and self.process and self.device:
            from ..plugins.script_context import ScriptContext
            detach_ctx = ScriptContext(
                backend=self._backend, process=self.process, device=self.device,
                runtime=getattr(self, '_last_runtime', ScriptRuntime.QJS),
                event_bus=self._event_bus, backend_name=self._backend.name,
                debug=self.debug, debug_output=self.debug_output,
            )
            self._plugin_loader.detach_all(detach_ctx)

        self.logger.info(f"Target process stopped: {reason}")
        self._log_session_end(reason)
        self.pcap_cleanup(self.full_capture,self.mobile,self.pcap_name)
        self.cleanup(self.live,self.socket_trace,self.full_capture,self.debug_output)

    def _to_datetime(self, ts):
        # support numeric timestamp (seconds or millis) or iso string
        if ts is None:
            return None
        try:
            # if float/int — detect likely ms vs s
            if isinstance(ts, (int, float)):
                # if ts looks like milliseconds (>= 1e12 typical for ms), convert
                if ts > 1e12:
                    return datetime.fromtimestamp(ts / 1000.0)
                # if ts looks like seconds (reasonable range)
                if ts > 1e9:  # seconds since epoch
                    return datetime.fromtimestamp(ts)
            # fallback: try parse ISO string
            return datetime.fromisoformat(str(ts))
        except Exception:
            return None

    def _short_file(self, path: str | None) -> str | None:
        if not path:
            return None
        p = str(path)
        # strip url-ish prefixes frida sometimes uses
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
            self._session_data_lock, self.json_output, self.debug_output, self.logger
        )

    def temp_fifo(self):
        self.tmpdir = tempfile.mkdtemp()
        self.filename = os.path.join(self.tmpdir, 'fritap_sharkfin')  # Temporary filename
        try:
            os.mkfifo(self.filename)  # Create FIFO
        except OSError as e:
            self.logger.error(f'Failed to create FIFO: {e}')
            return None
        return self.filename


    def on_fritap_message(self, job, message, data):
        """Callback for errors and messages sent from injected agent script.
        Logs captured packet data received from JavaScript to the console and/or a
        pcap file. See https://www.frida.re/docs/messages/ for more detail on
        the message protocol.
        Args:
        message: A dictionary containing the message "type" and other fields
            dependent on message type.
        data: The string of captured decrypted data or the caputured decryption keys
        """


        """
        This offers the possibility to work with the JobManger() from the AndroidFridaManager project.
        """
        if self.script is None:
            self.script = job.script

        msg_type = message.get('type')

        if msg_type == 'error':
            self.handle_frida_script_error(message)
            return

        if msg_type != 'send':
            return

        payload = message.get('payload')

        # Startup handshake: agent requests config values one by one
        if self.startup and isinstance(payload, str):
            if payload == 'config_batch':
                batch = {
                    'offsets': self.offsets_data,
                    'patterns': self.pattern_data,
                    'socket_tracing': self.socket_trace,
                    'defaultFD': self.enable_default_fd,
                    'experimental': self.experimental,
                    'protocol_select': self.protocol,
                    'install_lsass_hook': self.install_lsass_hook,
                    'use_modern': getattr(self, 'use_modern', False),
                    'library_scan': self.scan_results_data,
                    'library_scan_enabled': self._config.hooking.library_scan,
                    'ohttp_enabled': getattr(self._config.hooking, 'ohttp_enabled', True),
                    'quic_capture_mode': getattr(self._config.hooking, 'quic_capture_mode', 'stream'),
                    'quic_only': getattr(self._config.hooking, 'quic_only', False),
                    # Override for the HTTP/3 egress-headers chain layer. "auto" keeps
                    # the winner-takes-all fallback; anything else forces a specific
                    # layer so chain validation tests can exercise lower tiers on
                    # builds where the primary layer would otherwise always win.
                    'quic_egress_headers_layer': getattr(self._config.hooking, 'quic_egress_headers_layer', 'auto'),
                    # Mirrors the -do / --debugoutput CLI flag so the agent can
                    # cheaply skip expensive debug-only enumeration (e.g. listing all
                    # symbol-table candidates for a chain label) when the user did
                    # not ask for debug output. Without this gate every attach would
                    # walk the full Cronet/libmonochrome dynsym (~hundreds of MB).
                    'debug_output': bool(getattr(self._config, 'debug_output', False)),
                    # In full-capture (-f) mode the raw packets are taken by the external
                    # tcpdump/scapy thread and the in-agent plaintext datalog is discarded
                    # by message_handler (`... and not full_capture`), so don't install the
                    # plaintext read/write hooks at all — only the key-extraction hooks run.
                    'pcap_enabled': bool(self.pcap_name) and not self.full_capture,
                    # Symmetric counterpart to pcap_enabled. When the user requested only -p
                    # (plaintext pcap) without -k, the agent must skip every key-extraction
                    # path — otherwise it floods the channel with KeylogEvents and burns
                    # the pattern-scan budget on connections we don't care about. In -f mode
                    # this stays driven by -k: keys are needed to decrypt the full capture.
                    'keylog_enabled': bool(self.keylog),
                }
                self._backend.post_message(self.script, 'config_batch', batch)
                return
            from .message_handler import handle_startup_legacy
            handle_startup_legacy(self, payload)

        if not isinstance(payload, dict) or "contentType" not in payload:
            return

        # Emit events through the event bus for all content types
        self._emit_event_from_payload(payload, data)

        if self._handlers_active:
            # Socket trace / full capture set tracking (consumed by cleanup())
            if (self.socket_trace or self.full_capture) and "src_addr" in payload:
                src_addr = get_addr_string(payload["src_addr"], payload["ss_family"])
                dst_addr = get_addr_string(payload["dst_addr"], payload["ss_family"])
                if self.full_capture:
                    self.traced_scapy_socket_Set.add(frozenset({
                        "src_addr": src_addr, "dst_addr": dst_addr, "ss_family": payload["ss_family"]
                    }.items()))
                if self.socket_trace:
                    self._event_bus.emit(SocketTraceEvent(
                        src_addr=src_addr,
                        src_port=payload["src_port"],
                        dst_addr=dst_addr,
                        dst_port=payload["dst_port"],
                        ss_family=payload["ss_family"],
                    ))
                    self.traced_Socket_Set.add(frozenset({
                        "src_addr": src_addr, "dst_addr": dst_addr,
                        "src_port": payload["src_port"], "dst_port": payload["dst_port"],
                        "ss_family": payload["ss_family"]
                    }.items()))
                    self.traced_scapy_socket_Set.add(frozenset({
                        "src_addr": src_addr, "dst_addr": dst_addr, "ss_family": payload["ss_family"]
                    }.items()))
            return  # Output handlers process events via EventBus

        # Legacy path: inline output handling
        from .message_handler import handle_message_legacy
        handle_message_legacy(self, payload, data, message)

    def _emit_event_from_payload(self, payload: dict, data: bytes) -> None:
        """Parse an agent message payload and emit the corresponding event."""
        self._message_router.route(payload, data)

    def on_child_added(self, child):
        """Schedule child instrumentation via the message queue.

        Runs on Frida's event thread — enqueue and return fast (same
        pattern as the updated frida-python child_gating.py example
        which uses Reactor.schedule()).
        """
        try:
            self._message_queue.put_nowait((_ChildAddedSentinel(child), None))
        except queue.Full:
            self.logger.warning("Message queue full — child pid %s not instrumented", child.pid)

    def _handle_child_added(self, child):
        """Actually instrument a child process (runs on consumer thread)."""
        self.logger.info(f"Attached to child process with pid {child.pid}")
        self.instrument(self._backend.attach(self.device, str(child.pid)), self.own_message_handler)
        self._backend.resume(self.device, child.pid)


    def on_spawn_added(self, spawn):
        # If spawn_gating_all is set, instrument ALL spawned processes (old behavior)
        # Otherwise, filter by target app identifier
        if self.spawn_gating_all or self._should_instrument_spawn(spawn.identifier):
            self.logger.info(f"Instrumenting spawned process with pid {spawn.pid}. Name: {spawn.identifier}")
            self.instrument(self._backend.attach(self.device, str(spawn.pid)), self.own_message_handler)
            self._backend.resume(self.device, spawn.pid)
        else:
            # Resume unrelated processes immediately to prevent them from hanging
            self.logger.debug(f"Skipping unrelated spawn with pid {spawn.pid}. Name: {spawn.identifier}")
            self._backend.resume(self.device, spawn.pid)

    def _should_instrument_spawn(self, identifier):
        """Check if a spawned process should be instrumented based on its identifier."""
        if not identifier:
            return False

        # For mobile (Android/iOS), identifier is the package name
        # e.g., "com.example.app" or "com.example.app:service"
        if self.mobile:
            return identifier.startswith(self.target_app)

        # For desktop, check if target app name is contained in the identifier
        # The identifier could be a path or executable name
        target_name = self.target_app.split()[-1] if ' ' in self.target_app else self.target_app
        # Handle paths: extract base name for comparison
        if '/' in target_name:
            target_name = target_name.split('/')[-1]
        if '\\' in target_name:
            target_name = target_name.split('\\')[-1]

        return target_name.lower() in identifier.lower()


    def instrument(self, process, own_message_handler):
        runtime = ScriptRuntime.QJS
        debug_port = 1337
        if self.debug:
            if not self._backend.version_at_least(16):
                self._backend.enable_debugger(process, debug_port)
            self.logger.info("running in debug mode")
            self.logger.info(f"Chrome Inspector server listening on port {debug_port}")
            self.logger.info("Open Chrome with chrome://inspect for debugging")
            runtime = ScriptRuntime.V8
        self._last_runtime = runtime

        script_string = self.get_agent_script()
        if self.debug_output:
            self.logger.debug(f"loading friTap agent script: {self.agent_script}")

        if self.offsets_data is not None:
            self.logger.info(f"applying hooks at offset {self.offsets_data}")

        if self.pattern_data is not None:
            self.logger.info("Using pattern provided by pattern.json for hooking")

        # Build ScriptContext for plugins
        from ..plugins.script_context import ScriptContext
        from ..plugins.script_plugin import ScriptLoadOrder
        context = ScriptContext(
            backend=self._backend, process=process, device=self.device,
            runtime=runtime, event_bus=self._event_bus,
            backend_name=self._backend.name, debug=self.debug,
            debug_output=self.debug_output,
        )

        # Phase 1: BEFORE_MAIN script plugins (e.g. legacy --custom_script)
        if hasattr(self, '_plugin_loader'):
            self._plugin_loader.instrument_all(context, order=ScriptLoadOrder.BEFORE_MAIN)

        self.script = self._backend.create_script(process, script_string, runtime=runtime)

        if self.debug and self._backend.version_at_least(16):
            self._backend.enable_debugger(self.script, debug_port)

        if own_message_handler is not None:
            self._backend.on_message(self.script, self._provide_custom_hooking_handler(own_message_handler))
            return self.script
        else:
            self._backend.on_message(self.script, self._internal_callback_wrapper())
        self._backend.load_script(self.script)

        # Emit ScriptLoadedEvent for main friTap script
        self._event_bus.emit(ScriptLoadedEvent(
            script_name=self.agent_script, plugin_name="", load_order="main",
        ))

        # Phase 3: AFTER_MAIN script plugins
        if hasattr(self, '_plugin_loader'):
            self._plugin_loader.instrument_all(context, order=ScriptLoadOrder.AFTER_MAIN)

        # Emit InstrumentEvent
        self._event_bus.emit(InstrumentEvent(
            target=self.target_app, backend=self._backend.name,
        ))

        #script.post({'type':'readmod', 'payload': '0x440x410x53'})
        if self.payload_modification:
            class ModWatcher(FileSystemEventHandler):
                def __init__(self, process):

                    self.process = process

                def on_any_event(self, event):
                    try:
                        if(event.event_type == "modified" and ("readmod" in event.src_path)):
                            with open("./readmod.bin", "rb") as f:
                                buffer = f.read()
                                self._backend.post_message(self.script, 'readmod', buffer.hex())
                        elif(event.event_type == "modified" and ("writemod" in event.src_path)):
                            with open("./writemod.bin", "rb") as f:
                                buffer = f.read()
                                self._backend.post_message(self.script, 'writemod', buffer.hex())
                    except RuntimeError as e:
                        self.logger.error(f"Watcher error: {e}")



            self.logger.debug("Init watcher")
            event_handler = ModWatcher(process)

            self._observer = Observer()
            self._observer.schedule(event_handler, os.getcwd())
            self._observer.start()

        return self.script


    @staticmethod
    def _validate_patterns(patterns: dict) -> bool:
        """Validate pattern data structure and hex format.

        Expected structure: {lib_name: {arch: {function: [pattern_str, ...]}}}
        Pattern format: hex bytes separated by spaces, ? wildcards allowed.
        """
        from ..patterns.loader import PatternLoader
        return PatternLoader.validate(patterns)

    def load_patterns(self):
        """Load patterns: auto-load defaults, then deep-merge user patterns on top.

        Merge is granular: only the specific library/ABI/function entries
        in the user file override defaults. Everything else stays intact.
        """
        from ..patterns.loader import PatternLoader
        self.pattern_data = PatternLoader.load(self.patterns, self.logger)

    def _apply_sibling_coverage_suppression(self, scan_results: list[dict]) -> None:
        """Detect Cronet-split-topology and suppress redundant pattern scans.

        When ``--library-scan`` is on, lsLibHunter reports every loaded TLS
        library.  Some Cronet builds ship BoringSSL in a sibling module
        (e.g. ``stable_cronet_libssl.so``) while the higher-level runtime
        (``libmainlinecronet.<ver>.so``) merely imports it.  Pattern-scanning
        the runtime module is futile by construction.  This helper annotates
        such modules with ``covered_by_sibling`` (consumed by the agent's
        library_scanner) and strips matching entries from ``self.pattern_data``
        so the agent's auto-registered pattern hooks never schedule.

        Users can opt back in to scanning via ``--force-scan <name>`` (or the
        ``FRITAP_FORCE_SCAN`` env var, comma-separated).
        """
        from ..protocols.tls_handler import covered_by_sibling, strip_covered_modules

        force_set = self._config.hooking.force_scan_modules or ()
        covered = covered_by_sibling(scan_results, force_scan_modules=force_set)
        if not covered:
            return

        for entry in scan_results:
            name = entry.get("name")
            if name in covered:
                entry["covered_by_sibling"] = covered[name]

        self.logger.info(
            "Cronet split topology detected; skipping %d redundant scan(s): %s",
            len(covered), ", ".join(covered.keys()),
        )
        self.pattern_data = strip_covered_modules(
            self.pattern_data, covered, force_scan_modules=force_set
        )

    def _deep_merge(self, base: dict, override: dict) -> dict:
        """Deep merge two dicts. Override values win on conflict.

        Recurses into nested dicts so only leaf values are replaced.
        """
        from ..patterns.loader import PatternLoader
        return PatternLoader.deep_merge(base, override)

    def start_fritap_session_instrumentation(self, own_message_handler, process):
        self.process = process

        if self._config.proxy:
            self._inject_proxy_redirector(process)

        script = self.instrument(self.process, own_message_handler)
        return script

    @staticmethod
    def _parse_proxy_address(addr: str) -> tuple:
        """Parse host:port string, handling IPv6 bracket notation."""
        # IPv6 bracket notation: [::1]:8080
        if addr.startswith("["):
            bracket_end = addr.find("]")
            if bracket_end == -1 or bracket_end + 1 >= len(addr) or addr[bracket_end + 1] != ":":
                raise ValueError(f"Expected [host]:port format, got '{addr}'")
            host = addr[1:bracket_end]
            port_str = addr[bracket_end + 2:]
        elif ":" not in addr:
            raise ValueError(f"Expected host:port format, got '{addr}'")
        else:
            host, port_str = addr.rsplit(":", 1)

        try:
            port = int(port_str)
        except ValueError:
            raise ValueError(f"Invalid port '{port_str}' in proxy address '{addr}'")

        if not (1 <= port <= 65535):
            raise ValueError(f"Port {port} out of range (1-65535)")

        return host, port

    def _inject_proxy_redirector(self, process) -> None:
        """Inject fritap-proxy into the Frida session for connection redirect + pinning bypass."""
        try:
            from fritap_proxy import ProxyRedirector, ProxyConfig, ProxyTarget
        except ImportError:
            raise RuntimeError(
                "fritap-proxy package not installed. "
                "Install with: pip install fritap-proxy"
            )

        host, port = self._parse_proxy_address(self._config.proxy)
        proxy_config = ProxyConfig(
            target=self._config.target,
            proxy=ProxyTarget(host=host, port=port),
        )
        self._proxy_redirector = ProxyRedirector.inject(
            session=process,
            config=proxy_config,
        )
        self.logger.info("Proxy redirect active: connections -> %s:%d", host, port)

    def connect_live(self) -> bool:
        """Connect the live Wireshark FIFO handler.

        Emits LiveReadyEvent (so the TUI can launch Wireshark), waits
        briefly for the launch, then blocks until Wireshark connects to
        the FIFO or times out.

        Call this AFTER wiring any event subscribers (e.g. TuiOutputHandler)
        so they receive the LiveReadyEvent. Idempotent: no-op if no live
        handler or already connected.

        Returns True if connected (or not in live mode), False on timeout.
        """
        if self._live_handler is None:
            return True

        live_handler = self._live_handler
        self._live_handler = None  # Consume — idempotent

        from ..events import LiveReadyEvent
        self._event_bus.emit(LiveReadyEvent(fifo_path=self.filename))

        time.sleep(1.0)  # Give event loop time to process Wireshark launch

        connected = live_handler.connect(timeout=30)
        if connected:
            from ..events import WiresharkConnectedEvent
            self._event_bus.emit(WiresharkConnectedEvent(fifo_path=self.filename))
            return True

        from ..events import LiveConnectionFailedEvent
        self._event_bus.emit(LiveConnectionFailedEvent(
            fifo_path=self.filename,
            reason="Wireshark did not connect within 30 seconds",
        ))
        self._output_handlers.remove(live_handler)
        live_handler.close()
        return False

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
        """Surface a frida-thread routing error as an EventBus ErrorEvent.

        The traceback already hit the debug-log file via logger.exception;
        this additionally emits an ``ErrorEvent(severity="error")`` so the
        TUI activity log and any other subscriber observe the failure.
        Never raises.
        """
        try:
            import traceback as _tb
            from friTap.events import ErrorEvent, ERROR_SEVERITY_ERROR
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

        This keeps the Frida callback thread free (instant put_nowait)
        and gives the TUI thread fair GIL access via the 0.1 s timeout.
        """
        while not self._consumer_stop.is_set():
            try:
                message, data = self._message_queue.get(timeout=0.1)
            except queue.Empty:
                continue
            try:
                if isinstance(message, _ChildAddedSentinel):
                    self._handle_child_added(message.child)
                else:
                    self.on_fritap_message(None, message, data)
            except Exception as exc:
                # Frida-side message handlers run on a dedicated thread.
                # An uncaught exception here used to be debug-only and
                # would silently drop messages; upgrade to logger.exception
                # so the traceback always hits the debug log file, and
                # emit an ErrorEvent so the TUI's activity log + EventBus
                # subscribers see the failure too.
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
                if isinstance(message, _ChildAddedSentinel):
                    pass  # Skip child gating during shutdown drain
                else:
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

    # ------------------------------------------------------------------
    # Live passive analysis ("scan") of observed traffic
    # ------------------------------------------------------------------

    # Bound the in-flight scan queue so a slow analyzer can never grow memory
    # without limit. When full, completed flows are dropped (and counted)
    # rather than blocking the capture / Frida callback thread.
    _SCAN_QUEUE_MAXSIZE = 2048

    def _setup_live_scan(self):
        """Wire up live passive analysis of observed traffic, if requested.

        Must be called BEFORE instrumentation starts so no completed flows are
        missed. Subscribes a lightweight handler that ENQUEUES completed flows
        onto a bounded queue; a daemon worker thread drains it and runs the
        analyzers off the Frida callback thread. No-op when --scan is unset.
        """
        scan_spec = getattr(self._config.output, "scan", None)
        if not scan_spec:
            return

        try:
            from ..analysis import AnalyzerPlugin
            from ..analysis.registry import resolve_analyzers
            from ..flow.collector import FlowCollector
            from ..flow.models import FlowEventType
            from ..events import DatalogEvent, OhttpEvent, FlowEvent

            # Forward reveal_pii so the privacy analyzer keeps raw values when
            # --scan-show-pii is set; other analyzers ignore the opt. Redaction
            # is still enforced at the reporter layer in _finalize_live_scan.
            reveal_pii = getattr(self._config.output, "scan_show_pii", False)
            self._scan_plugins = [
                AnalyzerPlugin(a)
                for a in resolve_analyzers(scan_spec, reveal_pii=reveal_pii)
            ]
            if not self._scan_plugins:
                return

            # Mirror the TUI wiring (capture_controller.py): give the collector
            # the event bus and subscribe it to the data/ohttp/library events.
            if self._flow_collector is None:
                self._flow_collector = FlowCollector(event_bus=self._event_bus)
            self._flow_collector.set_event_bus(self._event_bus)
            self._event_bus.subscribe(DatalogEvent, self._flow_collector.on_data)
            self._event_bus.subscribe(OhttpEvent, self._flow_collector.on_ohttp)
            self._event_bus.subscribe(
                LibraryDetectedEvent, self._flow_collector.on_library_detected
            )
            self._event_bus.subscribe(
                SessionEvent, self._flow_collector.on_session_event
            )
            self._flow_collector.set_capture_target(self._config.target)

            # Bounded queue + daemon worker so analyzers never run inline on the
            # Frida callback thread.
            self._scan_queue = queue.Queue(maxsize=self._SCAN_QUEUE_MAXSIZE)
            self._scan_stop.clear()

            def _enqueue_completed_flow(event):
                if event.flow_event_type != FlowEventType.COMPLETED or event.flow is None:
                    return
                try:
                    self._scan_queue.put_nowait(event.flow)
                except queue.Full:
                    self._scan_drop_count += 1

            self._event_bus.subscribe(FlowEvent, _enqueue_completed_flow)

            self._scan_thread = threading.Thread(
                target=self._scan_worker, name="fritap-scan", daemon=True,
            )
            self._scan_thread.start()
            self.logger.info(
                "Passive analysis enabled (%s) — analyzing observed traffic",
                ", ".join(p.name for p in self._scan_plugins),
            )
        except Exception as e:
            # A scan setup failure must never break normal capture.
            self.logger.warning("Could not enable passive analysis: %s", e)
            self._scan_plugins = []
            self._scan_queue = None
            self._scan_thread = None

    def _scan_worker(self):
        """Daemon worker: drain completed flows and run them through analyzers."""
        while not (self._scan_stop.is_set() and self._scan_queue.empty()):
            try:
                flow = self._scan_queue.get(timeout=0.25)
            except queue.Empty:
                continue
            for plugin in self._scan_plugins:
                try:
                    plugin.analyze(flow)
                except Exception:
                    self.logger.debug("Analyzer raised on flow", exc_info=True)
            self._scan_queue.task_done()

    def _finalize_live_scan(self):
        """Flush, drain, and render passive-analysis findings. Never raises."""
        if not self._scan_plugins:
            return
        try:
            from ..commands.analyze import _REPORTER_REGISTRY
            from ..analysis.filtering import FindingFilter, apply, split_csv

            # Flush still-active flows so they complete and get enqueued.
            if self._flow_collector is not None:
                try:
                    self._flow_collector.flush()
                except Exception:
                    self.logger.debug("FlowCollector flush failed", exc_info=True)

            # Signal the worker to drain and stop, then wait for it to finish.
            # We must not read plugin.findings while the worker thread is still
            # calling plugin.analyze() -> findings.extend() on the same lists.
            self._scan_stop.set()
            if self._scan_thread is not None:
                self._scan_thread.join(timeout=10)
                if self._scan_thread.is_alive():
                    self.logger.warning(
                        "Passive-analysis worker did not finish draining within "
                        "10s; reported findings may be incomplete",
                    )

            # Snapshot each plugin's findings with list() — a single GIL-atomic
            # copy — so that even if the worker is still alive we never iterate a
            # list it is concurrently extending (which would raise "list changed
            # size during iteration"). The worst case is a few not-yet-appended
            # findings are omitted, which the warning above already flags.
            findings = []
            for plugin in self._scan_plugins:
                findings.extend(list(plugin.findings))

            min_sev = getattr(self._config.output, "scan_min_severity", "info")
            min_conf = getattr(self._config.output, "scan_min_confidence", 0.0)
            sources = split_csv(getattr(self._config.output, "scan_source", None))
            categories = split_csv(getattr(self._config.output, "scan_category", None))
            flt = FindingFilter(
                min_severity=min_sev,
                sources=sources,
                categories=categories,
                min_confidence=min_conf or None,
            )
            findings = apply(findings, flt)

            show_pii = getattr(self._config.output, "scan_show_pii", False)
            report_fmt = getattr(self._config.output, "scan_report", "table")
            reporter = _REPORTER_REGISTRY.get(report_fmt, _REPORTER_REGISTRY["table"])(
                redact_pii=not show_pii
            )
            meta = {"analyzers": [p.name for p in self._scan_plugins]}
            rendered = reporter.report(findings, meta)

            report_out = getattr(self._config.output, "scan_report_out", None)
            if report_out:
                with open(report_out, "w", encoding="utf-8") as fh:
                    fh.write(rendered)
                self.logger.info("Passive-analysis report written to %s", report_out)
            else:
                self.special_logger.info("\n%s", rendered)

            if self._scan_drop_count:
                self.logger.warning(
                    "Passive analysis dropped %d completed flows (queue full)",
                    self._scan_drop_count,
                )
        except Exception as e:
            self.logger.warning("Passive-analysis finalization failed: %s", e)

    def start_fritap_session(self, own_message_handler=None):
        self.connect_live()  # No-op if already connected or not in live mode
        # Wire passive analysis BEFORE instrumentation so no flows are missed.
        self._setup_live_scan()
        self._start_consumer_thread()
        return self._session_manager.start_session(own_message_handler)

    def request_stop(self):
        """Signal the capture to stop. Non-blocking, safe to call from any thread."""
        self.running = False
        self._consumer_stop.set()

    def finish_fritap(self):
        self._stop_consumer_thread()  # drain remaining messages before PCAP close
        if self._proxy_redirector is not None:
            try:
                self._proxy_redirector.stop()
            except Exception:
                pass
            self._proxy_redirector = None
        self._session_manager.finish()

    def _provide_custom_hooking_handler(self, handler):
        return handler


    def _internal_callback_wrapper(self):
        def wrapped_handler(message, data):
            # Enqueue only — return from the Frida callback thread ASAP
            # to prevent GIL contention that starves the TUI thread.
            try:
                self._message_queue.put_nowait((message, data))
            except queue.Full:
                self._queue_drop_count += 1

        return wrapped_handler


    def detach_with_timeout(self, timeout=30):
        """
        Attempt to detach from the instrumented process with a timeout.

        Args:
            process: The instrumented process to detach from.
            timeout: Time in seconds to wait before forcing detachment.
                     Default 30s — Frida's script.unload() blocks waiting for
                     in-flight Interceptor callbacks to drain, and a process
                     under heavy hook load (e.g. Chrome's QUIC stack with
                     dozens of stream-level hooks installed) can keep the JS
                     thread busy for >5s after Ctrl+C. The previous 5s default
                     was too aggressive and produced spurious
                     "Detach process timed out" warnings on QUIC-loaded
                     captures even when the underlying detach eventually
                     succeeded. Respects --timeout CLI arg when provided.
        """
        def detach():
            try:
                if self.debug_output or self.debug:
                    self.logger.debug("Attempting to detach from instrumented process...")

                # FAST PATH — the target already died (native crash inside a hook
                # surfaces as 'process-terminated', and the script is destroyed
                # with it). There is nothing left to unload or detach from: every
                # Frida call below would just block until the outer timeout
                # (default 30s), which delays cleanup()'s goodbye + os._exit and
                # makes the user think they must press Ctrl+C again. Short-circuit
                # so teardown finishes immediately.
                script_dead = bool(getattr(self.script, "is_destroyed", False))

                # Step 1 — graceful_detach RPC. Frida 17 splits the RPC proxy
                # into exports_sync (blocking) and exports (async coroutine).
                # We strictly prefer exports_sync so the call actually blocks
                # until the JS side returns; the async variant would fire-
                # and-forget the request and we'd race straight into unload.
                # The agent's gracefulDetach sets a module-scope shutdown
                # flag BEFORE calling Interceptor.detachAll, so any callback
                # already queued on the JS message loop short-circuits at
                # sendDatalog / emit (microsecond per pending callback
                # instead of a full IPC round-trip).
                graceful = None
                exports_sync = getattr(self.script, "exports_sync", None)
                if exports_sync is not None:
                    graceful = getattr(exports_sync, "graceful_detach", None)
                if graceful is None:
                    exports_async = getattr(self.script, "exports", None)
                    if exports_async is not None:
                        graceful = getattr(exports_async, "graceful_detach", None)
                if callable(graceful):
                    try:
                        graceful()
                    except Exception as e:
                        # A destroyed script raises here ("script has been
                        # destroyed") — treat that as the target being gone.
                        script_dead = True
                        if self.debug_output or self.debug:
                            self.logger.debug(f"graceful_detach RPC failed: {e}")

                # Target already gone — nothing to unload or detach. Return now so
                # cleanup()'s finally prints the goodbye and exits without delay.
                if script_dead:
                    if self.debug_output or self.debug:
                        self.logger.debug(
                            "target/script already gone — skipping unload + "
                            "session.detach()"
                        )
                    return

                # Step 2 — brief drain. Give the JS message loop a moment to
                # process any pending callbacks (they'll now short-circuit on
                # the shutdown flag) so the queue is empty when unload runs.
                # 200ms is plenty even for thousands of callbacks because
                # they each do nothing more than a single flag check.
                try:
                    threading.Event().wait(0.2)
                except Exception:
                    pass

                # Step 3 — unload_script with its OWN timeout. Frida's
                # script.unload() has no native timeout; if the JS thread is
                # still busy for any reason it would block forever.
                # Wrapping it lets us fall through to session.detach() after
                # 5s no matter what.
                unload_thread = threading.Thread(
                    target=lambda: self._backend.unload_script(self.script),
                    daemon=True,
                )
                unload_thread.start()
                unload_thread.join(timeout=5)

                # Step 4 — session.detach() (best-effort; backend handles
                # races with the target already exiting).
                #
                # ORDERING MATTERS — do not "simplify" this back into an
                # unconditional detach. If script.unload() is still in-flight on
                # the daemon thread, the Frida session is busy and calling
                # session.detach() into it serializes behind the stuck unload,
                # which is exactly what produced the 30s "Detach process timed
                # out" hang during heavy QUIC capture. gracefulDetach() already
                # ran Interceptor.detachAll() on the JS side (Step 1), so the
                # hooks are gone regardless; when unload is wedged we skip the
                # racing detach and let process exit / frida-server reclaim the
                # session. We only issue session.detach() when unload returned
                # cleanly (the common, non-flooded case).
                if unload_thread.is_alive():
                    if self.debug_output or self.debug:
                        self.logger.debug(
                            "script.unload() did not return within 5s; skipping "
                            "session.detach() to avoid racing the busy session "
                            "(hooks already removed via gracefulDetach; unload "
                            "thread will exit when the JS message loop drains)"
                        )
                else:
                    self._backend.detach(self.process)

            except Exception as e:
                self.logger.error(f"Error while detaching: {e}")

        # Create a thread to run the detach method
        detach_thread = threading.Thread(target=detach)
        detach_thread.start()

        # Wait for the thread to complete
        detach_thread.join(timeout=timeout)

        if detach_thread.is_alive():
            if self.debug_output:
                self.logger.warning(f"Detach process timed out after {timeout} seconds.")
            # Force cleanup if necessary
            # Note: force detach may not be supported, so handle gracefully
        else:
            if self.debug_output:
                self.logger.debug("Detached friTap from process successfully.")

    def set_keylog_file(self, keylog_name):
        self.keylog_file = open(keylog_name, "w")

    def pcap_cleanup(self, is_full_capture, is_mobile, pcap_name):
        self._session_manager.pcap_cleanup(is_full_capture, is_mobile, pcap_name)

    def cleanup(self, live=False, socket_trace=False, full_capture=False, debug_output=False, debug=False):
        if self._cleanup_done:
            return
        self._cleanup_done = True

        # Run all teardown steps, then ALWAYS print the goodbye banner and force
        # a clean process exit — even if a step raised (e.g. the target crashed
        # mid-teardown). This is the single chokepoint every stop path funnels
        # through: Ctrl+C (main thread via the SIGINT handler), process exit /
        # native crash (Frida callback thread via on_detach), and the normal or
        # --timeout return (the CLI's finally block in friTap.py).
        try:
            self._run_cleanup_steps(live, socket_trace, full_capture, debug_output, debug)
        except Exception as _cleanup_err:
            try:
                self.logger.error(f"Error during cleanup: {_cleanup_err}")
            except Exception:
                pass
        finally:
            self.special_logger.info("\nThanks for using friTap. Have a great day!")
            if not self._tui_mode:
                # os._exit, not sys.exit: SystemExit only unwinds the current
                # thread and still blocks interpreter shutdown while it joins the
                # non-daemon Frida reactor/finalizer thread that stays alive when
                # script.unload() is still draining the JS message loop. It also
                # does nothing at all when cleanup() runs on a Frida callback
                # thread (the crash/on_detach path). os._exit terminates the whole
                # process immediately from whichever thread we're on, so the user
                # never needs a second Ctrl+C.
                os._exit(0)

    def _run_cleanup_steps(self, live=False, socket_trace=False, full_capture=False, debug_output=False, debug=False):
        """Perform the actual teardown work. Always invoked via cleanup(), which
        guarantees the goodbye banner and a clean exit run afterward regardless
        of whether any step here raises."""
        self._stop_consumer_thread()

        # Unload plugins
        if hasattr(self, '_plugin_loader'):
            self._plugin_loader.unload_all(self._plugin_shim)

        # Finalize live passive analysis (flush flows, drain queue, render
        # findings) after plugins unload but before detaching. Guarded so a
        # scan error never breaks normal capture cleanup.
        self._finalize_live_scan()

        # Close output handlers (new modular path)
        if self._handlers_active:
            for handler in self._output_handlers:
                try:
                    handler.close()
                except Exception as e:
                    self.logger.error(f"Error closing handler: {e}")

        if self.pcap_obj is not None and full_capture:
            if self.pcap_obj.full_capture_thread.is_alive():
                self.pcap_obj.full_capture_thread.join()
                time.sleep(2)

        if not self._handlers_active:
            # Legacy cleanup for live/json when handlers not active
            from .cleanup_compat import cleanup_legacy
            cleanup_legacy(self)

        if isinstance(socket_trace, str):
            self.logger.info(f"Write traced sockets into {socket_trace}")
            self.write_socket_trace(socket_trace)
        if socket_trace:
            display_filter = PCAP.get_filter_from_traced_sockets(self.traced_Socket_Set, filter_type="display")
            self.logger.info(f"Generated Display Filter for Wireshark:\n{display_filter}")

        if full_capture:
            if debug_output or debug:
                display_filter = PCAP.get_filter_from_traced_sockets(self.traced_Socket_Set, filter_type="display")
                self.logger.debug(f"Generated Display Filter for Wireshark:\n{display_filter}")

            from ..output import KeyCollectorHandler
            formatted_keys = ()
            for handler in getattr(self, "_output_handlers", []):
                if isinstance(handler, KeyCollectorHandler):
                    formatted_keys = handler.get_collected_keys()
                    break

            pcap_name = self.pcap_obj.pcap_file_name
            try:
                if self.traced_scapy_socket_Set:
                    self.pcap_obj.create_application_traffic_pcap(
                        self.traced_scapy_socket_Set, self.pcap_obj,
                        formatted_keys=formatted_keys,
                    )
                else:
                    suffix = (
                        f"PCAP {pcap_name} will contain all captured traffic from "
                        f"the device (frida/adb infrastructure excluded by default)."
                    )
                    if socket_trace:
                        self.logger.warning(f"friTap observed no sockets during capture. The resulting {suffix}")
                    else:
                        self.logger.info(f"Socket tracing disabled. The resulting {suffix}")
                    # Seed manifest ports from the socket trace when available
                    # (populated only with --socket_trace). Pure --full_capture
                    # without it leaves this empty and ports stay unrecorded.
                    self.pcap_obj.finalize_full_capture(
                        formatted_keys,
                        traced_Socket_Set=self.traced_Socket_Set,
                    )
            except Exception as e:
                self.logger.error(f"Error: {e}")

        self.running = False
        self._done_event.set()
        if self.process:
            # Honor --timeout when explicitly set; otherwise use the
            # 30s default in detach_with_timeout (raised from 5s because Frida's
            # script.unload() drains in-flight Interceptor callbacks before
            # returning, which can take >5s on processes with many hot hooks
            # — typical for Chrome + QUIC capture).
            _cli_timeout = getattr(self._config.device, 'timeout', None)
            if isinstance(_cli_timeout, int) and _cli_timeout > 0:
                self.detach_with_timeout(timeout=_cli_timeout)
            else:
                self.detach_with_timeout()
        if self.process is not None and not self._detected_libraries and not self._config.hooking.library_scan:
            if self._config.protocol in ("tls", "auto", "all"):
                self.special_logger.info(
                    "\n[Hint] No TLS libraries were detected. Consider using "
                    "--library-scan (-ls) to discover renamed or statically linked libraries."
                )
            else:
                self.special_logger.info(
                    f"\n[Hint] No {self._config.protocol.upper()} libraries were detected. "
                    "If you believe this is incorrect, please open an issue at "
                    "https://github.com/fkie-cad/friTap/issues"
                )

    def wait_for_completion(self):
        """Block until the session ends. Responds to KeyboardInterrupt."""
        while not self._done_event.wait(timeout=0.5):
            pass

    def get_agent_script(self):
        with open(os.path.join(here, self.agent_script), encoding='utf-8', newline='\n') as f:
            return f.read()

    def inspect_libraries(self):
        """Inspect loaded libraries using the SSL Library Inspector"""
        from ..inspector import LibraryInspector
        return LibraryInspector.inspect(self._config, self.logger)

    def extract_libraries(self, output_dir):
        """Extract detected TLS libraries to disk using tlsLibHunter."""
        from ..inspector import LibraryInspector
        return LibraryInspector.extract_libraries(
            self._config, self.logger, output_dir)

    def get_agent_script_path(self):
        return os.path.join(here, self.agent_script)

    def install_signal_handler(self):
        self._session_manager.install_signal_handler()

    def _log_session_end(self, reason):
        """Log session end information"""
        self._event_bus.emit(SessionEvent(
            event_type="ended",
            session_id=str(id(self.process)) if self.process else "",
        ))
        if self.json_output:
            with self._session_data_lock:
                self.session_data["session_info"]["end_time"] = datetime.now(timezone.utc).isoformat()
                self.session_data["session_info"]["end_reason"] = reason
                self.session_data["statistics"]["total_sessions"] = len(self.session_data["ssl_sessions"])

    def _finalize_json_output(self):
        """Write final JSON output to file"""
        if self.json_file:
            try:
                with self._session_data_lock:
                    # Update statistics
                    self.session_data["session_info"]["end_time"] = datetime.now(timezone.utc).isoformat()

                    # Write JSON data
                    json.dump(self.session_data, self.json_file, indent=2, ensure_ascii=False)
                self.json_file.close()
                self.logger.info(f"JSON output saved to {self.json_output}")
            except Exception as e:
                self.logger.error(f"Error writing JSON output: {e}")

    def add_ssl_session(self, session_info):
        """Add SSL session information to JSON output"""
        if self.json_output:
            session_entry = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "session_id": session_info.get("session_id"),
                "cipher_suite": session_info.get("cipher_suite"),
                "protocol_version": session_info.get("protocol_version"),
                "server_name": session_info.get("server_name"),
                "certificate_info": session_info.get("certificate_info")
            }
            with self._session_data_lock:
                self.session_data["ssl_sessions"].append(session_entry)

    def add_library_detection(self, library_name, library_path):
        """Add detected SSL library information to JSON output"""
        self._event_bus.emit(LibraryDetectedEvent(
            library=library_name,
            path=library_path,
        ))
        if self.json_output:
            library_info = {
                "name": library_name,
                "path": library_path,
                "detected_at": datetime.now(timezone.utc).isoformat()
            }
            with self._session_data_lock:
                existing = self.session_data["statistics"]["libraries_detected"]
                already_known = any(
                    entry["name"] == library_name and entry["path"] == library_path
                    for entry in existing
                )
                if not already_known:
                    existing.append(library_info)

    def write_socket_trace(self, socket_trace_name):
        with open(socket_trace_name, 'a') as trace_file:
            trace_file.write(PCAP.get_filter_from_traced_sockets(self.traced_Socket_Set, filter_type="display") + '\n')


class _PluginSessionShim:
    """Minimal Session-like object for legacy SSL_Logger plugin loading.

    Provides the subset of Session API that plugins use in on_load/on_unload,
    backed by the SSL_Logger's EventBus.
    """

    def __init__(self, event_bus, pipeline=None, connection_index=None):
        self.lifecycle_bus = event_bus
        self.pipeline = pipeline
        self.connection_index = connection_index

    def register_sink(self, sink):
        """Register a sink (no-op in legacy mode unless pipeline is set)."""
        if self.pipeline is not None:
            self.pipeline.add_sink(sink)

    def push_message(self, payload, data=None):
        """Push a message — not supported in legacy shim."""
        raise NotImplementedError(
            "push_message() is not supported on the legacy SSL_Logger shim. "
            "Use CoreController + Session for pipeline-based message routing."
        )

    def astart(self):
        """Not available in legacy mode."""
        raise NotImplementedError(
            "astart() is not available in legacy mode. "
            "Use CoreController + Session for async API."
        )

    def astop(self):
        """Not available in legacy mode."""
        raise NotImplementedError(
            "astop() is not available in legacy mode. "
            "Use CoreController + Session for async API."
        )

    def await_done(self):
        """Not available in legacy mode."""
        raise NotImplementedError(
            "await_done() is not available in legacy mode. "
            "Use CoreController + Session for async API."
        )


def get_addr_string(socket_addr, ss_family):
    if ss_family == "AF_INET" and isinstance(socket_addr, int):
        return socket.inet_ntop(socket.AF_INET, struct.pack(">I", socket_addr))
    if ss_family == "AF_INET6" and isinstance(socket_addr, str):
        raw_addr = bytes.fromhex(socket_addr)
        return socket.inet_ntop(socket.AF_INET6, struct.pack(">16s", raw_addr))
    return str(socket_addr)
