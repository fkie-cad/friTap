#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from ..backends.base import BackendName, ScriptRuntime
import tempfile
import os
import struct
import socket
import time
import sys
import json
import threading
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
)
from ..config import FriTapConfig
from ..constants import SSL_READ, SSL_WRITE, ContentType
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


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

        # Protocol registry and handler
        from ..protocols.registry import create_default_registry
        self._protocol_registry = create_default_registry()
        self._detected_libraries = set()  # tracks libraries detected by agent
        if self._config.protocol == "auto":
            # Start with TLS as default; will be refined via LibraryDetectedEvent
            self._protocol_handler = self._protocol_registry.get("tls")
        else:
            self._protocol_handler = self._protocol_registry.get(self._config.protocol)
        if self._protocol_handler is None:
            self._protocol_handler = self._protocol_registry.get("tls")

        # Validate protocol-backend compatibility
        self._config.validate_protocol_backend(self._protocol_handler)

        # Session manager (extracted for file length management)
        from .session_manager import SessionManager
        self._session_manager = SessionManager(self)

        # Message router (extracted for file length management)
        from ..message_router import MessageRouter
        self._message_router = MessageRouter(self._event_bus)

        # Always track detected libraries (needed for exit hint message)
        self._event_bus.subscribe(LibraryDetectedEvent, self._on_library_detected)

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

            # Only switch protocol handler when in auto-detect mode
            if self._config.protocol == "auto":
                matched = self._protocol_registry.auto_detect(list(self._detected_libraries))
                if matched and matched[0].name != self._protocol_handler.name:
                    self._protocol_handler = matched[0]
                    self.logger.info("Auto-detect: switched protocol handler to %s", self._protocol_handler.name)



    def init_fritap(self):
        if not self._backend.version_at_least(17):
            self.agent_script = "_ssl_log_legacy.js"
        else:
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
            self.session_data, self.logger
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


    def on_detach(self, reason):
        if not self.running:
            return

        if reason == "application-requested":
            return

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
                }
                self._backend.post_message(self.script, 'config_batch', batch)
                return
            from .message_handler import handle_startup_legacy
            handle_startup_legacy(self, payload)

        if not isinstance(payload, dict) or "contentType" not in payload:
            return

        # Emit events through the event bus for all content types
        self._emit_event_from_payload(payload, data)

        content_type = payload.get("contentType")

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

    def _deep_merge(self, base: dict, override: dict) -> dict:
        """Deep merge two dicts. Override values win on conflict.

        Recurses into nested dicts so only leaf values are replaced.
        """
        from ..patterns.loader import PatternLoader
        return PatternLoader.deep_merge(base, override)

    def start_fritap_session_instrumentation(self, own_message_handler, process):
        self.process = process
        script = self.instrument(self.process, own_message_handler)
        return script

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

    def start_fritap_session(self, own_message_handler=None):
        self.connect_live()  # No-op if already connected or not in live mode
        return self._session_manager.start_session(own_message_handler)

    def finish_fritap(self):
        self._session_manager.finish()

    def _provide_custom_hooking_handler(self, handler):
        return handler


    def _internal_callback_wrapper(self):
        def wrapped_handler(message, data):
            self.on_fritap_message(None, message, data)

        return wrapped_handler


    def detach_with_timeout(self, timeout=5):
        """
        Attempt to detach from the instrumented process with a timeout.

        Args:
            process: The instrumented process to detach from.
            timeout: Time in seconds to wait before forcing detachment.
        """
        def detach():
            try:
                if self.debug_output or self.debug:
                    self.logger.debug("Attempting to detach from instrumented process...")
                self._backend.unload_script(self.script)
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

        # Unload plugins
        if hasattr(self, '_plugin_loader'):
            self._plugin_loader.unload_all(self._plugin_shim)

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

        if full_capture and self.traced_scapy_socket_Set:
            if debug_output or debug:
                display_filter = PCAP.get_filter_from_traced_sockets(self.traced_Socket_Set, filter_type="display")
                self.logger.debug(f"Generated Display Filter for Wireshark:\n{display_filter}")

            try:
                self.pcap_obj.create_application_traffic_pcap(self.traced_scapy_socket_Set,self.pcap_obj)
            except Exception as e:
                self.logger.error(f"Error: {e}")

        elif full_capture and not self.traced_scapy_socket_Set:
            if socket_trace:
                self.logger.warning(f"friTap was unable to identify the used sockets. The resulting PCAP _{self.pcap_obj.pcap_file_name} will contain all traffic from the device.")
            else:
                self.logger.info(f"friTap not trace the sockets in use (--socket_tracing option not enabled). The resulting PCAP _{self.pcap_obj.pcap_file_name} will contain all traffic from the device.")

        self.running = False
        self._done_event.set()
        if self.process:
            self.detach_with_timeout()  # Detach instrumented process if applicable
        if not self._detected_libraries and not self._config.hooking.library_scan:
            if self._config.protocol in ("tls", "auto"):
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
        self.special_logger.info("\nThanks for using friTap. Have a great day!")
        if not self._tui_mode:
            sys.exit(0)

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
