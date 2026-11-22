#!/usr/bin/env python3

import json
import logging
import os
import queue
import re
import threading
import time
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from ..about import __version__
from ..agent_socket_fields import (  # noqa: F401 - re-exported (message_router, message_handler, legacy/__init__, tests)
    DEFAULT_SS_FAMILY,
    FILTERABLE_SS_FAMILIES,
    KNOWN_SS_FAMILIES,
    MISSING_ADDRESS,
    coerce_port,
    get_addr_string,
    normalize_ss_family,
    resolve_ss_family,
    sanitize_raw_addr,
)
from ..backends.base import (
    BackendName,
    BackendScriptLoadTimeout,
    BackendTransportError,
    ScriptRuntime,
)
from ..config import FriTapConfig, effective_script_load_timeout, resolve_follow_exec
from ..constants import AGENT_ABI_VERSION, SSL_READ, SSL_WRITE
from ..events import (
    AntiTamperDetectedEvent,
    DatalogEvent,
    EventBus,
    HookBreadcrumbEvent,
    InstrumentEvent,
    KeylogEvent,
    LibraryDetectedEvent,
    PlatformReportEvent,
    ScriptLoadedEvent,
)
from ..fritap_utility import setup_fritap_logging, sha256_file
from ..pcap import PCAP
from .exec_follow import agent_abi_reporter
from .ssl_logger_agent_config import AgentConfigMixin
from .ssl_logger_crash import IOS_CRASH_REPORT_CLOCK_TOLERANCE, CrashReportMixin  # noqa: F401 - re-exported for tests
from .ssl_logger_following import ProcessFollowingMixin
from .ssl_logger_messages import (  # noqa: F401 - ByteBudgetQueue / MESSAGE_QUEUE_* re-exported for tests
    MESSAGE_QUEUE_DROP_LOG_INTERVAL,
    MESSAGE_QUEUE_MAX_BYTES,
    MESSAGE_QUEUE_MAX_MESSAGES,
    AgentMessagesMixin,
    ByteBudgetQueue,
)
from .ssl_logger_outputs import OutputsMixin, _PluginSessionShim  # noqa: F401 - re-exported via friTap.ssl_logger
from .ssl_logger_session import SessionLifecycleMixin
from .ssl_logger_state import (  # noqa: F401 - re-exported for tests
    UNKNOWN_TARGET_OS,
    TargetOS,
    _InstrumentRequest,
)
from .ssl_logger_teardown import TeardownMixin
from .ssl_logger_wine import WINE_BASENAMES, WineMixin  # noqa: F401 - re-exported for friTap.friTap

if TYPE_CHECKING:
    # Annotation-only; the runtime import stays function-local in _build_script_context.
    from ..plugins.script_context import ScriptContext

try:
    import hexdump  # pylint: disable=g-import-not-at-top
except ImportError:
    # Will be handled by logger later
    hexdump = None

# here - where we are.
here = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

# Optional full agent bundle (generic; absent from public builds) and the
# sidecar written by dev/compile_agent.sh holding the sha256 of the public
# bundle it was built alongside.
FULL_AGENT_BUNDLE_NAME = "fritap_agent_full.js"
FULL_AGENT_BUNDLE_SIDECAR_SUFFIX = ".src"


def _full_bundle_in_sync(full_bundle, public_bundle):
    """True if the full bundle's sidecar hash matches the public bundle."""
    try:
        with open(full_bundle + FULL_AGENT_BUNDLE_SIDECAR_SUFFIX, encoding="utf-8") as fh:
            expected = fh.read().strip().lower()
        return bool(expected) and expected == sha256_file(public_bundle)
    except (OSError, ValueError):
        # Missing, unreadable or non-UTF-8 sidecar (UnicodeDecodeError is a ValueError).
        return False


def _release_lsass_keylog_writer(logger):
    """Stop the separate LSASS worker session so it releases the shared ``-k`` file.

    The LSASS SSL_Logger (``hook_lsass`` in friTap.py) holds the keylog and the shared
    -p/--json handlers open until torn down; the CLI only stops it from an ``atexit``
    hook that ``os._exit`` skips. Idempotent and never raises.
    """
    try:
        from ..friTap import cleanup_lsass_hook
        cleanup_lsass_hook()
    except Exception:  # noqa: BLE001 - best effort; the relabel handles a held file
        logger.debug("Could not stop the LSASS hook before the keylog relabel",
                     exc_info=True)


class _PayloadModWatcher(FileSystemEventHandler):
    """-pm: push ./readmod.bin / ./writemod.bin to the main agent when modified.

    The agent's ``recv("readmod"|"writemod")`` expects the bytes as a hex string.
    ``self.script`` is looked up at event time so an exec'd image's new main agent is reached.
    """

    _FILES = (("readmod", "./readmod.bin"), ("writemod", "./writemod.bin"))

    def __init__(self, ssl_logger):
        super().__init__()
        self._ssl_logger = ssl_logger

    def on_any_event(self, event):
        if event.event_type != "modified":
            return
        for msg_type, path in self._FILES:
            if msg_type in event.src_path:
                self._post_file(msg_type, path)
                return

    def _post_file(self, msg_type, path):
        logger = self._ssl_logger
        script = getattr(logger, "script", None)
        if script is None:
            return
        try:
            with open(path, "rb") as f:
                buffer = f.read()
            logger._backend.post_message(script, msg_type, buffer.hex())
        except Exception as e:  # noqa: BLE001 - never kill the watchdog thread
            logger.logger.error(f"Watcher error: {e}")


class SSL_Logger(
    AgentConfigMixin,
    AgentMessagesMixin,
    OutputsMixin,
    ProcessFollowingMixin,
    SessionLifecycleMixin,
    TeardownMixin,
    CrashReportMixin,
    WineMixin,
):

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
        # Set by an embedding host (the API's FriTapSession, the TUI) whose
        # interpreter must outlive the session; see _owns_process_exit().
        self._embedded = False

        self.logger, self.special_logger = setup_fritap_logging(
            debug=self._config.debug, debug_output=self._config.debug_output
        )

        if hexdump is None:
            self.logger.warning("Unable to import hexdump module! Hexdump functionality will be disabled.")

        self._init_queues_and_workers()
        self._init_process_following()
        self._init_target_state()
        self._init_event_bus_and_backend()
        self._init_protocol_registry()

        from .session_manager import SessionManager
        self._session_manager = SessionManager(self)

        from ..message_router import MessageRouter
        self._message_router = MessageRouter(self._event_bus, active_protocol=list(self._config.protocols))
        self._open_learned_offsets()

        self._install_display_filter()
        self._init_capture_tracking()
        self._init_live_scan_state()
        self._init_session_data()

        self.init_fritap()

    def _init_queues_and_workers(self) -> None:
        """Runtime flags, the bounded Frida message queue and the instrument queue."""
        self.pcap_obj = None
        self.script = None
        self.own_message_handler = None
        self.running = True
        self._done_event = threading.Event()

        # Decouples the Frida callback from processing; avoids GIL contention
        # that freezes the TUI under high message rates.
        self._message_queue: queue.Queue = ByteBudgetQueue(
            maxsize=MESSAGE_QUEUE_MAX_MESSAGES, max_bytes=MESSAGE_QUEUE_MAX_BYTES)
        self._consumer_stop = threading.Event()
        self._consumer_thread: threading.Thread | None = None
        self._queue_drop_count = 0
        self._queue_drops_reported = 0
        self._queue_drop_logged_at = 0.0

        # Child/spawn gating events arrive on Frida's own event thread, where
        # instrument() must never run: it blocks in script.load() while the
        # agent installs its hooks.
        self._instrument_queue: queue.Queue = queue.Queue(maxsize=256)
        self._instrument_stop = threading.Event()
        self._instrument_thread: threading.Thread | None = None
        self._instrument_thread_lock = threading.Lock()
        # Every pid friTap holds suspended and still owes a resume (the spawned
        # target, each gated child/spawn). Teardown resumes whatever is left
        # (see _resume_suspended_pids).
        self._suspended_pids: set = set()
        self._suspended_pids_lock = threading.Lock()

    def _init_target_state(self) -> None:
        """Per-target state: process, device, loaded data files, traced sockets."""
        self.target_threads = None
        self.tmpdir = None
        self.filename = ""
        self.startup = True
        self.process = None
        self.pid = None
        # Set after a numeric-PID attach (see apply_resolved_process_name).
        self.resolved_process_name = None
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
        # -f --attribute-sdk request-context writer (_attach_request_context_sidecar).
        self._request_context_sidecar = None
        # Kept so readers resolve its lazily opened file at call time (_live_keylog_file).
        self._tls_keylog_handler = None

    def _init_event_bus_and_backend(self) -> None:
        """The event bus, the output-handler list and the instrumentation backend."""
        self._event_bus = EventBus()
        self._output_handlers = []
        self._handlers_active = False
        from ..backends import get_backend
        self._backend = get_backend(self._config.backend)

    def _init_protocol_registry(self) -> None:
        """The protocol registry and active handler; raises on an unregistered protocol."""
        # "auto" and "all" install the same hooks (only the user confirmation
        # differs) and keep every built-in registered so a LibraryDetectedEvent
        # can swap the active handler; an explicit selection loads only its hooks.
        from ..protocols.registry import create_default_registry
        if self._config.protocol in ("auto", "all"):
            self._protocol_registry = create_default_registry()
            self._detected_libraries = set()
            # TLS is the default until a LibraryDetectedEvent refines it.
            self._protocol_handler = self._protocol_registry.get("tls") \
                or next(iter(self._protocol_registry.get_all()), None)
        else:
            # Register every selected protocol's handler (e.g. ["tls", "rc4"]) so
            # all their hooks, keylog formatters and pcap wiring exist. The first
            # selection stays the active handler for single-handler call sites
            # (pcap protocol, auto-detect fallback).
            self._protocol_registry = create_default_registry(list(self._config.protocols))
            self._detected_libraries = set()
            self._protocol_handler = self._protocol_registry.get(self._config.protocol)
            if self._protocol_handler is None:
                raise RuntimeError(
                    f"Protocol '{self._config.protocol}' is not registered; "
                    "available: " + ", ".join(self._protocol_registry.list_protocols())
                )

        # Validate every selected handler, not just the primary; auto/all
        # resolve to no single handler and are skipped inside the validator.
        for _proto_name in self._config.protocols:
            _proto_handler = self._protocol_registry.get(_proto_name)
            if _proto_handler is not None:
                self._config.validate_protocol_backend(_proto_handler, _proto_name)

    def _install_display_filter(self) -> None:
        """Install the headless display filter when one is configured."""
        # Every headless entry point passes through here, so the policy is
        # enforced once: an invalid expression, or one using flow-only fields
        # (which would drop every data event), is logged and not installed.
        if self._config.output.filter_expression:
            try:
                from ..filter.pipeline_filter import build_headless_filter
                engine = build_headless_filter(self._config.output.filter_expression)
                if isinstance(engine, str):
                    self.logger.warning("%s", engine)
                else:
                    self._message_router.set_filter(engine)
                    self.logger.info(
                        "Display filter active: %s",
                        self._config.output.filter_expression,
                    )
            except Exception as e:
                self.logger.warning("Invalid filter expression: %s", e)

    def _init_capture_tracking(self) -> None:
        """Event-bus subscriptions plus the capture and crash-attribution state they feed."""
        self._event_bus.subscribe(LibraryDetectedEvent, self._on_library_detected)

        # `_detected_libraries` is only filled by the native LibraryDetectedEvent
        # path, so key paths that never emit it (Java Secret-Chat/E2E hooks, the
        # memory-scan engine) would wrongly trigger the "No <PROTO> libraries were
        # detected" exit hint. Every keylog producer emits a KeylogEvent, so one
        # subscription gives a source-agnostic "did we get keys?".
        self._captured_any_secret = False
        self._event_bus.subscribe(KeylogEvent, self._on_keylog_captured)
        self._event_bus.subscribe(DatalogEvent, self._on_traffic_captured)

        # Crash attribution: the last hook the agent reported entering, so
        # on_detach can name it if the target dies inside a hook. Memory only.
        self._last_hook_breadcrumb = ""
        # After "agent-init: complete" a script error is non-fatal (_is_fatal_script_error).
        self._agent_init_complete = False
        self._crash_reported = False
        self._event_bus.subscribe(HookBreadcrumbEvent, self._on_hook_breadcrumb)
        # The agent's platform-branch report; under --probe it also proves the
        # loaded bundle understands probe mode.
        self._platform_report = None
        self._platform_report_received = threading.Event()
        self._event_bus.subscribe(PlatformReportEvent, self._on_platform_report)
        # A reported anti-tamper runtime (e.g. PairIP), so a later
        # process-terminated crash can be attributed to it.
        self._anti_tamper_seen = ""
        self._event_bus.subscribe(AntiTamperDetectedEvent, self._on_anti_tamper_detected)
        # Native crash captured via the device 'process-crashed' signal, so the
        # later 'detached' handler can report the real cause when the detach
        # carries no crash object.
        self._pending_crash = None
        # Filled by _enrich_crash_log_ios() for the guidance block.
        self._ios_crash_report = None
        self._ios_crash_verdict = None
        # Filled by _enrich_crash_log_macos().
        self._macos_crash_report = None
        # Lower bound for "this crash report belongs to this run". Taken in the
        # constructor because every entry point goes through it; too early only
        # widens the window, too late would discard the report we want.
        self._session_start_time = time.time()

    def _init_live_scan_state(self) -> None:
        """Lazy FlowCollector slot and the live passive-analysis state."""
        # Created lazily, only when a plugin or the TUI asks (the TUI makes its own).
        self._flow_collector = None

        # Live --scan state, set up by _setup_live_scan(). Completed flows go
        # onto a bounded queue drained by a daemon thread, so analyzers never
        # run on the Frida callback thread.
        self._scan_plugins = []
        self._scan_queue = None
        self._scan_thread = None
        self._scan_stop = threading.Event()
        self._scan_drop_count = 0

    def _init_session_data(self) -> None:
        """The JSON session document skeleton."""
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

    def cleanup(self, live=False, socket_trace=False, full_capture=False, debug_output=False, debug=False,
                *, exit_process=True):
        """TeardownMixin.cleanup, then mark the teardown finished for wait_for_completion.

        Only the call that ran the steps marks it; a repeated call returns at once.
        On the CLI cleanup() usually ends in os._exit, so the mark matters only
        when it returns (or for the main thread waiting meanwhile)."""
        runs_teardown = not getattr(self, "_cleanup_done", False)
        try:
            return super().cleanup(live, socket_trace, full_capture, debug_output, debug,
                                   exit_process=exit_process)
        finally:
            if runs_teardown:
                self._teardown_finished.set()

    def _detach_with_cli_timeout(self) -> None:
        """Teardown's detach step, then a check that the target survived it.

        Wraps TeardownMixin's step: a target that crashes on the detach would
        otherwise end in a clean-looking exit (see CrashReportMixin).
        """
        super()._detach_with_cli_timeout()
        self._report_crash_after_detach()

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
    def target_argv(self) -> "list[str] | None":
        # Original argv tokens for spawn mode (None otherwise); avoids re-splitting target_app on spaces.
        return self._config.target_argv

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
    def exec_following_requested(self) -> bool:
        """Exec() is followed (target and children) only with --follow-exec; see config.resolve_follow_exec."""
        return resolve_follow_exec(self._config.device)

    @property
    def gates_children(self) -> bool:
        """Whether instrumented sessions gate their children (exec() is only caught that way)."""
        return self.exec_following_requested or bool(self.enable_child_gating)

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
    def wine_mode(self) -> str:
        return getattr(self._config.hooking, "wine_mode", "auto")

    @property
    def backend_explicit(self) -> bool:
        return getattr(self._config, "backend_explicit", False)

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

    @property
    def probe(self) -> bool:
        """--probe: dry run that reports the platform branch and installs no hooks."""
        return bool(getattr(self._config.hooking, 'probe', False))

    def init_fritap(self):
        self.agent_script = "fritap_agent.js"
        # Logged once so a run visibly confirms an overridden bundle (see _resolve_agent_bundle_path).
        _bundle_override = os.environ.get("FRITAP_AGENT_BUNDLE")
        if _bundle_override:
            self.logger.info("Loading agent bundle from FRITAP_AGENT_BUNDLE override: %s",
                             os.path.abspath(os.path.expanduser(_bundle_override)))

        if self.pcap_name:
            self.pcap_obj =  PCAP(self.pcap_name,SSL_READ,SSL_WRITE,self.full_capture, self.mobile,self.debug_output,
                                  owner_capture=self._config.output.owner_capture,
                                  owner_capture_opts={
                                      'strict': self._config.output.owner_strict,
                                      'no_dns': self._config.output.owner_no_dns,
                                      'nflog_group': self._config.output.owner_nflog_group,
                                  },
                                  target_package=self.target_app,
                                  target_pid=getattr(self, 'pid', None),
                                  include_loopback=getattr(self._config.output, 'include_loopback', False),
                                  filter_infrastructure=getattr(self._config.output, 'filter_infrastructure', True),
                                  pcap_format=self._config.output.pcap_container)
            self._seed_known_server_ports()


        if self.offsets is not None:
            self._load_offsets_data()

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

        # Non-Frida backends need the protocol processor and its own agent script.
        self._processor = None
        self._agent_script_path = None
        if self._config.backend != BackendName.FRIDA:
            processor_cls = self._protocol_registry.get_processor(self._config.protocol)
            if processor_cls is not None:
                self._processor = processor_cls(event_bus=self._event_bus)
            self._agent_script_path = self._protocol_registry.get_agent_script_path(
                self._config.protocol, self._config.backend
            )

        self._setup_output_handlers()
        self._handlers_active = True

    def _load_script_bounded(self, script) -> None:
        """Load an agent script under the configured time bound.

        The backend cannot see the agent's progress trail, so the last reported stage is
        attached to its ``BackendScriptLoadTimeout`` here for the CLI to name.
        """
        try:
            self._backend.load_script(
                script, timeout=effective_script_load_timeout(self._config)
            )
        except BackendScriptLoadTimeout as exc:
            if not exc.breadcrumb:
                exc.breadcrumb = self._last_hook_breadcrumb
            raise

    def _build_script_context(self, process, device, runtime) -> "ScriptContext":
        """Build the plugin-facing :class:`ScriptContext` snapshot.

        It is the seam between plugins and the host, so everything is resolved here, including
        the ``script.load()`` bound, which plugins share with the main agent (a wedged plugin
        script is just as uncancellable).
        """
        from ..plugins.script_context import ScriptContext

        return ScriptContext(
            backend=self._backend, process=process, device=device,
            runtime=runtime, event_bus=self._event_bus,
            backend_name=self._backend.name, debug=self.debug,
            debug_output=self.debug_output,
            script_load_timeout=effective_script_load_timeout(self._config),
        )

    def _is_memory_scan_only(self) -> bool:
        """Whether this run loads only the heap scanner (:func:`friTap.config.memory_scan_only`)."""
        from ..config import memory_scan_only
        return memory_scan_only(self._config)

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

        # With -ms alone the main TLS-hooking agent has nothing to do, so only
        # the memory scan runs. An own_message_handler consumes the MAIN agent's
        # messages, so it keeps that agent (and returns a live script to the
        # API caller).
        memory_scan_only = self._is_memory_scan_only() and own_message_handler is None

        script = None
        from ..plugins.script_plugin import ScriptLoadOrder

        if not memory_scan_only:
            script_string = self.get_agent_script()
            # Before load: a stale bundle fails during script.load(), too late
            # for the RPC-based check below.
            self._warn_on_stale_agent_bundle(script_string)
            if self.debug_output:
                self.logger.debug(f"loading friTap agent script: {self.agent_script}")

            if self.offsets_data is not None:
                self.logger.info(f"applying hooks at offset {self.offsets_data}")

            if self.pattern_data is not None:
                self.logger.info(self._describe_pattern_source())
        else:
            # Reached by -ms with no agent-backed output (-f takes its pcap from
            # tcpdump) or by a memory-only extraction method (hooking.intercept=False).
            self.logger.info(
                "memory-scan only (no hook-backed output requested; -f captures "
                "traffic via tcpdump): skipping the main friTap agent; the heap "
                "secret-scanner supplies the key material."
            )

        context = self._build_script_context(process, self.device, runtime)

        # BEFORE_MAIN script plugins (e.g. --custom_script).
        if hasattr(self, '_plugin_loader'):
            self._plugin_loader.instrument_all(context, order=ScriptLoadOrder.BEFORE_MAIN)

        # self.script is the MAIN target's agent only (the one graceful_detach,
        # the detach report and the unload address). Child agents live in _child_agents.
        is_main = self._is_main_target(process)

        if not memory_scan_only:
            # Local handle: the steps below must act on the script just created, whichever process it is.
            script = self._backend.create_script(process, script_string, runtime=runtime)
            if is_main:
                self.script = script
            else:
                self._register_child_agent(process, script)
            tracker = getattr(self, "_tracker", None)
            if tracker is not None:
                tracker.note_script(process, script)

            if self.debug and self._backend.version_at_least(16):
                self._backend.enable_debugger(script, debug_port)

            if own_message_handler is not None:
                self._backend.on_message(script, self._provide_custom_hooking_handler(own_message_handler))
                return script
            else:
                self._backend.on_message(script, self._internal_callback_wrapper(script))
            self._load_script_bounded(script)

            # Non-fatal ABI check of self.script (the main agent); a child runs
            # the same bundle.
            if is_main:
                self._check_agent_abi()

            self._event_bus.emit(ScriptLoadedEvent(
                script_name=self.agent_script, plugin_name="", load_order="main",
            ))
        elif is_main:
            # No main agent this run; the memory-scan plugin owns the session.
            self.script = None

        # AFTER_MAIN script plugins.
        if hasattr(self, '_plugin_loader'):
            self._plugin_loader.instrument_all(context, order=ScriptLoadOrder.AFTER_MAIN)

        # Started after the main agent hooks are in place; it owns its own
        # script/session. The heap scanner is best-effort, so a start failure
        # is logged and must not take down the main capture.
        if getattr(self, "_memory_scan_engine", None) is not None:
            try:
                self._memory_scan_engine.start(context)
            except Exception:  # noqa: BLE001 - a scanner failure must not abort the capture
                self.logger.warning(
                    "memory-scan: heap scanner failed to start; continuing without it",
                    exc_info=True,
                )

        self._event_bus.emit(InstrumentEvent(
            target=self.target_app, backend=self._backend.name,
        ))

        if self.payload_modification:
            # One watcher per session, started on the first instrument() only
            # (children are instrumented through here too).
            self._start_payload_mod_watcher()

        return script

    def start_fritap_session_instrumentation(self, own_message_handler, process):
        self.process = process

        if self._config.proxy:
            self._inject_proxy_redirector(process)

        script = self.instrument(self.process, own_message_handler)
        return script

    @staticmethod
    def _parse_proxy_address(addr: str) -> tuple:
        """Parse host:port string, handling IPv6 bracket notation."""
        # IPv6 bracket form: [::1]:8080
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
            from fritap_proxy import ProxyConfig, ProxyRedirector, ProxyTarget
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

    def start_fritap_session(self, own_message_handler=None):
        if self._should_use_wine_frida_watch():
            return self._run_wine_frida_watch_session(own_message_handler)
        if self._should_use_wine_gdb():
            return self._run_wine_gdb_session(own_message_handler)
        self.connect_live()  # no-op if already connected or not in live mode
        # Before instrumentation, so no flows are missed.
        self._setup_live_scan()
        self._start_consumer_thread()
        # Before gating is enabled, so the first child/spawn event has a thread to run on.
        if self.enable_child_gating or self.enable_spawn_gating or self.spawn_gating_all:
            self._start_instrument_thread()
        try:
            return self._session_manager.start_session(own_message_handler)
        except BaseException as exc:
            # start_session returns right after the capture start point, so a
            # transport error here is the target or device link dying during
            # startup: a runtime error, not "target detached".
            if isinstance(exc, BackendTransportError) and not self.capture_started():
                self._report_death_before_capture(f"transport error: {exc}")
            # A spawned target is resumed only after instrumentation succeeds, so
            # any raise in between (load timeout, failed hook install, Ctrl+C)
            # would leave it suspended forever.
            self._resume_uninstrumented_spawn()
            raise

    def _resume_uninstrumented_spawn(self) -> None:
        """Resume a spawned target we failed to instrument.

        Left suspended, the platform watchdog kills it and the user sees the target's own
        crash (``0x8badf00d`` on iOS) instead of friTap's instrumentation failure. The backend
        offers no kill, and a running-but-uninstrumented target beats a phantom crash, so the
        error log says loudly that it now runs without instrumentation.
        """
        if not self.spawn or self.pid is None or self.device is None:
            return
        if self._death_before_capture:
            # Already explained; the pid is probably gone, so resume quietly.
            self._resume_suspended(self.pid)
            return
        self.logger.error(
            "Instrumentation failed — resuming spawned pid %s so it is not left "
            "suspended. It is now running WITHOUT friTap instrumentation; no "
            "traffic will be captured from it.", self.pid
        )
        self._resume_suspended(self.pid)

    def _start_payload_mod_watcher(self) -> None:
        """Start the -pm file watcher once per session; later calls are no-ops."""
        if getattr(self, "_observer", None) is not None:
            return
        self.logger.debug("Init watcher")
        observer = Observer()
        observer.schedule(_PayloadModWatcher(self), os.getcwd())
        observer.start()
        self._observer = observer

    def _stop_payload_mod_watcher(self) -> None:
        """Stop and join the -pm file watcher (bounded); idempotent."""
        observer = getattr(self, "_observer", None)
        if observer is None:
            return
        self._observer = None
        try:
            observer.stop()
            observer.join(timeout=5)
        except Exception:  # noqa: BLE001 - teardown must not break on the watcher
            self.logger.debug("payload-mod watcher stop failed", exc_info=True)

    def _resolve_agent_bundle_path(self):
        """Resolve the agent bundle path to load (Frida backend).

        Not the non-Frida ``self._agent_script_path`` attribute. Precedence:
          1. ``FRITAP_AGENT_BUNDLE`` env var (``~`` expanded, relative to the cwd); always wins.
          2. A ``fritap.agent_bundle`` entry point whose ABI matches AGENT_ABI_VERSION
             (see _discover_agent_bundle).
          3. ``here/fritap_agent_full.js`` while in sync with the shipped bundle
             (see _resolve_full_agent_bundle).
          4. The shipped bundle (``here/self.agent_script``).

        Steps 2-4 are cached on the instance: child gating calls this per child and
        the full-bundle check hashes the public bundle.
        """
        override = os.environ.get("FRITAP_AGENT_BUNDLE")
        if override:
            return os.path.abspath(os.path.expanduser(override))
        cached = getattr(self, "_resolved_agent_bundle", None)
        if cached is None:
            cached = self._discover_agent_bundle()
            if not cached:
                default_bundle = os.path.join(here, self.agent_script)
                cached = self._resolve_full_agent_bundle(default_bundle) or default_bundle
            self._resolved_agent_bundle = cached
        return cached

    def _resolve_full_agent_bundle(self, default_bundle):
        """Return ``here/fritap_agent_full.js`` if present and in sync, else ``None``.

        The build script writes a sidecar ``.src`` with the sha256 of the public bundle. A
        missing sidecar or a hash differing from ``default_bundle`` means the full bundle is
        stale (it would lose public fixes), so this warns and falls back. The caller caches
        the result, so each message is logged once per instance.
        """
        full_bundle = os.path.join(here, FULL_AGENT_BUNDLE_NAME)
        if not os.path.isfile(full_bundle):
            return None
        if _full_bundle_in_sync(full_bundle, default_bundle):
            self.logger.info("Loading full agent bundle: %s", full_bundle)
            return full_bundle
        self.logger.warning(
            "full agent bundle is older than the public agent — rebuild with "
            "./dev/compile_agent.sh; falling back to the public bundle")
        return None

    def _discover_agent_bundle(self):
        """Return a bundle path from a ``fritap.agent_bundle`` entry point whose ABI matches, else ``None``.

        The entry point exposes ``AGENT_ABI_VERSION`` plus ``agent_bundle_path()`` or
        ``AGENT_BUNDLE_PATH``. ABI-mismatched, unloadable or missing-file contributions
        are skipped; the first valid match wins.
        """
        try:
            from importlib.metadata import entry_points
        except ImportError:  # pragma: no cover - py<3.8
            return None
        try:
            eps = entry_points(group="fritap.agent_bundle")  # py>=3.10 selection API
        except TypeError:  # pragma: no cover - py3.8/3.9 fallback
            eps = entry_points().get("fritap.agent_bundle", [])
        for ep in eps:
            try:
                obj = ep.load()
            except Exception as e:  # noqa: BLE001 - a broken contribution must not abort the load
                if self.debug_output or self.debug:
                    self.logger.debug("agent bundle entry point %r failed to load: %s", ep.name, e)
                continue
            abi = getattr(obj, "AGENT_ABI_VERSION", None)
            if abi != AGENT_ABI_VERSION:
                # Warn, not debug: a silently skipped extended bundle looks like
                # "my extra hooks stopped working"; the user needs the version pair.
                self.logger.warning(
                    "Agent bundle entry point %r declares ABI %s but this friTap "
                    "expects ABI %s — skipping it and falling back to the bundled "
                    "agent. Update that package to a build matching this friTap.",
                    ep.name, abi, AGENT_ABI_VERSION)
                continue
            getter = getattr(obj, "agent_bundle_path", None)
            path = getter() if callable(getter) else getattr(obj, "AGENT_BUNDLE_PATH", None)
            if not path:
                continue
            path = os.path.abspath(os.path.expanduser(path))
            if os.path.isfile(path):
                self.logger.info("Loading agent bundle from entry point %r: %s", ep.name, path)
                return path
            if self.debug_output or self.debug:
                self.logger.debug("agent bundle entry point %r path not found: %s", ep.name, path)
        return None

    def _check_agent_abi(self):
        """Warn when the loaded bundle's ABI differs from AGENT_ABI_VERSION (config_batch fields, ContentTypes, rpc.exports).

        Non-fatal. Only the blocking ``exports_sync`` proxy is used (the async proxy
        returns a coroutine); older bundles without the export are tolerated.
        """
        reporter = agent_abi_reporter(self.script)
        if reporter is None:
            return  # async-only proxy or older bundle — skip
        try:
            bundle_abi = reporter()
        except Exception as e:  # noqa: BLE001 - never let a version probe break capture
            if self.debug_output or self.debug:
                self.logger.debug("agent_abi_version RPC failed: %s", e)
            return
        if bundle_abi != AGENT_ABI_VERSION:
            self.logger.warning(
                "Agent bundle ABI %s does not match host ABI %s — the loaded "
                "bundle may be stale or built against a different JS<->Python "
                "boundary; rebuild the agent (./dev/compile_agent.sh) if hooks "
                "misbehave.", bundle_abi, AGENT_ABI_VERSION)

    # The ABI constant as frida-compile emits it (`AGENT_ABI_VERSION = <n>`)
    # from agent/shared/generated_constants.ts.
    _AGENT_ABI_PATTERN = re.compile(r"AGENT_ABI_VERSION\s*=\s*(\d+)")

    @staticmethod
    def _check_agent_abi_static(source: str):
        """Read the ABI from the bundle *source* before it loads; ``None`` when undeterminable.

        The RPC-based ``_check_agent_abi`` runs only after load, too late for a stale bundle
        that misbehaves during load. Non-fatal: a hand-built bundle may lack the constant.
        """
        if not isinstance(source, str):
            return None
        match = SSL_Logger._AGENT_ABI_PATTERN.search(source)
        return int(match.group(1)) if match else None

    def _warn_on_stale_agent_bundle(self, source: str) -> None:
        """Warn when the bundle about to be loaded was built for another ABI."""
        bundle_abi = self._check_agent_abi_static(source)
        if bundle_abi is None:
            if self.debug_output or self.debug:
                self.logger.debug(
                    "agent bundle declares no ABI constant; skipping the static check")
            return
        if bundle_abi != AGENT_ABI_VERSION:
            self.logger.warning(
                "Agent bundle at %s was built for ABI %s but this friTap expects "
                "ABI %s. The bundle is pre-compiled — nothing rebuilds it at run "
                "time — so rebuild it with ./dev/compile_agent.sh before trusting "
                "this run.", self._resolve_agent_bundle_path(), bundle_abi,
                AGENT_ABI_VERSION)

    def get_agent_script(self):
        with open(self._resolve_agent_bundle_path(), encoding='utf-8', newline='\n') as f:
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
        return self._resolve_agent_bundle_path()
