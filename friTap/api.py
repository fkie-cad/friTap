#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Clean builder-pattern API for programmatic friTap usage.

Usage:
    from friTap import FriTap

    # Simple key extraction
    session = (
        FriTap("com.example.app")
        .mobile()
        .keylog("keys.log")
        .start()
    )

    # With callbacks
    session = (
        FriTap("com.example.app")
        .mobile("device-id")
        .pcap("capture.pcap")
        .on_keylog(lambda e: print(e.key_data))
        .on_data(lambda e: print(f"{e.src_addr}:{e.src_port} -> {e.dst_addr}:{e.dst_port}"))
        .start()
    )
"""

from __future__ import annotations
import logging
from typing import Callable, List, Optional, TYPE_CHECKING

from .config import FriTapConfig, DeviceConfig, OutputConfig, HookingConfig
from .events import EventBus, KeylogEvent, DatalogEvent, LibraryDetectedEvent, SessionEvent, FlowEvent

if TYPE_CHECKING:
    from .ssl_logger import SSL_Logger


class FriTapSession:
    """
    Handle to a running friTap capture session.

    Returned by :meth:`FriTap.start`. Provides methods to interact
    with or stop the session.
    """

    def __init__(self, ssl_logger: "SSL_Logger", event_bus: EventBus, flow_collector=None) -> None:
        self._logger_instance = ssl_logger
        self._event_bus = event_bus
        self._flow_collector = flow_collector  # kept alive to prevent GC

    @property
    def event_bus(self) -> EventBus:
        """Access the event bus for subscribing to live events."""
        return self._event_bus

    @property
    def is_running(self) -> bool:
        return self._logger_instance.running

    def stop(self) -> None:
        """Gracefully stop the capture session."""
        self._logger_instance.finish_fritap()

    def wait(self) -> None:
        """Block until the session ends (e.g. process exits)."""
        while self._logger_instance.running:
            import time
            time.sleep(0.1)


class FriTap:
    """
    Builder-pattern API for configuring and starting a friTap session.

    Each setter method returns ``self`` for chaining.
    """

    def __init__(self, target: str) -> None:
        self._target = target
        self._device = DeviceConfig()
        self._output = OutputConfig()
        self._hooking = HookingConfig()
        self._protocol = "tls"
        self._backend_name = "frida"
        self._debug = False
        self._debug_output = False
        self._custom_hook_script: Optional[str] = None
        self._environment_file: Optional[str] = None
        self._install_lsass_hook = True
        self._proxy_address: Optional[str] = None

        # Event callbacks registered before start()
        self._keylog_callbacks: List[Callable] = []
        self._data_callbacks: List[Callable] = []
        self._library_callbacks: List[Callable] = []
        self._session_callbacks: List[Callable] = []
        self._flow_callbacks: List[Callable] = []

        self._logger = logging.getLogger("friTap.api")

        # Script plugins registered before start()
        self._script_plugins: List = []

    # ------------------------------------------------------------------
    # Device configuration
    # ------------------------------------------------------------------

    def mobile(self, device_id: Optional[str] = None) -> "FriTap":
        """Target a mobile device (USB or by device ID)."""
        self._device.mobile = device_id if device_id else True
        return self

    def host(self, address: str) -> "FriTap":
        """Target a remote Frida device."""
        self._device.host = address
        return self

    def spawn(self, enable: bool = True) -> "FriTap":
        """Spawn the target instead of attaching."""
        self._device.spawn = enable
        return self

    def spawn_gating(self, enable: bool = True, all_processes: bool = False) -> "FriTap":
        """Enable spawn gating for multi-process apps."""
        self._device.enable_spawn_gating = enable
        self._device.spawn_gating_all = all_processes
        return self

    def child_gating(self, enable: bool = True) -> "FriTap":
        """Enable child process gating."""
        self._device.enable_child_gating = enable
        return self

    def timeout(self, seconds: int) -> "FriTap":
        """Set timeout before resuming the target process."""
        self._device.timeout = seconds
        return self

    # ------------------------------------------------------------------
    # Output configuration
    # ------------------------------------------------------------------

    def pcap(self, path: str) -> "FriTap":
        """Write decrypted traffic to a PCAP file.

        The filename extension is authoritative: ``.pcap`` writes classic
        libpcap, ``.pcapng`` writes pcapng (with embedded DSB if keys are
        extracted). Extension overrides any prior call to :meth:`pcapng`.
        """
        self._output.pcap = path
        return self

    def pcapng(self, path: str) -> "FriTap":
        """Write self-decrypting PCAPNG (with DSB).

        Equivalent to :meth:`pcap` with a ``.pcapng`` extension. If `path`
        has a different extension, the extension still wins — e.g.
        ``.pcapng("a.pcap")`` writes classic libpcap.
        """
        self._output.pcap = path
        self._output.output_format = "pcapng"
        return self

    def keylog(self, path: str) -> "FriTap":
        """Write key material in the Wireshark-loadable format for the active protocol.

        The exact format follows the protocol selected via :meth:`protocol`:
        NSS SSLKEYLOGFILE for TLS, ``<cookie> SHARED_SECRET <hex>`` for SSH.
        With ``--protocol all|auto`` and multiple protocols emitting keys,
        ``path`` is split per protocol as ``<stem>.<proto><ext>`` (for example,
        ``keys.log`` → ``keys.tls.log`` and ``keys.ssh.log``).
        """
        self._output.keylog = path
        return self

    def json_output(self, path: str) -> "FriTap":
        """Write session metadata as JSON."""
        self._output.json_output = path
        return self

    def verbose(self, enable: bool = True) -> "FriTap":
        """Enable verbose console output."""
        self._output.verbose = enable
        return self

    def live(self, enable: bool = True) -> "FriTap":
        """Stream to Wireshark via named pipe."""
        self._output.live = enable
        return self

    def full_capture(self, enable: bool = True) -> "FriTap":
        """Do a full network capture (not just decrypted payload)."""
        self._output.full_capture = enable
        return self

    # ------------------------------------------------------------------
    # Hooking configuration
    # ------------------------------------------------------------------

    def patterns(self, path: str) -> "FriTap":
        """Use pattern-based hooking from a JSON file."""
        self._hooking.patterns = path
        return self

    def offsets(self, path: str) -> "FriTap":
        """Use offset-based hooking from a JSON file."""
        self._hooking.offsets = path
        return self

    def experimental(self, enable: bool = True) -> "FriTap":
        """Enable experimental features."""
        self._hooking.experimental = enable
        return self

    def anti_root(self, enable: bool = True) -> "FriTap":
        """Enable anti-root detection hooks (Android)."""
        self._hooking.anti_root = enable
        return self

    def payload_modification(self, enable: bool = True) -> "FriTap":
        """Enable payload modification capability."""
        self._hooking.payload_modification = enable
        return self

    def force_scan(self, name: str) -> "FriTap":
        """Force-scan a specific module even when friTap would otherwise skip
        it due to Cronet-split-topology suppression.

        ``name`` may be a literal module name, a stem prefix (suffix with
        ``*``) or a regex prefixed with ``re:``.  May be called multiple
        times.
        """
        if name and name not in self._hooking.force_scan_modules:
            self._hooking.force_scan_modules.append(name)
        return self

    # ------------------------------------------------------------------
    # Protocol & backend
    # ------------------------------------------------------------------

    def protocol(self, proto: str) -> "FriTap":
        """Set the target protocol: tls, ipsec, ssh, signal, smb3, auto."""
        self._protocol = proto
        return self

    def backend(self, backend: str) -> "FriTap":
        """Set the instrumentation backend: frida, ebpf, gdb, lldb."""
        self._backend_name = backend
        return self

    # ------------------------------------------------------------------
    # Debug
    # ------------------------------------------------------------------

    def debug(self, enable: bool = True) -> "FriTap":
        """Enable debug mode with Chrome Inspector."""
        self._debug = enable
        self._debug_output = enable
        return self

    def debug_output(self, enable: bool = True) -> "FriTap":
        """Enable debug output only (no inspector)."""
        self._debug_output = enable
        return self

    # ------------------------------------------------------------------
    # Misc
    # ------------------------------------------------------------------

    def custom_script(self, path: str) -> "FriTap":
        """Load a custom Frida script before friTap hooks."""
        self._custom_hook_script = path
        return self

    def add_script_plugin(self, plugin) -> "FriTap":
        """Register a ScriptPlugin to be loaded when the session starts."""
        self._script_plugins.append(plugin)
        return self

    def environment(self, path: str) -> "FriTap":
        """Provide environment variables JSON for spawn."""
        self._environment_file = path
        return self

    def proxy(self, address: str) -> "FriTap":
        """Redirect connections to a proxy and bypass cert pinning.

        Requires the ``fritap-proxy`` package (``pip install fritap-proxy``).

        Parameters
        ----------
        address
            Proxy address in ``host:port`` format (e.g., ``127.0.0.1:8080``).
        """
        self._proxy_address = address
        return self

    # ------------------------------------------------------------------
    # Event callbacks
    # ------------------------------------------------------------------

    def on_keylog(self, callback: Callable) -> "FriTap":
        """Register a callback for key material extraction events."""
        self._keylog_callbacks.append(callback)
        return self

    def on_data(self, callback: Callable) -> "FriTap":
        """Register a callback for decrypted data events."""
        self._data_callbacks.append(callback)
        return self

    def on_library_detected(self, callback: Callable) -> "FriTap":
        """Register a callback for library detection events."""
        self._library_callbacks.append(callback)
        return self

    def on_session(self, callback: Callable) -> "FriTap":
        """Register a callback for session lifecycle events."""
        self._session_callbacks.append(callback)
        return self

    def on_flow(self, callback: Callable) -> "FriTap":
        """Register a callback for flow events (created, updated, completed).

        The callback receives a :class:`~friTap.events.FlowEvent` with
        ``flow`` (a :class:`~friTap.flow.models.Flow` object) and
        ``flow_event_type`` (``"created"``, ``"updated"``, or ``"completed"``).
        """
        self._flow_callbacks.append(callback)
        return self

    # ------------------------------------------------------------------
    # Build & start
    # ------------------------------------------------------------------

    def build_config(self) -> FriTapConfig:
        """Build the FriTapConfig from the current builder state."""
        return FriTapConfig(
            target=self._target,
            device=self._device,
            output=self._output,
            hooking=self._hooking,
            protocol=self._protocol,
            backend=self._backend_name,
            debug=self._debug,
            debug_output=self._debug_output,
            custom_hook_script=self._custom_hook_script,
            environment_file=self._environment_file,
            install_lsass_hook=self._install_lsass_hook,
            proxy=self._proxy_address,
        )

    def start(self) -> FriTapSession:
        """
        Build the configuration, create an SSL_Logger, wire up
        the event bus, and start the capture session.

        Returns a :class:`FriTapSession` handle.
        """
        from .ssl_logger import SSL_Logger

        config = self.build_config()

        # Create SSL_Logger with the config (output handlers subscribe to its EventBus)
        ssl_log = SSL_Logger(config=config)

        # Register user callbacks on the SSL_Logger's existing event bus
        # (output handlers are already subscribed to it from _setup_output_handlers)
        event_bus = ssl_log._event_bus
        for cb in self._keylog_callbacks:
            event_bus.subscribe(KeylogEvent, cb)
        for cb in self._data_callbacks:
            event_bus.subscribe(DatalogEvent, cb)
        for cb in self._library_callbacks:
            event_bus.subscribe(LibraryDetectedEvent, cb)
        for cb in self._session_callbacks:
            event_bus.subscribe(SessionEvent, cb)

        # Register user-provided script plugins
        for plugin in self._script_plugins:
            ssl_log._plugin_loader.register_builtin(plugin, event_bus)

        # Wire FlowCollector if on_flow callbacks are registered
        flow_collector = None
        if self._flow_callbacks:
            from .flow import FlowCollector
            flow_collector = FlowCollector(event_bus=event_bus)
            flow_collector.set_capture_target(self._target)
            event_bus.subscribe(DatalogEvent, flow_collector.on_data)
            event_bus.subscribe(LibraryDetectedEvent, flow_collector.on_library_detected)
            event_bus.subscribe(SessionEvent, flow_collector.on_session_event)
            for cb in self._flow_callbacks:
                event_bus.subscribe(FlowEvent, cb)

        ssl_log.install_signal_handler()
        ssl_log.start_fritap_session()

        return FriTapSession(ssl_log, event_bus, flow_collector=flow_collector)
