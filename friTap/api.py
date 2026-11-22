#!/usr/bin/env python3

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

    # Live decrypted Signal messages
    session = (
        FriTap("org.thoughtcrime.securesms")
        .mobile()
        .protocol("signal")
        .on_message(lambda m: print(f"{m.sender}: {m.body}"))
        .start()
    )
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Callable, List, Optional

from .config import DeviceConfig, FriTapConfig, HookingConfig, OutputConfig
from .events import (
    DatalogEvent,
    EventBus,
    FlowEvent,
    KeylogEvent,
    LibraryDetectedEvent,
    MessageEvent,
    SessionEvent,
)
from .pcap_utility import PCAP_FORMAT_AUTO, PCAP_FORMAT_PCAPNG

if TYPE_CHECKING:
    from .ssl_logger import SSL_Logger


class FriTapSession:
    """Handle to a running capture session, returned by :meth:`FriTap.start`."""

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
        """Stop the session with the CLI's teardown (detach, outputs finalized) without exiting the interpreter.

        Calling it again is harmless.
        """
        self._logger_instance.stop_fritap_session()

    def wait(self) -> None:
        """Block until the session is stopped or its teardown has completed (e.g. target died)."""
        logger = self._logger_instance
        done_event = getattr(logger, "_done_event", None)
        while logger.running:
            if done_event is not None and done_event.wait(0.1):
                return
            if done_event is None:
                import time
                time.sleep(0.1)


class FriTap:
    """Builder for configuring and starting a session; every setter returns ``self``."""

    def __init__(self, target: str) -> None:
        self._target = target
        self._device = DeviceConfig()
        self._output = OutputConfig()
        self._hooking = HookingConfig()
        # Ordered protocol selection; the first entry is the primary protocol.
        self._protocols: List[str] = ["tls"]
        self._backend_name = "frida"
        self._debug = False
        self._debug_output = False
        self._custom_hook_script: Optional[str] = None
        self._environment_file: Optional[str] = None
        self._install_lsass_hook = True
        self._proxy_address: Optional[str] = None
        # Off by default: the embedding program owns SIGINT/SIGTERM.
        self._install_signal_handler = False

        self._keylog_callbacks: List[Callable] = []
        self._data_callbacks: List[Callable] = []
        self._library_callbacks: List[Callable] = []
        self._session_callbacks: List[Callable] = []
        self._flow_callbacks: List[Callable] = []
        self._message_callbacks: List[Callable] = []

        self._logger = logging.getLogger("friTap.api")

        self._script_plugins: List = []


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

    def follow_exec(self, enable: bool = True) -> "FriTap":
        """Follow instrumented processes across exec(). Auto is off everywhere (Frida fork-child crash)."""
        self._device.follow_exec = enable
        return self

    def timeout(self, seconds: int) -> "FriTap":
        """Set timeout before resuming the target process."""
        self._device.timeout = seconds
        return self


    def pcap(self, path: str) -> "FriTap":
        """Write decrypted traffic to a PCAP file.

        A ``.pcapng`` extension writes pcapng (with embedded DSB if keys are
        extracted), anything else libpcap. Resets a prior :meth:`pcapng` call.
        """
        self._output.pcap = path
        self._output.output_format = PCAP_FORMAT_AUTO
        return self

    def pcapng(self, path: str) -> "FriTap":
        """Write self-decrypting PCAPNG (with DSB), whatever the extension.

        Same as ``--pcap-format pcapng``; a contradicting extension only logs a warning.
        """
        self._output.pcap = path
        self._output.output_format = PCAP_FORMAT_PCAPNG
        return self

    def keylog(self, path: str) -> "FriTap":
        """Write key material in the Wireshark-loadable format for the active protocol.

        The format follows :meth:`protocol`: NSS SSLKEYLOGFILE for TLS,
        ``<cookie> SHARED_SECRET <hex>`` for SSH. With several protocols
        emitting keys, ``path`` is split as ``<stem>.<proto><ext>``
        (``keys.log`` -> ``keys.tls.log``, ``keys.ssh.log``).
        """
        self._output.keylog = path
        return self

    def json_output(self, path: str) -> "FriTap":
        """Write session metadata as JSON.

        Key material is redacted in the JSON unless :meth:`keylog` or
        :meth:`json_keys` is also set.
        """
        self._output.set_json_target(path)
        return self

    def tap(self, path: str) -> "FriTap":
        """Write the decrypted flows to a ``.tap`` file (``--tap``), openable with ``fritap --analyze`` or the TUI."""
        self._output.tap_output = path
        return self

    def json_keys(self, enable: bool = True) -> "FriTap":
        """Include raw ``key_data`` in the JSON output (``--json-keys``).

        Otherwise (and without :meth:`keylog`) keylog records are redacted to
        their label and public client_random with ``"redacted": true``.
        """
        self._output.json_keys = enable
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


    def scan(self, spec: str = "all") -> "FriTap":
        """Enable live passive analysis; ``spec`` is ``"all"`` or comma-separated analyzer names (``"credentials,ioc"``)."""
        self._output.scan = spec
        return self

    def analyzer_path(self, path: str) -> "FriTap":
        """Load an external analyzer (repeatable); ``path`` is ``module`` (classes marked ``is_fritap_analyzer = True``) or ``module:Class``."""
        self._output.scan_analyzer_path = (self._output.scan_analyzer_path or []) + [path]
        return self

    def scan_report(self, fmt: str) -> "FriTap":
        """Set the end-of-capture scan report format: json, csv, md, table."""
        self._output.scan_report = fmt
        return self

    def scan_min_severity(self, sev: str) -> "FriTap":
        """Only report scan findings at or above this severity.

        One of: critical, high, medium, low, info.
        """
        self._output.scan_min_severity = sev
        return self

    def scan_show_pii(self, enable: bool = True) -> "FriTap":
        """Reveal PII/secret values in the scan report instead of redacting them."""
        self._output.scan_show_pii = enable
        return self


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
        """Force-scan a module that Cronet-split-topology suppression would skip (repeatable).

        ``name`` is a literal module name, a stem prefix ending in ``*``, or ``re:<regex>``.
        """
        if name and name not in self._hooking.force_scan_modules:
            self._hooking.force_scan_modules.append(name)
        return self


    def protocol(self, proto: str) -> "FriTap":
        """Set the target protocol: tls, ipsec, ssh, all, auto."""
        self._protocols = [proto]
        return self

    def protocols(self, names: List[str]) -> "FriTap":
        """Select several protocols (``--protocol tls,rc4``); the first is primary, an empty list changes nothing."""
        selected = list(dict.fromkeys(name for name in names if name))
        if selected:
            self._protocols = selected
        return self

    def backend(self, backend: str) -> "FriTap":
        """Set the instrumentation backend: frida, ebpf, gdb, lldb."""
        self._backend_name = backend
        return self


    def debug(self, enable: bool = True) -> "FriTap":
        """Enable debug mode with Chrome Inspector."""
        self._debug = enable
        self._debug_output = enable
        return self

    def debug_output(self, enable: bool = True) -> "FriTap":
        """Enable debug output only (no inspector)."""
        self._debug_output = enable
        return self


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

    def signal_handler(self, enable: bool = True) -> "FriTap":
        """Opt in to friTap handling SIGINT/SIGTERM for this session.

        Off by default (the embedder owns its signals). When enabled and
        :meth:`start` runs on the main thread, those signals act like
        ``stop()`` and the previous handlers are restored afterwards.
        """
        self._install_signal_handler = enable
        return self

    def proxy(self, address: str) -> "FriTap":
        """Redirect connections to a proxy and bypass cert pinning.

        Requires ``fritap-proxy``; ``address`` is ``host:port``.
        """
        self._proxy_address = address
        return self


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

        It receives a :class:`~friTap.events.FlowEvent` with ``flow``
        (:class:`~friTap.flow.models.Flow`) and ``flow_event_type``.
        Signal-over-OHTTP inner payloads are on ``flow.ohttp_inner_request`` /
        ``ohttp_inner_response``.
        """
        self._flow_callbacks.append(callback)
        return self

    def on_message(self, callback: Callable) -> "FriTap":
        """Register a callback for decrypted, structured chat messages.

        It receives a :class:`~friTap.events.MessageEvent` per decrypted message
        (``sender``, ``direction``, ``kind``, ``body``, ``timestamp``,
        attachment/quote/reaction flags, raw inner ``Content`` bytes).

        Live coverage is Signal only; Telegram/MTProto is decrypted offline via
        :func:`friTap.offline.pcap_to_tap.convert_pcap_to_tap`. A message's key
        must arrive before or with its bytes, otherwise it is recovered offline.
        """
        self._message_callbacks.append(callback)
        return self


    def build_config(self) -> FriTapConfig:
        """Build the FriTapConfig from the current builder state."""
        return FriTapConfig(
            target=self._target,
            device=self._device,
            output=self._output,
            hooking=self._hooking,
            protocol=self._protocols[0],
            protocols=list(self._protocols),
            backend=self._backend_name,
            debug=self._debug,
            debug_output=self._debug_output,
            custom_hook_script=self._custom_hook_script,
            environment_file=self._environment_file,
            install_lsass_hook=self._install_lsass_hook,
            proxy=self._proxy_address,
        )

    def start(self) -> FriTapSession:
        """Build the config, create the SSL_Logger, wire the event bus and start; returns the session handle."""
        from .ssl_logger import SSL_Logger

        config = self.build_config()

        ssl_log = SSL_Logger(config=config)
        # This interpreter belongs to the caller: a target death must finalize
        # the outputs and end the session, never os._exit the whole program.
        ssl_log._embedded = True  # see SSL_Logger.set_embedded

        event_bus = ssl_log._event_bus
        for cb in self._keylog_callbacks:
            event_bus.subscribe(KeylogEvent, cb)
        for cb in self._data_callbacks:
            event_bus.subscribe(DatalogEvent, cb)
        for cb in self._library_callbacks:
            event_bus.subscribe(LibraryDetectedEvent, cb)
        for cb in self._session_callbacks:
            event_bus.subscribe(SessionEvent, cb)

        for plugin in self._script_plugins:
            ssl_log._plugin_loader.register_builtin(plugin, event_bus)

        # on_message needs the collector to reassemble bytes and run the live Signal decryptor.
        flow_collector = None
        if self._flow_callbacks or self._message_callbacks:
            from .flow import FlowCollector
            flow_collector = FlowCollector(
                event_bus=event_bus,
                signal_messages=bool(self._message_callbacks),
            )
            flow_collector.set_capture_target(self._target)
            flow_collector.subscribe_to(event_bus)
            for cb in self._flow_callbacks:
                event_bus.subscribe(FlowEvent, cb)
            for cb in self._message_callbacks:
                event_bus.subscribe(MessageEvent, cb)

        # Never take over the host's signals unless asked (the CLI's handler
        # would os._exit the embedding program; the embedded one stops only).
        if self._install_signal_handler:
            ssl_log.install_signal_handler()
        ssl_log.start_fritap_session()
        # A numeric-PID attach resolves the real process name during
        # start_fritap_session(); re-target this collector with it.
        resolved_name = getattr(ssl_log, "resolved_process_name", None)
        if flow_collector is not None and resolved_name:
            flow_collector.set_capture_target(self._target, process_name=resolved_name)

        return FriTapSession(ssl_log, event_bus, flow_collector=flow_collector)
