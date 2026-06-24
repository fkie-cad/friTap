#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Configuration dataclasses for friTap.

Replaces the 25+ parameter SSL_Logger constructor with structured,
validated configuration objects.
"""

from __future__ import annotations
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .backends.base import BackendName


class UnsupportedProtocolBackendError(ValueError):
    """Raised when a protocol does not support the selected backend."""
    pass


@dataclass
class DeviceConfig:
    """Configuration for target device connection."""
    device_id: Optional[str] = None  # Frida device ID (from TUI enumeration)
    mobile: bool | str = False
    host: Optional[str] = None
    spawn: bool = False
    enable_spawn_gating: bool = False
    spawn_gating_all: bool = False
    enable_child_gating: bool = False
    timeout: Optional[int] = None


@dataclass
class OutputConfig:
    """Configuration for output destinations and formats."""
    pcap: Optional[str] = None
    keylog: Optional[str] = None
    json_output: Optional[str] = None
    output_format: str = "auto"
    live: bool = False
    live_mode: str = ""  # "", "wireshark", "live_pcapng"
    verbose: bool = False
    full_capture: bool = False
    socket_trace: bool | str = False
    filter_expression: Optional[str] = None  # Wireshark-like display filter
    # Drop frida/adb infrastructure traffic (ports 5037/5555/27042/27043) by default
    filter_infrastructure: bool = True
    # Include loopback/localhost traffic (e.g. Firefox NSS IPC) — off by default
    include_loopback: bool = False
    # Live passive-analysis ("scan") of observed traffic during capture.
    # ``scan`` is an analyzer spec (None disables; "all" / comma-list selects).
    scan: Optional[str] = None
    scan_report: str = "table"
    scan_report_out: Optional[str] = None
    scan_min_severity: str = "info"
    scan_min_confidence: float = 0.0
    scan_source: Optional[str] = None
    scan_category: Optional[str] = None
    scan_show_pii: bool = False
    # External analyzer references ("module" or "module:Class") to load for the
    # live scan, mirroring offline ``analyze --analyzer-path``. Repeatable.
    scan_analyzer_path: Optional[List[str]] = None


@dataclass
class HookingConfig:
    """Configuration for hooking strategies."""
    offsets: Optional[str] = None
    patterns: Optional[str] = None
    experimental: bool = False
    enable_default_fd: bool = False
    anti_root: bool = False
    payload_modification: bool = False
    library_scan: bool = False
    # QUIC plaintext capture boundary: "stream" (default lower-boundary
    # stream-level Readv hooks) or "app-api" (Boundary-4 decoded HTTP/3
    # headers; Chrome/Android Google QUICHE only).
    quic_capture_mode: str = "stream"
    # When True, the agent installs ONLY the Google QUICHE hooks and skips every
    # TLS-library hook (BoringSSL, Conscrypt, NSS, …), the Java hooks, OHTTP,
    # and the keylog scan-result hooks. Useful when the user only wants HTTP/3
    # capture: attach is dramatically lighter (no multi-megabyte Memory.scanSync
    # passes, no Java VM safepoint sync), which also helps fritap attach to a
    # target that is already in the middle of active QUIC traffic.
    quic_only: bool = False
    # When True, the agent skips the inline android_dlopen_ext loader hook. This
    # is the hook PairIP / anti-tamper runtimes detect and SIGSEGV on during a
    # spawn-time integrity scan (fkie-cad/friTap#64). Only already-loaded /
    # explicitly-selected TLS libraries are then hooked. The agent also auto-
    # skips it in spawn mode when an anti-tamper library is detected.
    no_loader_hook: bool = False
    # EXPERIMENTAL (Android). Watch android_dlopen_ext via a hardware breakpoint
    # (ARM64 debug registers, no linker code patch) instead of the inline
    # trampoline, so late-loaded TLS libs can be hooked on PairIP-protected apps
    # without tripping the anti-tamper scan. Unvalidated on-device; default OFF.
    stealth_loader: bool = False
    # Override which layer of the HTTP/3 egress-headers fallback chain the
    # agent actually attaches to. "auto" (default) keeps the winner-takes-all
    # logic: quiche-internal QuicSpdyStream::WriteHeaders preferred, then
    # net::QuicChromiumClientStream::WriteHeaders, then
    # quic::QuicSpdySession::WriteHeadersOnHeadersStream as a last-resort gQUIC
    # fallback. Set to "chrome-shim" or "session-level" to FORCE a fallback
    # layer for testing — useful for validating chain behavior on builds where
    # the quiche-internal layer still resolves. Only effective in app-api mode.
    quic_egress_headers_layer: str = "auto"
    # Generic memory-region key-scan target (--scan-keys-region). None disables
    # the scan. Passed through to the agent via config_batch.extensions.scan_region;
    # protocol-agnostic (the public scan engine and any private scan binding both
    # read it). See agent/shared/scan/.
    scan_keys_region: Optional[str] = None
    encapsulated_protocols: Dict[str, bool] = field(
        default_factory=lambda: {"ohttp": True}
    )
    # Module names that should bypass the Cronet-split-topology suppression
    # check, even when friTap would otherwise treat them as covered by a
    # sibling library. Accepts literal names, prefixes (a value ending in '*'
    # is treated as a stem prefix), or regexes prefixed with "re:".
    force_scan_modules: List[str] = field(default_factory=list)

    @property
    def ohttp_enabled(self) -> bool:
        return self.encapsulated_protocols.get("ohttp", True)

    def __post_init__(self) -> None:
        env_value = os.environ.get("FRITAP_FORCE_SCAN")
        if env_value:
            extra = [item.strip() for item in env_value.split(",") if item.strip()]
            for item in extra:
                if item not in self.force_scan_modules:
                    self.force_scan_modules.append(item)


@dataclass
class FriTapConfig:
    """
    Top-level configuration for a friTap session.

    Usage:
        config = FriTapConfig(
            target="com.example.app",
            device=DeviceConfig(mobile=True, spawn=True),
            output=OutputConfig(pcap="capture.pcap", keylog="keys.log"),
        )
    """
    target: str
    device: DeviceConfig = field(default_factory=DeviceConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    hooking: HookingConfig = field(default_factory=HookingConfig)
    protocol: str = "tls"
    backend: str = BackendName.FRIDA
    debug: bool = False
    debug_output: bool = False
    custom_hook_script: Optional[str] = None
    environment_file: Optional[str] = None
    install_lsass_hook: bool = True
    proxy: Optional[str] = None  # "host:port" or "[ipv6]:port" format

    def __post_init__(self):
        if self.debug:
            self.debug_output = True

    def validate_protocol_backend(self, protocol_handler=None) -> None:
        """Validate that the selected backend supports the configured protocol.

        Parameters
        ----------
        protocol_handler
            A ProtocolHandler instance. If None, validation is skipped.

        Raises
        ------
        UnsupportedProtocolBackendError
            When the backend support level is STUB or UNSUPPORTED.
        """
        if self.protocol == "auto":
            return  # auto always starts with Frida default
        if protocol_handler is None:
            return
        from .protocols.base import BackendSupport
        level = protocol_handler.get_backend_support_level(self.backend)
        if level != BackendSupport.FULL:
            supported = [
                name for name, lvl in protocol_handler.supported_backends.items()
                if lvl == BackendSupport.FULL
            ]
            raise UnsupportedProtocolBackendError(
                f"Protocol '{self.protocol}' does not fully support the "
                f"'{self.backend}' backend (level: {level}). "
                f"Supported backends: {', '.join(supported)}"
            )

    @classmethod
    def from_legacy_params(
        cls,
        app: str,
        pcap_name: Optional[str] = None,
        verbose: bool = False,
        spawn: bool = False,
        keylog: bool | str = False,
        enable_spawn_gating: bool = False,
        spawn_gating_all: bool = False,
        enable_child_gating: bool = False,
        mobile: bool | str = False,
        live: bool = False,
        environment_file: Optional[str] = None,
        debug_mode: bool = False,
        full_capture: bool = False,
        socket_trace: bool | str = False,
        host: bool | str = False,
        offsets: Optional[str] = None,
        debug_output: bool = False,
        experimental: bool = False,
        anti_root: bool = False,
        payload_modification: bool = False,
        library_scan: bool = False,
        enable_default_fd: bool = False,
        patterns: Optional[str] = None,
        custom_hook_script: Optional[str] = None,
        json_output: Optional[str] = None,
        install_lsass_hook: bool = True,
        timeout: Optional[int] = None,
        backend: str = BackendName.FRIDA,
        protocol: str = "tls",
        proxy: Optional[str] = None,
        filter_expression: Optional[str] = None,
        filter_infrastructure: bool = True,
        include_loopback: bool = False,
        force_scan_modules: Optional[List[str]] = None,
        quic_capture_mode: str = "stream",
        quic_only: bool = False,
        no_loader_hook: bool = False,
        stealth_loader: bool = False,
        quic_egress_headers_layer: str = "auto",
        scan_keys_region: Optional[str] = None,
        scan: Optional[str] = None,
        scan_report: str = "table",
        scan_report_out: Optional[str] = None,
        scan_min_severity: str = "info",
        scan_min_confidence: float = 0.0,
        scan_source: Optional[str] = None,
        scan_category: Optional[str] = None,
        scan_show_pii: bool = False,
        scan_analyzer_path: Optional[List[str]] = None,
    ) -> "FriTapConfig":
        """
        Build a FriTapConfig from the legacy SSL_Logger constructor parameters.
        Ensures full backward compatibility.
        """
        return cls(
            target=app,
            device=DeviceConfig(
                mobile=mobile,
                host=host if host else None,
                spawn=spawn,
                enable_spawn_gating=enable_spawn_gating,
                spawn_gating_all=spawn_gating_all,
                enable_child_gating=enable_child_gating,
                timeout=timeout,
            ),
            output=OutputConfig(
                pcap=pcap_name,
                keylog=keylog if isinstance(keylog, str) else (keylog or None),
                json_output=json_output,
                live=live,
                verbose=verbose,
                full_capture=full_capture,
                socket_trace=socket_trace,
                filter_expression=filter_expression,
                filter_infrastructure=filter_infrastructure,
                include_loopback=include_loopback,
                scan=scan,
                scan_report=scan_report,
                scan_report_out=scan_report_out,
                scan_min_severity=scan_min_severity,
                scan_min_confidence=scan_min_confidence,
                scan_source=scan_source,
                scan_category=scan_category,
                scan_show_pii=scan_show_pii,
                scan_analyzer_path=scan_analyzer_path,
            ),
            hooking=HookingConfig(
                offsets=offsets,
                patterns=patterns,
                experimental=experimental,
                enable_default_fd=enable_default_fd,
                anti_root=anti_root,
                payload_modification=payload_modification,
                library_scan=library_scan,
                force_scan_modules=list(force_scan_modules or []),
                quic_capture_mode=quic_capture_mode,
                quic_only=quic_only,
                no_loader_hook=no_loader_hook,
                stealth_loader=stealth_loader,
                quic_egress_headers_layer=quic_egress_headers_layer,
                scan_keys_region=scan_keys_region,
            ),
            protocol=protocol,
            backend=backend,
            debug=debug_mode,
            debug_output=debug_output,
            custom_hook_script=custom_hook_script,
            environment_file=environment_file,
            install_lsass_hook=install_lsass_hook,
            proxy=proxy,
        )
