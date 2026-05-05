#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Configuration dataclasses for friTap.

Replaces the 25+ parameter SSL_Logger constructor with structured,
validated configuration objects.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, Optional

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
    encapsulated_protocols: Dict[str, bool] = field(
        default_factory=lambda: {"ohttp": True}
    )

    @property
    def ohttp_enabled(self) -> bool:
        return self.encapsulated_protocols.get("ohttp", True)


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
            ),
            hooking=HookingConfig(
                offsets=offsets,
                patterns=patterns,
                experimental=experimental,
                enable_default_fd=enable_default_fd,
                anti_root=anti_root,
                payload_modification=payload_modification,
                library_scan=library_scan,
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
