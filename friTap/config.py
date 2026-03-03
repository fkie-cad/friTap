#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Configuration dataclasses for friTap.

Replaces the 25+ parameter SSL_Logger constructor with structured,
validated configuration objects.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class DeviceConfig:
    """Configuration for target device connection."""
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
    verbose: bool = False
    full_capture: bool = False
    socket_trace: bool | str = False


@dataclass
class HookingConfig:
    """Configuration for hooking strategies."""
    offsets: Optional[str] = None
    patterns: Optional[str] = None
    experimental: bool = False
    enable_default_fd: bool = False
    anti_root: bool = False
    payload_modification: bool = False


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
    backend: str = "frida"
    debug: bool = False
    debug_output: bool = False
    custom_hook_script: Optional[str] = None
    environment_file: Optional[str] = None
    install_lsass_hook: bool = True

    def __post_init__(self):
        if self.debug:
            self.debug_output = True

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
        enable_default_fd: bool = False,
        patterns: Optional[str] = None,
        custom_hook_script: Optional[str] = None,
        json_output: Optional[str] = None,
        install_lsass_hook: bool = True,
        timeout: Optional[int] = None,
        backend: str = "frida",
        protocol: str = "tls",
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
            ),
            hooking=HookingConfig(
                offsets=offsets,
                patterns=patterns,
                experimental=experimental,
                enable_default_fd=enable_default_fd,
                anti_root=anti_root,
                payload_modification=payload_modification,
            ),
            protocol=protocol,
            backend=backend,
            debug=debug_mode,
            debug_output=debug_output,
            custom_hook_script=custom_hook_script,
            environment_file=environment_file,
            install_lsass_hook=install_lsass_hook,
        )
