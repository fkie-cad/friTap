#!/usr/bin/env python3

"""Pydantic models for host -> agent configuration (handshake and runtime)."""

from __future__ import annotations

from typing import Any, Dict, Literal

from pydantic import BaseModel


class AgentHandshakeConfig(BaseModel):
    """Initial configuration sent to the agent during handshake."""
    experimental: bool = False
    enable_default_fd: bool = False
    socket_trace: bool = False
    protocol: str = "tls"
    anti_root: bool = False
    payload_modification: bool = False
    debug: bool = False


class PatternConfig(BaseModel):
    """Pattern data for pattern-based hooking."""
    pattern_type: str = "openssl"  # "openssl", "gnutls", etc.
    patterns: Dict[str, Any] = {}


class OffsetConfig(BaseModel):
    """Offset data for offset-based hooking."""
    offsets: Dict[str, Any] = {}


class ScriptInjection(BaseModel):
    """Custom script source to inject alongside main agent."""
    source: str
    plugin_name: str = ""
    load_order: Literal["before", "after"] = "after"


class RuntimeCommand(BaseModel):
    """Runtime command sent to the agent."""
    command: str  # "detach", "update_config", etc.
    payload: Dict[str, Any] = {}
