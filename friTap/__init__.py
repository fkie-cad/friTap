#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
friTap — Frida-based encrypted-traffic interception and key extraction.

Public API surface (covered by SemVer guarantees from friTap 2.0.0 onward).
The full stability policy (promotion rules, deprecation cycle, MAJOR/MINOR/PATCH
semantics) lives in `RELEASING.md`; the listing below is a quick reference and
must stay in sync with that document and with `__all__` below.


    - Builder API: FriTap, FriTapSession
    - Configuration: FriTapConfig, DeviceConfig, OutputConfig, HookingConfig
    - Event types: KeylogEvent, DatalogEvent, LibraryDetectedEvent,
      SessionEvent, ConsoleEvent, ErrorEvent, SocketTraceEvent, DetachEvent,
      FlowEvent, FriTapEvent (base), EventBus
    - Flow analysis: Flow, FlowChunk, FlowState, FlowEventType, FlowSummary,
      TapReader, Severity, Finding, BaseAnalyzer, analyze_tap,
      analyze_tap_multi, AnalyzerPlugin
    - Protobuf utilities: decode_raw, format_message, ProtobufMessage,
      ProtobufField, ProtobufProcessor
    - Version: __version__

The CLI (`fritap`) is the *primary* SemVer-stable contract. The Python API
listed above is also stable: removing or breaking anything in the stable
tier requires a friTap MAJOR bump; adding to it is MINOR. See
RELEASING.md for the full policy.

Symbols imported into this module but NOT in __all__ (`CoreController`,
`Session`, `SessionState`, `MessagePipeline`, `create_default_pipeline`)
are internal orchestration. They remain importable for backward
compatibility, but they are not covered by SemVer guarantees — pin a
specific friTap version if you depend on them.

Deprecation: `SSL_Logger` is retained for backward compatibility and will
be removed in friTap 3.0. New code should use the Builder API (`FriTap`)
or `CoreController`.

Usage:
    # Legacy API (deprecated, will be removed in friTap 3.0)
    from friTap import SSL_Logger

    # Builder API
    from friTap import FriTap
    session = FriTap("com.example.app").mobile().keylog("keys.log").start()

    # New core API (recommended)
    from friTap import CoreController
    from friTap.config import FriTapConfig
    ctrl = CoreController()
    session = ctrl.create_session(FriTapConfig(target="com.example.app"))
"""

# Version (read from .about, the single source of truth — see setup.py:25)
from .about import __version__

# Expose SSL_Logger at the package level (backward compatible)
from .friTap import SSL_Logger

# New clean API
from .api import FriTap, FriTapSession

# Core API (Phase 1) — kept importable but NOT in __all__; see module docstring
from .core import CoreController
from .session import Session, SessionState

# Configuration
from .config import FriTapConfig, DeviceConfig, OutputConfig, HookingConfig

# Event system
from .events import (
    EventBus,
    FriTapEvent,
    KeylogEvent,
    DatalogEvent,
    LibraryDetectedEvent,
    SessionEvent,
    ConsoleEvent,
    ErrorEvent,
    SocketTraceEvent,
    DetachEvent,
    FlowEvent,
)

# Pipeline — kept importable but NOT in __all__; see module docstring
from .pipeline import MessagePipeline, create_default_pipeline

# Flow models
from .flow import Flow, FlowChunk, FlowState, FlowEventType, FlowSummary, TapReader

# Analysis framework
from .analysis import (
    Severity,
    Finding,
    BaseAnalyzer,
    analyze_tap,
    analyze_tap_multi,
    AnalyzerPlugin,
)

# Protobuf decoding
from .parsers.protobuf import (
    decode_raw,
    format_message,
    ProtobufMessage,
    ProtobufField,
    ProtobufProcessor,
)

__all__ = [
    # --- Stable public API (covered by SemVer guarantees) ---
    "__version__",
    # Builder API
    "FriTap",
    "FriTapSession",
    # Config
    "FriTapConfig",
    "DeviceConfig",
    "OutputConfig",
    "HookingConfig",
    # Events
    "EventBus",
    "FriTapEvent",
    "KeylogEvent",
    "DatalogEvent",
    "LibraryDetectedEvent",
    "SessionEvent",
    "ConsoleEvent",
    "ErrorEvent",
    "SocketTraceEvent",
    "DetachEvent",
    "FlowEvent",
    # Flow models
    "Flow",
    "FlowChunk",
    "FlowState",
    "FlowEventType",
    "FlowSummary",
    "TapReader",
    # Analysis framework
    "Severity",
    "Finding",
    "BaseAnalyzer",
    "analyze_tap",
    "analyze_tap_multi",
    "AnalyzerPlugin",
    # Protobuf
    "decode_raw",
    "format_message",
    "ProtobufMessage",
    "ProtobufField",
    "ProtobufProcessor",
    # --- Deprecated; will be removed in friTap 3.0 ---
    "SSL_Logger",
]
