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
      TapReader, TapMeta, Severity, Finding, BaseAnalyzer, analyze_tap,
      analyze_tap_multi, AnalyzerPlugin, severity_rank
    - Offline analyze: analyze_tap_report, AnalyzeReport, list_analyzers,
      list_report_formats, Reporter, JsonReporter, CsvReporter,
      MarkdownReporter, TableReporter
    - Offline pcap -> tap: pcap_to_tap, convert_pcap_to_tap, ConvertResult,
      NoDecryptionKeysError
    - Flow replay / overview: ReplayController, IFlowSource
    - Parsed-metadata types: ParseResult, ProtocolLayer, TlsLayer, QuicLayer,
      SshLayer
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
from .core import CoreController  # noqa: F401
from .session import Session, SessionState  # noqa: F401

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
from .pipeline import MessagePipeline, create_default_pipeline  # noqa: F401

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

# Offline analyze orchestration — reusable report function + reporters/discovery
from .analysis import severity_rank
from .analysis.reporters import (
    Reporter,
    JsonReporter,
    CsvReporter,
    MarkdownReporter,
    TableReporter,
)
from .commands.analyze import (
    AnalyzeReport,
    analyze_tap_report,
    list_analyzers,
    list_report_formats,
)

# Offline pcap -> tap reconstruction. ``pcap_to_tap`` is imported from the
# submodule directly (not the offline package) so it does not shadow — and is
# not shadowed by — the ``friTap.offline.pcap_to_tap`` module attribute.
from .offline import convert_pcap_to_tap, ConvertResult, NoDecryptionKeysError
from .offline.pcap_to_tap import pcap_to_tap

# Flow replay / high-level overview + parsed-metadata types
from .flow import ReplayController, IFlowSource, TapMeta
from .flow.layers import ProtocolLayer, TlsLayer, QuicLayer, SshLayer
from .parsers.base import ParseResult

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
    # Offline analyze orchestration
    "analyze_tap_report",
    "AnalyzeReport",
    "list_analyzers",
    "list_report_formats",
    "severity_rank",
    "Reporter",
    "JsonReporter",
    "CsvReporter",
    "MarkdownReporter",
    "TableReporter",
    # Offline pcap -> tap
    "pcap_to_tap",
    "convert_pcap_to_tap",
    "ConvertResult",
    "NoDecryptionKeysError",
    # Flow replay / overview
    "ReplayController",
    "IFlowSource",
    "TapMeta",
    # Parsed-metadata types
    "ParseResult",
    "ProtocolLayer",
    "TlsLayer",
    "QuicLayer",
    "SshLayer",
    # --- Deprecated; will be removed in friTap 3.0 ---
    "SSL_Logger",
]
