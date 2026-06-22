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
      FlowEvent, MessageEvent, FriTapEvent (base), EventBus
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

# Version (read from .about, the single source of truth — see setup.py:25).
# Kept EAGER: .about is pure-Python (no third-party deps), so ``import friTap``
# and ``friTap.__version__`` stay cheap and dependency-free.
from .about import __version__

from typing import TYPE_CHECKING

# --- Lazy public API (PEP 562 module __getattr__) -----------------------------
# Every other public symbol is imported ON FIRST ACCESS instead of at package
# import time. This keeps ``import friTap`` — and importing any leaf submodule
# such as ``friTap.schemas`` / ``friTap.constants`` / ``friTap.connection_index``
# — free of the heavy runtime stack: frida (pulled by .friTap → ssl_logger) and
# the rich / textual / scapy / crypto dependencies that the flow, analysis and
# offline modules drag in. Tooling that only needs the schema or constants
# modules (e.g. ``dev/generate_agent_types.py``, whose CI job installs *only*
# pydantic) therefore imports cleanly without the full dependency set.
#
# Backward compatible: ``from friTap import SSL_Logger`` / ``FriTap`` /
# ``CoreController`` / ``Session`` … all still work — resolved on demand by
# ``__getattr__`` below and cached, so there is no per-access overhead after the
# first lookup. ``__all__`` (unchanged) remains the stable public surface.
_LAZY_EXPORTS = {
    # Legacy API (deprecated, removed in friTap 3.0) — the only frida-coupled export
    "SSL_Logger": ".friTap",
    # Builder API
    "FriTap": ".api",
    "FriTapSession": ".api",
    # Core API (Phase 1) — importable but NOT in __all__; see module docstring
    "CoreController": ".core",
    "Session": ".session",
    "SessionState": ".session",
    # Configuration
    "FriTapConfig": ".config",
    "DeviceConfig": ".config",
    "OutputConfig": ".config",
    "HookingConfig": ".config",
    # Event system
    "EventBus": ".events",
    "FriTapEvent": ".events",
    "KeylogEvent": ".events",
    "DatalogEvent": ".events",
    "LibraryDetectedEvent": ".events",
    "SessionEvent": ".events",
    "ConsoleEvent": ".events",
    "ErrorEvent": ".events",
    "SocketTraceEvent": ".events",
    "DetachEvent": ".events",
    "FlowEvent": ".events",
    "MessageEvent": ".events",
    # Pipeline — importable but NOT in __all__; see module docstring
    "MessagePipeline": ".pipeline",
    "create_default_pipeline": ".pipeline",
    # Flow models + replay / high-level overview
    "Flow": ".flow",
    "FlowChunk": ".flow",
    "FlowState": ".flow",
    "FlowEventType": ".flow",
    "FlowSummary": ".flow",
    "TapReader": ".flow",
    "ReplayController": ".flow",
    "IFlowSource": ".flow",
    "TapMeta": ".flow",
    # Analysis framework
    "Severity": ".analysis",
    "Finding": ".analysis",
    "BaseAnalyzer": ".analysis",
    "analyze_tap": ".analysis",
    "analyze_tap_multi": ".analysis",
    "AnalyzerPlugin": ".analysis",
    "severity_rank": ".analysis",
    "FindingFilter": ".analysis.filtering",
    "Reporter": ".analysis.reporters",
    "JsonReporter": ".analysis.reporters",
    "CsvReporter": ".analysis.reporters",
    "MarkdownReporter": ".analysis.reporters",
    "TableReporter": ".analysis.reporters",
    # Protobuf decoding
    "decode_raw": ".parsers.protobuf",
    "format_message": ".parsers.protobuf",
    "ProtobufMessage": ".parsers.protobuf",
    "ProtobufField": ".parsers.protobuf",
    "ProtobufProcessor": ".parsers.protobuf",
    # Offline analyze orchestration
    "AnalyzeReport": ".commands.analyze",
    "analyze_tap_report": ".commands.analyze",
    "list_analyzers": ".commands.analyze",
    "list_analyzers_detailed": ".commands.analyze",
    "list_report_formats": ".commands.analyze",
    # Offline pcap -> tap reconstruction. ``pcap_to_tap`` is taken from the
    # submodule directly (not the offline package) so it neither shadows nor is
    # shadowed by the ``friTap.offline.pcap_to_tap`` module attribute.
    "convert_pcap_to_tap": ".offline",
    "ConvertResult": ".offline",
    "NoDecryptionKeysError": ".offline",
    "pcap_to_tap": ".offline.pcap_to_tap",
    # Parsed-metadata types
    "ProtocolLayer": ".flow.layers",
    "TlsLayer": ".flow.layers",
    "QuicLayer": ".flow.layers",
    "SshLayer": ".flow.layers",
    "ParseResult": ".parsers.base",
}


def __getattr__(name: str):
    """PEP 562 lazy loader for the public API symbols (see ``_LAZY_EXPORTS``)."""
    module = _LAZY_EXPORTS.get(name)
    if module is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    import importlib

    value = getattr(importlib.import_module(module, __name__), name)
    globals()[name] = value  # cache: later access skips __getattr__ entirely
    return value


def __dir__():
    return sorted(set(globals()) | set(_LAZY_EXPORTS))


if TYPE_CHECKING:  # static analysers / IDEs see the real symbols, no runtime cost
    from .friTap import SSL_Logger
    from .api import FriTap, FriTapSession
    from .core import CoreController  # noqa: F401  (lazy re-export, not in __all__)
    from .session import Session, SessionState  # noqa: F401  (lazy re-export, not in __all__)
    from .config import FriTapConfig, DeviceConfig, OutputConfig, HookingConfig
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
        MessageEvent,
    )
    from .pipeline import MessagePipeline, create_default_pipeline  # noqa: F401  (lazy re-export, not in __all__)
    from .flow import (
        Flow,
        FlowChunk,
        FlowState,
        FlowEventType,
        FlowSummary,
        TapReader,
        ReplayController,
        IFlowSource,
        TapMeta,
    )
    from .analysis import (
        Severity,
        Finding,
        BaseAnalyzer,
        analyze_tap,
        analyze_tap_multi,
        AnalyzerPlugin,
        severity_rank,
    )
    from .analysis.filtering import FindingFilter
    from .analysis.reporters import (
        Reporter,
        JsonReporter,
        CsvReporter,
        MarkdownReporter,
        TableReporter,
    )
    from .parsers.protobuf import (
        decode_raw,
        format_message,
        ProtobufMessage,
        ProtobufField,
        ProtobufProcessor,
    )
    from .commands.analyze import (
        AnalyzeReport,
        analyze_tap_report,
        list_analyzers,
        list_analyzers_detailed,
        list_report_formats,
    )
    from .offline import convert_pcap_to_tap, ConvertResult, NoDecryptionKeysError
    from .offline.pcap_to_tap import pcap_to_tap
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
    "MessageEvent",
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
    "list_analyzers_detailed",
    "list_report_formats",
    "severity_rank",
    "FindingFilter",
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
