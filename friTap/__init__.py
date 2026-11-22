#!/usr/bin/env python3

"""
friTap — Frida-based encrypted-traffic interception and key extraction.

Public API surface (SemVer-stable from 2.0.0). The stability policy lives in
`RELEASING.md`; the list below must stay in sync with it and with `__all__`.

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

The CLI (`fritap`) is the primary SemVer-stable contract; the Python API above
is stable too (removal needs a MAJOR bump, additions are MINOR). See RELEASING.md.

Symbols imported here but not in __all__ (`CoreController`, `Session`,
`SessionState`, `MessagePipeline`, `create_default_pipeline`) are internal
orchestration and not covered by SemVer. `SSL_Logger` is deprecated and will be
removed in friTap 3.0; use `FriTap` or `CoreController`.

Usage:
    from friTap import FriTap
    session = FriTap("com.example.app").mobile().keylog("keys.log").start()
"""

from typing import TYPE_CHECKING

# Eager: .about is pure Python, so ``import friTap`` / ``__version__`` stay cheap.
from .about import __version__

# Lazy public API (PEP 562): every other symbol is imported on first access, so
# ``import friTap`` and leaf submodules (``friTap.schemas``, ``friTap.constants``)
# do not pull in frida, rich, textual or scapy. ``dev/generate_agent_types.py``
# runs in a CI job that installs only pydantic and relies on this.
_LAZY_EXPORTS = {
    # Deprecated; the only frida-coupled export
    "SSL_Logger": ".friTap",
    # Builder API
    "FriTap": ".api",
    "FriTapSession": ".api",
    # Internal; importable but not in __all__
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
    # Internal; importable but not in __all__
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
    # ``pcap_to_tap`` comes from the submodule so it does not clash with the
    # ``friTap.offline.pcap_to_tap`` module attribute.
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
    from .analysis import (
        AnalyzerPlugin,
        BaseAnalyzer,
        Finding,
        Severity,
        analyze_tap,
        analyze_tap_multi,
        severity_rank,
    )
    from .analysis.filtering import FindingFilter
    from .analysis.reporters import (
        CsvReporter,
        JsonReporter,
        MarkdownReporter,
        Reporter,
        TableReporter,
    )
    from .api import FriTap, FriTapSession
    from .commands.analyze import (
        AnalyzeReport,
        analyze_tap_report,
        list_analyzers,
        list_analyzers_detailed,
        list_report_formats,
    )
    from .config import DeviceConfig, FriTapConfig, HookingConfig, OutputConfig
    from .core import CoreController  # noqa: F401  (lazy re-export, not in __all__)
    from .events import (
        ConsoleEvent,
        DatalogEvent,
        DetachEvent,
        ErrorEvent,
        EventBus,
        FlowEvent,
        FriTapEvent,
        KeylogEvent,
        LibraryDetectedEvent,
        MessageEvent,
        SessionEvent,
        SocketTraceEvent,
    )
    from .flow import (
        Flow,
        FlowChunk,
        FlowEventType,
        FlowState,
        FlowSummary,
        IFlowSource,
        ReplayController,
        TapMeta,
        TapReader,
    )
    from .flow.layers import ProtocolLayer, QuicLayer, SshLayer, TlsLayer
    from .friTap import SSL_Logger
    from .offline import ConvertResult, NoDecryptionKeysError, convert_pcap_to_tap
    from .offline.pcap_to_tap import pcap_to_tap
    from .parsers.base import ParseResult
    from .parsers.protobuf import (
        ProtobufField,
        ProtobufMessage,
        ProtobufProcessor,
        decode_raw,
        format_message,
    )
    from .pipeline import (  # noqa: F401  (lazy re-export, not in __all__)
        MessagePipeline,
        create_default_pipeline,
    )
    from .session import (  # noqa: F401  (lazy re-export, not in __all__)
        Session,
        SessionState,
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
