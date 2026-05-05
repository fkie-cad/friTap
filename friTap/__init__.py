#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
friTap - Frida-based encrypted traffic interception and key extraction.

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

# Expose SSL_Logger at the package level (backward compatible)
from .friTap import SSL_Logger

# New clean API
from .api import FriTap, FriTapSession

# Core API (Phase 1)
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

# Pipeline
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
    # Legacy (deprecated)
    "SSL_Logger",
    # Builder API
    "FriTap",
    "FriTapSession",
    # Core API
    "CoreController",
    "Session",
    "SessionState",
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
    # Pipeline
    "MessagePipeline",
    "create_default_pipeline",
    # Events (flow)
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
]
