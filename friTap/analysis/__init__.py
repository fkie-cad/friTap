"""
friTap analysis framework — composable analyzers for .tap file analysis.

Works both offline (via TapReader) and live (via AnalyzerPlugin + EventBus).

Usage::

    from friTap.analysis import analyze_tap, IocAnalyzer, CredentialAnalyzer

    # Offline: analyze a .tap file
    findings = analyze_tap(IocAnalyzer(), "capture.tap")
    for f in findings:
        print(f"{f.severity.value}: {f.title}")

    # Compose multiple analyzers
    findings = analyze_tap_multi([IocAnalyzer(), CredentialAnalyzer()], "capture.tap")

    # Live: wire an analyzer to the EventBus via plugin adapter
    plugin = AnalyzerPlugin(IocAnalyzer())
    session.lifecycle_bus.subscribe(FlowEvent, plugin.on_flow)
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol, runtime_checkable, TYPE_CHECKING

if TYPE_CHECKING:
    from friTap.events import FlowEvent
    from friTap.flow.models import Flow


class Severity(str, Enum):
    """Finding severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass(frozen=True)
class Finding:
    """An immutable analysis finding.

    Attributes:
        severity: Finding severity level.
        title: Short human-readable title.
        description: Detailed description of the finding.
        source: Name of the analyzer that produced this finding.
        flow_id: ID of the flow that triggered the finding (empty for cross-flow).
        confidence: Confidence score from 0.0 to 1.0.
        timestamp: When the finding was created (epoch float).
        evidence: Structured evidence data (flow_id, matched_data, location, etc.).
        metadata: Optional extension fields (MITRE ATT&CK ID, CVE, etc.).
    """
    severity: Severity
    title: str
    description: str
    source: str
    flow_id: str = ""
    confidence: float = 1.0
    timestamp: float = field(default_factory=time.time)
    evidence: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)


@runtime_checkable
class BaseAnalyzer(Protocol):
    """Protocol for flow-level analyzers.

    Implement ``analyze_flow`` to produce findings from a single flow.
    The analyzer is agnostic to whether it runs live or offline —
    the AnalyzerPlugin adapter handles live mode.
    """
    name: str

    def analyze_flow(self, flow: "Flow") -> list[Finding]:
        """Analyze a single flow and return findings."""
        ...


def analyze_tap(analyzer: BaseAnalyzer, tap_path: str) -> list[Finding]:
    """Run an analyzer over all flows in a .tap file.

    This is a free function — not a method on BaseAnalyzer — because
    it composes TapReader iteration with analyzer logic.

    Args:
        analyzer: An object implementing the BaseAnalyzer protocol.
        tap_path: Path to a .tap capture file.

    Returns:
        List of findings from all flows.
    """
    from friTap.flow.tap_reader import TapReader

    findings: list[Finding] = []
    with TapReader(tap_path) as reader:
        for summary in reader.read_flow_summaries():
            flow = reader.read_flow(summary.flow_id)
            if flow is not None:
                findings.extend(analyzer.analyze_flow(flow))
    return findings


def analyze_tap_multi(analyzers: list[BaseAnalyzer], tap_path: str) -> list[Finding]:
    """Run multiple analyzers over all flows in a .tap file.

    Each flow is passed to every analyzer. This avoids re-reading the
    .tap file once per analyzer.

    Args:
        analyzers: List of analyzer instances.
        tap_path: Path to a .tap capture file.

    Returns:
        Combined list of findings from all analyzers and flows.
    """
    from friTap.flow.tap_reader import TapReader

    findings: list[Finding] = []
    with TapReader(tap_path) as reader:
        for summary in reader.read_flow_summaries():
            flow = reader.read_flow(summary.flow_id)
            if flow is not None:
                for analyzer in analyzers:
                    findings.extend(analyzer.analyze_flow(flow))
    return findings


class AnalyzerPlugin:
    """Thin adapter that wires any BaseAnalyzer to the EventBus for live analysis.

    Usage::

        from friTap.analysis import AnalyzerPlugin, IocAnalyzer

        plugin = AnalyzerPlugin(IocAnalyzer())
        # In a FriTapPlugin.on_load():
        session.lifecycle_bus.subscribe(FlowEvent, plugin._on_flow)

        # After capture:
        for finding in plugin.findings:
            print(finding)
    """

    def __init__(self, analyzer: BaseAnalyzer) -> None:
        self._analyzer = analyzer
        self.findings: list[Finding] = []

    @property
    def name(self) -> str:
        return f"analyzer:{self._analyzer.name}"

    def on_flow(self, event: "FlowEvent") -> None:
        """EventBus callback for FlowEvent. Analyzes completed flows."""
        from friTap.flow.models import FlowEventType
        if event.flow_event_type == FlowEventType.COMPLETED and event.flow is not None:
            self.findings.extend(self._analyzer.analyze_flow(event.flow))

    def clear(self) -> None:
        """Clear accumulated findings."""
        self.findings.clear()


__all__ = [
    "Severity",
    "Finding",
    "BaseAnalyzer",
    "analyze_tap",
    "analyze_tap_multi",
    "AnalyzerPlugin",
]
