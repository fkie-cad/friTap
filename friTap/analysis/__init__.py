"""
Composable analyzers for .tap files, offline (TapReader) or live (EventBus).

Usage::

    findings = analyze_tap(IocAnalyzer(), "capture.tap")
    findings = analyze_tap_multi([IocAnalyzer(), CredentialAnalyzer()], "capture.tap")

    plugin = AnalyzerPlugin(IocAnalyzer())  # live
    session.lifecycle_bus.subscribe(FlowEvent, plugin.on_flow)
"""

from __future__ import annotations

import dataclasses
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

if TYPE_CHECKING:
    from friTap.events import FlowEvent
    from friTap.flow.models import Flow

logger = logging.getLogger("friTap.analysis")


class Severity(str, Enum):
    """Finding severity levels, declared most-severe first."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# Rank follows declaration order (CRITICAL=0 .. INFO=4); use ``severity_rank``.
_SEVERITY_RANK: dict[Severity, int] = {sev: i for i, sev in enumerate(Severity)}


def severity_rank(severity) -> int:
    """Rank of a :class:`Severity` (or its string); lower is more severe, unknown ranks as INFO."""
    try:
        sev = severity if isinstance(severity, Severity) else Severity(severity)
    except ValueError:
        sev = Severity.INFO
    return _SEVERITY_RANK[sev]


@dataclass(frozen=True)
class Finding:
    """An immutable analysis finding.

    ``source`` is the producing analyzer's name; ``flow_id`` is empty for
    cross-flow findings; ``confidence`` is 0.0-1.0; ``timestamp`` is epoch seconds;
    ``evidence`` is structured data (matched_data, location, ...); ``metadata``
    holds extension fields (category, cwe, MITRE ATT&CK ID, CVE, ...).
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

    @property
    def category(self) -> str | None:
        """``metadata["category"]`` (taxonomy: :mod:`friTap.analysis.filtering`)."""
        return self.metadata.get("category")

    def to_dict(self) -> dict[str, Any]:
        """JSON dict shared by reporters, the ``.tap`` REC_FINDING and the sidecar (severity as string)."""
        data = dataclasses.asdict(self)
        data["severity"] = self.severity.value
        return data

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Finding":
        """Inverse of :meth:`to_dict`; ignores unknown keys, maps bad severity to INFO, never raises."""
        field_names = {f.name for f in dataclasses.fields(cls)}
        kwargs = {k: v for k, v in d.items() if k in field_names}

        # Required strings have no dataclass default; keep from_dict total.
        for required in ("title", "description", "source"):
            kwargs.setdefault(required, "")

        try:
            kwargs["severity"] = Severity(d.get("severity", "info"))
        except ValueError:
            kwargs["severity"] = Severity.INFO

        # Falsy evidence/metadata (e.g. None) becomes {}.
        for opt in ("evidence", "metadata"):
            if opt in kwargs and not kwargs[opt]:
                kwargs[opt] = {}

        return cls(**kwargs)


# Priority-ordered keys holding a finding's matched value; shared by the TUI
# detail view and list preview so they agree.
EVIDENCE_VALUE_KEYS = (
    "matched_data", "match", "value", "secret", "token", "credential", "data",
)


def primary_evidence_value(finding: "Finding") -> "str | None":
    """First non-empty string evidence value among :data:`EVIDENCE_VALUE_KEYS`, or ``None``."""
    evidence = getattr(finding, "evidence", None) or {}
    for key in EVIDENCE_VALUE_KEYS:
        val = evidence.get(key)
        if isinstance(val, str) and val:
            return val
    return None


@runtime_checkable
class BaseAnalyzer(Protocol):
    """Protocol for flow-level analyzers; live or offline (AnalyzerPlugin adapts live mode)."""
    name: str

    def analyze_flow(self, flow: "Flow") -> list[Finding]:
        """Return findings for one flow."""
        ...


ANALYZER_ERROR_TITLE = "Analyzer error"


def _analyzer_error_finding(analyzer_name: str, flow_id: str, exc: BaseException) -> Finding:
    """INFO finding recorded when an analyzer crashes on a flow."""
    message = str(exc)[:120]
    return Finding(
        severity=Severity.INFO,
        title=ANALYZER_ERROR_TITLE,
        description=(
            f"Analyzer '{analyzer_name}' failed on this flow "
            f"({type(exc).__name__}); its findings for the flow are incomplete."
        ),
        source=analyzer_name,
        flow_id=flow_id,
        confidence=1.0,
        evidence={"error_type": type(exc).__name__, "error": message},
        metadata={"category": "protocol", "analyzer_error": True},
    )


def run_analyzer_safely(analyzer: BaseAnalyzer, flow: "Flow") -> list[Finding]:
    """Run ``analyzer.analyze_flow(flow)``, isolating any exception.

    Input is attacker-controlled (decrypted traffic), so one malformed flow
    must never abort a whole analysis run. On failure the error is logged and
    a single INFO "Analyzer error" finding is returned instead.
    """
    name = str(getattr(analyzer, "name", type(analyzer).__name__))
    flow_id = str(getattr(flow, "flow_id", "") or "")
    try:
        return list(analyzer.analyze_flow(flow))
    except Exception as exc:  # noqa: BLE001 - isolation boundary by design
        logger.warning("Analyzer %r failed on flow %s: %s: %s",
                       name, flow_id, type(exc).__name__, str(exc)[:200])
        logger.debug("Analyzer %r traceback for flow %s", name, flow_id, exc_info=True)
        return [_analyzer_error_finding(name, flow_id, exc)]


def analyze_tap(analyzer: BaseAnalyzer, tap_path: str) -> list[Finding]:
    """Findings of *analyzer* over every flow of a .tap file."""
    from friTap.flow.tap_reader import TapReader

    findings: list[Finding] = []
    with TapReader(tap_path) as reader:
        for summary in reader.read_flow_summaries():
            flow = reader.read_flow(summary.flow_id)
            if flow is not None:
                findings.extend(run_analyzer_safely(analyzer, flow))
    return findings


def analyze_tap_multi(analyzers: list[BaseAnalyzer], tap_path: str) -> list[Finding]:
    """Like :func:`analyze_tap` for several analyzers in one read."""
    from friTap.flow.tap_reader import TapReader

    findings: list[Finding] = []
    with TapReader(tap_path) as reader:
        for summary in reader.read_flow_summaries():
            flow = reader.read_flow(summary.flow_id)
            if flow is not None:
                for analyzer in analyzers:
                    findings.extend(run_analyzer_safely(analyzer, flow))
    return findings


class AnalyzerPlugin:
    """Adapter that wires a BaseAnalyzer to the EventBus for live analysis.

    Subscribe ``plugin.on_flow`` to ``FlowEvent``; results accumulate in ``plugin.findings``.
    """

    def __init__(self, analyzer: BaseAnalyzer) -> None:
        self._analyzer = analyzer
        self.findings: list[Finding] = []

    @property
    def name(self) -> str:
        return f"analyzer:{self._analyzer.name}"

    def analyze(self, flow: "Flow") -> list[Finding]:
        """Analyze a completed flow; accumulates and returns its findings."""
        found = run_analyzer_safely(self._analyzer, flow)
        self.findings.extend(found)
        return found

    def on_flow(self, event: "FlowEvent") -> None:
        """FlowEvent callback; analyzes completed flows."""
        from friTap.flow.models import FlowEventType
        if event.flow_event_type == FlowEventType.COMPLETED and event.flow is not None:
            self.analyze(event.flow)

    def clear(self) -> None:
        """Clear accumulated findings."""
        self.findings.clear()


__all__ = [
    "Severity",
    "severity_rank",
    "Finding",
    "BaseAnalyzer",
    "analyze_tap",
    "analyze_tap_multi",
    "run_analyzer_safely",
    "AnalyzerPlugin",
]
