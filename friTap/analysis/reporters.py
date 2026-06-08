"""
Reporters — format analysis findings into various output formats.

Reporters are separate from analyzers (SRP): analyzers produce findings,
reporters format them. This module provides JSON, CSV, Markdown, and
a base Reporter protocol for custom implementations.

Usage::

    from friTap.analysis import analyze_tap, IocAnalyzer
    from friTap.analysis.reporters import JsonReporter, CsvReporter

    findings = analyze_tap(IocAnalyzer(), "capture.tap")
    print(JsonReporter().report(findings))
"""

from __future__ import annotations

import csv
import io
import json
from typing import Any, Protocol, runtime_checkable

from friTap.analysis import Finding, Severity


def _count_by_severity(findings: list[Finding]) -> dict[str, int]:
    """Count findings by severity level."""
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
    return counts


@runtime_checkable
class Reporter(Protocol):
    """Protocol for finding reporters."""

    def report(self, findings: list[Finding], meta: dict[str, Any] | None = None) -> str:
        """Format findings into a string output.

        Args:
            findings: List of findings to format.
            meta: Optional metadata (tap file path, analyzer names, etc.).

        Returns:
            Formatted output string.
        """
        ...


def _finding_to_dict(finding: Finding) -> dict[str, Any]:
    """Convert a Finding to a plain dict for serialization.

    Delegates to ``Finding.to_dict()`` so there is a single serialization
    contract shared by reporters, the ``.tap`` REC_FINDING record, and the
    findings sidecar.
    """
    return finding.to_dict()


class JsonReporter:
    """Report findings as a JSON document."""

    def __init__(self, *, indent: int = 2, include_meta: bool = True) -> None:
        self._indent = indent
        self._include_meta = include_meta

    def report(self, findings: list[Finding], meta: dict[str, Any] | None = None) -> str:
        output: dict[str, Any] = {}

        if self._include_meta and meta:
            output["meta"] = meta

        output["summary"] = self._build_summary(findings)
        output["findings"] = [_finding_to_dict(f) for f in findings]

        return json.dumps(output, indent=self._indent, default=str)

    def _build_summary(self, findings: list[Finding]) -> dict[str, Any]:
        source_counts: dict[str, int] = {}
        for f in findings:
            source_counts[f.source] = source_counts.get(f.source, 0) + 1

        return {
            "total": len(findings),
            "by_severity": _count_by_severity(findings),
            "by_source": source_counts,
        }


class CsvReporter:
    """Report findings as CSV."""

    _COLUMNS = [
        "severity", "title", "source", "flow_id",
        "confidence", "description",
    ]

    def report(self, findings: list[Finding], meta: dict[str, Any] | None = None) -> str:
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=self._COLUMNS, extrasaction="ignore")
        writer.writeheader()

        for f in findings:
            writer.writerow({
                "severity": f.severity.value,
                "title": f.title,
                "source": f.source,
                "flow_id": f.flow_id,
                "confidence": f.confidence,
                "description": f.description,
            })

        return output.getvalue()


class MarkdownReporter:
    """Report findings as a Markdown document."""

    def __init__(self, *, include_evidence: bool = False) -> None:
        self._include_evidence = include_evidence

    def report(self, findings: list[Finding], meta: dict[str, Any] | None = None) -> str:
        lines: list[str] = []

        lines.append("# friTap Analysis Report\n")

        if meta:
            if "tap_file" in meta:
                lines.append(f"**Capture:** `{meta['tap_file']}`\n")
            if "analyzers" in meta:
                lines.append(f"**Analyzers:** {', '.join(meta['analyzers'])}\n")

        lines.append("## Summary\n")
        severity_counts = _count_by_severity(findings)

        for sev in ["critical", "high", "medium", "low", "info"]:
            count = severity_counts.get(sev, 0)
            if count > 0:
                lines.append(f"- **{sev.upper()}**: {count}")
        lines.append(f"- **Total**: {len(findings)}\n")

        # Group by severity
        for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            sev_findings = [f for f in findings if f.severity == sev]
            if not sev_findings:
                continue

            lines.append(f"## {sev.value.upper()} ({len(sev_findings)})\n")

            for f in sev_findings:
                confidence_str = f" (confidence: {f.confidence:.0%})" if f.confidence < 1.0 else ""
                lines.append(f"### {f.title}{confidence_str}\n")
                lines.append(f"{f.description}\n")

                if f.flow_id:
                    lines.append(f"- **Flow:** `{f.flow_id}`")
                lines.append(f"- **Source:** {f.source}")

                if self._include_evidence and f.evidence:
                    lines.append("\n**Evidence:**")
                    lines.append("```json")
                    lines.append(json.dumps(f.evidence, indent=2, default=str))
                    lines.append("```")

                lines.append("")

        return "\n".join(lines)


class TableReporter:
    """Report findings as an aligned text table (for terminal output)."""

    def report(self, findings: list[Finding], meta: dict[str, Any] | None = None) -> str:
        if not findings:
            return "No findings.\n"

        lines: list[str] = []

        # Compute column widths
        sev_w = max(len(f.severity.value) for f in findings)
        sev_w = max(sev_w, 8)
        src_w = max(len(f.source) for f in findings)
        src_w = max(src_w, 6)
        title_w = min(max(len(f.title) for f in findings), 60)
        title_w = max(title_w, 5)

        header = f"{'Severity':<{sev_w}}  {'Source':<{src_w}}  {'Title':<{title_w}}  Description"
        sep = "-" * max(len(header), 80)

        lines.append(sep)
        lines.append(header)
        lines.append(sep)

        for f in findings:
            title = f.title[:title_w]
            desc = f.description[:80]
            lines.append(f"{f.severity.value:<{sev_w}}  {f.source:<{src_w}}  {title:<{title_w}}  {desc}")

        lines.append(sep)

        severity_counts = _count_by_severity(findings)
        summary_parts = [f"{k}: {v}" for k, v in severity_counts.items()]
        lines.append(f"\nTotal: {len(findings)} findings ({', '.join(summary_parts)})")

        return "\n".join(lines)


__all__ = [
    "Reporter",
    "JsonReporter",
    "CsvReporter",
    "MarkdownReporter",
    "TableReporter",
]
