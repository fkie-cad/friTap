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


# Categories whose values are sensitive and redacted by default in reports.
_SENSITIVE_CATEGORIES = frozenset({"pii", "secret"})

# Redaction is deny-by-default: for a sensitive (pii/secret) finding, EVERY
# string evidence value is masked unless its key names purely-descriptive
# context (a name/type/location/metric/flag — never the matched content). This
# allowlist is the safe set; any other key (``value``, ``payload``, ``bearer``,
# a future analyzer's new key, …) is treated as sensitive and masked. This is
# the robust inverse of an easily-outgrown denylist of "sensitive" key names.
_SAFE_EVIDENCE_KEYS = frozenset({
    "location", "host", "type", "header", "field", "context", "content_type",
    "cwe", "scheme", "port", "algorithm", "pii_type", "pattern", "parameter",
    "method", "direction", "charset", "category", "id_type", "card_scheme",
    "status", "kty", "redacted", "redactable", "confidence", "length", "size",
    "entropy", "suppressed", "reasons", "locations", "issues",
})

# Don't scrub very short raw values out of title/description — a 1-3 char value
# would mangle unrelated substrings. Such values are still masked in evidence.
_MIN_SCRUB_LEN = 5


def _mask(value: str, keep: int = 4) -> str:
    """Mask a sensitive string, keeping only the first ``keep`` characters."""
    if len(value) <= keep:
        return "****"
    return value[:keep] + "****"


def _redact_finding(finding: Finding) -> Finding:
    """Return a redaction-safe copy of *finding* for presentation.

    The reporter layer is the single enforcement point for redaction (the
    ``.tap``/in-memory finding keeps full fidelity for the TUI/API). Only
    findings in :data:`_SENSITIVE_CATEGORIES` that are not already redacted by
    their analyzer (``evidence["redacted"]``) are touched. Every evidence string
    value whose key is not in :data:`_SAFE_EVIDENCE_KEYS` is masked, and each
    such raw value is scrubbed from the title and description so a value embedded
    in free text (e.g. the IOC email title) does not leak.
    """
    import dataclasses

    if finding.category not in _SENSITIVE_CATEGORIES:
        return finding
    if finding.evidence.get("redacted"):
        return finding

    raw_values: list[str] = []
    new_evidence = dict(finding.evidence)
    for key, val in finding.evidence.items():
        if key in _SAFE_EVIDENCE_KEYS:
            continue
        if isinstance(val, str) and val:
            raw_values.append(val)
            new_evidence[key] = _mask(val)
    if not raw_values:
        return finding  # nothing sensitive to mask

    new_evidence["redacted"] = True

    title = finding.title
    description = finding.description
    for raw in sorted(set(raw_values), key=len, reverse=True):
        if len(raw) < _MIN_SCRUB_LEN:
            continue
        masked = _mask(raw)
        title = title.replace(raw, masked)
        description = description.replace(raw, masked)

    return dataclasses.replace(
        finding, title=title, description=description, evidence=new_evidence
    )


def _prepare(findings: list[Finding], redact_pii: bool) -> list[Finding]:
    """Apply reporter-layer redaction to *findings* when *redact_pii* is set."""
    if not redact_pii:
        return findings
    return [_redact_finding(f) for f in findings]


class JsonReporter:
    """Report findings as a JSON document."""

    def __init__(self, *, indent: int = 2, include_meta: bool = True, redact_pii: bool = True) -> None:
        self._indent = indent
        self._include_meta = include_meta
        self._redact_pii = redact_pii

    def report(self, findings: list[Finding], meta: dict[str, Any] | None = None) -> str:
        findings = _prepare(findings, self._redact_pii)
        output: dict[str, Any] = {}

        if self._include_meta and meta:
            output["meta"] = meta

        output["summary"] = self._build_summary(findings)
        output["findings"] = [_finding_to_dict(f) for f in findings]

        return json.dumps(output, indent=self._indent, default=str)

    def _build_summary(self, findings: list[Finding]) -> dict[str, Any]:
        source_counts: dict[str, int] = {}
        category_counts: dict[str, int] = {}
        for f in findings:
            source_counts[f.source] = source_counts.get(f.source, 0) + 1
            cat = f.category or "uncategorized"
            category_counts[cat] = category_counts.get(cat, 0) + 1

        return {
            "total": len(findings),
            "by_severity": _count_by_severity(findings),
            "by_source": source_counts,
            "by_category": category_counts,
        }


class CsvReporter:
    """Report findings as CSV."""

    _COLUMNS = [
        "severity", "title", "source", "category", "flow_id",
        "confidence", "description",
    ]

    def __init__(self, *, redact_pii: bool = True) -> None:
        self._redact_pii = redact_pii

    def report(self, findings: list[Finding], meta: dict[str, Any] | None = None) -> str:
        findings = _prepare(findings, self._redact_pii)
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=self._COLUMNS, extrasaction="ignore")
        writer.writeheader()

        for f in findings:
            writer.writerow({
                "severity": f.severity.value,
                "title": f.title,
                "source": f.source,
                "category": f.category or "",
                "flow_id": f.flow_id,
                "confidence": f.confidence,
                "description": f.description,
            })

        return output.getvalue()


class MarkdownReporter:
    """Report findings as a Markdown document."""

    def __init__(self, *, include_evidence: bool = False, redact_pii: bool = True) -> None:
        self._include_evidence = include_evidence
        self._redact_pii = redact_pii

    def report(self, findings: list[Finding], meta: dict[str, Any] | None = None) -> str:
        findings = _prepare(findings, self._redact_pii)
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
                if f.category:
                    lines.append(f"- **Category:** {f.category}")
                if f.metadata.get("compliance"):
                    lines.append(f"- **Compliance:** {', '.join(f.metadata['compliance'])}")

                if self._include_evidence and f.evidence:
                    lines.append("\n**Evidence:**")
                    lines.append("```json")
                    lines.append(json.dumps(f.evidence, indent=2, default=str))
                    lines.append("```")

                lines.append("")

        return "\n".join(lines)


class TableReporter:
    """Report findings as an aligned text table (for terminal output)."""

    def __init__(self, *, redact_pii: bool = True) -> None:
        self._redact_pii = redact_pii

    def report(self, findings: list[Finding], meta: dict[str, Any] | None = None) -> str:
        findings = _prepare(findings, self._redact_pii)
        if not findings:
            return "No findings.\n"

        lines: list[str] = []

        # Compute column widths
        sev_w = max(len(f.severity.value) for f in findings)
        sev_w = max(sev_w, 8)
        src_w = max(len(f.source) for f in findings)
        src_w = max(src_w, 6)
        cat_w = max((len(f.category or "-") for f in findings), default=8)
        cat_w = max(cat_w, 8)
        title_w = min(max(len(f.title) for f in findings), 60)
        title_w = max(title_w, 5)

        header = (
            f"{'Severity':<{sev_w}}  {'Source':<{src_w}}  {'Category':<{cat_w}}  "
            f"{'Title':<{title_w}}  Description"
        )
        sep = "-" * max(len(header), 80)

        lines.append(sep)
        lines.append(header)
        lines.append(sep)

        for f in findings:
            cat = f.category or "-"
            title = f.title[:title_w]
            desc = f.description[:80]
            lines.append(
                f"{f.severity.value:<{sev_w}}  {f.source:<{src_w}}  {cat:<{cat_w}}  "
                f"{title:<{title_w}}  {desc}"
            )

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
