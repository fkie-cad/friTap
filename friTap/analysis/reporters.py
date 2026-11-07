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
import html
import io
import json
import re
from typing import Any, Protocol, runtime_checkable

from friTap.analysis import Finding, Severity
from friTap.analysis.masvs import classify_masvs
from friTap.analysis.redaction import redact_finding

# ---------------------------------------------------------------------------
# Output sanitisation (finding text is attacker-controlled)
# ---------------------------------------------------------------------------

# C0 controls, DEL and C1 controls. Tab/newline are excluded here and handled
# per call site, since some formats need them structurally.
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
_NEWLINES_RE = re.compile(r"\r\n|[\r\n]")
# Spreadsheet formula triggers (CSV injection, CWE-1236).
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")
# Markdown-significant characters escaped with a backslash.
_MARKDOWN_SPECIAL_RE = re.compile(r"([\\`*_\[\]()#|~!])")
_BACKTICK_RUN_RE = re.compile(r"`+")


def _escape_control_chars(text: str, *, keep_tab: bool = True, keep_newline: bool = True) -> str:
    """Replace C0/C1 control characters in *text* with visible ``\\xNN`` escapes."""
    text = _CONTROL_CHARS_RE.sub(lambda m: f"\\x{ord(m.group(0)):02x}", text)
    if not keep_tab:
        text = text.replace("\t", "\\x09")
    if not keep_newline:
        text = text.replace("\n", "\\x0a")
    return text


def _sanitize_text(value: Any, *, single_line: bool = False) -> str:
    """Single sanitiser for attacker-controlled text in text reporters.

    Escapes control characters; with *single_line* newlines collapse to a
    space and tabs are escaped (for titles and table cells).
    """
    text = value if isinstance(value, str) else str(value)
    if single_line:
        text = _NEWLINES_RE.sub(" ", text)
        return _escape_control_chars(text, keep_tab=False, keep_newline=False)
    return _escape_control_chars(text)


def _csv_cell(value: Any) -> Any:
    """Neutralise CSV formula injection and control characters in one cell."""
    if not isinstance(value, str):
        return value
    prefix = "'" if value.startswith(_FORMULA_PREFIXES) else ""
    return prefix + _sanitize_text(value)


def _markdown_text(value: Any, *, single_line: bool = False) -> str:
    """Escape *value* for Markdown prose (HTML entities + Markdown specials)."""
    text = _sanitize_text(value, single_line=single_line)
    text = html.escape(text, quote=False)
    return _MARKDOWN_SPECIAL_RE.sub(r"\\\1", text)


def _longest_backtick_run(text: str) -> int:
    return max((len(m) for m in _BACKTICK_RUN_RE.findall(text)), default=0)


def _markdown_code_span(value: Any) -> str:
    """Wrap *value* in an inline code span that its backticks cannot close."""
    text = _sanitize_text(value, single_line=True)
    fence = "`" * (_longest_backtick_run(text) + 1)
    pad = " " if text.startswith("`") or text.endswith("`") else ""
    return f"{fence}{pad}{text}{pad}{fence}"


def _markdown_code_block(body: str, info: str = "") -> list[str]:
    """Return fenced-code-block lines whose fence outlasts any backtick run."""
    fence = "`" * max(3, _longest_backtick_run(body) + 1)
    return [f"{fence}{info}", body, fence]


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


# Redaction rules live in :mod:`friTap.analysis.redaction` (shared with the
# ``fritap report`` digest).


def _prepare(findings: list[Finding], redact_pii: bool) -> list[Finding]:
    """Apply reporter-layer redaction to *findings* when *redact_pii* is set."""
    if not redact_pii:
        return findings
    return [redact_finding(f) for f in findings]


class JsonReporter:
    """Report findings as a JSON document."""

    def __init__(self, *, indent: int = 2, include_meta: bool = True, redact_pii: bool = True,
                 masvs: bool = False) -> None:
        self._indent = indent
        self._include_meta = include_meta
        self._redact_pii = redact_pii
        self._masvs = masvs

    def report(self, findings: list[Finding], meta: dict[str, Any] | None = None) -> str:
        findings = _prepare(findings, self._redact_pii)
        output: dict[str, Any] = {}

        if self._include_meta and meta:
            output["meta"] = meta

        output["summary"] = self._build_summary(findings)
        output["findings"] = [self._finding_entry(f) for f in findings]

        return json.dumps(output, indent=self._indent, default=str)

    def _finding_entry(self, finding: Finding) -> dict[str, Any]:
        """Finding dict, plus the MASVS controls it maps to when enabled.

        The ``masvs`` key is added only when requested and non-empty, so the
        default output is byte-identical to before.
        """
        entry = _finding_to_dict(finding)
        if self._masvs:
            controls = classify_masvs(finding)
            if controls:
                entry["masvs"] = controls
        return entry

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

    def __init__(self, *, redact_pii: bool = True, masvs: bool = False) -> None:
        self._redact_pii = redact_pii
        self._masvs = masvs

    def report(self, findings: list[Finding], meta: dict[str, Any] | None = None) -> str:
        findings = _prepare(findings, self._redact_pii)
        output = io.StringIO()
        columns = [*self._COLUMNS, "masvs"] if self._masvs else self._COLUMNS
        writer = csv.DictWriter(output, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()

        for f in findings:
            row = {
                "severity": f.severity.value,
                "title": _csv_cell(f.title),
                "source": _csv_cell(f.source),
                "category": _csv_cell(f.category or ""),
                "flow_id": _csv_cell(f.flow_id),
                "confidence": f.confidence,
                "description": _csv_cell(f.description),
            }
            if self._masvs:
                row["masvs"] = ";".join(classify_masvs(f))
            writer.writerow(row)

        return output.getvalue()


class MarkdownReporter:
    """Report findings as a Markdown document."""

    def __init__(self, *, include_evidence: bool = False, redact_pii: bool = True,
                 masvs: bool = False) -> None:
        self._include_evidence = include_evidence
        self._redact_pii = redact_pii
        self._masvs = masvs

    def report(self, findings: list[Finding], meta: dict[str, Any] | None = None) -> str:
        findings = _prepare(findings, self._redact_pii)
        lines: list[str] = []

        lines.append("# friTap Analysis Report\n")

        if meta:
            if "tap_file" in meta:
                lines.append(f"**Capture:** {_markdown_code_span(meta['tap_file'])}\n")
            if "analyzers" in meta:
                analyzers = ", ".join(_markdown_text(a, single_line=True) for a in meta["analyzers"])
                lines.append(f"**Analyzers:** {analyzers}\n")

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
                title = _markdown_text(f.title, single_line=True)
                lines.append(f"### {title}{confidence_str}\n")
                lines.append(f"{_markdown_text(f.description)}\n")

                if f.flow_id:
                    lines.append(f"- **Flow:** {_markdown_code_span(f.flow_id)}")
                lines.append(f"- **Source:** {_markdown_text(f.source, single_line=True)}")
                if f.category:
                    lines.append(f"- **Category:** {_markdown_text(f.category, single_line=True)}")
                if f.metadata.get("compliance"):
                    compliance = ", ".join(
                        _markdown_text(c, single_line=True) for c in f.metadata["compliance"]
                    )
                    lines.append(f"- **Compliance:** {compliance}")
                if self._masvs:
                    controls = classify_masvs(f)
                    if controls:
                        lines.append(f"- **MASVS:** {', '.join(controls)}")

                if self._include_evidence and f.evidence:
                    lines.append("\n**Evidence:**")
                    evidence = json.dumps(f.evidence, indent=2, default=str)
                    lines.extend(_markdown_code_block(evidence, "json"))

                lines.append("")

        return "\n".join(lines)


class TableReporter:
    """Report findings as an aligned text table (for terminal output)."""

    def __init__(self, *, redact_pii: bool = True, masvs: bool = False) -> None:
        self._redact_pii = redact_pii
        self._masvs = masvs

    def report(self, findings: list[Finding], meta: dict[str, Any] | None = None) -> str:
        findings = _prepare(findings, self._redact_pii)
        if not findings:
            return "No findings.\n"

        lines: list[str] = []
        rows = [self._sanitized_row(f) for f in findings]

        # Optional MASVS column (between Category and Title); None when disabled,
        # so the default table layout is byte-identical.
        masvs_cells = ([",".join(classify_masvs(f)) or "-" for f in findings]
                       if self._masvs else None)

        # Compute column widths
        sev_w = max(len(f.severity.value) for f in findings)
        sev_w = max(sev_w, 8)
        src_w = max(len(r["source"]) for r in rows)
        src_w = max(src_w, 6)
        cat_w = max((len(r["category"]) for r in rows), default=8)
        cat_w = max(cat_w, 8)
        title_w = min(max(len(r["title"]) for r in rows), 60)
        title_w = max(title_w, 5)

        masvs_head = ""
        if masvs_cells is not None:
            masvs_w = max(max((len(c) for c in masvs_cells), default=5), len("MASVS"))
            masvs_head = f"{'MASVS':<{masvs_w}}  "

        header = (
            f"{'Severity':<{sev_w}}  {'Source':<{src_w}}  {'Category':<{cat_w}}  "
            f"{masvs_head}{'Title':<{title_w}}  Description"
        )
        sep = "-" * max(len(header), 80)

        lines.append(sep)
        lines.append(header)
        lines.append(sep)

        for i, (f, row) in enumerate(zip(findings, rows)):
            cat = row["category"]
            title = row["title"][:title_w]
            desc = row["description"][:80]
            masvs_cell = f"{masvs_cells[i]:<{masvs_w}}  " if masvs_cells is not None else ""
            lines.append(
                f"{f.severity.value:<{sev_w}}  {row['source']:<{src_w}}  {cat:<{cat_w}}  "
                f"{masvs_cell}{title:<{title_w}}  {desc}"
            )

        lines.append(sep)

        severity_counts = _count_by_severity(findings)
        summary_parts = [f"{k}: {v}" for k, v in severity_counts.items()]
        lines.append(f"\nTotal: {len(findings)} findings ({', '.join(summary_parts)})")

        return "\n".join(lines)

    @staticmethod
    def _sanitized_row(finding: Finding) -> dict[str, str]:
        """Single-line, control-char-escaped text cells for one finding."""
        return {
            "source": _sanitize_text(finding.source, single_line=True),
            "category": _sanitize_text(finding.category or "-", single_line=True),
            "title": _sanitize_text(finding.title, single_line=True),
            "description": _sanitize_text(finding.description, single_line=True),
        }


__all__ = [
    "Reporter",
    "JsonReporter",
    "CsvReporter",
    "MarkdownReporter",
    "TableReporter",
]
