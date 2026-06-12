"""
Offline ``.tap`` analysis CLI — passive analysis of observed traffic.

Runs friTap's analyzers over a captured ``.tap`` file and renders the findings
in the chosen report format. This is a *passive* analysis of already-captured
traffic; it never touches the target or generates any network activity.

Entry point::

    fritap analyze capture.tap --scanners credentials,ioc --report table

The ``_REPORTER_REGISTRY`` and ``_filter_min_severity`` helpers defined here
are the single source of truth for report selection and severity filtering;
the live-scan path in ssl_logger_core imports them rather than duplicating.
"""

from __future__ import annotations

import argparse
import logging
import os
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable

from friTap.analysis import Severity, analyze_tap_multi, severity_rank
from friTap.analysis.registry import resolve_analyzers
from friTap.analysis.reporters import (
    CsvReporter,
    JsonReporter,
    MarkdownReporter,
    TableReporter,
)

if TYPE_CHECKING:
    from friTap.analysis import Finding

logger = logging.getLogger("friTap.analyze")


# Severity string -> rank for --min-severity filtering, derived from the
# canonical ``Severity`` enum order (lower rank == more severe) so there is a
# single source of truth. Used for the argparse choices and the filter below.
_SEVERITY_ORDER: dict[str, int] = {sev.value: severity_rank(sev) for sev in Severity}

# Report format -> reporter factory. Shared with the live-scan path.
_REPORTER_REGISTRY: dict[str, Callable[[], object]] = {
    "json": JsonReporter,
    "csv": CsvReporter,
    "md": MarkdownReporter,
    "table": TableReporter,
}

# Findings at or above this severity make run_analyze_cli return non-zero (2),
# so the command is usable as a CI gate.
_GATE_SEVERITY = "medium"


def _filter_min_severity(findings: list["Finding"], min_severity: str) -> list["Finding"]:
    """Return findings whose severity is at least *min_severity*.

    Thin wrapper over :class:`~friTap.analysis.filtering.FindingFilter` (the
    single filtering primitive). An unknown *min_severity* falls back to
    ``"info"`` (keep all), preserving the historical behaviour byte-for-byte.
    """
    from friTap.analysis.filtering import FindingFilter, apply

    normalized = min_severity if min_severity in _SEVERITY_ORDER else "info"
    return apply(findings, FindingFilter(min_severity=normalized))


def _sidecar_path(tap_file: str) -> str:
    """Return the ``<tap_stem>.findings.json`` sidecar path for *tap_file*."""
    stem, _ext = os.path.splitext(tap_file)
    return f"{stem}.findings.json"


@dataclass(frozen=True)
class AnalyzeReport:
    """Result of a programmatic ``.tap`` analysis.

    Carries both the structured (already severity-filtered) findings and the
    report rendered in the requested format, so web / TUI / CLI callers can use
    whichever they need without re-running the analyzers. Returned by
    :func:`analyze_tap_report`.
    """

    findings: list["Finding"]
    rendered: str
    report_format: str
    analyzer_names: list[str] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)
    gate_severity: str = _GATE_SEVERITY

    @property
    def gate_tripped(self) -> bool:
        """True iff any finding is at or above :attr:`gate_severity`.

        Mirrors the condition under which :func:`run_analyze_cli` returns the
        non-zero CI-gate exit code.
        """
        return bool(_filter_min_severity(self.findings, self.gate_severity))

    @property
    def exit_code(self) -> int:
        """CLI-parity exit code: 2 when :attr:`gate_tripped`, else 0."""
        return 2 if self.gate_tripped else 0


def analyze_tap_report(
    tap_file: str,
    *,
    scanners: str | None = None,
    analyzer_path: str | None = None,
    min_severity: str = "info",
    report_format: str = "table",
    include_private_ips: bool = False,
    protobuf_schema: str | None = None,
    min_confidence: float = 0.0,
    source: str | None = None,
    category: str | None = None,
    show_pii: bool = False,
) -> AnalyzeReport:
    """Run analyzers over *tap_file* and return findings + a rendered report.

    Pure orchestration shared by the CLI and external tools: resolve analyzers
    (``scanners`` is a comma-separated name list, or ``None``/``"all"`` for the
    built-ins) → run them → filter (severity/confidence/source/category) →
    render in *report_format* (one of :func:`list_report_formats`). Performs no
    stdout, no sidecar write and never calls ``sys.exit`` — callers decide how
    to surface the result.

    The filter arguments are all additive and default to no-ops, so existing
    callers are unaffected:

    * ``min_confidence`` — keep findings with confidence at or above this value.
    * ``source`` — comma-separated analyzer source names to keep (which findings
      *show*; distinct from ``scanners``, which selects analyzers that *run*).
    * ``category`` — comma-separated finding categories to keep
      (``secret``/``pii``/``network``/``protocol``).
    * ``show_pii`` — reveal PII/secret values instead of redacting them
      (forwarded to analyzers as ``reveal_pii``; default redacts).

    Raises ``ValueError`` for an unknown *report_format* or an unresolvable
    analyzer spec, ``ImportError`` for a bad ``analyzer_path``; any .tap
    read/analyze failure propagates.
    """
    from friTap.analysis.filtering import FindingFilter, apply, split_csv

    if report_format not in _REPORTER_REGISTRY:
        raise ValueError(
            f"unknown report format {report_format!r}; "
            f"choose from {', '.join(sorted(_REPORTER_REGISTRY))}"
        )

    analyzers = resolve_analyzers(
        scanners,
        analyzer_path=analyzer_path,
        include_private_ips=include_private_ips,
        protobuf_schema=protobuf_schema,
        reveal_pii=show_pii,
    )
    findings = analyze_tap_multi(analyzers, tap_file)
    normalized_severity = min_severity if min_severity in _SEVERITY_ORDER else "info"
    finding_filter = FindingFilter(
        min_severity=normalized_severity,
        sources=split_csv(source),
        categories=split_csv(category),
        min_confidence=min_confidence if min_confidence > 0.0 else None,
    )
    filtered = apply(findings, finding_filter)
    analyzer_names = [a.name for a in analyzers]
    meta = {"tap_file": tap_file, "analyzers": analyzer_names}
    # AnalyzeReport.findings keep full fidelity; only the rendered report is
    # redacted (unless show_pii). The reporter is the redaction enforcement point.
    rendered = _REPORTER_REGISTRY[report_format](redact_pii=not show_pii).report(filtered, meta)
    return AnalyzeReport(
        findings=filtered,
        rendered=rendered,
        report_format=report_format,
        analyzer_names=analyzer_names,
        meta=meta,
    )


def list_report_formats() -> list[str]:
    """Return the available report-format names (e.g. ``json``/``csv``/``md``/``table``)."""
    return sorted(_REPORTER_REGISTRY)


def list_analyzers() -> list[str]:
    """Return the names of the built-in analyzers available to ``--scan``/analyze."""
    from friTap.analysis.registry import available_analyzers
    return available_analyzers()


def _build_parser() -> argparse.ArgumentParser:
    """Build the standalone argument parser for the analyze sub-command."""
    parser = argparse.ArgumentParser(
        prog="fritap analyze",
        description=(
            "Passive analysis of observed traffic in a captured .tap file. "
            "Runs friTap analyzers offline; no network activity is generated."
        ),
    )
    parser.add_argument("tap_file", help="Path to the .tap capture file to analyze.")
    parser.add_argument(
        "--scanners",
        default=None,
        help="Comma-separated analyzer names (default: all built-ins).",
    )
    parser.add_argument(
        "--report",
        choices=sorted(_REPORTER_REGISTRY),
        default="table",
        help="Report output format (default: table).",
    )
    parser.add_argument(
        "--report-out",
        default=None,
        help="Write the report to this path instead of stdout.",
    )
    parser.add_argument(
        "--min-severity",
        choices=sorted(_SEVERITY_ORDER, key=lambda s: _SEVERITY_ORDER[s]),
        default="info",
        help="Only report findings at or above this severity (default: info).",
    )
    parser.add_argument(
        "--min-confidence",
        type=float,
        default=0.0,
        help="Only report findings with confidence at or above this value (0.0-1.0; default: 0.0).",
    )
    parser.add_argument(
        "--source",
        default=None,
        help=(
            "Comma-separated analyzer source names to include in the report "
            "(e.g. credentials,privacy). Filters which findings show; use "
            "--scanners to choose which analyzers run. Default: all."
        ),
    )
    parser.add_argument(
        "--category",
        default=None,
        help=(
            "Comma-separated finding categories to include "
            "(secret,pii,network,protocol). Default: all."
        ),
    )
    parser.add_argument(
        "--show-pii",
        action="store_true",
        help="Reveal PII/secret values in the report instead of redacting them (default: redacted).",
    )
    parser.add_argument(
        "--analyzer-path",
        default=None,
        help="Load an external analyzer ('module' or 'module:Class').",
    )
    parser.add_argument(
        "--include-private-ips",
        action="store_true",
        help="Include private/reserved IP addresses in IOC findings.",
    )
    parser.add_argument(
        "--protobuf-schema",
        default=None,
        help="Path to a protobuf schema for the protobuf analyzer.",
    )
    return parser


def run_analyze_cli(argv: list[str]) -> int:
    """Run the offline ``.tap`` analysis CLI.

    Returns 0 on success, 2 when any finding is at or above the gate severity
    (medium), and 1 for usage/IO errors (missing file, bad scanner name).
    """
    parser = _build_parser()
    args = parser.parse_args(argv)

    if not os.path.isfile(args.tap_file):
        logger.error("tap file not found: %s", args.tap_file)
        return 1

    # Resolve analyzers first so a bad scanner name / --analyzer-path surfaces
    # the precise "Could not resolve analyzers" diagnostic. analyze_tap_report
    # resolves again internally, but resolution is pure, cheap object
    # construction — the duplicate call is worth keeping the two-stage error
    # classification (resolve failure vs. analyze/read/render failure), so a
    # ValueError raised while reading a corrupt .tap is not mislabeled as a
    # scanner-resolution problem.
    try:
        resolve_analyzers(
            args.scanners,
            analyzer_path=args.analyzer_path,
            include_private_ips=args.include_private_ips,
            protobuf_schema=args.protobuf_schema,
        )
    except (ValueError, ImportError) as exc:
        logger.error("Could not resolve analyzers: %s", exc)
        return 1

    try:
        report = analyze_tap_report(
            args.tap_file,
            scanners=args.scanners,
            analyzer_path=args.analyzer_path,
            min_severity=args.min_severity,
            report_format=args.report,
            include_private_ips=args.include_private_ips,
            protobuf_schema=args.protobuf_schema,
            min_confidence=args.min_confidence,
            source=args.source,
            category=args.category,
            show_pii=args.show_pii,
        )
    except Exception as exc:  # noqa: BLE001 — surface any read/analyze failure cleanly
        logger.error("Analysis failed: %s", exc)
        return 1

    filtered = report.findings
    meta = report.meta
    rendered = report.rendered

    if args.report_out:
        # Mirror the sidecar write below: an unwritable path must surface as the
        # documented exit code 1, not an unhandled OSError crash (#8).
        try:
            with open(args.report_out, "w", encoding="utf-8") as fh:
                fh.write(rendered)
        except OSError as exc:
            logger.error("Could not write report to %s: %s", args.report_out, exc)
            return 1
        logger.info("Report written to %s", args.report_out)
    else:
        print(rendered)

    # Always write the JSON findings sidecar next to the tap file. The sidecar
    # is a shareable derived artifact, so redact by default (unless --show-pii).
    try:
        sidecar = _sidecar_path(args.tap_file)
        with open(sidecar, "w", encoding="utf-8") as fh:
            fh.write(JsonReporter(redact_pii=not args.show_pii).report(filtered, meta))
        logger.info("Findings sidecar written to %s", sidecar)
    except OSError as exc:
        logger.warning("Could not write findings sidecar: %s", exc)

    # Gate: non-zero exit when any finding is at or above _GATE_SEVERITY.
    # Reuse the AnalyzeReport gate rather than a second bespoke severity scan.
    return report.exit_code


__all__ = [
    "run_analyze_cli",
    "AnalyzeReport",
    "analyze_tap_report",
    "list_report_formats",
    "list_analyzers",
    "_REPORTER_REGISTRY",
    "_SEVERITY_ORDER",
    "_filter_min_severity",
]
