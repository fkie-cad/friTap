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
from typing import TYPE_CHECKING, Callable

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

    Severity comparison uses :data:`_SEVERITY_ORDER` (lower rank == more
    severe). An unknown *min_severity* falls back to ``"info"`` (keep all).
    """
    threshold = _SEVERITY_ORDER.get(min_severity, _SEVERITY_ORDER["info"])
    return [
        f for f in findings
        if _SEVERITY_ORDER.get(f.severity.value, _SEVERITY_ORDER["info"]) <= threshold
    ]


def _sidecar_path(tap_file: str) -> str:
    """Return the ``<tap_stem>.findings.json`` sidecar path for *tap_file*."""
    stem, _ext = os.path.splitext(tap_file)
    return f"{stem}.findings.json"


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

    try:
        analyzers = resolve_analyzers(
            args.scanners,
            analyzer_path=args.analyzer_path,
            include_private_ips=args.include_private_ips,
            protobuf_schema=args.protobuf_schema,
        )
    except (ValueError, ImportError) as exc:
        logger.error("Could not resolve analyzers: %s", exc)
        return 1

    try:
        findings = analyze_tap_multi(analyzers, args.tap_file)
    except Exception as exc:  # noqa: BLE001 — surface any read/analyze failure cleanly
        logger.error("Analysis failed: %s", exc)
        return 1

    filtered = _filter_min_severity(findings, args.min_severity)
    meta = {
        "tap_file": args.tap_file,
        "analyzers": [a.name for a in analyzers],
    }

    reporter = _REPORTER_REGISTRY[args.report]()
    rendered = reporter.report(filtered, meta)

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

    # Always write the JSON findings sidecar next to the tap file.
    try:
        sidecar = _sidecar_path(args.tap_file)
        with open(sidecar, "w", encoding="utf-8") as fh:
            fh.write(JsonReporter().report(filtered, meta))
        logger.info("Findings sidecar written to %s", sidecar)
    except OSError as exc:
        logger.warning("Could not write findings sidecar: %s", exc)

    # Gate: non-zero exit when any finding is at or above _GATE_SEVERITY.
    # Reuse the filter rather than a second bespoke severity scan.
    return 2 if _filter_min_severity(filtered, _GATE_SEVERITY) else 0


__all__ = [
    "run_analyze_cli",
    "_REPORTER_REGISTRY",
    "_SEVERITY_ORDER",
    "_filter_min_severity",
]
