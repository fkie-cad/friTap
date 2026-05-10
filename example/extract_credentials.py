#!/usr/bin/env python3
"""Extract credentials and secrets from a friTap .tap capture file.

Usage:
    python extract_credentials.py capture.tap
    python extract_credentials.py capture.tap --format json
    python extract_credentials.py capture.tap --format csv --output findings.csv

This script demonstrates how to use the friTap analysis framework to:
  - Scan captured HTTP flows for credentials, API keys, and secrets
  - Detect Bearer tokens, Basic auth, JWT tokens, password fields
  - Find known API key patterns (AWS, GCP, Stripe, GitHub, etc.)
  - Identify high-entropy strings that may be unknown secrets
  - Output findings in multiple formats (table, JSON, CSV, Markdown)
"""

import argparse
import sys
from pathlib import Path

# Allow standalone execution from the example/ directory
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from friTap.analysis import analyze_tap
from friTap.analysis.credentials import CredentialAnalyzer
from friTap.analysis.reporters import (
    JsonReporter,
    CsvReporter,
    MarkdownReporter,
    TableReporter,
)


def main():
    parser = argparse.ArgumentParser(
        description="Extract credentials and secrets from a friTap .tap capture.",
    )
    parser.add_argument(
        "tap_file",
        help="Path to the .tap capture file",
    )
    parser.add_argument(
        "--format", "-f",
        choices=["table", "json", "csv", "markdown"],
        default="table",
        help="Output format (default: table)",
    )
    parser.add_argument(
        "--output", "-o",
        help="Output file path (default: stdout)",
    )
    parser.add_argument(
        "--min-severity",
        choices=["critical", "high", "medium", "low", "info"],
        default="low",
        help="Minimum severity to report (default: low)",
    )
    args = parser.parse_args()

    tap_path = args.tap_file
    if not Path(tap_path).is_file():
        print(f"Error: file not found: {tap_path}", file=sys.stderr)
        sys.exit(1)

    # Run the credential analyzer
    analyzer = CredentialAnalyzer()
    findings = analyze_tap(analyzer, tap_path)

    # Filter by severity
    severity_order = ["critical", "high", "medium", "low", "info"]
    min_idx = severity_order.index(args.min_severity)
    findings = [
        f for f in findings
        if severity_order.index(f.severity.value) <= min_idx
    ]

    if not findings:
        print("No credentials or secrets found in the capture.")
        return

    # Sort by severity (critical first)
    findings.sort(key=lambda f: severity_order.index(f.severity.value))

    # Format output
    meta = {"tap_file": tap_path, "analyzers": ["credentials"]}
    reporters = {
        "table": TableReporter,
        "json": JsonReporter,
        "csv": CsvReporter,
        "markdown": MarkdownReporter,
    }
    reporter = reporters[args.format]()
    output = reporter.report(findings, meta=meta)

    if args.output:
        Path(args.output).write_text(output)
        print(f"Findings written to {args.output}")
    else:
        print(output)


if __name__ == "__main__":
    main()
