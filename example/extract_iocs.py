#!/usr/bin/env python3
"""Extract Indicators of Compromise (IOCs) from a friTap .tap capture file.

Usage:
    python extract_iocs.py capture.tap
    python extract_iocs.py capture.tap --format json --output iocs.json
    python extract_iocs.py capture.tap --format csv --output iocs.csv
    python extract_iocs.py capture.tap --type domain,ip,hash

This script demonstrates how to use the friTap analysis framework to:
  - Extract domains, IPs, URLs, file hashes from captured traffic
  - Identify User-Agent strings, server software, email addresses
  - Export IOCs in multiple formats (table, JSON, CSV, Markdown)
  - Filter by IOC type for targeted extraction
"""

import argparse
import sys
from pathlib import Path

# Allow standalone execution from the example/ directory
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from friTap.analysis import analyze_tap
from friTap.analysis.ioc import IocAnalyzer
from friTap.analysis.reporters import (
    JsonReporter,
    CsvReporter,
    MarkdownReporter,
    TableReporter,
)


def main():
    parser = argparse.ArgumentParser(
        description="Extract IOCs from a friTap .tap capture.",
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
        "--type", "-t",
        help="Comma-separated IOC types to extract (domain,ip,url,hash,email,user-agent,server). Default: all",
    )
    parser.add_argument(
        "--include-private-ips",
        action="store_true",
        help="Include private/reserved IP addresses in output",
    )
    parser.add_argument(
        "--deduplicate",
        action="store_true",
        default=True,
        help="Deduplicate IOCs by type+value (default: true)",
    )
    args = parser.parse_args()

    tap_path = args.tap_file
    if not Path(tap_path).is_file():
        print(f"Error: file not found: {tap_path}", file=sys.stderr)
        sys.exit(1)

    # Run the IOC analyzer
    analyzer = IocAnalyzer(include_private_ips=args.include_private_ips)
    findings = analyze_tap(analyzer, tap_path)

    # Filter by IOC type if specified
    if args.type:
        allowed_types = set(args.type.split(","))
        findings = [
            f for f in findings
            if f.evidence.get("type", "") in allowed_types
        ]

    # Deduplicate by type+value
    if args.deduplicate:
        seen: set[tuple[str, str]] = set()
        deduped = []
        for f in findings:
            key = (f.evidence.get("type", ""), f.evidence.get("value", ""))
            if key not in seen:
                seen.add(key)
                deduped.append(f)
        findings = deduped

    if not findings:
        print("No IOCs found in the capture.")
        return

    # Format output
    meta = {"tap_file": tap_path, "analyzers": ["ioc"]}
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
        print(f"IOCs written to {args.output}")
    else:
        print(output)

    # Print quick summary
    if args.format == "table":
        type_counts: dict[str, int] = {}
        for f in findings:
            ioc_type = f.evidence.get("type", "unknown")
            type_counts[ioc_type] = type_counts.get(ioc_type, 0) + 1
        parts = [f"{t}: {c}" for t, c in sorted(type_counts.items())]
        print(f"\nIOC types: {', '.join(parts)}")


if __name__ == "__main__":
    main()
