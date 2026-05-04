#!/usr/bin/env python3
"""Extract protobuf and gRPC messages from a friTap .tap capture file.

Usage:
    python extract_protobufs.py capture.tap
    python extract_protobufs.py capture.tap --format json --output protos.json
    python extract_protobufs.py capture.tap --format csv --output protos.csv
    python extract_protobufs.py capture.tap --no-grpc
    python extract_protobufs.py capture.tap --message-type protobuf_decoded

This script demonstrates how to use the friTap analysis framework to:
  - Detect gRPC endpoints from content-type headers
  - Decode protobuf wire format from request/response bodies
  - Identify unusual protobuf structures (high field numbers, deep nesting)
  - Export findings in multiple formats (table, JSON, CSV, Markdown)
"""

import argparse
import sys
from pathlib import Path

# Allow standalone execution from the example/ directory
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from friTap.analysis import analyze_tap
from friTap.analysis.protobuf_analyzer import ProtobufAnalyzer
from friTap.analysis.reporters import (
    JsonReporter,
    CsvReporter,
    MarkdownReporter,
    TableReporter,
)


def main():
    parser = argparse.ArgumentParser(
        description="Extract protobuf/gRPC messages from a friTap .tap capture.",
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
        "--schema", "-s",
        help="Path to .proto schema file for typed decoding (optional)",
    )
    parser.add_argument(
        "--message-type",
        help=(
            "Comma-separated finding types to include "
            "(grpc_endpoint,protobuf_decoded,protobuf_decode_failure,protobuf_anomaly). "
            "Default: all"
        ),
    )
    parser.add_argument(
        "--grpc/--no-grpc",
        dest="grpc",
        default=True,
        help="Include/exclude gRPC endpoint findings (default: include)",
    )
    args = parser.parse_args()

    tap_path = args.tap_file
    if not Path(tap_path).is_file():
        print(f"Error: file not found: {tap_path}", file=sys.stderr)
        sys.exit(1)

    # Run the protobuf analyzer
    analyzer = ProtobufAnalyzer(schema_path=args.schema)
    findings = analyze_tap(analyzer, tap_path)

    # Filter out gRPC endpoint findings if --no-grpc
    if not args.grpc:
        findings = [
            f for f in findings
            if f.evidence.get("type") != "grpc_endpoint"
        ]

    # Filter by message type if specified
    if args.message_type:
        allowed_types = set(args.message_type.split(","))
        findings = [
            f for f in findings
            if f.evidence.get("type", "") in allowed_types
        ]

    if not findings:
        print("No protobuf/gRPC content found in the capture.")
        return

    # Format output
    meta = {"tap_file": tap_path, "analyzers": ["protobuf"]}
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
        print(f"Protobuf findings written to {args.output}")
    else:
        print(output)

    # Print quick summary
    if args.format == "table":
        endpoint_count = sum(
            1 for f in findings if f.evidence.get("type") == "grpc_endpoint"
        )
        structure_count = sum(
            1 for f in findings if f.evidence.get("type") == "protobuf_decoded"
        )
        anomaly_count = sum(
            1 for f in findings if f.evidence.get("type") == "protobuf_anomaly"
        )
        failure_count = sum(
            1 for f in findings if f.evidence.get("type") == "protobuf_decode_failure"
        )
        parts = []
        if endpoint_count:
            parts.append(f"gRPC endpoints: {endpoint_count}")
        if structure_count:
            parts.append(f"decoded structures: {structure_count}")
        if anomaly_count:
            parts.append(f"anomalies: {anomaly_count}")
        if failure_count:
            parts.append(f"decode failures: {failure_count}")
        if parts:
            print(f"\nSummary: {', '.join(parts)}")


if __name__ == "__main__":
    main()
