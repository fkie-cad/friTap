#!/usr/bin/env python3
"""Generate a TLS library attribution report from a live friTap capture.

Usage:
    # Live capture mode (recommended — full library data available)
    python library_attribution_report.py --live com.example.app --mobile
    python library_attribution_report.py --live com.example.app --mobile --duration 30

    # Offline .tap file mode (connection metadata only, no library identity)
    python library_attribution_report.py capture.tap

This script leverages friTap's UNIQUE capability: knowing which TLS library
handled each connection. No other tool has this data.

In live mode, it correlates LibraryDetectedEvent with DatalogEvent to build
a mapping of: endpoint -> TLS library -> system vs bundled.

In offline mode, it reports connection metadata (endpoints, session IDs,
connection patterns) without library identity since .tap files don't store
library detection events.
"""

import argparse
import json
import sys
import time
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from friTap.flow.models import format_byte_size


def _make_endpoint_data(default_library: str = "unknown") -> dict[str, dict]:
    """Create a defaultdict for endpoint aggregation."""
    return defaultdict(lambda: {
        "library": default_library,
        "connections": 0,
        "bytes": 0,
        "methods": set(),
        "status_codes": set(),
    })


def _run_live_capture(target: str, mobile: bool, duration: int, output: str | None) -> None:
    """Run a live capture and build library attribution from EventBus events."""
    from friTap import FriTap
    from friTap.events import LibraryDetectedEvent, DatalogEvent

    endpoint_data = _make_endpoint_data()
    detected_libraries: list[dict] = []
    # Pre-computed set for O(1) lookups on the hot path
    detected_lib_names: set[str] = set()

    def on_library(event: LibraryDetectedEvent) -> None:
        detected_libraries.append({"library": event.library, "module": event.module, "path": event.path})
        detected_lib_names.add(event.library.lower())
        print(f"  [lib] {event.library}: {event.path or event.module}")

    def on_data(event: DatalogEvent) -> None:
        key = f"{event.dst_addr}:{event.dst_port}"
        ep = endpoint_data[key]
        ep["connections"] += 1
        ep["bytes"] += len(event.data)
        ep["dst_addr"] = event.dst_addr
        ep["dst_port"] = event.dst_port

        func = event.function.lower()
        if "wolfssl" in func:
            ep["library"] = "WolfSSL"
        elif "gnutls" in func:
            ep["library"] = "GnuTLS"
        elif "nss" in func or "pr_read" in func or "pr_write" in func:
            ep["library"] = "NSS"
        elif "mbedtls" in func:
            ep["library"] = "mbedTLS"
        elif "s2n" in func:
            ep["library"] = "s2n-tls"
        elif "ssl_read" in func or "ssl_write" in func:
            if any("boring" in name for name in detected_lib_names):
                ep["library"] = "BoringSSL"
            elif any("openssl" in name for name in detected_lib_names):
                ep["library"] = "OpenSSL"
            else:
                ep["library"] = "OpenSSL/BoringSSL"

    from friTap.flow.models import FlowEventType

    def on_flow(event) -> None:
        if event.flow_event_type != FlowEventType.COMPLETED or event.flow is None:
            return
        flow = event.flow
        key = f"{flow.dst_addr}:{flow.dst_port}"
        ep = endpoint_data[key]
        if flow.request and flow.request.method:
            ep["methods"].add(flow.request.method)
        if flow.request and flow.request.host:
            ep["host"] = flow.request.host
        if flow.response and flow.response.status_code:
            ep["status_codes"].add(flow.response.status_code)

    print(f"Starting live capture of '{target}' for {duration}s...")

    builder = FriTap(target)
    if mobile:
        builder = builder.mobile()

    session = (
        builder
        .on_library_detected(on_library)
        .on_data(on_data)
        .on_flow(on_flow)
        .start()
    )

    try:
        time.sleep(duration)
    except KeyboardInterrupt:
        print("\nCapture interrupted.")
    finally:
        session.stop()

    _print_report(endpoint_data, detected_libraries, output)


def _run_offline(tap_path: str, output: str | None) -> None:
    """Analyze a .tap file for connection patterns (no library identity)."""
    from friTap.flow.tap_reader import TapReader

    endpoint_data = _make_endpoint_data(default_library="unknown (offline)")

    with TapReader(tap_path) as reader:
        summaries = reader.read_flow_summaries()
        print(f"Loaded {len(summaries)} flows from {tap_path}\n")

        for summary in summaries:
            key = f"{summary.dst_addr}:{summary.dst_port}"
            ep = endpoint_data[key]
            ep["connections"] += 1
            ep["bytes"] += summary.body_size or summary.total_size or 0
            ep["dst_addr"] = summary.dst_addr
            ep["dst_port"] = summary.dst_port
            if summary.method:
                ep["methods"].add(summary.method)
            if summary.host:
                ep["host"] = summary.host
            if summary.status_code:
                ep["status_codes"].add(summary.status_code)

    print("NOTE: Library identity is only available in live capture mode.")
    print("      Use --live <target> for full TLS library attribution.\n")
    _print_report(endpoint_data, [], output)


def _print_report(
    endpoint_data: dict[str, dict],
    detected_libraries: list[dict],
    output: str | None,
) -> None:
    """Format and print the attribution report."""
    if not endpoint_data:
        print("No connections captured.")
        return

    lines: list[str] = []
    lines.append("=" * 80)
    lines.append("TLS Library Attribution Report")
    lines.append("=" * 80)

    # Detected libraries section
    if detected_libraries:
        lines.append("\n## Detected TLS Libraries\n")
        seen = set()
        for lib in detected_libraries:
            key = lib["library"]
            if key not in seen:
                seen.add(key)
                path = lib.get("path", "")
                # Heuristic: bundled if path is inside app-specific directories
                bundled_indicators = ("/data/", "/app/", ".framework/", "\\AppData\\", "/Contents/")
                bundled = "bundled" if any(ind in path for ind in bundled_indicators) else "system"
                lines.append(f"  {key:<25} [{bundled}] {path}")

    # Endpoint matrix
    lines.append("\n## Endpoint → Library Matrix\n")

    # Sort by library then host for grouping
    sorted_eps = sorted(
        endpoint_data.items(),
        key=lambda kv: (kv[1].get("library", ""), kv[1].get("host", kv[0])),
    )

    # Compute column widths
    host_w = max(
        len(ep.get("host", key)) for key, ep in sorted_eps
    )
    host_w = max(host_w, 4)
    lib_w = max(len(ep.get("library", "unknown")) for _, ep in sorted_eps)
    lib_w = max(lib_w, 7)

    header = f"  {'Host':<{host_w}}  {'Library':<{lib_w}}  {'Conns':>5}  {'Bytes':>10}  Methods"
    lines.append(header)
    lines.append("  " + "-" * (len(header) - 2))

    for key, ep in sorted_eps:
        host = ep.get("host", key)
        library = ep.get("library", "unknown")
        conns = ep["connections"]
        total_bytes = ep["bytes"]
        methods = ", ".join(sorted(ep["methods"])) if ep["methods"] else "-"
        size_str = format_byte_size(total_bytes)

        lines.append(
            f"  {host:<{host_w}}  {library:<{lib_w}}  {conns:>5}  {size_str:>10}  {methods}"
        )

    # Summary
    lines.append("\n## Summary\n")
    lib_counts: dict[str, int] = defaultdict(int)
    for ep in endpoint_data.values():
        lib_counts[ep.get("library", "unknown")] += 1

    for lib, count in sorted(lib_counts.items(), key=lambda x: -x[1]):
        lines.append(f"  {lib}: {count} endpoint(s)")

    total_endpoints = len(endpoint_data)
    total_libraries = len(lib_counts)
    lines.append(f"\n  Total: {total_endpoints} endpoints, {total_libraries} unique TLS library(ies)")

    # Risk flags
    if total_libraries > 1:
        lines.append("\n## Risk Flags\n")
        lines.append("  [!] Multiple TLS libraries detected — this may indicate:")
        lines.append("      - Third-party SDKs bundling their own TLS implementation")
        lines.append("      - Potentially outdated or unpatched bundled libraries")
        lines.append("      - Custom C2 using a different library than legitimate traffic")

    lines.append("\n" + "=" * 80)

    report = "\n".join(lines)
    print(report)

    if output:
        # Also save as JSON for machine consumption
        json_data = {
            "detected_libraries": detected_libraries,
            "endpoints": {
                key: {
                    **{k: v for k, v in ep.items() if k not in ("methods", "status_codes")},
                    "methods": sorted(ep["methods"]),
                    "status_codes": sorted(ep["status_codes"]),
                }
                for key, ep in endpoint_data.items()
            },
            "library_counts": dict(lib_counts),
        }
        Path(output).write_text(json.dumps(json_data, indent=2, default=str))
        print(f"\nJSON report saved to {output}")


def main():
    parser = argparse.ArgumentParser(
        description="TLS library attribution report — leverages friTap's unique capability.",
    )
    parser.add_argument(
        "tap_file",
        nargs="?",
        help="Path to a .tap file (offline mode, limited — no library identity)",
    )
    parser.add_argument(
        "--live",
        metavar="TARGET",
        help="Target app for live capture (e.g., com.example.app or PID)",
    )
    parser.add_argument("--mobile", action="store_true", help="Use mobile (USB) device")
    parser.add_argument(
        "--duration", "-d",
        type=int,
        default=30,
        help="Capture duration in seconds (default: 30)",
    )
    parser.add_argument("--output", "-o", help="Output file path for JSON report")
    args = parser.parse_args()

    if args.live:
        _run_live_capture(args.live, args.mobile, args.duration, args.output)
    elif args.tap_file:
        if not Path(args.tap_file).is_file():
            print(f"Error: file not found: {args.tap_file}", file=sys.stderr)
            sys.exit(1)
        _run_offline(args.tap_file, args.output)
    else:
        parser.error("Provide either a .tap file or --live TARGET")


if __name__ == "__main__":
    main()
