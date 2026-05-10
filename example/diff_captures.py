#!/usr/bin/env python3
"""Semantic diff between two friTap .tap capture files.

Usage:
    python diff_captures.py before.tap after.tap
    python diff_captures.py v1.tap v2.tap --format json --output diff.json
    python diff_captures.py baseline.tap consent_denied.tap

Compares two captures at the HTTP layer and reports:
  - New endpoints (host + path pattern) that appeared
  - Removed endpoints that disappeared
  - Changed response status codes
  - New/removed request headers
  - New/removed response headers
  - Changed content types
  - Size changes

Use cases:
  - Compare app versions (detect new third-party SDKs, changed APIs)
  - Compare consent granted vs denied (GDPR research)
  - Compare VPN on vs off
  - Regression testing between releases
"""

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from friTap.flow.tap_reader import TapReader

_RE_UUID = re.compile(r"/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
_RE_NUMERIC_ID = re.compile(r"/\d{6,}")
_RE_HEX_ID = re.compile(r"/[0-9a-fA-F]{24,}")


def _normalize_path(url: str) -> str:
    """Collapse path segments that look like IDs into placeholders.

    /users/123456/posts → /users/{id}/posts
    """
    if not url:
        return "/"
    path = url.split("?", 1)[0]

    path = _RE_UUID.sub("/{uuid}", path)
    path = _RE_NUMERIC_ID.sub("/{id}", path)
    path = _RE_HEX_ID.sub("/{hex_id}", path)
    return path


def _endpoint_key(method: str, host: str, path: str) -> str:
    """Create a normalized endpoint key."""
    return f"{method} {host}{path}"


def _extract_endpoints(tap_path: str) -> dict:
    """Extract endpoint data from a .tap file.

    Returns a dict keyed by normalized endpoint with aggregated metadata.
    """
    endpoints: dict[str, dict] = {}

    with TapReader(tap_path) as reader:
        summaries = reader.read_flow_summaries()

        for summary in summaries:
            method = summary.method or "???"
            host = summary.host or "unknown"
            path = _normalize_path(summary.url)
            key = _endpoint_key(method, host, path)

            if key not in endpoints:
                endpoints[key] = {
                    "method": method,
                    "host": host,
                    "path": path,
                    "status_codes": set(),
                    "request_headers": set(),
                    "response_headers": set(),
                    "content_types": set(),
                    "count": 0,
                    "total_bytes": 0,
                }

            ep = endpoints[key]
            ep["count"] += 1
            if summary.status_code:
                ep["status_codes"].add(summary.status_code)
            ep["total_bytes"] += summary.body_size or summary.total_size or 0

            # Load full flow for header details
            flow = reader.read_flow(summary.flow_id)
            if flow is not None:
                if flow.request:
                    for h in flow.request.headers:
                        ep["request_headers"].add(h.lower())
                if flow.response:
                    for h in flow.response.headers:
                        ep["response_headers"].add(h.lower())
                    ct = flow.response_content_type
                    if ct:
                        ep["content_types"].add(ct.split(";", 1)[0].strip())

    return endpoints


def _compute_diff(before: dict, after: dict) -> dict:
    """Compute the semantic diff between two endpoint sets."""
    before_keys = set(before.keys())
    after_keys = set(after.keys())

    added = sorted(after_keys - before_keys)
    removed = sorted(before_keys - after_keys)
    common = sorted(before_keys & after_keys)

    changes = []
    for key in common:
        b = before[key]
        a = after[key]
        diffs = []

        # Status code changes
        old_codes = b["status_codes"]
        new_codes = a["status_codes"]
        if old_codes != new_codes:
            diffs.append({
                "field": "status_codes",
                "before": sorted(old_codes),
                "after": sorted(new_codes),
            })

        # New request headers
        old_req_h = b["request_headers"]
        new_req_h = a["request_headers"]
        added_h = new_req_h - old_req_h
        removed_h = old_req_h - new_req_h
        if added_h:
            diffs.append({"field": "request_headers_added", "values": sorted(added_h)})
        if removed_h:
            diffs.append({"field": "request_headers_removed", "values": sorted(removed_h)})

        # New response headers
        old_resp_h = b["response_headers"]
        new_resp_h = a["response_headers"]
        added_rh = new_resp_h - old_resp_h
        removed_rh = old_resp_h - new_resp_h
        if added_rh:
            diffs.append({"field": "response_headers_added", "values": sorted(added_rh)})
        if removed_rh:
            diffs.append({"field": "response_headers_removed", "values": sorted(removed_rh)})

        # Content type changes
        old_ct = b["content_types"]
        new_ct = a["content_types"]
        if old_ct != new_ct:
            diffs.append({
                "field": "content_types",
                "before": sorted(old_ct),
                "after": sorted(new_ct),
            })

        # Request count change
        if a["count"] != b["count"]:
            diffs.append({
                "field": "request_count",
                "before": b["count"],
                "after": a["count"],
            })

        if diffs:
            changes.append({"endpoint": key, "changes": diffs})

    # Group added endpoints by host for readability
    added_by_host: dict[str, list[str]] = defaultdict(list)
    for key in added:
        host = after[key]["host"]
        added_by_host[host].append(key)

    removed_by_host: dict[str, list[str]] = defaultdict(list)
    for key in removed:
        host = before[key]["host"]
        removed_by_host[host].append(key)

    return {
        "summary": {
            "endpoints_before": len(before_keys),
            "endpoints_after": len(after_keys),
            "added": len(added),
            "removed": len(removed),
            "changed": len(changes),
            "unchanged": len(common) - len(changes),
        },
        "added_endpoints": added,
        "added_by_host": dict(added_by_host),
        "removed_endpoints": removed,
        "removed_by_host": dict(removed_by_host),
        "changed_endpoints": changes,
    }


def _format_markdown(diff: dict, before_path: str, after_path: str) -> str:
    """Format a diff result as Markdown."""
    lines: list[str] = []
    s = diff["summary"]

    lines.append("# Capture Diff Report\n")
    lines.append(f"**Before:** `{before_path}`  ")
    lines.append(f"**After:** `{after_path}`\n")

    lines.append("## Summary\n")
    lines.append("| Metric | Count |")
    lines.append("|--------|-------|")
    lines.append(f"| Endpoints before | {s['endpoints_before']} |")
    lines.append(f"| Endpoints after | {s['endpoints_after']} |")
    lines.append(f"| Added | {s['added']} |")
    lines.append(f"| Removed | {s['removed']} |")
    lines.append(f"| Changed | {s['changed']} |")
    lines.append(f"| Unchanged | {s['unchanged']} |")
    lines.append("")

    if diff["added_endpoints"]:
        lines.append(f"## Added Endpoints ({s['added']})\n")
        for host, endpoints in sorted(diff["added_by_host"].items()):
            lines.append(f"### {host}\n")
            for ep in sorted(endpoints):
                lines.append(f"- `{ep}`")
            lines.append("")

    if diff["removed_endpoints"]:
        lines.append(f"## Removed Endpoints ({s['removed']})\n")
        for host, endpoints in sorted(diff["removed_by_host"].items()):
            lines.append(f"### {host}\n")
            for ep in sorted(endpoints):
                lines.append(f"- `{ep}`")
            lines.append("")

    if diff["changed_endpoints"]:
        lines.append(f"## Changed Endpoints ({s['changed']})\n")
        for change in diff["changed_endpoints"]:
            lines.append(f"### `{change['endpoint']}`\n")
            for c in change["changes"]:
                field = c["field"]
                if "before" in c and "after" in c:
                    lines.append(f"- **{field}**: `{c['before']}` → `{c['after']}`")
                elif "values" in c:
                    lines.append(f"- **{field}**: {', '.join(f'`{v}`' for v in c['values'])}")
            lines.append("")

    if not diff["added_endpoints"] and not diff["removed_endpoints"] and not diff["changed_endpoints"]:
        lines.append("## No differences found.\n")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Semantic diff between two friTap .tap captures.",
    )
    parser.add_argument("before", help="Path to the 'before' .tap file")
    parser.add_argument("after", help="Path to the 'after' .tap file")
    parser.add_argument(
        "--format", "-f",
        choices=["markdown", "json"],
        default="markdown",
        help="Output format (default: markdown)",
    )
    parser.add_argument("--output", "-o", help="Output file path (default: stdout)")
    args = parser.parse_args()

    for path in [args.before, args.after]:
        if not Path(path).is_file():
            print(f"Error: file not found: {path}", file=sys.stderr)
            sys.exit(1)

    print(f"Analyzing {args.before}...", file=sys.stderr)
    before = _extract_endpoints(args.before)
    print(f"Analyzing {args.after}...", file=sys.stderr)
    after = _extract_endpoints(args.after)

    diff = _compute_diff(before, after)

    if args.format == "json":
        output = json.dumps(diff, indent=2, default=lambda o: sorted(o) if isinstance(o, set) else str(o))
    else:
        output = _format_markdown(diff, args.before, args.after)

    if args.output:
        Path(args.output).write_text(output)
        print(f"Diff written to {args.output}", file=sys.stderr)
    else:
        print(output)


if __name__ == "__main__":
    main()
