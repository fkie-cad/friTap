#!/usr/bin/env python3
"""Convert a friTap .tap capture file to HTTP Archive (HAR 1.2) format.

Usage:
    python tap_to_har.py capture.tap
    python tap_to_har.py capture.tap --output capture.har
    python tap_to_har.py capture.tap --include-bodies

The HAR format is universally supported by Chrome DevTools, Burp Suite,
mitmproxy, and many other tools. This script bridges friTap captures
into the broader HTTP analysis ecosystem.

HAR 1.2 spec: http://www.softwareishard.com/blog/har-12-spec/
"""

import argparse
import base64
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from friTap.flow.tap_reader import TapReader
from friTap.flow.models import Flow


def _get_fritap_version() -> str:
    """Get the friTap version string, with fallback."""
    try:
        from friTap import __version__ as VERSION
        return VERSION
    except Exception:
        return "unknown"


def _iso_timestamp(epoch: float) -> str:
    """Convert epoch float to ISO 8601 string."""
    if epoch <= 0:
        return datetime.now(timezone.utc).isoformat()
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()


def _headers_to_har(headers: dict) -> list[dict]:
    """Convert a header dict to HAR name/value list."""
    return [{"name": k, "value": v} for k, v in headers.items()]


def _query_string_to_har(url: str) -> list[dict]:
    """Extract query parameters from a URL as HAR name/value pairs."""
    if "?" not in url:
        return []
    try:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        result = []
        for name, values in params.items():
            for value in values:
                result.append({"name": name, "value": value})
        return result
    except Exception:
        return []


def _mime_type(content_type: str) -> str:
    """Extract MIME type from a Content-Type header value."""
    if not content_type:
        return "x-unknown"
    return content_type.split(";", 1)[0].strip()


def _body_to_har(body: bytes, content_type: str, include_body: bool) -> dict:
    """Convert body bytes to a HAR postData or content object."""
    if not body or not include_body:
        return {"size": len(body) if body else 0, "mimeType": _mime_type(content_type)}

    # Try text decoding first
    mime = _mime_type(content_type)
    is_text = any(t in mime for t in (
        "text", "json", "xml", "html", "javascript", "css",
        "x-www-form-urlencoded", "svg", "yaml",
    ))

    if is_text:
        try:
            text = body.decode("utf-8")
            return {"size": len(body), "mimeType": mime, "text": text}
        except UnicodeDecodeError:
            pass

    # Fall back to base64 encoding for binary content
    return {
        "size": len(body),
        "mimeType": mime,
        "text": base64.b64encode(body).decode("ascii"),
        "encoding": "base64",
    }


def flow_to_har_entry(flow: Flow, include_bodies: bool = False) -> dict | None:
    """Convert a single Flow to a HAR entry dict. Returns None for non-HTTP flows."""
    if flow.request is None and flow.response is None:
        return None

    started = _iso_timestamp(flow.started)
    duration_ms = max(0, int((flow.ended - flow.started) * 1000)) if flow.ended > 0 else 0

    # Build request object
    req = flow.request
    method = req.method if req else "GET"
    url = ""
    if req:
        host = req.host or flow.get_request_header("host") or flow.dst_addr or "unknown"
        path = req.url or "/"
        url = f"https://{host}{path}"

    request_headers = _headers_to_har(req.headers) if req else []
    request_content_type = flow.request_content_type
    request_body_bytes = flow.get_decompressed_request_body() if (req and include_bodies) else b""
    request_body_size = len(request_body_bytes) if include_bodies else (req.body_size if req else 0)

    har_request: dict = {
        "method": method,
        "url": url,
        "httpVersion": req.protocol if req else "HTTP/1.1",
        "cookies": [],
        "headers": request_headers,
        "queryString": _query_string_to_har(req.url if req else ""),
        "headersSize": -1,
        "bodySize": request_body_size,
    }

    if request_body_bytes and include_bodies:
        har_request["postData"] = _body_to_har(
            request_body_bytes, request_content_type, include_bodies
        )

    # Build response object
    resp = flow.response
    status_code = resp.status_code if resp else 0
    status_text = resp.status_text if resp else ""
    response_headers = _headers_to_har(resp.headers) if resp else []
    response_content_type = flow.response_content_type
    response_body_bytes = flow.get_decompressed_response_body() if (resp and include_bodies) else b""
    response_body_size = len(response_body_bytes) if include_bodies else (resp.body_size if resp else 0)

    har_response: dict = {
        "status": status_code,
        "statusText": status_text,
        "httpVersion": resp.protocol if resp else "HTTP/1.1",
        "cookies": [],
        "headers": response_headers,
        "content": _body_to_har(response_body_bytes, response_content_type, include_bodies),
        "redirectURL": flow.get_response_header("location"),
        "headersSize": -1,
        "bodySize": response_body_size,
    }

    # Build timings (approximate — friTap has start/end, not detailed phases)
    har_timings = {
        "send": 0,
        "wait": duration_ms,
        "receive": 0,
    }

    # Connection info
    server_ip = flow.dst_addr or ""
    connection = flow.connection_id or ""

    entry: dict = {
        "startedDateTime": started,
        "time": duration_ms,
        "request": har_request,
        "response": har_response,
        "cache": {},
        "timings": har_timings,
        "serverIPAddress": server_ip,
        "connection": connection,
    }

    # Add friTap-specific metadata as a comment
    comment_parts = []
    if flow.ssl_session_id:
        comment_parts.append(f"ssl_session_id={flow.ssl_session_id[:16]}...")
    if flow.flow_id:
        comment_parts.append(f"flow_id={flow.flow_id}")
    if comment_parts:
        entry["comment"] = " | ".join(comment_parts)

    return entry


def tap_to_har(tap_path: str, include_bodies: bool = False) -> dict:
    """Convert an entire .tap file to a HAR 1.2 document."""
    entries = []

    with TapReader(tap_path) as reader:
        summaries = reader.read_flow_summaries()

        for summary in summaries:
            flow = reader.read_flow(summary.flow_id)
            if flow is None:
                continue

            entry = flow_to_har_entry(flow, include_bodies=include_bodies)
            if entry is not None:
                entries.append(entry)

    har: dict = {
        "log": {
            "version": "1.2",
            "creator": {
                "name": "friTap",
                "version": _get_fritap_version(),
                "comment": "Converted from .tap capture file",
            },
            "entries": entries,
        }
    }

    return har


def main():
    parser = argparse.ArgumentParser(
        description="Convert a friTap .tap capture to HAR 1.2 format.",
    )
    parser.add_argument("tap_file", help="Path to the .tap capture file")
    parser.add_argument(
        "--output", "-o",
        help="Output file path (default: <tap_file>.har)",
    )
    parser.add_argument(
        "--include-bodies",
        action="store_true",
        help="Include request/response bodies (increases file size significantly)",
    )
    parser.add_argument(
        "--compact",
        action="store_true",
        help="Compact JSON output (no indentation)",
    )
    args = parser.parse_args()

    tap_path = args.tap_file
    if not Path(tap_path).is_file():
        print(f"Error: file not found: {tap_path}", file=sys.stderr)
        sys.exit(1)

    har = tap_to_har(tap_path, include_bodies=args.include_bodies)

    indent = None if args.compact else 2
    output = json.dumps(har, indent=indent, default=str)

    entry_count = len(har["log"]["entries"])

    if args.output:
        out_path = args.output
    else:
        out_path = str(Path(tap_path).with_suffix(".har"))

    Path(out_path).write_text(output)
    print(f"Exported {entry_count} HTTP entries to {out_path}")


if __name__ == "__main__":
    main()
