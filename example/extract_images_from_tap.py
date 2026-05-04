#!/usr/bin/env python3
"""Extract images from a friTap .tap capture file.

Usage:
    python extract_images_from_tap.py capture.tap
    python extract_images_from_tap.py capture.tap --output-dir ./my_images

This script demonstrates how to use the friTap API to:
  - Open and parse a .tap capture file with TapReader
  - Iterate over captured HTTP flows using streaming reads
  - Detect image responses via content-type header AND magic-byte sniffing
  - Decompress response bodies (gzip, br, zstd, deflate)
  - Extract images from raw chunks when HTTP parsing is incomplete
  - Extract and save image files with proper filenames
"""

import argparse
import sys
from pathlib import Path

# Allow standalone execution from the example/ directory
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from friTap.flow.models import format_byte_size
from friTap.flow.tap_reader import TapReader
from friTap.flow.http_utils import (
    detect_image_mime_from_bytes,
    is_image_content_type,
    extension_for_image_mime,
    filename_from_url,
    parse_content_disposition_filename,
    sanitize_filename,
)


def determine_filename(flow, content_type: str) -> str:
    """Determine the best filename for an extracted image.

    Priority:
      1. Content-Disposition header filename
      2. URL path basename (if it has an extension)
      3. Fallback: 'image_<flow_id>.<ext>'
    """
    cd_header = flow.get_response_header("content-disposition")
    if cd_header:
        cd_name = parse_content_disposition_filename(cd_header)
        if cd_name:
            return sanitize_filename(cd_name)

    url = flow.request.url if flow.request else ""
    url_name = filename_from_url(url)
    if url_name:
        return sanitize_filename(url_name)

    ext = extension_for_image_mime(content_type)
    safe_id = sanitize_filename(flow.flow_id) if flow.flow_id else "unknown"
    if len(safe_id) > 40:
        safe_id = safe_id[:40]
    return f"image_{safe_id}{ext}"


def deduplicate_name(name: str, seen: set) -> str:
    """Append a numeric suffix if the name already exists in ``seen``."""
    if name not in seen:
        seen.add(name)
        return name

    stem, dot, ext = name.rpartition(".")
    if not dot:
        stem, ext = name, ""

    counter = 1
    while True:
        candidate = f"{stem}_{counter}.{ext}" if ext else f"{stem}_{counter}"
        if candidate not in seen:
            seen.add(candidate)
            return candidate
        counter += 1


def _save_image(body, content_type, flow, output_dir, seen_names, extracted):
    """Save a single image body and record it in the extracted list."""
    name = determine_filename(flow, content_type)
    name = deduplicate_name(name, seen_names)
    (output_dir / name).write_bytes(body)

    extracted.append({
        "file": name,
        "size": len(body),
        "type": content_type.split(";", 1)[0].strip(),
        "url": (flow.request.url if flow.request else ""),
        "status": flow.display_status,
    })


def main():
    parser = argparse.ArgumentParser(
        description="Extract images from a friTap .tap capture file.",
    )
    parser.add_argument(
        "tap_file",
        help="Path to the .tap capture file",
    )
    parser.add_argument(
        "--output-dir", "-o",
        default="./extracted_images",
        help="Directory to save extracted images (default: ./extracted_images)",
    )
    args = parser.parse_args()

    tap_path = args.tap_file
    output_dir = Path(args.output_dir)

    if not Path(tap_path).is_file():
        print(f"Error: file not found: {tap_path}", file=sys.stderr)
        sys.exit(1)

    output_dir.mkdir(parents=True, exist_ok=True)

    extracted = []
    seen_names: set = set()

    with TapReader(tap_path) as reader:
        summaries = reader.read_flow_summaries()
        print(f"Loaded {len(summaries)} flow(s) from {tap_path}\n")

        for summary in summaries:
            flow = reader.read_flow(summary.flow_id)
            if flow is None:
                continue

            # ---------------------------------------------------------------
            # Educational: accessing headers and body via the friTap API
            # ---------------------------------------------------------------
            # server = flow.get_response_header("server")
            # cache = flow.get_response_header("cache-control")
            # body = flow.response_body  # raw (possibly compressed)
            # body = flow.get_decompressed_response_body()  # always decompressed
            # ---------------------------------------------------------------

            # --- Strategy 1: parsed response with content-type header ---
            if flow.response is not None:
                content_type = flow.response_content_type
                body = flow.get_decompressed_response_body()

                if body:
                    # Fall back to magic-byte detection when content-type is missing
                    if not is_image_content_type(content_type):
                        detected = detect_image_mime_from_bytes(body)
                        if detected:
                            content_type = detected

                    if is_image_content_type(content_type):
                        _save_image(body, content_type, flow, output_dir, seen_names, extracted)
                        continue

            # --- Strategy 2: scan raw chunks for image magic bytes ---
            # Handles flows where HTTP parsing was incomplete (e.g. HTTP/2
            # responses without fully decoded headers)
            for chunk in flow.chunks:
                detected = detect_image_mime_from_bytes(chunk.data)
                if detected:
                    _save_image(chunk.data, detected, flow, output_dir, seen_names, extracted)

    if not extracted:
        print("No images found in the capture.")
        return

    col_file = max(len(e["file"]) for e in extracted)
    col_file = max(col_file, 8)
    col_type = max(len(e["type"]) for e in extracted)
    col_type = max(col_type, 12)

    header = f"{'Filename':<{col_file}}  {'Size':>10}  {'Content-Type':<{col_type}}  Status  URL"
    sep = "-" * len(header)

    print(sep)
    print(header)
    print(sep)

    for e in extracted:
        size_str = format_byte_size(e["size"])
        url_display = e["url"]
        if len(url_display) > 60:
            url_display = url_display[:57] + "..."
        print(
            f"{e['file']:<{col_file}}  {size_str:>10}  "
            f"{e['type']:<{col_type}}  {e['status']:<6}  {url_display}"
        )

    print(sep)
    total_bytes = sum(e["size"] for e in extracted)
    print(
        f"\nExtracted {len(extracted)} image(s), "
        f"{format_byte_size(total_bytes)} total, "
        f"saved to {output_dir.resolve()}"
    )


if __name__ == "__main__":
    main()
