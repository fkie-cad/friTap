#!/usr/bin/env python3
"""Open a friTap .tap capture in the embedded viewer (embedding mode A: launch).

Usage:
    python tap_viewer_launch.py capture.tap
    python tap_viewer_launch.py capture.tap --title "Case 42" --output-dir ./out

This script demonstrates how a host program can:
  - call ``friTap.ui.open_tap`` to run the viewer and block until it closes
  - keep its own root logging handler (open_tap mutes only friTap loggers
    while the viewer runs, and restores them afterwards)
  - turn a missing file or a missing textual install into a clean message
    and exit code instead of a traceback
"""

import argparse
import logging
import sys
from pathlib import Path

# Allow standalone execution from the example/ directory
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

EXIT_OK = 0
EXIT_FILE_NOT_FOUND = 2
EXIT_MISSING_DEPENDENCY = 3

host_log = logging.getLogger("host_app")


def install_host_logging() -> None:
    """The host's own root handler: it keeps working after the viewer closes."""
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("[host] %(levelname)s %(message)s"))
    logging.getLogger().addHandler(handler)
    logging.getLogger().setLevel(logging.INFO)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Open a friTap .tap capture in the embedded viewer.",
    )
    parser.add_argument("tap_file", help="Path to the .tap capture file")
    parser.add_argument("--title", help="Title shown by the viewer")
    parser.add_argument("--output-dir", help="Directory for files the viewer saves")
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    install_host_logging()
    try:
        from friTap.ui import open_tap
        open_tap(args.tap_file, title=args.title, output_dir=args.output_dir)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_FILE_NOT_FOUND
    except ImportError as exc:
        print(f"error: the viewer needs textual ({exc}); pip install textual",
              file=sys.stderr)
        return EXIT_MISSING_DEPENDENCY
    host_log.info("viewer closed for %s; the host logger still works", args.tap_file)
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
