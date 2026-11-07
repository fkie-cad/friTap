"""
``fritap report`` — token-efficient capture digest for AI agents.

Condenses a ``.tap`` capture into a few hundred tokens: hosts contacted, the
endpoints called with the keys/value shapes they send (never the values), E2E
message kinds and an analyzer findings summary. Passive and offline; it never
touches the target.

Every digest row carries a short ref (``f<N>`` / ``f<N>#m<k>``); ``--flow``
resolves one to that flow's metadata and decoded messages (redacted unless
``--show-values``, never key material).

Entry points::

    fritap report capture.tap --focus privacy --format md --budget 800
    fritap report capture.tap --flow f12 --max-bytes 2048 --format md
"""

from __future__ import annotations

import argparse
import logging
import os

from friTap.analysis.digest import DEFAULT_BUDGET_TOKENS, FOCUS_CHOICES, build_digest
from friTap.analysis.digest_flow import DEFAULT_MAX_BYTES, build_flow_detail
from friTap.analysis.digest_render import FLOW_RENDERERS, RENDERERS

logger = logging.getLogger("friTap.report")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fritap report",
        description=(
            "Token-efficient digest of a .tap capture for AI agents: hosts, "
            "endpoints (keys and value shapes only) and findings, grouped per protocol."
        ),
    )
    parser.add_argument("tap_file", help="Path to the .tap capture file.")
    parser.add_argument("--focus", choices=FOCUS_CHOICES, default="all",
                        help="Findings focus: privacy (pii), security (secret/network/protocol) "
                             "or all (default).")
    parser.add_argument("--protocol", default=None,
                        help="Keep flows carrying this protocol anywhere in the stack "
                             "(tls, quic, http2, signal, telegram, ...).")
    parser.add_argument("--app-protocol", default=None,
                        help="Keep flows of this digest group (http, http2, grpc, websocket, "
                             "mtproto, ...).")
    parser.add_argument("--filter", dest="filter_expr", default=None,
                        help="Display-filter expression, e.g. 'http.response.code >= 400'.")
    parser.add_argument("--budget", type=int, default=DEFAULT_BUDGET_TOKENS,
                        help=f"Approximate token budget (default: {DEFAULT_BUDGET_TOKENS}); "
                             "lowest-volume rows are dropped first.")
    parser.add_argument("--format", dest="output_format", choices=sorted(RENDERERS),
                        default="json", help="Output format (default: json).")
    parser.add_argument("--show-values", action="store_true",
                        help="Reveal finding values (and, with --flow, payload values) "
                             "instead of redacting them.")
    parser.add_argument("--masvs", action="store_true",
                        help="Tag each finding with the OWASP MASVS v2.1 controls it maps "
                             "to (e.g. MASVS-NETWORK-1); omitted, the digest is unchanged.")
    parser.add_argument("--flow", dest="flow_ref", default=None, metavar="REF",
                        help="Drill into one digest ref (f12, f12#m3, or a full flow id): "
                             "print its metadata and decoded messages instead of the digest.")
    parser.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES,
                        help=f"With --flow: cap each body/message preview at this many bytes "
                             f"(default: {DEFAULT_MAX_BYTES}).")
    parser.add_argument("-o", "--output", default=None,
                        help="Write the digest to this path instead of stdout.")
    return parser


def _write(rendered: str, output: str | None) -> int:
    if not output:
        print(rendered, end="" if rendered.endswith("\n") else "\n")
        return 0
    try:
        with open(output, "w", encoding="utf-8") as fh:
            fh.write(rendered)
    except OSError as exc:
        logger.error("Could not write digest to %s: %s", output, exc)
        return 1
    logger.info("Digest written to %s", output)
    return 0


def run_report_cli(argv: list[str]) -> int:
    """Run ``fritap report``. Returns 0 on success, 1 on usage/IO/analysis/ref errors."""
    args = _build_parser().parse_args(argv)
    if not os.path.isfile(args.tap_file):
        logger.error("tap file not found: %s", args.tap_file)
        return 1
    try:
        rendered = _flow_detail(args) if args.flow_ref else _digest(args)
    except Exception as exc:  # noqa: BLE001 — surface any ref/filter/read failure cleanly
        logger.error("Report failed: %s", exc)
        return 1
    return _write(rendered, args.output)


def _digest(args: argparse.Namespace) -> str:
    digest = build_digest(
        args.tap_file,
        focus=args.focus,
        protocol=args.protocol,
        app_protocol=args.app_protocol,
        filter_expr=args.filter_expr,
        budget_tokens=args.budget,
        show_values=args.show_values,
        masvs=args.masvs,
    )
    return RENDERERS[args.output_format](digest)


def _flow_detail(args: argparse.Namespace) -> str:
    detail = build_flow_detail(args.tap_file, args.flow_ref, max_bytes=args.max_bytes,
                               show_values=args.show_values)
    return FLOW_RENDERERS[args.output_format](detail)


__all__ = ["run_report_cli"]
