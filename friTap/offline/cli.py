#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Command-line entry point for the offline pcap-to-tap pipeline.

Invoked from ``friTap.friTap.main()`` when ``--from-pcap`` appears in argv.
Owns its own small argparse so it stays decoupled from the live-capture CLI.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
from typing import Sequence

from .pcap_to_tap import ConvertResult, NoDecryptionKeysError, convert_pcap_to_tap
from .tshark import find_tshark

logger = logging.getLogger(__name__)

# Sidecar manifest suffix written by friTap at end-of-capture (see pcap.py).
MANIFEST_SUFFIX = ".fritap.json"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fritap --from-pcap",
        description="Offline: reconstruct a friTap .tap from a captured "
                    "pcap/pcapng — decrypt with tshark when keys are available "
                    "(--keylog or an embedded DSB), or ingest an already-plaintext "
                    "capture directly when no keys are given.",
    )
    parser.add_argument("--from-pcap", dest="from_pcap", required=True,
                        help="Capture file (pcap or pcapng): encrypted (decrypted "
                             "via --keylog / embedded DSB) or already-plaintext.")
    parser.add_argument("--keylog", dest="keylog", default=None,
                        help="NSS SSLKEYLOGFILE. Omit for a plaintext capture or a "
                             "DSB-embedded pcapng.")
    parser.add_argument("--tap", dest="tap", default=None,
                        help="Output .tap path (default: <pcap stem>.tap).")
    parser.add_argument("--scan", action="store_true",
                        help="Run analyzers over the produced .tap and report findings.")
    parser.add_argument("--tls-port", dest="tls_ports", type=int, action="append",
                        default=[], help="Custom TCP port to Decode-As TLS (repeatable).")
    parser.add_argument("--quic-port", dest="quic_ports", type=int, action="append",
                        default=[], help="Custom UDP port to Decode-As QUIC (repeatable).")
    parser.add_argument("--decode-as", dest="decode_as", action="append",
                        default=[], help="Raw tshark -d Decode-As rule (repeatable).")
    parser.add_argument("--tls-heuristic", dest="tls_heuristic", action="store_true",
                        help="Enable tshark TLS-over-TCP heuristic dissection.")
    parser.add_argument("--tshark-path", dest="tshark_path", default=None,
                        help="Path to the tshark binary (else auto-discovered; "
                             "also honors $FRITAP_TSHARK). Useful on macOS where "
                             "tshark lives in Wireshark.app and is not on PATH.")
    return parser


def load_manifest(pcap_path: str) -> dict:
    """Load a ``<pcap>.fritap.json`` sidecar manifest if present.

    Returns an empty dict when the sidecar is missing or unreadable, so the
    caller can merge unconditionally.
    """
    manifest_path = pcap_path + MANIFEST_SUFFIX
    if not os.path.isfile(manifest_path):
        return {}
    try:
        with open(manifest_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        logger.warning("Could not read manifest %s", manifest_path, exc_info=True)
        return {}


def merge_manifest(args: argparse.Namespace, manifest: dict) -> dict:
    """Merge CLI flags with a sidecar *manifest*; CLI values win.

    Returns a kwargs dict for :func:`convert_pcap_to_tap`. The manifest only
    supplies values the user did not give explicitly on the command line.
    """
    tls_ports = list(args.tls_ports) or list(manifest.get("tls_ports", []))
    quic_ports = list(args.quic_ports) or list(manifest.get("quic_ports", []))
    keylog = args.keylog if args.keylog else manifest.get("keylog") or None

    return {
        "keylog_path": keylog,
        "tls_ports": tuple(tls_ports),
        "quic_ports": tuple(quic_ports),
        "extra_decode_as": tuple(args.decode_as),
        "heuristic": bool(args.tls_heuristic),
    }


def _print_summary(result: ConvertResult, run_scan: bool) -> None:
    """Print a human-readable summary of the conversion result."""
    print(f"Wrote {result.tap_path}")
    print(f"  flows:             {result.flow_count}")
    print(f"  decrypted packets: {result.decrypted_packet_count}")
    print(f"  streams:           {result.stream_count}")
    if result.dropped_packet_count:
        print(f"  dropped packets:   {result.dropped_packet_count}")
    if result.encrypted_streams_skipped:
        print(f"  encrypted streams: {result.encrypted_streams_skipped} (skipped — need keys)")
    if run_scan:
        print(f"  findings:          {result.findings_count}")


def run_offline_pcap_to_tap(argv: Sequence[str]) -> int:
    """Parse *argv*, run the conversion, print a summary, and return an exit code.

    Returns 0 on success; nonzero on error: 2 (pcap not found), 3 (tshark
    missing), 5 (no decryption keys: no keylog and no embedded DSB), 1 (other
    conversion failure), 4 (ran but produced no decrypted packets — usually
    wrong keys/ports).
    """
    args = _build_parser().parse_args(list(argv))

    if not os.path.isfile(args.from_pcap):
        print(f"Error: pcap not found: {args.from_pcap}")
        return 2

    manifest = load_manifest(args.from_pcap)
    kwargs = merge_manifest(args, manifest)

    try:
        find_tshark(args.tshark_path)
    except RuntimeError as exc:
        print(f"Error: {exc}")
        return 3

    try:
        result = convert_pcap_to_tap(
            args.from_pcap,
            tap_path=args.tap,
            run_scan=args.scan,
            tshark_path=args.tshark_path,
            **kwargs,
        )
    except NoDecryptionKeysError as exc:
        print(f"Error: {exc}")
        return 5
    except Exception as exc:
        print(f"Error during offline conversion: {exc}")
        logger.error("Offline conversion failed", exc_info=True)
        return 1

    _print_summary(result, args.scan)

    if result.decrypted_packet_count == 0:
        if result.encrypted_streams_skipped:
            print(
                f"Warning: no plaintext application data was produced; "
                f"{result.encrypted_streams_skipped} stream(s) look encrypted "
                "(TLS/QUIC) and were skipped. This capture needs keys — pass "
                "--keylog <SSLKEYLOGFILE>, or use a pcapng with an embedded "
                "Decryption Secrets Block (DSB)."
            )
        else:
            print(
                "Warning: no application data was produced. If this capture is "
                "encrypted, it needs keys — pass --keylog <SSLKEYLOGFILE> (or use "
                "a pcapng with an embedded DSB) and check --tls-port / --quic-port "
                "/ --decode-as. If it is already plaintext, no extractable payload "
                "was found."
            )
        return 4

    return 0
