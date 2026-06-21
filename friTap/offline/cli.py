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


def _iter_decryptor_cli_modules():
    """Yield the importable ``friTap.offline.<protocol_name>`` module for each
    registered offline decryptor that ships one.

    Lets the public CLI discover a decryptor's optional CLI-extension hooks
    (``register_offline_cli_extras`` / ``handle_offline_cli_extras`` /
    ``offline_cli_dependency_warnings``) generically — by the registry-supplied
    protocol name — without naming any specific extension protocol. A protocol
    with no such module (e.g. the registry entry was registered elsewhere) is
    skipped. Never raises.
    """
    import importlib

    from .registry import get_offline_decryptor_registry

    for entry in get_offline_decryptor_registry().list():
        try:
            yield entry, importlib.import_module(f"friTap.offline.{entry.protocol_name}")
        except Exception:  # noqa: BLE001 - a missing/broken module is just skipped
            logger.debug("no CLI module for offline decryptor %r",
                         entry.protocol_name, exc_info=True)


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
    # Per-protocol keylog flags (``--signal-keylog``, ``--mtproto-keylog``, and any
    # plugin protocol) are generated from the offline-decryptor registry so a new
    # protocol gets its CLI flag for free. dests match each entry's cli_dest, which
    # convert_pcap_to_tap consumes (named back-compat args + the generic map).
    from .registry import get_offline_decryptor_registry

    for entry in get_offline_decryptor_registry().list():
        parser.add_argument(entry.cli_flag, dest=entry.cli_dest, default=None,
                            help=entry.cli_help or f"friTap {entry.protocol_name} keylog.")
    # Optional per-decryptor extra flags (e.g. a keylog re-export action) are
    # contributed by each decryptor's CLI module hook, so the public CLI never
    # names a specific extension protocol's extras.
    for _entry, mod in _iter_decryptor_cli_modules():
        register_extras = getattr(mod, "register_offline_cli_extras", None)
        if callable(register_extras):
            try:
                register_extras(parser)
            except Exception:  # noqa: BLE001 - a bad hook must not break the CLI
                logger.debug("offline CLI extras registration failed for %r",
                             _entry.protocol_name, exc_info=True)
    parser.add_argument("--tap", dest="tap", default=None,
                        help="Output .tap path (default: <pcap stem>.tap).")
    parser.add_argument("--scan", action="store_true",
                        help="Run analyzers over the produced .tap and report findings.")
    parser.add_argument("--show-layers", dest="show_layers", action="store_true",
                        help="Print each decrypted flow's protocol layer stack.")
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
    from .registry import get_offline_decryptor_registry

    tls_ports = list(args.tls_ports) or list(manifest.get("tls_ports", []))
    quic_ports = list(args.quic_ports) or list(manifest.get("quic_ports", []))
    keylog = args.keylog if args.keylog else manifest.get("keylog") or None

    # Per-protocol keylogs are registry-driven: each entry's dest (CLI value or
    # manifest fallback) feeds the generic protocol_keylogs map. Back-compat named
    # ``<proto>_keylog`` kwargs are emitted generically from each entry's cli_dest
    # (so no specific extension protocol is named here); convert_pcap_to_tap folds
    # them into its generic map. The per-protocol "keylogs" map is the
    # AUTHORITATIVE source: for a multi-protocol capture (a TLS-riding protocol
    # also emits TLS keys) it records each protocol's split <base>.<proto>.log.
    # Prefer it over the top-level cli_dest field, which historically held the
    # base/TLS path and could point a protocol's keylog at the wrong file.
    # Precedence: explicit CLI > keylogs map > top-level cli_dest (back-compat).
    manifest_keylogs = manifest.get("keylogs", {}) or {}
    protocol_keylogs: dict[str, str] = {}
    named_keylog_kwargs: dict[str, str | None] = {}
    for entry in get_offline_decryptor_registry().list():
        value = (
            getattr(args, entry.cli_dest, None)
            or manifest_keylogs.get(entry.protocol_name)
            or manifest.get(entry.cli_dest)
            or None
        )
        # Back-compat named kwarg derived from the registry dest (a runtime
        # string, never a hardcoded protocol name in this file).
        named_keylog_kwargs[entry.cli_dest] = value
        if value:
            protocol_keylogs[entry.protocol_name] = value

    merged = {
        "keylog_path": keylog,
        "protocol_keylogs": protocol_keylogs,
        "tls_ports": tuple(tls_ports),
        "quic_ports": tuple(quic_ports),
        "extra_decode_as": tuple(args.decode_as),
        "heuristic": bool(args.tls_heuristic),
    }
    merged.update(named_keylog_kwargs)
    return merged


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
    # Per-protocol offline-decryptor counters are reported generically from the
    # registry-driven ``per_protocol`` map, so every registered protocol (built-in
    # or plugin) prints its counts without the CLI naming any specific protocol.
    for proto in sorted(result.per_protocol):
        counts = result.per_protocol[proto]
        messages = counts.get("messages", 0)
        undecryptable = counts.get("undecryptable", 0)
        degraded = counts.get("degraded", 0)
        if not (messages or undecryptable or degraded):
            continue
        print(f"  {proto} messages:   {messages}")
        if undecryptable:
            print(f"  {proto} undecryptable records: {undecryptable} "
                  "(no matching key / unsupported transport / wrong key?)")
        if degraded:
            print(f"  {proto} degraded streams: {degraded} "
                  "(capture started mid-stream / unsupported transport)")
            print("  ! messages on those streams could NOT be decrypted — re-capture "
                  "from connection start (spawn mode) to recover them.")
    if run_scan:
        print(f"  findings:          {result.findings_count}")


def _layer_metadata_hint(layer) -> str:
    """Return a short ``key=value`` hint for a layer's most useful field.

    ``sni`` for TLS/QUIC; ``chat`` for any messaging layer that exposes a
    ``chat_type`` — empty when nothing meaningful is set. Driven by the layer's
    own attributes rather than naming a specific protocol, so a plugin protocol's
    layer surfaces its chat type for free. Used by ``--show-layers``.
    """
    name = getattr(layer, "name", "")
    if name in ("tls", "quic"):
        sni = getattr(layer, "sni", "")
        return f"sni={sni}" if sni else ""
    chat_type = getattr(layer, "chat_type", "")
    if chat_type:
        return f"chat={chat_type}"
    return ""


def _print_layer_stacks(tap_path: str) -> None:
    """Print the protocol layer stack for each multi-layer flow in *tap_path*.

    Read-only: opens the produced .tap, lists every flow whose stack has more
    than one layer, and prints the stack with each layer's key metadata and
    decrypted byte counts. Failures here must never affect the exit code, so
    the caller wraps this in try/except.
    """
    from friTap.flow.tap_reader import TapReader

    printed_header = False
    with TapReader(tap_path) as reader:
        for flow in reader.read_all_flows():
            layers = getattr(flow, "layers", None) or []
            if len(layers) <= 1:
                continue
            if not printed_header:
                print("\nLayer stacks:")
                printed_header = True

            endpoints = (
                f"{flow.src_addr}:{flow.src_port} -> "
                f"{flow.dst_addr}:{flow.dst_port}"
            )
            stack = " > ".join(ly.name for ly in layers)
            print(f"  {endpoints}  {stack}")

            for ly in layers:
                hint = _layer_metadata_hint(ly)
                data = getattr(ly, "data", None)
                bytes_str = ""
                if data is not None and getattr(data, "data_source", "none") != "none":
                    w = len(data.write)
                    r = len(data.read)
                    if w or r:
                        bytes_str = f"c2s={w:,}B s2c={r:,}B"
                detail = "  ".join(p for p in (hint, bytes_str) if p)
                if detail:
                    print(f"      [{ly.depth}] {ly.name}: {detail}")


def run_offline_pcap_to_tap(argv: Sequence[str]) -> int:
    """Parse *argv*, run the conversion, print a summary, and return an exit code.

    Returns 0 on success; nonzero on error: 2 (pcap not found), 3 (tshark
    missing), 5 (no decryption keys: no keylog and no embedded DSB), 1 (other
    conversion failure), 4 (ran but produced no decrypted packets — usually
    wrong keys/ports).
    """
    # Discover plugin offline decryptors BEFORE building the parser so their
    # --<proto>-keylog flags are registry-generated alongside the built-ins.
    # Opt out with FRITAP_DISABLE_OFFLINE_DECRYPTOR_DISCOVERY=1.
    try:
        from .discovery import discover_external_offline_decryptors, discovery_disabled
        if not discovery_disabled():
            discover_external_offline_decryptors()
    except Exception:  # pragma: no cover - discovery must never block the CLI
        logger.debug("offline decryptor discovery failed", exc_info=True)

    args = _build_parser().parse_args(list(argv))

    # Per-decryptor extra CLI actions (e.g. a keylog re-export) run BEFORE
    # touching the pcap and may short-circuit with their own exit code. Driven by
    # each decryptor's CLI-module hook, so the public CLI names no extension.
    for entry, mod in _iter_decryptor_cli_modules():
        handle_extras = getattr(mod, "handle_offline_cli_extras", None)
        if not callable(handle_extras):
            continue
        try:
            rc = handle_extras(args)
        except Exception:  # noqa: BLE001 - a bad hook must not crash the CLI
            logger.debug("offline CLI extras handling failed for %r",
                         entry.protocol_name, exc_info=True)
            continue
        if rc is not None:
            return rc

    if not os.path.isfile(args.from_pcap):
        print(f"Error: pcap not found: {args.from_pcap}")
        return 2

    manifest = load_manifest(args.from_pcap)
    kwargs = merge_manifest(args, manifest)

    # If MTProto decryption was requested but its optional backend is missing,
    # say so loudly and up front (rather than silently producing a .tap without
    # the Telegram flows). Non-fatal: any TLS/QUIC passes still run.
    if kwargs.get("mtproto_keylog"):
        from friTap.offline.mtproto import MTPROTO_DEPENDENCY_HINT, mtproto_backend_available
        if not mtproto_backend_available():
            print(f"Warning: {MTPROTO_DEPENDENCY_HINT}")
            print("         MTProto streams in this capture will be skipped.")

    # Per-decryptor up-front dependency / prerequisite warnings (e.g. a missing
    # optional crypto backend, or a TLS-riding protocol given without a TLS
    # keylog). Driven by each decryptor's CLI-module hook so no extension protocol
    # is named here. The protocol's keylog value comes from the generic map.
    proto_keylogs = kwargs.get("protocol_keylogs") or {}
    tls_keylog_path = kwargs.get("keylog_path")
    for entry, mod in _iter_decryptor_cli_modules():
        warn_hook = getattr(mod, "offline_cli_dependency_warnings", None)
        if not callable(warn_hook):
            continue
        try:
            for line in warn_hook(proto_keylogs.get(entry.protocol_name), tls_keylog_path):
                print(line)
        except Exception:  # noqa: BLE001 - a bad hook must not crash the CLI
            logger.debug("offline CLI dependency-warning hook failed for %r",
                         entry.protocol_name, exc_info=True)

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

    # Optional per-flow layer-stack view. Read-only and fully guarded so a
    # reader hiccup never changes the exit code of an otherwise-successful run.
    if getattr(args, "show_layers", False):
        try:
            _print_layer_stacks(result.tap_path)
        except Exception:  # pragma: no cover - never break a good conversion
            logger.debug("--show-layers printing failed", exc_info=True)

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
