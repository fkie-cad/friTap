#!/usr/bin/env python3

"""Command-line entry point for the offline pcap-to-tap pipeline.

Invoked from ``friTap.friTap.main()`` when ``--from-pcap`` appears in argv.
Owns its own small argparse so it stays decoupled from the live-capture CLI.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
from typing import Optional, Sequence

from . import keylog_coverage
from .mtproto.transport import (
    DEFAULT_OBF_ENDPOINT_MATCH_BLOCKS,
    DEFAULT_OBF_MAX_BLOCKS,
)
from .pcap_to_tap import (
    MESSAGING_PREFIXES,
    ConvertResult,
    NoDecryptionKeysError,
    convert_pcap_to_tap,
    messaging_buckets,
)
from .tshark import TsharkNotFoundError, find_tshark

logger = logging.getLogger(__name__)

# Upper bound for --resync-search-depth (and the TUI's advanced field). The
# resync search materialises ~2 * 16 bytes of keystream per block of depth, so
# the depth is a memory knob: 4x the endpoint-matched auto-widen ceiling (the
# deepest search the pipeline ever runs on its own) leaves headroom for manual
# un-attributed-key searches while capping one search at ~256 MB of keystream
# instead of letting a typo allocate many GB. 0 is allowed (no lag search).
RESYNC_SEARCH_DEPTH_MAX = 4 * DEFAULT_OBF_ENDPOINT_MATCH_BLOCKS


def parse_resync_search_depth(raw: str) -> int:
    """argparse ``type=`` for ``--resync-search-depth``: an int in range.

    Raises :class:`argparse.ArgumentTypeError` (argparse turns it into a clean
    usage error) for non-integers and values outside
    ``0..RESYNC_SEARCH_DEPTH_MAX``. A negative depth used to silently disable
    mid-stream recovery; a huge one allocated gigabytes.
    """
    try:
        value = int(str(raw).strip())
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"resync search depth must be an integer, got {raw!r}"
        ) from None
    if not 0 <= value <= RESYNC_SEARCH_DEPTH_MAX:
        raise argparse.ArgumentTypeError(
            f"resync search depth must be between 0 and "
            f"{RESYNC_SEARCH_DEPTH_MAX}, got {value}"
        )
    return value

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
    parser.add_argument(
        "--resync-search-depth", dest="resync_search_depth",
        type=parse_resync_search_depth,
        default=DEFAULT_OBF_MAX_BLOCKS,
        help="Maximum search depth (in cipher blocks/units) when re-aligning a "
             "mid-stream flow to a memory-recovered key. Applies to offline "
             "decryptors that support mid-stream key recovery (currently MTProto "
             f"obfuscated transport; default {DEFAULT_OBF_MAX_BLOCKS}). "
             "Endpoint-matched keys auto-search further; raise this for "
             f"un-attributed keys (range 0..{RESYNC_SEARCH_DEPTH_MAX}).")
    parser.add_argument(
        "--tls-midstream-secrets", dest="tls_midstream_secrets", default=None,
        help="Path to a TLS mid-stream secret-bundle sidecar "
             "(a *.tls_midstream.secrets.jsonl written by a memory scan). "
             "Decrypts TLS 1.3 flows captured with no ClientHello — no handshake "
             "for tshark to follow. Overrides the manifest's "
             "tls_midstream_secrets value when both are present.")
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
    parser.add_argument("--repair-keylog", dest="repair_keylog", action="store_true",
                        help="Before converting, fix a --keylog by trial decryption "
                             "against the capture: re-pair secrets whose client_random "
                             "is wrong or '???' (e.g. Schannel/lsass dumps), and correct "
                             "TLS 1.3 labels the live hook may have swapped "
                             "(HANDSHAKE<->TRAFFIC_SECRET_0). Writes "
                             "<keylog stem>.relabeled.keylog next to the keylog and "
                             "decrypts with it; otherwise keeps the original keylog.")
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


def _resolve_midstream_secrets(args: argparse.Namespace, manifest: dict) -> str | None:
    """Pick the TLS mid-stream secret-bundle sidecar path for this run.

    Precedence: the explicit ``--tls-midstream-secrets`` flag wins, else the
    manifest's ``tls_midstream_secrets`` value. A relative path is resolved
    against the pcap's directory (the sidecar is co-located with the capture),
    mirroring how memory-scan sidecars are located. Returns ``None`` when
    neither source supplies a path.
    """
    path = getattr(args, "tls_midstream_secrets", None) or manifest.get(
        "tls_midstream_secrets") or None
    if path and not os.path.isabs(path):
        pcap = getattr(args, "from_pcap", "") or ""
        pcap_dir = os.path.dirname(os.path.abspath(pcap)) if pcap else ""
        if pcap_dir:
            path = os.path.join(pcap_dir, path)
    return path


def merge_manifest(args: argparse.Namespace, manifest: dict) -> dict:
    """Merge CLI flags with a sidecar *manifest*; CLI values win.

    Returns a kwargs dict for :func:`convert_pcap_to_tap`. The manifest only
    supplies values the user did not give explicitly on the command line.
    """
    from .registry import get_offline_decryptor_registry

    tls_ports = list(args.tls_ports) or list(manifest.get("tls_ports", []))
    quic_ports = list(args.quic_ports) or list(manifest.get("quic_ports", []))
    keylog = args.keylog or manifest.get("keylog") or None

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

    # Memory-scan sidecars (nested ``memory_scan_keylogs`` map) carry keys the hook
    # keylog lacks — e.g. the MTProto OBF + perm auth keys that make de-obfuscation
    # possible. The registry loop above never sees that map, so union each sidecar
    # into the selected keylog for its protocol (same as the manifest-aware
    # ``pcap_to_tap`` wrapper), so ``fritap --from-pcap`` uses the scanner keys too.
    ms_map = manifest.get("memory_scan_keylogs") or {}
    if ms_map:
        from .keylog_picker import merge_memory_scan_sidecars

        def _current(proto: str) -> str | None:
            if proto == "tls":
                return keylog
            return protocol_keylogs.get(proto) or named_keylog_kwargs.get(f"{proto}_keylog")

        merged_sidecars = merge_memory_scan_sidecars(
            ms_map, _current,
            out_dir=os.path.dirname(os.path.abspath(args.from_pcap)) or None)
        keylog = merged_sidecars.pop("tls", keylog)
        for proto, merged_path in merged_sidecars.items():
            protocol_keylogs[proto] = merged_path
            named_keylog_kwargs[f"{proto}_keylog"] = merged_path

    merged = {
        "keylog_path": keylog,
        "protocol_keylogs": protocol_keylogs,
        "tls_ports": tuple(tls_ports),
        "quic_ports": tuple(quic_ports),
        "extra_decode_as": tuple(args.decode_as),
        "heuristic": bool(args.tls_heuristic),
        # Generic mid-stream resync depth: the boundary maps it to each emitter's
        # own unit (MTProto's obf_max_blocks today) via the _emitter_accepts gate.
        "resync_search_depth": getattr(
            args, "resync_search_depth", DEFAULT_OBF_MAX_BLOCKS
        ),
        # Mid-stream TLS 1.3 secret-bundle sidecar. Applied by the Python API
        # (convert_pcap_to_tap) but historically dropped by this CLI merge, so
        # the headless `fritap --from-pcap` workflow got no mid-stream decrypt.
        # Precedence (flag > manifest) and path resolution live in the helper.
        "tls_midstream_secrets": _resolve_midstream_secrets(args, manifest),
    }
    merged.update(named_keylog_kwargs)
    return merged


# Shared tail of both E2E-only warnings (summary line + 0-flow explanation).
_E2E_ONLY_CONSEQUENCE = (
    " — the transport envelope can't be decrypted, so the messages inside can't "
    "be reached. Capture transport auth keys with a spawn -k run or -ms memory-scan."
)
_MAX_UNKNOWN_IDS_SHOWN = 8


def _format_unknown_ids(unknown_key_ids) -> str:
    """Sorted auth_key_ids, the first 8 shown and the rest as ``… (+N more)``."""
    shown = ", ".join(sorted(unknown_key_ids)[:_MAX_UNKNOWN_IDS_SHOWN])
    hidden = len(unknown_key_ids) - _MAX_UNKNOWN_IDS_SHOWN
    if hidden > 0:
        shown += f", … (+{hidden} more)"
    return shown


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
        # Richer degraded breakdown. ``degraded`` now counts only degraded streams
        # with positive protocol evidence (e.g. MTProto: a Telegram-DC peer), so it
        # is no longer inflated by foreign/empty streams. The two keys below are
        # read defensively: they default to 0 until a decryptor plumbs them through
        # ``record_protocol`` (that plumbing is owned by another workstream), so
        # this stays behaviour-preserving today and prints the detail once present.
        degraded_non = counts.get("degraded_non_mtproto", 0)
        partial = counts.get("partial", 0)
        # Workstream F: streams re-derived mid-stream from memory-recovered
        # obfuscation keys (and those a recovery attempt could not align). Read
        # defensively so buckets without the keys print exactly as before.
        recovered = counts.get("recovered_via_obf", 0)
        degraded_unrecovered = counts.get("degraded_unrecovered", 0)
        # Honest diagnostics: streams that could not be opened for reasons that are
        # NOT "started mid-connection" (short/lossy client run or an unsupported
        # transport framing), the E2E-only signal, and the clear-text auth_key_ids
        # of records naming a key we did not hold. All read defensively (default 0/
        # False/{}) so buckets without them print exactly as before.
        short = counts.get("short", 0)
        unsupported_framing = counts.get("unsupported_framing", 0)
        e2e_only = counts.get("e2e_only", False)
        unknown_key_ids = counts.get("unknown_key_ids") or {}
        if not (messages or undecryptable or degraded or degraded_non or partial
                or recovered or short or unsupported_framing or e2e_only
                or unknown_key_ids):
            continue
        print(f"  {proto} messages:   {messages}")
        if recovered:
            print(f"  {proto} recovered streams: {recovered} "
                  "(mid-stream, re-derived from memory-recovered obfuscation keys)")
        if partial:
            print(f"  {proto} partial streams: {partial} "
                  "(valid start, later gap — decrypted the records before the gap)")
        if undecryptable:
            print(f"  {proto} undecryptable records: {undecryptable} "
                  "(no matching key / unsupported transport / wrong key?)")
        if degraded:
            print(f"  {proto} degraded streams: {degraded} "
                  "(capture started mid-stream / unsupported transport)")
            print("  ! messages on those streams could NOT be decrypted — re-capture "
                  "from connection start (spawn mode) to recover them.")
        if degraded_unrecovered:
            print(f"  {proto} unrecovered degraded streams: {degraded_unrecovered} "
                  "(obfuscation-key recovery attempted, no key aligned)")
        if degraded_non:
            print(f"  {proto} non-{proto} degraded streams: {degraded_non} "
                  "(init-less streams with no protocol evidence — not counted above)")
        if short:
            print(f"  {proto} short streams: {short} "
                  "(a start gap / too little client data — NOT mid-connection; "
                  "re-capture without loss from connection start)")
        if unsupported_framing:
            print(f"  {proto} unsupported-framing streams: {unsupported_framing} "
                  "(padded-intermediate / full / Fake-TLS — start captured, framing "
                  "not yet decodable; NOT mid-connection)")
        if e2e_only:
            print(f"  ! {proto}: a secret-chat (E2E) key was present but no transport "
                  f"auth key{_E2E_ONLY_CONSEQUENCE}")
        if unknown_key_ids:
            print(f"  {proto} unknown auth_key_id(s) on the wire (capture these keys): "
                  f"{_format_unknown_ids(unknown_key_ids)}")
    if run_scan:
        print(f"  findings:          {result.findings_count}")


def _print_prefixed_lines(prefix: str, lines: Sequence[str]) -> None:
    """Print *lines* with *prefix* on the first and an aligned indent on the rest."""
    for index, line in enumerate(lines):
        lead = prefix if index == 0 else " " * len(prefix)
        print(f"{lead}{line}")


def _keylog_coverage(tshark_bin: str, pcap: str, keylog: Optional[str],
                     capture: Optional[keylog_coverage.CaptureTls] = None,
                     ) -> Optional[keylog_coverage.Coverage]:
    """Coverage of the TLS *keylog* over *pcap*, or ``None`` when unavailable.

    ``None`` when no (readable) TLS keylog was supplied — e.g. a DSB-only
    capture — or the coverage check itself failed. Never raises: the check is
    advisory and must never change the CLI's outcome.
    """
    if not keylog or not os.path.isfile(keylog):
        return None
    try:
        return keylog_coverage.check_keylog_coverage(tshark_bin, pcap, keylog, capture=capture)
    except Exception:  # noqa: BLE001 - advisory only
        logger.debug("Keylog coverage check failed for %r", pcap, exc_info=True)
        return None


def _print_coverage_explanation(coverage: Optional[keylog_coverage.Coverage]) -> None:
    """Explain *coverage* after a run that produced no decrypted packets."""
    if coverage is None:
        return
    severity, lines = keylog_coverage.describe(coverage)
    _print_prefixed_lines("Warning: " if severity == "warning" else "Note: ", lines)


_MESSAGING_PREFIXES = MESSAGING_PREFIXES


def _print_messaging_zero_flow_explanation(result: ConvertResult) -> None:
    """Print honest messaging-protocol reasons a 0-packet run decrypted nothing.

    Reads ``result.per_protocol`` generically (MTProto/Telegram/Signal) so a
    ``telegram``-prefixed keylog is covered too. Mirrors the TUI wording:
      * E2E-only  -- a secret-chat key but no transport auth key.
      * unknown auth_key_ids seen in the clear -- exactly the keys to capture.
    Advisory only: never changes the exit code, prints nothing when neither
    signal is present.
    """
    for proto, counts in messaging_buckets(result):
        if counts.get("e2e_only"):
            print(
                f"Warning: {proto}: the keylog has a secret-chat (E2E) key but no "
                f"MTProto transport auth key{_E2E_ONLY_CONSEQUENCE}"
            )
        unknown_key_ids = counts.get("unknown_key_ids") or {}
        if unknown_key_ids:
            print(
                f"Note: {proto} unknown auth_key_id(s) seen on the wire (in the "
                f"clear — capture these keys): {_format_unknown_ids(unknown_key_ids)}"
            )


def _print_partial_coverage_note(coverage: Optional[keylog_coverage.Coverage]) -> None:
    """One-line note when a successful run's keylog misses some handshakes."""
    if coverage is None or not coverage.covered or not coverage.uncovered:
        return
    _severity, lines = keylog_coverage.describe(coverage)
    if lines:
        print(f"Note: {lines[0]}")


def _repair_keylog_if_needed(tshark_bin: str, pcap: str,
                             keylog: Optional[str]) -> Optional[str]:
    """Run ``--repair-keylog``; return the keylog path to convert with.

    Returns the repaired keylog on a hit, else the original *keylog* (with the
    reason printed). Never raises — a failed rescue just keeps the original.
    """
    if not keylog or not os.path.isfile(keylog):
        print("Note: --repair-keylog needs a readable --keylog; skipping re-pair.")
        return keylog
    # relabel_keylog is a superset of repair_keylog: besides re-pairing orphan
    # sessions it trial-decrypts every secret to fix the ncrypt hook's TLS 1.3
    # HANDSHAKE<->TRAFFIC_SECRET_0 label swap and its ``???`` client_randoms. A
    # mislabeled-but-present session is invisible to the coverage gate, so this
    # runs whenever --repair-keylog is set (it is a no-op when nothing changes).
    try:
        result = keylog_coverage.relabel_keylog(
            tshark_bin, pcap, keylog,
            progress=lambda msg: print(f"Re-pair: {msg}"))
    except Exception as exc:  # noqa: BLE001 - keep the original keylog
        logger.debug("Keylog re-pair failed for %r", pcap, exc_info=True)
        print(f"Note: keylog re-pair failed ({exc}); using the original keylog.")
        return keylog
    if result.repaired_path:
        print(f"Re-pair: {result.message}")
        print(f"         decrypting with {result.repaired_path}")
        return result.repaired_path
    print(f"Note: {result.message} Using the original keylog.")
    return keylog


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
        from friTap.offline.mtproto import (
            MTPROTO_DEPENDENCY_HINT,
            mtproto_backend_available,
        )
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
        tshark_bin = find_tshark(args.tshark_path)
    except TsharkNotFoundError as exc:
        print(f"Error: {exc}")
        return 3

    # Opt-in rescue: re-pair keylog secrets whose client_random is not in the
    # capture (Schannel/lsass) by trial decryption, and convert with the result.
    if getattr(args, "repair_keylog", False):
        kwargs["keylog_path"] = _repair_keylog_if_needed(
            tshark_bin, args.from_pcap, kwargs.get("keylog_path"))

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

    # Advisory TLS keylog coverage (only when a TLS keylog was used — a DSB-only
    # capture has nothing to match). Explains 0-decrypted runs and flags
    # partially covered successful ones; never changes the exit code.
    coverage = _keylog_coverage(tshark_bin, args.from_pcap, kwargs.get("keylog_path"))

    if result.decrypted_packet_count == 0:
        _print_coverage_explanation(coverage)
        # Honest messaging-protocol diagnostics, mirrored from the TUI: an E2E-only
        # keylog (secret-chat key but no transport auth key) and any clear-text
        # auth_key_ids seen on the wire that we lacked the key for. Both are the
        # actual, actionable reasons a Telegram capture produced nothing.
        _print_messaging_zero_flow_explanation(result)
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

    _print_partial_coverage_note(coverage)
    return 0
