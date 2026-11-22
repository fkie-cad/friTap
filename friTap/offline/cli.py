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

from ..pcap_utility import MANIFEST_SUFFIX
from . import keylog_coverage
from .keylog_paths import is_safe_protocol_name, validate_manifest_path
from .mtproto.transport import DEFAULT_OBF_ENDPOINT_MATCH_BLOCKS
from .pcap_to_tap import (
    ConvertResult,
    NoDecryptionKeysError,
    convert_pcap_to_tap,
    messaging_buckets,
)
from .tshark import TsharkLimitError, TsharkNotFoundError, find_tshark

logger = logging.getLogger(__name__)

# Upper bound for --resync-search-depth (and the TUI field). The search materialises ~32 bytes of keystream per block of depth, so this memory knob is 4x the auto-widen ceiling (~256 MB) instead of letting a typo allocate many GB. 0 is allowed (no lag search).
RESYNC_SEARCH_DEPTH_MAX = 4 * DEFAULT_OBF_ENDPOINT_MATCH_BLOCKS


def parse_resync_search_depth(raw: str) -> int:
    """argparse ``type=`` for ``--resync-search-depth``: an int in ``0..RESYNC_SEARCH_DEPTH_MAX``.

    Raises :class:`argparse.ArgumentTypeError` otherwise (a huge depth allocated gigabytes).
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


def _resync_defaults_text(entries) -> str:
    """``"name: depth, ..."`` of each decoder family's resync default (MTProto and Telegram share one decoder, listed once)."""
    from .registry import entry_family

    seen: dict = {}
    for entry in entries:
        value = getattr(entry, "resync_default", None)
        if value is not None:
            seen.setdefault(entry_family(entry), f"{entry.protocol_name}: {value}")
    return ", ".join(seen.values())


def _iter_decryptor_cli_modules():
    """Yield ``(entry, module)`` for each registered decryptor with a ``friTap.offline.<protocol_name>`` module; never raises.

    The module may define ``register_offline_cli_extras``, ``handle_offline_cli_extras`` and ``offline_cli_dependency_warnings``.
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
    # ``--<proto>-keylog`` flags come from the registry; each dest is the entry's cli_dest.
    from .registry import get_offline_decryptor_registry

    for entry in get_offline_decryptor_registry().list():
        parser.add_argument(entry.cli_flag, dest=entry.cli_dest, default=None,
                            help=entry.cli_help or f"friTap {entry.protocol_name} keylog.")
    # Per-decryptor extra flags come from each decryptor's CLI module hook.
    for _entry, mod in _iter_decryptor_cli_modules():
        register_extras = getattr(mod, "register_offline_cli_extras", None)
        if callable(register_extras):
            try:
                register_extras(parser)
            except Exception:  # noqa: BLE001 - a bad hook must not break the CLI
                logger.debug("offline CLI extras registration failed for %r",
                             _entry.protocol_name, exc_info=True)
    resync_defaults = _resync_defaults_text(get_offline_decryptor_registry().list())
    parser.add_argument(
        "--resync-search-depth", dest="resync_search_depth",
        type=parse_resync_search_depth,
        default=None,
        help="Maximum search depth (in cipher blocks/units) when re-aligning a "
             "mid-stream flow to a memory-recovered key. Applies to offline "
             "decryptors that support mid-stream key recovery (currently MTProto "
             f"obfuscated transport; default: each decryptor's own "
             f"({resync_defaults})). "
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
    """Load a ``<pcap>.fritap.json`` sidecar manifest; ``{}`` when missing or unreadable.

    The manifest is untrusted (it may ship with a third-party capture), so the result is
    sanitized by :func:`vet_manifest`. Paths are kept as written;
    :func:`resolve_manifest_keylog_paths` resolves them.
"""
    manifest_path = pcap_path + MANIFEST_SUFFIX
    if not os.path.isfile(manifest_path):
        return {}
    try:
        with open(manifest_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        logger.warning("Could not read manifest %s", manifest_path, exc_info=True)
        return {}
    if not isinstance(data, dict):
        return {}
    return vet_manifest(pcap_path, sanitize_manifest_ports(data))


_MANIFEST_PORT_KEYS = ("tls_ports", "quic_ports")


def _is_valid_port(value) -> bool:
    """True for an ``int`` (not ``bool``) in ``1..65535``."""
    return isinstance(value, int) and not isinstance(value, bool) and 1 <= value <= 65535


def manifest_ports(manifest: dict, key: str) -> list[int]:
    """The manifest's *key* port list, or ``[]`` (with a warning) when malformed.

    Valid is a list of ints in ``1..65535``; anything else is ignored as a whole rather than raising.
"""
    value = manifest.get(key)
    if value is None:
        return []
    if isinstance(value, list) and all(_is_valid_port(port) for port in value):
        return list(value)
    logger.warning("Ignoring malformed manifest %r value %r", key, value)
    return []


def sanitize_manifest_ports(manifest: dict) -> dict:
    """Copy of *manifest* with each port list validated by :func:`manifest_ports`."""
    sanitized = dict(manifest)
    for key in _MANIFEST_PORT_KEYS:
        if key in sanitized:
            sanitized[key] = manifest_ports(manifest, key)
    return sanitized


def _resolve_relative_path(path: str, base_dirs: Sequence[str]) -> str:
    """*path* joined to the first of *base_dirs* where it exists ("" = the CWD).

    Absolute paths are unchanged. If none exists the first base wins, so errors name the first location looked at.
"""
    if os.path.isabs(path):
        return path
    candidates = [os.path.join(base, path) if base else path for base in base_dirs]
    for candidate in candidates:
        if os.path.isfile(candidate):
            return candidate
    return candidates[0] if candidates else path


def resolve_manifest_path(pcap_path: str, path: str | None) -> str | None:
    """Resolve a (possibly relative) path read from ``<pcap>.fritap.json``.

    The manifest's directory is tried first (independent of the reader's CWD), then
    the CWD (live-capture manifests record paths relative to *its* CWD). The manifest
    is untrusted, so an existing target must be a bounded regular file
    (:func:`friTap.offline.keylog_paths.validate_manifest_path`); otherwise ``None``.
    Copying manifest-named files is guarded at the sink
    (:func:`~friTap.offline.keylog_picker.merge_keylogs`).
"""
    if not path:
        return None
    manifest_dir = os.path.dirname(os.path.abspath(pcap_path)) if pcap_path else ""
    return validate_manifest_path(manifest_dir, path)


# Manifest maps whose values are keylog paths (protocol -> path).
_MANIFEST_KEYLOG_MAPS = ("keylogs", "memory_scan_keylogs")
# Top-level manifest keys holding a single non-keylog sidecar path.
_MANIFEST_SIDECAR_KEYS = ("tls_midstream_secrets", "request_contexts")
_KEYLOG_KEY_SUFFIX = "_keylog"


def _manifest_keylog_keys() -> frozenset[str]:
    """Top-level manifest keys holding keylog paths: ``keylog``, each decryptor's ``cli_dest``, and any ``*_keylog`` by suffix."""
    from .registry import get_offline_decryptor_registry

    dests = {entry.cli_dest for entry in get_offline_decryptor_registry().list()}
    return frozenset({"keylog", *dests})


def _resolve_manifest_value(pcap_path: str, value):
    """:func:`resolve_manifest_path` for a string *value*; a falsy value is kept, any other non-string becomes ``None`` so it never reaches ``open()``."""
    if isinstance(value, str):
        return resolve_manifest_path(pcap_path, value)
    return value if not value else None


def _is_safe_keylog_key(key: str, keylog_keys: frozenset[str]) -> bool:
    """A registry/``keylog`` key, or ``<proto>_keylog`` with a safe *proto*."""
    if key in keylog_keys:
        return True
    return is_safe_protocol_name(key[: -len(_KEYLOG_KEY_SUFFIX)])


def _vetted_manifest_value(pcap_path: str, value):
    """*value* unchanged when it resolves safely, else ``None`` (falsy kept)."""
    resolved = _resolve_manifest_value(pcap_path, value)
    return value if resolved is not None and isinstance(value, str) else resolved


def _transform_manifest_map(map_key: str, mapping: dict, transform) -> dict:
    """Apply *transform* to a ``{protocol: path}`` map, dropping unsafe names."""
    result: dict = {}
    for name, path in mapping.items():
        if not is_safe_protocol_name(name):
            logger.warning("Ignoring manifest %s entry with unsafe protocol name %r",
                           map_key, name)
            continue
        result[name] = transform(path)
    return result


def _transform_manifest_paths(manifest: dict, transform) -> dict:
    """Copy of *manifest* with *transform* applied to every path value.

    Path values: ``keylog``, ``<proto>_keylog`` / ``cli_dest`` keys, ``_MANIFEST_SIDECAR_KEYS`` and
    ``_MANIFEST_KEYLOG_MAPS`` values. Keys and map entries whose protocol name is not
    ``^[a-z0-9_]+$`` are dropped (the name ends up in output file names), as is a non-dict path map.
"""
    keylog_keys = _manifest_keylog_keys()
    result = dict(manifest)
    for key, value in manifest.items():
        is_keylog_key = key in keylog_keys or key.endswith(_KEYLOG_KEY_SUFFIX)
        if is_keylog_key and not _is_safe_keylog_key(key, keylog_keys):
            logger.warning("Ignoring manifest key with unsafe protocol name %r", key)
            del result[key]
        elif is_keylog_key or key in _MANIFEST_SIDECAR_KEYS:
            result[key] = transform(value)
    for map_key in _MANIFEST_KEYLOG_MAPS:
        mapping = manifest.get(map_key)
        if isinstance(mapping, dict):
            result[map_key] = _transform_manifest_map(map_key, mapping, transform)
        elif map_key in manifest:
            result.pop(map_key, None)
    return result


def vet_manifest(pcap_path: str, manifest: dict) -> dict:
    """Copy of *manifest* with unsafe protocol names dropped and unsafe paths nulled (non-regular, oversized or non-string); paths stay as written."""
    return _transform_manifest_paths(
        manifest, lambda value: _vetted_manifest_value(pcap_path, value))


def resolve_manifest_keylog_paths(pcap_path: str, manifest: dict) -> dict:
    """Copy of *manifest* with every keylog path resolved (:func:`resolve_manifest_path`; unsafe targets become ``None``).

    Shared with :func:`friTap.offline.pcap_to_tap.pcap_to_tap` so the result does not depend on the CWD.
"""
    return _transform_manifest_paths(
        manifest, lambda value: _resolve_manifest_value(pcap_path, value))


def manifest_protocol_keylogs(manifest: dict) -> dict[str, str]:
    """``{protocol_name: keylog}`` the manifest supplies per offline decryptor.

    The ``keylogs`` map wins over the top-level ``cli_dest`` field (a multi-protocol
    capture splits keys into ``<base>.<proto>.log`` while the field may hold the base/TLS path).
"""
    from .registry import get_offline_decryptor_registry

    keylogs_map = manifest.get("keylogs") or {}
    if not isinstance(keylogs_map, dict):
        keylogs_map = {}
    found: dict[str, str] = {}
    for entry in get_offline_decryptor_registry().list():
        value = keylogs_map.get(entry.protocol_name) or manifest.get(entry.cli_dest)
        if value:
            found[entry.protocol_name] = value
    return found


def resolve_cli_path(path: str | None, pcap_path: str) -> str | None:
    """Resolve a path typed on the command line: CWD first, then the pcap's directory."""
    if not path:
        return None
    pcap_dir = os.path.dirname(os.path.abspath(pcap_path)) if pcap_path else ""
    return _resolve_relative_path(path, ["", pcap_dir] if pcap_dir else [""])


def _resolve_midstream_secrets(args: argparse.Namespace, manifest: dict) -> str | None:
    """The TLS mid-stream secret-bundle sidecar for this run: the ``--tls-midstream-secrets`` flag, else the manifest value, else ``None``."""
    pcap = getattr(args, "from_pcap", "") or ""
    explicit = getattr(args, "tls_midstream_secrets", None)
    if explicit:
        return resolve_cli_path(explicit, pcap)
    return resolve_manifest_path(pcap, manifest.get("tls_midstream_secrets") or None)


def merge_manifest(args: argparse.Namespace, manifest: dict) -> dict:
    """Merge CLI flags with a sidecar *manifest* into kwargs for :func:`convert_pcap_to_tap`; CLI values win."""
    from .registry import get_offline_decryptor_registry

    pcap = getattr(args, "from_pcap", "") or ""
    manifest = resolve_manifest_keylog_paths(pcap, manifest)
    tls_ports = list(args.tls_ports) or manifest_ports(manifest, "tls_ports")
    quic_ports = list(args.quic_ports) or manifest_ports(manifest, "quic_ports")
    keylog = args.keylog or manifest.get("keylog") or None

    # Precedence: CLI > manifest "keylogs" map > top-level cli_dest (the map wins because a multi-protocol capture splits keys per protocol while the field may hold the base/TLS path). Each value also feeds a ``<cli_dest>`` kwarg.
    from_manifest = manifest_protocol_keylogs(manifest)
    protocol_keylogs: dict[str, str] = {}
    named_keylog_kwargs: dict[str, str | None] = {}
    for entry in get_offline_decryptor_registry().list():
        value = (
            getattr(args, entry.cli_dest, None)
            or from_manifest.get(entry.protocol_name)
            or None
        )
        named_keylog_kwargs[entry.cli_dest] = value
        if value:
            protocol_keylogs[entry.protocol_name] = value

    # Memory-scan sidecars carry keys the hook keylog lacks (e.g. MTProto OBF/auth keys); union each into its protocol's keylog, as pcap_to_tap does.
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
        # Mapped to each emitter's own unit via the _emitter_accepts gate; None keeps each decryptor's default.
        "resync_search_depth": getattr(args, "resync_search_depth", None),
        # Mid-stream TLS 1.3 secret bundle; flag > manifest, see the helper.
        "tls_midstream_secrets": _resolve_midstream_secrets(args, manifest),
        # Resolved with the other _MANIFEST_SIDECAR_KEYS at the top of this function.
        "request_contexts": manifest.get("request_contexts") or None,
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


# Bounded-memory cap counters (bucket key, summary label, explanation), recorded only when non-zero.
_CAP_DROP_COUNTERS = (
    ("unknown_key_ids_overflow", "unknown auth_key_id records over the cap",
     "further unknown ids not listed above"),
    ("users_dropped", "users dropped",
     "user-reference cap reached — some names may be unresolved"),
    ("chat_nodes_dropped", "chat nodes dropped",
     "chat-reference cap reached — some chats may be unresolved"),
)


def _cap_drop_counts(counts: dict) -> list[tuple[str, int, str]]:
    """``(label, count, explanation)`` for each non-zero cap counter in *counts*."""
    return [(label, counts[key], why) for key, label, why in _CAP_DROP_COUNTERS
            if counts.get(key)]


def _print_cap_drops(proto: str, cap_drops: list[tuple[str, int, str]]) -> None:
    """Print the cap-overflow counters of one protocol bucket."""
    for label, count, why in cap_drops:
        print(f"  {proto} {label}: {count} ({why})")


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
    # Counters per registered protocol; keys absent from a bucket print nothing.
    for proto in sorted(result.per_protocol):
        counts = result.per_protocol[proto]
        messages = counts.get("messages", 0)
        undecryptable = counts.get("undecryptable", 0)
        degraded = counts.get("degraded", 0)
        # ``degraded`` counts only streams with positive protocol evidence; the rest are ``degraded_non_mtproto``.
        degraded_non = counts.get("degraded_non_mtproto", 0)
        partial = counts.get("partial", 0)
        # Streams re-derived mid-stream from memory-recovered obfuscation keys,
        # and those a recovery attempt could not align.
        recovered = counts.get("recovered_via_obf", 0)
        degraded_unrecovered = counts.get("degraded_unrecovered", 0)
        # Failures that are NOT "started mid-connection" (short/lossy start or
        # unsupported framing), the E2E-only signal, and clear-text auth_key_ids
        # of records whose key was not held.
        short = counts.get("short", 0)
        unsupported_framing = counts.get("unsupported_framing", 0)
        e2e_only = counts.get("e2e_only", False)
        unknown_key_ids = counts.get("unknown_key_ids") or {}
        cap_drops = _cap_drop_counts(counts)
        if not (messages or undecryptable or degraded or degraded_non or partial
                or recovered or short or unsupported_framing or e2e_only
                or unknown_key_ids or cap_drops):
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
        _print_cap_drops(proto, cap_drops)
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
    """Coverage of the TLS *keylog* over *pcap*, or ``None`` without a readable keylog or on failure.

    Never raises: the check is advisory and must not change the CLI outcome.
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


def _print_messaging_zero_flow_explanation(result: ConvertResult) -> None:
    """Print messaging-protocol reasons a 0-packet run decrypted nothing (E2E-only keys, unknown clear-text auth_key_ids); mirrors the TUI. Advisory."""
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
    """Run ``--repair-keylog``; returns the repaired keylog on a hit, else the original *keylog*. Never raises."""
    if not keylog or not os.path.isfile(keylog):
        print("Note: --repair-keylog needs a readable --keylog; skipping re-pair.")
        return keylog
    # relabel_keylog also fixes the ncrypt hook's TLS 1.3 HANDSHAKE<->TRAFFIC label swap and ``???`` client_randoms; a mislabeled session is invisible to the coverage gate, so this always runs.
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
    """Short ``key=value`` hint for ``--show-layers``: ``sni`` for TLS/QUIC, ``chat`` for layers with ``chat_type``, else empty."""
    name = getattr(layer, "name", "")
    if name in ("tls", "quic"):
        sni = getattr(layer, "sni", "")
        return f"sni={sni}" if sni else ""
    chat_type = getattr(layer, "chat_type", "")
    if chat_type:
        return f"chat={chat_type}"
    return ""


def _print_layer_stacks(tap_path: str) -> None:
    """Print the layer stack for each multi-layer flow in *tap_path* (read-only; the caller guards failures)."""
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


def _report_no_decrypted_data(result: ConvertResult,
                              coverage: Optional[keylog_coverage.Coverage]) -> int:
    """Explain a run that decrypted no packets; return the CLI exit code.

    0 when metadata-only flows (e.g. SSH) were still written, else 4.
    """
    _print_coverage_explanation(coverage)
    # Messaging diagnostics mirrored from the TUI: E2E-only keylog and unknown
    # clear-text auth_key_ids.
    _print_messaging_zero_flow_explanation(result)
    if result.flow_count:
        # Metadata-only flows (e.g. SSH KEXINIT) still make a usable .tap.
        print(
            f"Note: no application data was decrypted; the {result.flow_count} "
            "flow(s) written carry connection metadata only (e.g. SSH handshakes)."
        )
        return 0
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


def _missing_explicit_key_inputs(args: argparse.Namespace, kwargs: dict) -> list[str]:
    """Describe each key file named by a command-line flag that does not exist.

    Covers each decryptor's ``--<proto>-keylog`` / sidecar flag and ``--tls-midstream-secrets``.
    Manifest paths are not checked here (the conversion warns).
"""
    from .registry import get_offline_decryptor_registry

    missing = []
    for entry in get_offline_decryptor_registry().list():
        path = getattr(args, entry.cli_dest, None)
        if path and not os.path.isfile(path):
            missing.append(f"{entry.protocol_name} keylog not found ({entry.cli_flag}): {path}")
    if getattr(args, "tls_midstream_secrets", None):
        sidecar = kwargs.get("tls_midstream_secrets")
        if not sidecar or not os.path.isfile(sidecar):
            missing.append("TLS mid-stream secret-bundle sidecar not found "
                           f"(--tls-midstream-secrets): {sidecar or args.tls_midstream_secrets}")
    return missing


def run_offline_pcap_to_tap(argv: Sequence[str]) -> int:
    """Parse *argv*, run the conversion, print a summary and return an exit code.

    0 success; 2 pcap not found; 3 tshark missing; 5 no decryption keys (no keylog
    or DSB, or a flag-named keylog/sidecar is missing); 1 other failure (including a
    tshark run stopped by its time or output limit, printed as one line); 4 no
    decrypted packets and no metadata-only flow (usually wrong keys/ports).
"""
    # Plugin discovery must run before the parser is built so their flags exist (opt out: FRITAP_DISABLE_OFFLINE_DECRYPTOR_DISCOVERY=1).
    try:
        from .discovery import discover_external_offline_decryptors, discovery_disabled
        if not discovery_disabled():
            discover_external_offline_decryptors()
    except Exception:  # pragma: no cover - discovery must never block the CLI
        logger.debug("offline decryptor discovery failed", exc_info=True)

    args = _build_parser().parse_args(list(argv))

    # Per-decryptor extra actions run before the pcap is touched and may
    # short-circuit with their own exit code.
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

    # A typo in an explicit keylog/sidecar flag must not silently drop a decryptor.
    missing_inputs = _missing_explicit_key_inputs(args, kwargs)
    if missing_inputs:
        for line in missing_inputs:
            print(f"Error: {line}")
        return 5

    # Non-fatal per-decryptor prerequisite warnings (e.g. a missing optional
    # crypto backend, or a TLS-riding protocol without a TLS keylog).
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
    except TsharkLimitError as exc:  # tshark timed out / flooded: one line, no traceback
        print(f"Error: {exc}")
        logger.debug("Offline conversion stopped by a tshark run limit", exc_info=True)
        return 1
    except Exception as exc:
        print(f"Error during offline conversion: {exc}")
        logger.error("Offline conversion failed", exc_info=True)
        return 1

    _print_summary(result, args.scan)

    # Guarded so a reader error never changes the exit code of a good run.
    if getattr(args, "show_layers", False):
        try:
            _print_layer_stacks(result.tap_path)
        except Exception:  # pragma: no cover - never break a good conversion
            logger.debug("--show-layers printing failed", exc_info=True)

    # Advisory TLS keylog coverage (None without a TLS keylog); never changes
    # the exit code.
    coverage = _keylog_coverage(tshark_bin, args.from_pcap, kwargs.get("keylog_path"))

    if result.decrypted_packet_count == 0:
        return _report_no_decrypted_data(result, coverage)

    _print_partial_coverage_note(coverage)
    return 0
