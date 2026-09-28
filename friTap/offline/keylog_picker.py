"""Pure helpers behind the pcap-to-tap keylog *protocol picker* (no TUI code).

The raw offline-decryptor registry lists every friTap-owned decryptor
(``mtproto``, ``telegram``, ``rc4``, ``schannel``, ``signal``, ...). The picker
shows a friendlier set:

  * ``tls`` always comes first (tshark's own TLS decryption).
  * Custom ciphers (e.g. ``rc4``) are grouped under one ``custom`` entry
    (displayed as "custom encryption"), listed last.
  * Entries with a ``picker_group`` (e.g. ``schannel``, a Windows TLS backend)
    are hidden; they are reached through their group entry instead —
    :func:`resolve_keylog_protocol` routes a keylog supplied under the group to
    the grouped entry whose ``accepts_keylog`` predicate accepts it (a Schannel
    ``.schannel.unpaired`` sidecar under ``tls`` -> ``schannel``).

Every function here is total: failures degrade to a safe default, never raise.
"""

from __future__ import annotations

import logging
import os
import tempfile
from typing import Callable, Dict, List, Mapping, NamedTuple, Optional, Sequence

from friTap.offline.registry import (
    OfflineDecryptorEntry,
    OfflineDecryptorRegistry,
    get_offline_decryptor_registry,
)
from friTap.protocols.registry import CUSTOM_GROUP

logger = logging.getLogger(__name__)

TLS_PICKER_NAME = "tls"
CUSTOM_PICKER_NAME = CUSTOM_GROUP

PICKER_DISPLAY_NAMES = {CUSTOM_PICKER_NAME: "custom encryption"}


def picker_display_name(name: str) -> str:
    """Human-readable label for picker entry *name* (falls back to *name*)."""
    return PICKER_DISPLAY_NAMES.get(name, name)


def _resolve_registry(registry: Optional[OfflineDecryptorRegistry]) -> OfflineDecryptorRegistry:
    """Return *registry*, or the global one with the built-ins registered."""
    if registry is not None:
        return registry
    try:
        import friTap.offline.pcap_to_tap  # noqa: F401  (registers built-ins on import)
    except Exception:  # pragma: no cover - defensive
        logger.debug("Could not import pcap_to_tap to populate the registry", exc_info=True)
    return get_offline_decryptor_registry()


def offline_custom_ciphers(registry: Optional[OfflineDecryptorRegistry] = None) -> List[str]:
    """Offline decryptor names that are custom ciphers (grouped under ``custom``)."""
    try:
        from friTap.protocols.registry import custom_cipher_names

        cipher_names = set(custom_cipher_names())
        return [name for name in _resolve_registry(registry).names() if name in cipher_names]
    except Exception:
        logger.debug("Could not resolve offline custom ciphers", exc_info=True)
        return []


def picker_protocol_names(registry: Optional[OfflineDecryptorRegistry] = None) -> List[str]:
    """Picker entries: ``tls``, standalone decryptors, then ``custom`` if any."""
    try:
        resolved = _resolve_registry(registry)
        custom_ciphers = offline_custom_ciphers(resolved)
        standalone = [
            entry.protocol_name
            for entry in resolved.list()
            if not entry.picker_group and entry.protocol_name not in custom_ciphers
        ]
        names = [TLS_PICKER_NAME, *standalone]
        if custom_ciphers:
            names.append(CUSTOM_PICKER_NAME)
        return list(dict.fromkeys(names))
    except Exception:
        logger.debug("Could not build keylog picker names", exc_info=True)
        return [TLS_PICKER_NAME]


def _grouped_entry_accepting(
    picker_name: str,
    path: str,
    registry: OfflineDecryptorRegistry,
) -> Optional[OfflineDecryptorEntry]:
    """First entry grouped under *picker_name* whose predicate accepts *path*."""
    for entry in registry.list():
        if entry.picker_group != picker_name or entry.accepts_keylog is None:
            continue
        try:
            if entry.accepts_keylog(path):
                return entry
        except Exception:
            logger.debug("accepts_keylog failed for %r", entry.protocol_name, exc_info=True)
    return None


def resolve_keylog_protocol(
    picker_name: str,
    path: str,
    registry: Optional[OfflineDecryptorRegistry] = None,
) -> str:
    """Map a picker choice + keylog *path* to the offline protocol to run.

    The first registered entry whose ``picker_group`` is *picker_name* and whose
    ``accepts_keylog`` predicate accepts *path* wins (e.g. a Schannel sidecar
    supplied under ``tls`` is routed to ``schannel``); otherwise the choice
    passes through unchanged.
    """
    if not path:
        return picker_name
    try:
        entry = _grouped_entry_accepting(picker_name, path, _resolve_registry(registry))
    except Exception:
        logger.debug("Could not resolve grouped keylog protocol", exc_info=True)
        return picker_name
    return entry.protocol_name if entry is not None else picker_name


def keylog_protocol_label(
    protocol: str,
    custom_ciphers: Optional[List[str]] = None,
    registry: Optional[OfflineDecryptorRegistry] = None,
) -> str:
    """Readable label for a stored (decryptor-keyed) keylog *protocol*.

    A grouped decryptor reads ``"<group> (<protocol>)"`` (e.g.
    ``"tls (schannel)"``), a custom cipher ``"custom encryption (rc4)"``; every
    other name is returned unchanged. Pass *custom_ciphers* (from
    :func:`offline_custom_ciphers`) to avoid recomputing it per call.
    """
    resolved = _resolve_registry(registry)
    try:
        entry = resolved.get(protocol)
    except Exception:
        logger.debug("Could not look up decryptor %r", protocol, exc_info=True)
        entry = None
    if entry is not None and entry.picker_group:
        return f"{entry.picker_group} ({entry.protocol_name})"
    if custom_ciphers is None:
        custom_ciphers = offline_custom_ciphers(resolved)
    if protocol in custom_ciphers:
        return f"{picker_display_name(CUSTOM_PICKER_NAME)} ({protocol})"
    return protocol


class MergedKeylog(NamedTuple):
    """Result of :func:`merge_keylogs`.

    * ``path`` — the combined keylog file on disk.
    * ``key_count`` — number of distinct (de-duplicated) key lines it holds.
    """

    path: str
    key_count: int


def _merged_output_name(first: str, protocol: str) -> str:
    """Deterministic ``<stem>.merged.<proto>.keylog`` basename for *first*.

    Strips any prior ``.merged`` / ``.merged.<proto>`` marker so re-merging an
    already-merged file (the incremental "store a third keylog" case) keeps a
    stable name instead of growing ``.merged.merged.…`` on every pass.
    """
    stem = os.path.splitext(os.path.basename(first))[0]
    marker = f".merged.{protocol}"
    if stem.endswith(marker):
        stem = stem[: -len(marker)]
    elif stem.endswith(".merged"):
        stem = stem[: -len(".merged")]
    return f"{stem or 'keylog'}.merged.{protocol}.keylog"


def _read_keylog_sections(path: str) -> tuple[List[str], List[str]]:
    """Return ``(comment_lines, key_lines)`` read from keylog *path*.

    ``comment_lines`` are the ``#``-prefixed header lines; ``key_lines`` are the
    non-blank, non-comment lines (the actual secrets). Order is preserved.
    """
    comments: List[str] = []
    keys: List[str] = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            stripped = raw.strip()
            if not stripped:
                continue
            if stripped.startswith("#"):
                comments.append(stripped)
            else:
                keys.append(stripped)
    return comments, keys


def count_distinct_keys(paths: Sequence[str]) -> int:
    """Count the DISTINCT non-comment key lines across every readable *paths*.

    Uses the same de-duplication rule as :func:`merge_keylogs` (first-seen set of
    :func:`_read_keylog_sections` key lines), so a keylog-count and a later merge
    of the same files agree. Total: unreadable/missing paths are skipped, never
    raises; returns 0 when nothing readable is found.
    """
    seen_keys: set = set()
    for path in paths:
        if not path:
            continue
        try:
            _comments, keys = _read_keylog_sections(path)
        except OSError:
            continue
        seen_keys.update(keys)
    return len(seen_keys)


def merge_keylogs(
    paths: Sequence[str],
    protocol: str,
    out_dir: Optional[str] = None,
) -> Optional[MergedKeylog]:
    """Merge same-protocol keylog *paths* into ONE combined keylog file.

    Produces the UNION of the de-duplicated, non-comment key lines from every
    readable input (first-seen order preserved), keeping a single header/comment
    block (the union of the inputs' ``#`` comment lines). For an MTProto keylog
    this keeps every distinct ``MTPROTO_AUTH_KEY`` / ``MTPROTO_E2E_KEY`` /
    ``MTPROTO_OBF_KEY`` line, so an E2E-only file merged with an
    auth+E2E+OBF file yields one file carrying all three key types.

    The result is written to *out_dir* (default: the system temp dir) as
    ``<stem>.merged.<proto>.keylog`` and returned as a :class:`MergedKeylog`.

    Total: returns ``None`` (never raises) when nothing readable is found or the
    write fails, so the caller can fall back to its previous behavior.
    """
    try:
        readable = [p for p in paths if p]
        comment_lines: List[str] = []
        key_lines: List[str] = []
        seen_comments: set = set()
        seen_keys: set = set()
        read_any = False
        for path in readable:
            try:
                comments, keys = _read_keylog_sections(path)
            except OSError:
                logger.debug("Could not read keylog %r for merge", path, exc_info=True)
                continue
            read_any = True
            for comment in comments:
                if comment not in seen_comments:
                    seen_comments.add(comment)
                    comment_lines.append(comment)
            for key in keys:
                if key not in seen_keys:
                    seen_keys.add(key)
                    key_lines.append(key)
        if not read_any:
            return None

        target_dir = out_dir or tempfile.gettempdir()
        os.makedirs(target_dir, exist_ok=True)
        out_path = os.path.join(target_dir, _merged_output_name(readable[0], protocol))
        with open(out_path, "w", encoding="utf-8") as fh:
            for comment in comment_lines:
                fh.write(comment + "\n")
            for key in key_lines:
                fh.write(key + "\n")
        return MergedKeylog(out_path, len(key_lines))
    except Exception:
        logger.debug("Could not merge keylogs %r", list(paths), exc_info=True)
        return None


# Sidecar map keys that feed the MTProto keylog slot ("telegram" is its alias).
_MTPROTO_SIDECAR_KEYS = ("mtproto", "telegram")


def merge_memory_scan_sidecars(
    sidecars: Mapping[str, str],
    current_keylog: Callable[[str], Optional[str]],
    out_dir: Optional[str] = None,
) -> Dict[str, str]:
    """Union each memory-scan sidecar keylog into the selected keylog for its protocol.

    *sidecars* is a manifest's nested ``memory_scan_keylogs`` map (protocol ->
    path; ``"telegram"`` is folded into ``"mtproto"``). *current_keylog* returns
    the caller's currently selected keylog for a protocol (or ``None``). Returns
    ``{protocol: merged_path}`` for every sidecar that exists and merged; a
    missing sidecar or failed merge is simply absent, so the caller keeps its
    previous keylog. Never raises (see :func:`merge_keylogs`).
    """
    def _merge(protocol: str, sidecar: Optional[str]) -> None:
        if not sidecar or not os.path.isfile(sidecar):
            return
        paths = [p for p in (current_keylog(protocol), sidecar) if p]
        merged = merge_keylogs(paths, protocol, out_dir=out_dir)
        if merged:
            result[protocol] = merged.path

    result: Dict[str, str] = {}
    _merge("tls", sidecars.get("tls"))
    _merge("mtproto", next(
        (sidecars[k] for k in _MTPROTO_SIDECAR_KEYS if sidecars.get(k)), None))
    for protocol, sidecar in sidecars.items():
        if protocol not in ("tls",) + _MTPROTO_SIDECAR_KEYS:
            _merge(protocol, sidecar)
    return result


__all__ = [
    "CUSTOM_PICKER_NAME",
    "TLS_PICKER_NAME",
    "PICKER_DISPLAY_NAMES",
    "MergedKeylog",
    "picker_display_name",
    "offline_custom_ciphers",
    "picker_protocol_names",
    "resolve_keylog_protocol",
    "keylog_protocol_label",
    "merge_keylogs",
    "merge_memory_scan_sidecars",
    "count_distinct_keys",
]
