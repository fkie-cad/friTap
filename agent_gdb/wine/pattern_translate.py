"""Translate a friTap ``--patterns`` file into the Wine GDB extractor's format.

The gdb script (``gdb_script/gdb_wine_extract.py``) reads ``FRITAP_PATTERNS`` as
a FLAT map, the format ``utils/wine_hunter.py`` emits::

    {"<hex bytes>": {"name": "...", "offset": 0, "handler": "<BP class>"}}

It scans executable memory for the exact bytes (``bytes.find``, no wildcard
masks) and plants ``handler`` at ``match address + offset``.

friTap's own pattern files use the nested v2 schema the Frida Wine agent reads
(``agent/shared/wine_keylog_pattern_hook.ts``, ``agent/shared/libressl_kdf.ts``)::

    modules.<library>.wine.<arch>.<signature id>.{primary,fallback,second_fallback}
    modules.libressl.<arch>.<kdf kind>            (string, list or the dict above)
    libressl.windows.<arch>.<kdf kind>

:func:`wine_patterns_for_gdb` passes a flat file through unchanged and turns
the Wine-relevant v2 entries into a temporary flat file. The Frida agent hooks
a v2 pattern at the match start (the function entry), so each translated entry
gets ``offset`` 0. The gdb handlers read x86-64 registers, so only ``x64``
entries translate; wildcard (``??``) patterns cannot be expressed as exact
bytes and are skipped with a warning.
"""

import json
import logging
import os
import re
import tempfile
from typing import Dict, Iterator, List, Optional, Tuple

# (library, signature id) under modules.<library>.wine.<arch> -> gdb handler.
WINE_SIGNATURE_HANDLERS = {
    ("gnutls", "gnutls_keylog_sysv"): "GnuTLSCallKeylogUnixBP",
    ("gnutls", "gnutls_keylog_win64"): "GnuTLSCallKeylogWindowsBP",
    ("openssl", "openssl_log_secret_win64"): "OpenSSLCallSSLLogSecretWindowsBP",
}

# LibreSSL KDF kind (agent/shared/libressl_kdf.ts) -> gdb handler.
LIBRESSL_KDF_HANDLERS = {
    "hkdfWithLen": "LibreSSLHkdfExpandLabelWinBP",
    "prf": "LibreSSLTls1PrfWinBP",
}

GDB_ARCH = "x64"
_PATTERN_SLOTS = ("primary", "fallback", "second_fallback")
_FLAT_KEY_RE = re.compile(r"^(?:[0-9A-Fa-f]{2})+$")
_HEX_TOKEN_RE = re.compile(r"^[0-9A-Fa-f]{2}$")
_NOTHING_APPLICABLE = "--patterns has no Wine/GDB-applicable entries; ignored"

# One v2 entry: (where it came from, handler name or None, raw pattern node).
_Entry = Tuple[str, Optional[str], object]


def _default_logger(logger):
    return logger or logging.getLogger("friTap.wine.patterns")


def is_flat_gdb_format(data) -> bool:
    """True for a non-empty ``{"<hex>": {"handler": ...}}`` map."""
    if not isinstance(data, dict) or not data:
        return False
    return all(
        _FLAT_KEY_RE.match(key) and isinstance(value, dict) and "handler" in value
        for key, value in data.items()
    )


def _pattern_strings(node) -> List[str]:
    """A v2 pattern node (string, list, or primary/fallback dict) as a list."""
    if isinstance(node, str):
        return [node] if node.strip() else []
    if isinstance(node, list):
        return [p for p in node if isinstance(p, str) and p.strip()]
    if isinstance(node, dict):
        return [node[k] for k in _PATTERN_SLOTS
                if isinstance(node.get(k), str) and node[k].strip()]
    return []


def _hex_key(pattern: str) -> Optional[str]:
    """``"F3 0F 1E"`` -> ``"f30f1e"``; None for wildcards or malformed bytes."""
    tokens = pattern.split()
    if not tokens or not all(_HEX_TOKEN_RE.match(t) for t in tokens):
        return None
    return "".join(tokens).lower()


def _wine_signature_entries(modules: dict) -> Iterator[_Entry]:
    for library, platforms in modules.items():
        wine = platforms.get("wine") if isinstance(platforms, dict) else None
        if not isinstance(wine, dict):
            continue
        for arch, signatures in wine.items():
            if not isinstance(signatures, dict):
                continue
            for sig_id, node in signatures.items():
                where = f"modules.{library}.wine.{arch}.{sig_id}"
                handler = WINE_SIGNATURE_HANDLERS.get((library, sig_id))
                yield where, handler if arch == GDB_ARCH else None, node


def _libressl_kdf_entries(prefix: str, arches) -> Iterator[_Entry]:
    if not isinstance(arches, dict):
        return
    for arch, kinds in arches.items():
        if arch == "wine" or not isinstance(kinds, dict):
            continue
        for kind, node in kinds.items():
            if kind.startswith("_"):
                continue
            handler = LIBRESSL_KDF_HANDLERS.get(kind) if arch == GDB_ARCH else None
            yield f"{prefix}.{arch}.{kind}", handler, node


def iter_v2_wine_entries(data: dict) -> Iterator[_Entry]:
    """Every v2 entry the Frida Wine agent would read, with its gdb handler
    (None when there is no x86-64 gdb handler for it)."""
    modules = data.get("modules")
    if isinstance(modules, dict):
        yield from _wine_signature_entries(modules)
        yield from _libressl_kdf_entries("modules.libressl", modules.get("libressl"))
    libressl = data.get("libressl")
    if isinstance(libressl, dict):
        yield from _libressl_kdf_entries("libressl.windows", libressl.get("windows"))


def _flat_entries_for(where, handler, node, log) -> Dict[str, dict]:
    flat = {}
    for pattern in _pattern_strings(node):
        key = _hex_key(pattern)
        if key is None:
            log.warning("--patterns %s: %r has wildcards or invalid bytes; the GDB "
                        "extractor needs exact bytes, skipped", where, pattern)
            continue
        flat[key] = {"name": f"{where} (--patterns)", "offset": 0, "handler": handler}
    return flat


def translate_v2_to_flat(data: dict, logger=None) -> Dict[str, dict]:
    """The flat gdb map for the Wine-applicable entries of a v2 pattern dict."""
    log = _default_logger(logger)
    flat = {}
    for where, handler, node in iter_v2_wine_entries(data):
        if handler is None:
            log.warning("--patterns %s has no GDB handler (x86-64 only: %s); skipped",
                        where, ", ".join(sorted(_known_ids())))
            continue
        flat.update(_flat_entries_for(where, handler, node, log))
    return flat


def _known_ids() -> List[str]:
    return [sid for _lib, sid in WINE_SIGNATURE_HANDLERS] + list(LIBRESSL_KDF_HANDLERS)


def _write_temp_flat(flat: Dict[str, dict]) -> str:
    fd, path = tempfile.mkstemp(prefix="fritap_wine_patterns_", suffix=".json")
    with os.fdopen(fd, "w") as fh:
        json.dump(flat, fh, indent=2)
    return path


def _load_json(path: str, log) -> Optional[dict]:
    try:
        with open(path) as fh:
            return json.load(fh)
    except (OSError, ValueError) as exc:
        log.warning("Could not read --patterns file %s for the Wine GDB route: %s",
                    path, exc)
        return None


def wine_patterns_for_gdb(path: Optional[str], logger=None) -> Optional[str]:
    """A patterns file the gdb extractor understands, or None.

    A flat gdb-format file is returned unchanged. A v2 friTap file is
    translated into a new temporary flat file (remove it with
    :func:`discard_translated_patterns`). Returns None, with a warning, when
    nothing in the file applies to the GDB route.
    """
    if not path:
        return None
    log = _default_logger(logger)
    data = _load_json(path, log)
    if data is None:
        return None
    if is_flat_gdb_format(data):
        return path
    flat = translate_v2_to_flat(data, log) if isinstance(data, dict) else {}
    if not flat:
        log.warning(_NOTHING_APPLICABLE)
        return None
    log.info("Translated %d --patterns entr%s for the Wine GDB extractor",
             len(flat), "y" if len(flat) == 1 else "ies")
    return _write_temp_flat(flat)


def discard_translated_patterns(translated: Optional[str], original: Optional[str]) -> None:
    """Delete a temp file made by :func:`wine_patterns_for_gdb` (never the
    user's own file, which is passed through unchanged)."""
    if not translated or translated == original:
        return
    try:
        os.remove(translated)
    except OSError:
        pass
