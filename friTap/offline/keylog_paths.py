"""
Keylog path identity.

One canonical answer to "do these two paths name the same keylog file?", shared
by the pcap -> tap converter, the keylog suggester and the TUI wizard; plus
the validation rules for paths read from an (untrusted) capture manifest.
"""

from __future__ import annotations

import logging
import os
import re
import stat

logger = logging.getLogger(__name__)


def canonical_keylog_path(path: str) -> str:
    """Canonical form of *path* for identity comparisons.

    Symlinks and relative segments are resolved (``realpath``) and the case is
    folded where the platform's paths are case-insensitive (``normcase``). A
    path that cannot be resolved falls back to its normalized absolute form.
    """
    try:
        resolved = os.path.realpath(path)
    except (OSError, ValueError):
        resolved = os.path.normpath(os.path.abspath(path))
    return os.path.normcase(resolved)


def same_keylog_path(a: str, b: str) -> bool:
    """True when *a* and *b* name the same keylog file."""
    if a == b:
        return True
    try:
        return canonical_keylog_path(a) == canonical_keylog_path(b)
    except (OSError, ValueError):
        return False


# ---------------------------------------------------------------------------
# Manifest path validation
#
# A ``<pcap>.fritap.json`` manifest shipped with a third-party capture is
# untrusted. friTap's own manifests legitimately record absolute paths and
# paths relative to the capture's CWD (``-k /tmp/k.log -p out/cap.pcap``), so
# paths are NOT confined to the manifest directory. Instead:
#
# * a manifest path must name a bounded regular file (never a FIFO, device or
#   directory — a FIFO would block the reader forever), and
# * the exfiltration risk is closed at the sink: when manifest-named files are
#   merged into a new keylog only well-formed keylog lines are copied (see
#   :func:`friTap.offline.keylog_picker.merge_keylogs`), so an arbitrary file
#   such as ``~/.ssh/id_rsa`` contributes zero lines.
#
# Protocol names (used in output file names) are restricted to a safe charset.
# ---------------------------------------------------------------------------

# Upper bound for a manifest-referenced keylog / sidecar file.
MANIFEST_FILE_MAX_BYTES = 512 * 1024 * 1024

_SAFE_PROTOCOL_NAME_RE = re.compile(r"^[a-z0-9_]+$")


def is_safe_protocol_name(name) -> bool:
    """True when *name* is a ``^[a-z0-9_]+$`` protocol name (safe in file names)."""
    return isinstance(name, str) and bool(_SAFE_PROTOCOL_NAME_RE.fullmatch(name))


def is_bounded_regular_file(path: str, max_bytes: int | None = None) -> bool:
    """True when *path* is a regular file (not a FIFO/device/dir) of <= *max_bytes*.

    *max_bytes* defaults to :data:`MANIFEST_FILE_MAX_BYTES`.
    """
    limit = MANIFEST_FILE_MAX_BYTES if max_bytes is None else max_bytes
    try:
        info = os.stat(path)
    except (OSError, ValueError, TypeError):
        return False
    return stat.S_ISREG(info.st_mode) and info.st_size <= limit


def _manifest_path_candidates(manifest_dir: str, path: str) -> list[str]:
    """Lookup order for *path*: as-is when absolute, else manifest dir then CWD."""
    if os.path.isabs(path):
        return [path]
    first = os.path.join(manifest_dir, path) if manifest_dir else path
    return [first, path]


def validate_manifest_path(manifest_dir: str, path) -> str | None:
    """Resolve manifest-supplied *path*, rejecting anything unsafe to read.

    Resolution order is unchanged from friTap's historical behaviour: an
    absolute path is used as-is; a relative one is looked up next to the
    manifest first, then in the CWD (live captures record paths relative to
    *their* CWD). The first candidate that exists must be a regular file of at
    most :data:`MANIFEST_FILE_MAX_BYTES` — a FIFO, device, directory or
    oversized file is rejected (``None``, with a warning). When no candidate
    exists the first one is returned unchanged, so a later "not found" error
    names the location looked at first (nothing is read).

    Never raises; a non-string, empty or NUL-containing *path* yields ``None``.
    """
    if not isinstance(path, str) or not path or "\x00" in path:
        return None
    candidates = _manifest_path_candidates(manifest_dir, path)
    for candidate in candidates:
        if not os.path.lexists(candidate):
            continue
        if is_bounded_regular_file(candidate):
            logger.info("Manifest path %r resolved to %r", path, candidate)
            return candidate
        logger.warning(
            "Ignoring manifest path %r: %r is not a regular file of at most %d bytes",
            path, candidate, MANIFEST_FILE_MAX_BYTES)
        return None
    return candidates[0]
