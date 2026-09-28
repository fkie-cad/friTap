"""
Keylog path identity.

One canonical answer to "do these two paths name the same keylog file?", shared
by the pcap -> tap converter, the keylog suggester and the TUI wizard.
"""

from __future__ import annotations

import os


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
