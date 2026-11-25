#!/usr/bin/env python3
"""Set ``.claude-plugin/plugin.json``'s version to ``friTap/about.py``'s ``__version__``.

tests/unit/test_claude_plugin.py requires the two to match. Usage:

    python3 scripts/sync_plugin_version.py [TREE]   # TREE defaults to the repo root

Run it after bumping about.py. publish_public.sh also runs it on the public tree
after ``--no-release`` freezes about.py at the published version, so the
snapshot's own test suite (public CI) stays green.

Only the version string is rewritten; the rest of plugin.json keeps its exact
formatting. Exit codes: 0 = in sync (changed or already), 1 = cannot sync.
"""
from __future__ import annotations

import json
import os
import re
import sys

ABOUT_PY = os.path.join("friTap", "about.py")
PLUGIN_JSON = os.path.join(".claude-plugin", "plugin.json")
_VERSION_ASSIGNMENT = re.compile(r"""^__version__\s*=\s*["']([^"']+)["']""", re.MULTILINE)


class VersionSyncError(Exception):
    """about.py or plugin.json cannot be read or updated safely."""


def read_package_version(tree: str) -> str:
    """The ``__version__`` literal in TREE/friTap/about.py (parsed, never imported)."""
    with open(os.path.join(tree, ABOUT_PY), encoding="utf-8") as fh:
        match = _VERSION_ASSIGNMENT.search(fh.read())
    if not match:
        raise VersionSyncError(f"no __version__ assignment in {ABOUT_PY}")
    return match.group(1)


def _replace_top_level_version(text: str, old: str, new: str) -> str:
    pattern = re.compile(r'("version"\s*:\s*")' + re.escape(old) + r'"')
    updated = pattern.sub(lambda m: m.group(1) + new + '"', text, count=1)
    if json.loads(updated).get("version") != new:
        raise VersionSyncError(f"could not rewrite the top-level version in {PLUGIN_JSON}")
    return updated


def sync_plugin_version(tree: str) -> str:
    """Align TREE's plugin.json version with about.py; return a one-line status."""
    plugin_path = os.path.join(tree, PLUGIN_JSON)
    if not os.path.isfile(plugin_path):
        return f"no {PLUGIN_JSON} (skipped)"
    version = read_package_version(tree)
    with open(plugin_path, encoding="utf-8") as fh:
        text = fh.read()
    current = json.loads(text).get("version")
    if current == version:
        return f"{PLUGIN_JSON} already at {version}"
    if not isinstance(current, str):
        raise VersionSyncError(f"{PLUGIN_JSON} has no top-level version string")
    updated = _replace_top_level_version(text, current, version)  # validate before truncating
    with open(plugin_path, "w", encoding="utf-8") as fh:
        fh.write(updated)
    return f"{PLUGIN_JSON}: {current} -> {version}"


def main(argv: list[str]) -> int:
    tree = argv[1] if len(argv) > 1 else os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    try:
        print(f"  sync_plugin_version: {sync_plugin_version(tree)}")
    except (OSError, ValueError, VersionSyncError) as exc:
        print(f"ERROR: sync_plugin_version: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
