"""Packaging guard for the offline attribution datasets.

The shipped tracker seed, SDK signature table and PSL snapshot must be listed
as ``friTap`` package data, while the local-only ``trackers_full.json`` (full
Tracker Radar distillation, CC BY-NC-SA 4.0) must never be matched by
``package_data`` or pulled into the sdist by ``MANIFEST.in``.

Static checks only: ``setup.py`` is parsed with :mod:`ast`, never executed.
"""

from __future__ import annotations

import ast
import fnmatch
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
_DATA = "analysis/attribution/data"
_SHIPPED = (
    f"{_DATA}/trackers.json",
    f"{_DATA}/sdk_signatures.json",
    f"{_DATA}/public_suffix_list.dat",
)
_LOCAL_ONLY = f"{_DATA}/trackers_full.json"
_LOCAL_ONLY_SDIST = f"friTap/{_LOCAL_ONLY}"


def _setup_call(tree: ast.AST) -> ast.Call | None:
    """Return the ``setup(...)`` call node in a parsed ``setup.py``."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and getattr(node.func, "id", None) == "setup":
            return node
    return None


def _fritap_package_data() -> list:
    """Return ``package_data["friTap"]`` from ``setup.py`` without running it."""
    setup_py = _REPO_ROOT / "setup.py"
    if not setup_py.is_file():
        pytest.skip("setup.py not present")
    call = _setup_call(ast.parse(setup_py.read_text(encoding="utf-8")))
    assert call is not None, "setup.py has no setup(...) call"
    for keyword in call.keywords:
        if keyword.arg == "package_data":
            return ast.literal_eval(keyword.value)["friTap"]
    pytest.fail("setup(...) has no package_data= keyword")


def _manifest_line_includes(line: str, path: str) -> bool:
    """True if one MANIFEST.in command line would pull ``path`` into the sdist."""
    words = line.split()
    if not words:
        return False
    command, args = words[0], words[1:]
    name = path.rsplit("/", 1)[-1]
    if command == "include":
        return any(fnmatch.fnmatch(path, pattern) for pattern in args)
    if command == "global-include":
        return any(fnmatch.fnmatch(name, pattern) for pattern in args)
    if command in ("recursive-include", "graft") and args:
        under_dir = path.startswith(args[0].rstrip("/") + "/")
        if command == "graft":
            return under_dir
        return under_dir and any(fnmatch.fnmatch(name, pattern) for pattern in args[1:])
    return False


def test_shipped_attribution_datasets_are_package_data() -> None:
    patterns = _fritap_package_data()
    missing = [path for path in _SHIPPED if path not in patterns]
    assert missing == []


def test_full_tracker_map_is_not_package_data() -> None:
    patterns = _fritap_package_data()
    matching = [pattern for pattern in patterns if fnmatch.fnmatch(_LOCAL_ONLY, pattern)]
    assert matching == []


@pytest.mark.parametrize(
    "line, expected",
    [
        ("include friTap/analysis/attribution/data/trackers.json", False),
        ("include friTap/analysis/attribution/data/*.json", True),
        ("recursive-include friTap/analysis/attribution *.json", True),
        ("recursive-include friTap/patterns *.json", False),
        ("graft friTap/analysis", True),
        ("global-include trackers_*.json", True),
    ],
)
def test_manifest_line_check_detects_full_map(line: str, expected: bool) -> None:
    # Guards the guard: a broad glob must be caught, an exact name must not.
    assert _manifest_line_includes(line, _LOCAL_ONLY_SDIST) is expected


def test_manifest_does_not_include_full_tracker_map() -> None:
    manifest = _REPO_ROOT / "MANIFEST.in"
    if not manifest.is_file():
        pytest.skip("MANIFEST.in not present")
    lines = manifest.read_text(encoding="utf-8").splitlines()
    offending = [line for line in lines if _manifest_line_includes(line, _LOCAL_ONLY_SDIST)]
    assert offending == []
