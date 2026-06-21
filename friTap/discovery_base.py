"""Shared, stateless scaffolding for friTap's zero-config discovery modules.

friTap discovers user-provided extensions from a couple of identical sources —
a per-user drop-in directory and a setuptools entry-point group — guarded by an
opt-out environment variable. The directory resolution (platform-native path +
legacy ``~/.fritap`` fallback), the Python-3.9-compatible entry-point shim, the
env-disable check, and the ``*.py`` drop-in loading boilerplate were copied
across :mod:`friTap.analysis.discovery` and :mod:`friTap.offline.discovery`.

This module owns that shared, **stateless** plumbing so the discovery modules
no longer duplicate it. Each discovery module keeps its OWN module-global caches
(``_*_DIR`` / ``_CACHE``) and its per-source loaders — those differ in what they
collect (analyzer instances vs. registered decryptor entries) and are the part
tests monkeypatch — and simply calls the helpers here for the identical parts.
(:mod:`friTap.parsers.registry` and :mod:`friTap.plugins.loader` carry the same
pattern and could adopt these helpers too.)
"""

from __future__ import annotations

import importlib.metadata
import importlib.util
import logging
import os
from pathlib import Path
from types import ModuleType
from typing import Iterator, Tuple

import platformdirs


def discovery_disabled(env_var: str) -> bool:
    """True when ambient discovery is opted out via *env_var*.

    Disabled for any value other than unset / ``""`` / ``0`` / ``false`` /
    ``False`` (so ``=1``, ``=true``, ``=yes`` all disable).
    """
    return os.environ.get(env_var, "").strip() not in ("", "0", "false", "False")


def resolve_dropin_dir(subdir: str, logger: logging.Logger,
                       *, label: str | None = None) -> Path:
    """Resolve a friTap drop-in directory with native paths + legacy fallback.

    Platform paths (``<user-data>/friTap/<subdir>/``):
      - Linux:   ``~/.local/share/friTap/<subdir>/``  (XDG)
      - macOS:   ``~/Library/Application Support/friTap/<subdir>/``
      - Windows: ``C:\\Users\\<user>\\AppData\\Local\\friTap\\<subdir>\\``

    If the legacy ``~/.fritap/<subdir>/`` directory exists and the native path
    does not, the legacy location is used for backwards compatibility. *label*
    is used only in the "could not create" warning (defaults to *subdir*).
    """
    native_dir = Path(platformdirs.user_data_dir("friTap")) / subdir
    legacy_dir = Path.home() / ".fritap" / subdir

    if legacy_dir.exists() and not native_dir.exists():
        return legacy_dir

    try:
        native_dir.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        logger.warning("Could not create %s directory %s: %s",
                       label or subdir, native_dir, e)
    return native_dir


def get_entry_points(group: str, **kwargs: str) -> list:
    """Return entry points for *group*, compatible with Python 3.9+.

    Newer ``importlib.metadata`` exposes ``entry_points().select(group=...)``;
    older versions return a dict keyed by group. Honors an optional ``name=``
    filter on both paths.
    """
    eps = importlib.metadata.entry_points()
    if hasattr(eps, "select"):
        return list(eps.select(group=group, **kwargs))
    matches = eps.get(group, [])
    if kwargs.get("name"):
        matches = [ep for ep in matches if ep.name == kwargs["name"]]
    return list(matches)


def iter_dropin_modules(directory: Path, module_prefix: str,
                        logger: logging.Logger,
                        *, label: str = "module") -> Iterator[Tuple[Path, ModuleType]]:
    """Yield ``(path, loaded_module)`` for each importable ``*.py`` in *directory*.

    Files whose name starts with ``_`` (dunder / private) are skipped. Each file
    is loaded via ``spec_from_file_location`` + ``exec_module`` under a unique
    ``<module_prefix><stem>`` module name; a file that fails to import is logged
    (using *label*) and skipped so one bad drop-in never aborts the scan. Yields
    nothing when *directory* does not exist.

    SECURITY: loading a ``.py`` file executes its top-level code, exactly like
    the plugin loader — callers gate this behind an opt-out env var.
    """
    if not directory.exists():
        return
    for item in sorted(directory.iterdir()):
        if item.suffix != ".py" or item.name.startswith("_"):
            continue
        try:
            spec = importlib.util.spec_from_file_location(
                f"{module_prefix}{item.stem}", item
            )
            if not spec or not spec.loader:
                continue
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
        except Exception as e:  # noqa: BLE001 — one bad file must not kill discovery
            logger.error("Failed to load %s file %s: %s", label, item, e)
            continue
        yield item, mod


__all__ = [
    "discovery_disabled",
    "resolve_dropin_dir",
    "get_entry_points",
    "iter_dropin_modules",
]
