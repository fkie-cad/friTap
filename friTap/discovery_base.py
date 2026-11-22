"""Stateless plumbing for friTap's zero-config discovery modules.

Drop-in directory resolution (native path + legacy ``~/.fritap``), the Python-3.9
entry-point shim, the env opt-out check and ``*.py`` drop-in loading. Each discovery
module (:mod:`friTap.analysis.discovery`, :mod:`friTap.offline.discovery`) keeps its
own caches and loaders, which tests monkeypatch.
"""

from __future__ import annotations

import importlib.metadata
import importlib.util
import logging
import os
from pathlib import Path
from types import ModuleType
from typing import Callable, Iterator, Optional, Tuple


def discovery_disabled(env_var: str) -> bool:
    """True when discovery is opted out via *env_var* (any value except unset, ``""``, ``0``, ``false``)."""
    return os.environ.get(env_var, "").strip() not in ("", "0", "false", "False")


def resolve_dropin_dir(subdir: str, logger: logging.Logger,
                       *, label: str | None = None, create: bool = True) -> Path:
    """Resolve a friTap drop-in directory: ``<user-data>/friTap/<subdir>/``.

    Linux ``~/.local/share`` (XDG), macOS ``~/Library/Application Support``, Windows
    ``%LOCALAPPDATA%``. The legacy ``~/.fritap/<subdir>/`` is used when it exists and the
    native path does not. *label* names the "could not create" warning (default *subdir*);
    ``create=False`` returns the native path without creating it.
    """
    import platformdirs  # lazy: importing the parser registry must work without it

    native_dir = Path(platformdirs.user_data_dir("friTap")) / subdir
    legacy_dir = Path.home() / ".fritap" / subdir

    if legacy_dir.exists() and not native_dir.exists():
        return legacy_dir
    if not create:
        return native_dir

    try:
        native_dir.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        logger.warning("Could not create %s directory %s: %s",
                       label or subdir, native_dir, e)
    return native_dir


def get_entry_points(group: str, **kwargs: str) -> list:
    """Entry points for *group* on Python 3.9+ (older ``importlib.metadata`` returns a dict); honors ``name=``."""
    eps = importlib.metadata.entry_points()
    if hasattr(eps, "select"):
        return list(eps.select(group=group, **kwargs))
    matches = eps.get(group, [])
    if kwargs.get("name"):
        matches = [ep for ep in matches if ep.name == kwargs["name"]]
    return list(matches)


def iter_dropin_modules(
    directory: Path, module_prefix: str, logger: logging.Logger,
    *, label: str = "module",
    on_error: Optional[Callable[[Path, BaseException], None]] = None,
) -> Iterator[Tuple[Path, ModuleType]]:
    """Yield ``(path, loaded_module)`` for each importable ``*.py`` in *directory*.

    ``_``-prefixed files are skipped; each loads as ``<module_prefix><stem>``. A file that
    fails to import is logged (with *label*) and skipped; *on_error(path, exc)* is called
    after each (must not raise). Yields nothing if *directory* is missing.

    SECURITY: loading executes top-level code like the plugin loader, so callers gate it behind an opt-out env var.
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
        except Exception as e:  # noqa: BLE001 - one bad drop-in must not abort scan
            logger.error("Failed to load %s file %s: %s", label, item, e)
            if on_error is not None:
                on_error(item, e)
            continue
        yield item, mod


__all__ = [
    "discovery_disabled",
    "resolve_dropin_dir",
    "get_entry_points",
    "iter_dropin_modules",
]
