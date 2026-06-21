"""Zero-config discovery of external (user-provided) analyzers.

This module makes custom analyzers discoverable *everywhere* — the Python API,
the CLI (live ``--scan`` and offline ``analyze``) and the TUI — without the user
having to re-pass ``--analyzer-path`` each time. It mirrors the discovery
patterns already used for full plugins in :mod:`friTap.plugins.loader`, but is
deliberately **Session-independent**: analyzers must be enumerable *before* any
capture starts (for ``--list-analyzers``, the offline analyze path and the TUI
analyzer panel at config time), so we do not route them through
``FriTapPlugin.on_load(session)``.

Three discovery sources are scanned:

1. A drop-in directory — ``<user-data>/friTap/analyzers/*.py`` (plus the legacy
   ``~/.fritap/analyzers/``). Classes that set ``is_fritap_analyzer = True`` are
   instantiated and registered by their ``.name``.
2. A setuptools entry-points group ``fritap.analyzers`` — third-party packages
   can ship analyzers that appear automatically once installed.
3. A bridge for existing :class:`~friTap.plugins.base.FriTapPlugin` authors:
   any plugin exposing the optional ``register_analyzers()`` hook contributes
   its analyzers here (called without a Session).

Security note — loading a ``.py`` file or an entry point *executes that code* at
import time, exactly like the existing plugin loader. Set
``FRITAP_DISABLE_ANALYZER_DISCOVERY=1`` to disable ambient discovery entirely
(restores the pre-discovery behaviour: built-ins + explicit ``--analyzer-path``
only).
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional, TYPE_CHECKING

from friTap import discovery_base

if TYPE_CHECKING:
    from friTap.analysis import BaseAnalyzer

logger = logging.getLogger("friTap.analysis.discovery")

ANALYZER_ENTRY_POINT_GROUP = "fritap.analyzers"
_DISABLE_ENV = "FRITAP_DISABLE_ANALYZER_DISCOVERY"


@dataclass
class DiscoveredAnalyzer:
    """An externally-discovered analyzer instance and where it came from."""

    instance: "BaseAnalyzer"
    source: str  # e.g. "dir:/path/to/file.py", "entrypoint:<name>", "plugin:<name>"


def discovery_disabled() -> bool:
    """True when ambient discovery is opted out via the environment."""
    return discovery_base.discovery_disabled(_DISABLE_ENV)


# ----------------------------------------------------------------------------
# Directory resolution
# ----------------------------------------------------------------------------

_ANALYZER_DIR: Optional[Path] = None


def _get_analyzer_dir() -> Path:
    """Return the resolved analyzers directory, lazily initializing on first call."""
    global _ANALYZER_DIR
    if _ANALYZER_DIR is None:
        _ANALYZER_DIR = discovery_base.resolve_dropin_dir(
            "analyzers", logger, label="analyzer")
    return _ANALYZER_DIR


def _get_analyzer_entry_points(**kwargs: str) -> list:
    """Return ``fritap.analyzers`` entry points, compatible with Python 3.9+."""
    return discovery_base.get_entry_points(ANALYZER_ENTRY_POINT_GROUP, **kwargs)


# ----------------------------------------------------------------------------
# Per-source loaders
# ----------------------------------------------------------------------------

def _coerce_instance(obj: object) -> "BaseAnalyzer | None":
    """Turn a class/factory/instance into a validated BaseAnalyzer, else None."""
    from friTap.analysis import BaseAnalyzer

    try:
        instance = obj() if isinstance(obj, type) else obj
    except Exception as e:  # noqa: BLE001 — one bad analyzer must not kill discovery
        logger.warning("Analyzer construction failed: %s", e)
        return None
    if not isinstance(instance, BaseAnalyzer):
        return None
    # A non-empty string name is required: discovered names are sorted and used
    # as dict keys, so a None/empty name would poison enumeration (e.g. crash
    # available_analyzers()/--list-analyzers) for every analyzer.
    name = getattr(instance, "name", None)
    if not isinstance(name, str) or not name:
        logger.warning("Discovered analyzer has invalid name %r; skipping", name)
        return None
    return instance


def _load_dir_analyzers(found: Dict[str, DiscoveredAnalyzer]) -> None:
    """Scan the analyzers directory for opt-in BaseAnalyzer classes."""
    from friTap.analysis.registry import _is_discoverable_analyzer

    for item, mod in discovery_base.iter_dropin_modules(
        _get_analyzer_dir(), "fritap_analyzer_", logger, label="analyzer",
    ):
        for attr_name in dir(mod):
            obj = getattr(mod, attr_name)
            if not _is_discoverable_analyzer(obj, mod):
                continue
            instance = _coerce_instance(obj)
            if instance is not None:
                found[instance.name] = DiscoveredAnalyzer(instance, f"dir:{item}")


def _load_entrypoint_analyzers(found: Dict[str, DiscoveredAnalyzer]) -> None:
    """Load analyzers advertised via the ``fritap.analyzers`` entry-points group."""
    try:
        entry_points = _get_analyzer_entry_points()
    except Exception as e:  # noqa: BLE001
        logger.error("Failed to enumerate analyzer entry points: %s", e)
        return

    for ep in entry_points:
        try:
            obj = ep.load()
        except Exception as e:  # noqa: BLE001
            logger.error("Failed to load analyzer entry point %s: %s", ep.name, e)
            continue
        instance = _coerce_instance(obj)
        if instance is not None:
            found[instance.name] = DiscoveredAnalyzer(instance, f"entrypoint:{ep.name}")


def _load_plugin_bridge_analyzers(found: Dict[str, DiscoveredAnalyzer]) -> None:
    """Collect analyzers exposed by FriTapPlugin authors via register_analyzers().

    This is Session-free: we instantiate plugin classes and call the optional
    ``register_analyzers()`` hook only. Plugins without the hook (the default)
    contribute nothing here.
    """
    try:
        from friTap.plugins.base import FriTapPlugin
        from friTap.plugins.loader import PluginLoader, _get_plugin_dir
    except Exception:  # pragma: no cover - plugins subsystem optional
        return

    plugin_classes: list[type] = []

    # Entry-point plugins
    try:
        for ep in PluginLoader._get_fritap_entry_points():
            try:
                cls = ep.load()
                if isinstance(cls, type) and issubclass(cls, FriTapPlugin):
                    plugin_classes.append(cls)
            except Exception as e:  # noqa: BLE001
                logger.error("Failed to load plugin entry point %s: %s", ep.name, e)
    except Exception:  # noqa: BLE001
        pass

    # File-based plugins (look for a top-level ``Plugin`` class, per loader convention)
    try:
        for _item, mod in discovery_base.iter_dropin_modules(
            _get_plugin_dir(), "fritap_plugin_", logger, label="plugin",
        ):
            cls = getattr(mod, "Plugin", None)
            if isinstance(cls, type) and issubclass(cls, FriTapPlugin):
                plugin_classes.append(cls)
    except Exception:  # noqa: BLE001
        pass

    for cls in plugin_classes:
        try:
            plugin = cls()
            analyzers = plugin.register_analyzers()
        except Exception as e:  # noqa: BLE001
            logger.error("Plugin %s register_analyzers() failed: %s", cls.__name__, e)
            continue
        for obj in analyzers or []:
            instance = _coerce_instance(obj)
            if instance is not None:
                source = f"plugin:{getattr(plugin, 'name', cls.__name__)}"
                found[instance.name] = DiscoveredAnalyzer(instance, source)


# ----------------------------------------------------------------------------
# Public API
# ----------------------------------------------------------------------------

_CACHE: Optional[Dict[str, DiscoveredAnalyzer]] = None
_CACHE_LOCK = threading.Lock()


def discover_external_analyzers(*, force: bool = False) -> Dict[str, DiscoveredAnalyzer]:
    """Discover external analyzers from all sources.

    Results are cached after the first call; pass ``force=True`` to re-scan
    (e.g. for a TUI "reload analyzers" action). Returns a mapping of analyzer
    ``.name`` -> :class:`DiscoveredAnalyzer`. Returns an empty mapping when
    discovery is disabled via ``FRITAP_DISABLE_ANALYZER_DISCOVERY``.

    Thread-safe: the scan + cache publish happen under a lock and the cache is
    only published once fully populated, so a concurrent caller never observes
    a partial result.
    """
    global _CACHE
    if discovery_disabled():
        return {}
    if _CACHE is not None and not force:
        return _CACHE

    with _CACHE_LOCK:
        if _CACHE is not None and not force:
            return _CACHE
        found: Dict[str, DiscoveredAnalyzer] = {}
        _load_dir_analyzers(found)
        _load_entrypoint_analyzers(found)
        _load_plugin_bridge_analyzers(found)
        _CACHE = found
        return found


def discovered_analyzer_names() -> list[str]:
    """Return the sorted names of all discovered external analyzers."""
    return sorted(discover_external_analyzers())
