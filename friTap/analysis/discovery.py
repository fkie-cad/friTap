"""Zero-config discovery of external (user-provided) analyzers.

Makes custom analyzers available in the Python API, CLI and TUI without
re-passing ``--analyzer-path``. Mirrors :mod:`friTap.plugins.loader` but is
Session-independent: analyzers must be enumerable before any capture starts
(``--list-analyzers``, offline analyze, TUI config), so they bypass
``FriTapPlugin.on_load(session)``.

Sources:

1. Drop-in directory ``<user-data>/friTap/analyzers/*.py`` (and the legacy
   ``~/.fritap/analyzers/``): classes with ``is_fritap_analyzer = True``.
2. Entry-points group ``fritap.analyzers``.
3. ``FriTapPlugin.register_analyzers()``, called without a Session.

Security: loading a ``.py`` file or entry point executes that code at import,
like the plugin loader. ``FRITAP_DISABLE_ANALYZER_DISCOVERY=1`` disables ambient
discovery (built-ins and explicit ``--analyzer-path`` only).
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Dict, Optional

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


_ANALYZER_DIR: Optional[Path] = None


def _get_analyzer_dir() -> Path:
    """The analyzers directory, resolved lazily."""
    global _ANALYZER_DIR
    if _ANALYZER_DIR is None:
        _ANALYZER_DIR = discovery_base.resolve_dropin_dir(
            "analyzers", logger, label="analyzer")
    return _ANALYZER_DIR


def _get_analyzer_entry_points(**kwargs: str) -> list:
    """``fritap.analyzers`` entry points (Python 3.9+ compatible)."""
    return discovery_base.get_entry_points(ANALYZER_ENTRY_POINT_GROUP, **kwargs)


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
    # A non-string/empty name would break sorting and dict keys in
    # available_analyzers()/--list-analyzers for every analyzer.
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
    """Collect analyzers from FriTapPlugin.register_analyzers(); Session-free, hook only."""
    try:
        from friTap.plugins.base import FriTapPlugin
        from friTap.plugins.loader import PluginLoader, _get_plugin_dir
    except Exception:  # pragma: no cover - plugins subsystem optional
        return

    plugin_classes: list[type] = []

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

    # File-based plugins: top-level ``Plugin`` class, per loader convention
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


_CACHE: Optional[Dict[str, DiscoveredAnalyzer]] = None
_CACHE_LOCK = threading.Lock()


def discover_external_analyzers(*, force: bool = False) -> Dict[str, DiscoveredAnalyzer]:
    """Discover external analyzers from all sources: ``.name`` -> :class:`DiscoveredAnalyzer`.

    Cached after the first call (``force=True`` re-scans); empty when discovery
    is disabled. Thread-safe: the cache is published only once fully populated.
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
    """Sorted names of discovered external analyzers."""
    return sorted(discover_external_analyzers())
