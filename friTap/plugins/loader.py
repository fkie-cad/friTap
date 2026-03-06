#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Plugin discovery and loading."""

from __future__ import annotations
import importlib
import logging
from pathlib import Path
from typing import Dict, List, Optional, TYPE_CHECKING

import platformdirs

from .base import FriTapPlugin

if TYPE_CHECKING:
    from ..events import EventBus
    from .script_context import ScriptContext
    from .script_plugin import ScriptLoadOrder

logger = logging.getLogger("friTap.plugins")


def _resolve_plugin_dir() -> Path:
    """Resolve plugin directory with platform-native paths and legacy fallback.

    Platform paths:
      - Linux:   ~/.local/share/friTap/plugins/  (XDG)
      - macOS:   ~/Library/Application Support/friTap/plugins/
      - Windows: C:\\Users\\<user>\\AppData\\Local\\friTap\\plugins\\

    If the legacy ``~/.fritap/plugins/`` directory exists and the native
    path does not, the legacy location is used for backwards compatibility.
    """
    native_dir = Path(platformdirs.user_data_dir("friTap")) / "plugins"
    legacy_dir = Path.home() / ".fritap" / "plugins"

    # Prefer legacy if it exists and native doesn't (backwards compat)
    if legacy_dir.exists() and not native_dir.exists():
        return legacy_dir

    # Auto-create native directory
    try:
        native_dir.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        logger.warning("Could not create plugin directory %s: %s", native_dir, e)
    return native_dir


PLUGIN_DIR = _resolve_plugin_dir()


class PluginLoader:
    """Discovers and manages friTap plugins."""

    def __init__(self) -> None:
        self._plugins: Dict[str, FriTapPlugin] = {}

    @staticmethod
    def _get_fritap_entry_points(**kwargs: str) -> list:
        """Return fritap.plugins entry points, compatible with Python 3.9+."""
        eps = importlib.metadata.entry_points()
        if hasattr(eps, "select"):
            return list(eps.select(group="fritap.plugins", **kwargs))
        matches = eps.get("fritap.plugins", [])
        if kwargs.get("name"):
            matches = [ep for ep in matches if ep.name == kwargs["name"]]
        return list(matches)

    def _activate_plugin(self, plugin: FriTapPlugin, event_bus: "EventBus") -> None:
        """Call on_load, register, and log a loaded plugin."""
        plugin.on_load(event_bus)
        self._plugins[plugin.name] = plugin
        logger.info("Loaded plugin: %s v%s", plugin.name, plugin.version)

    def discover(self) -> List[str]:
        """Discover available plugins from all sources."""
        found = []

        # 1. Check plugin directory (auto-created at import; guard kept for safety)
        if PLUGIN_DIR.exists():
            for item in PLUGIN_DIR.iterdir():
                if item.suffix == ".py" and not item.name.startswith("_"):
                    found.append(f"file:{item}")

        # 2. Check Python entry points
        try:
            if hasattr(importlib.metadata, "entry_points"):
                for ep in self._get_fritap_entry_points():
                    found.append(f"entrypoint:{ep.name}")
        except Exception:
            pass

        return found

    def load_all(self, event_bus: "EventBus") -> None:
        """Load all discovered plugins."""
        for source in self.discover():
            try:
                self._load_plugin(source, event_bus)
            except Exception as e:
                logger.error("Failed to load plugin %s: %s", source, e)

    def _load_plugin(self, source: str, event_bus: "EventBus") -> None:
        """Load a single plugin from source descriptor."""
        if source.startswith("file:"):
            path = source[5:]
            spec = importlib.util.spec_from_file_location("fritap_plugin", path)
            if spec and spec.loader:
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                if hasattr(mod, "Plugin"):
                    plugin = mod.Plugin()
                    if isinstance(plugin, FriTapPlugin):
                        self._activate_plugin(plugin, event_bus)

        elif source.startswith("entrypoint:"):
            name = source[11:]
            for ep in self._get_fritap_entry_points(name=name):
                plugin_cls = ep.load()
                plugin = plugin_cls()
                if isinstance(plugin, FriTapPlugin):
                    self._activate_plugin(plugin, event_bus)

    def unload_all(self) -> None:
        """Unload all loaded plugins."""
        for name, plugin in self._plugins.items():
            try:
                plugin.on_unload()
                logger.info("Unloaded plugin: %s", name)
            except Exception as e:
                logger.error("Error unloading plugin %s: %s", name, e)
        self._plugins.clear()

    def get_plugin(self, name: str) -> FriTapPlugin | None:
        return self._plugins.get(name)

    def list_plugins(self) -> List[str]:
        return list(self._plugins.keys())

    # ------------------------------------------------------------------
    # ScriptPlugin support
    # ------------------------------------------------------------------

    def register_builtin(self, plugin: FriTapPlugin, event_bus: "EventBus") -> None:
        """Register a built-in plugin (not from file discovery).

        Calls ``on_load`` immediately and adds the plugin to the registry.
        """
        self._activate_plugin(plugin, event_bus)

    def check_backend_compatibility(self, backend_name: str) -> List[str]:
        """Return names of ScriptPlugins that won't work with the given backend."""
        return [p.name for p in self.get_script_plugins()
                if not p.is_compatible_with(backend_name)]

    def get_script_plugins(self, order: "Optional[ScriptLoadOrder]" = None) -> list:
        """Return ScriptPlugin instances, optionally filtered by load order.

        Results are sorted: BEFORE_MAIN first, then AFTER_MAIN.
        """
        from .script_plugin import ScriptPlugin, ScriptLoadOrder

        plugins = [p for p in self._plugins.values() if isinstance(p, ScriptPlugin)]

        if order is not None:
            plugins = [p for p in plugins if p.load_order == order]
        else:
            # Sort: BEFORE_MAIN (value="before") < AFTER_MAIN (value="after")
            plugins.sort(key=lambda p: 0 if p.load_order == ScriptLoadOrder.BEFORE_MAIN else 1)
        return plugins

    def instrument_all(
        self,
        context: "ScriptContext",
        order: "Optional[ScriptLoadOrder]" = None,
    ) -> None:
        """Invoke ``on_instrument()`` on matching ScriptPlugins.

        Failures in individual plugins are logged but do not block others.
        """
        for plugin in self.get_script_plugins(order=order):
            try:
                plugin.on_instrument(context)
            except Exception as e:
                logger.error(
                    "Plugin %s failed during instrument: %s", plugin.name, e,
                    exc_info=True,
                )

    def detach_all(self, context: "ScriptContext") -> None:
        """Invoke ``on_detach_process()`` on all ScriptPlugins."""
        from .script_plugin import ScriptPlugin

        for plugin in self._plugins.values():
            if isinstance(plugin, ScriptPlugin):
                try:
                    plugin.on_detach_process(context)
                except Exception as e:
                    logger.error(
                        "Plugin %s failed during detach: %s", plugin.name, e,
                        exc_info=True,
                    )
