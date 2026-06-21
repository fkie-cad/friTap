"""Zero-config discovery of external (user-provided/plugin) offline decryptors.

This module makes custom :class:`~friTap.offline.registry.OfflineDecryptorEntry`
declarations discoverable without the user having to wire them in by hand,
mirroring the analyzer-discovery model in :mod:`friTap.analysis.discovery`. A
discovered decryptor is *registered into the process-global registry*
(:func:`~friTap.offline.registry.register_offline_decryptor`), so it then gets
the offline pipeline, the generated ``--<proto>-keylog`` CLI flag and the
layered flow view exactly like a built-in.

Two discovery sources are scanned:

1. A drop-in directory — ``<user-data>/friTap/offline_decryptors/*.py`` (plus
   the legacy ``~/.fritap/offline_decryptors/``).
2. A setuptools entry-points group ``fritap.offline_decryptors`` — third-party
   packages can ship decryptors that appear automatically once installed.

The discoverable unit is a *module* that sets the module-level marker
``is_fritap_offline_decryptor = True``. From such a module every module-level
value that is an :class:`OfflineDecryptorEntry` instance is collected and
registered. The marker lives on the module (not on the frozen entry instance,
which cannot carry extra attributes).

Security note — loading a ``.py`` file or an entry point *executes that code* at
import time, exactly like the plugin/analyzer loaders. Set
``FRITAP_DISABLE_OFFLINE_DECRYPTOR_DISCOVERY=1`` to disable ambient discovery
entirely (built-ins + explicit registration only).
"""

from __future__ import annotations

import logging
import threading
from pathlib import Path
from types import ModuleType
from typing import Dict, Optional

from friTap import discovery_base
from friTap.offline.registry import (
    OFFLINE_DECRYPTOR_DISCOVERY_DISABLE_ENV,
    OFFLINE_DECRYPTOR_ENTRYPOINT_GROUP,
    OFFLINE_DECRYPTOR_MARKER_ATTR,
    OfflineDecryptorEntry,
    register_offline_decryptor,
)

logger = logging.getLogger("friTap.offline.discovery")


def discovery_disabled() -> bool:
    """True when ambient offline-decryptor discovery is opted out via the environment."""
    return discovery_base.discovery_disabled(OFFLINE_DECRYPTOR_DISCOVERY_DISABLE_ENV)


# ----------------------------------------------------------------------------
# Directory resolution
# ----------------------------------------------------------------------------

_OFFLINE_DECRYPTOR_DIR: Optional[Path] = None


def _get_offline_decryptor_dir() -> Path:
    """Return the resolved offline-decryptors directory, lazily initialized."""
    global _OFFLINE_DECRYPTOR_DIR
    if _OFFLINE_DECRYPTOR_DIR is None:
        _OFFLINE_DECRYPTOR_DIR = discovery_base.resolve_dropin_dir(
            "offline_decryptors", logger, label="offline-decryptor")
    return _OFFLINE_DECRYPTOR_DIR


def _get_offline_decryptor_entry_points(**kwargs: str) -> list:
    """Return ``fritap.offline_decryptors`` entry points, compatible with Python 3.9+."""
    return discovery_base.get_entry_points(OFFLINE_DECRYPTOR_ENTRYPOINT_GROUP, **kwargs)


# ----------------------------------------------------------------------------
# Module inspection / registration
# ----------------------------------------------------------------------------

def _module_is_offline_decryptor(mod: ModuleType) -> bool:
    """True when *mod* opts in via the module-level discovery marker."""
    return bool(getattr(mod, OFFLINE_DECRYPTOR_MARKER_ATTR, False))


def _register_module_entries(mod: ModuleType, source: str, found: Dict[str, str]) -> None:
    """Register every module-level OfflineDecryptorEntry found in *mod*.

    A bad single registration is logged and skipped — it must never abort
    discovery of the rest.
    """
    if not _module_is_offline_decryptor(mod):
        return
    for attr_name in dir(mod):
        try:
            obj = getattr(mod, attr_name)
        except Exception as e:  # noqa: BLE001 — defensive: descriptor side effects
            logger.warning("Could not read attribute %s from %s: %s", attr_name, source, e)
            continue
        if not isinstance(obj, OfflineDecryptorEntry):
            continue
        try:
            register_offline_decryptor(obj)
            found[obj.protocol_name] = source
        except Exception as e:  # noqa: BLE001 — one bad entry must not kill discovery
            logger.warning(
                "Failed to register offline decryptor %r from %s: %s",
                getattr(obj, "protocol_name", "<unknown>"),
                source,
                e,
            )


# ----------------------------------------------------------------------------
# Per-source loaders
# ----------------------------------------------------------------------------

def _load_dir_decryptors(found: Dict[str, str]) -> None:
    """Scan the drop-in directory for opt-in offline-decryptor modules."""
    for item, mod in discovery_base.iter_dropin_modules(
        _get_offline_decryptor_dir(), "fritap_offline_decryptor_", logger,
        label="offline-decryptor",
    ):
        _register_module_entries(mod, f"dir:{item}", found)


def _load_entrypoint_decryptors(found: Dict[str, str]) -> None:
    """Load decryptors advertised via the ``fritap.offline_decryptors`` group."""
    try:
        entry_points = _get_offline_decryptor_entry_points()
    except Exception as e:  # noqa: BLE001
        logger.error("Failed to enumerate offline-decryptor entry points: %s", e)
        return

    for ep in entry_points:
        try:
            obj = ep.load()
        except Exception as e:  # noqa: BLE001
            logger.error("Failed to load offline-decryptor entry point %s: %s", ep.name, e)
            continue
        if isinstance(obj, ModuleType):
            _register_module_entries(obj, f"entrypoint:{ep.name}", found)
            continue
        # The entry point may resolve directly to an OfflineDecryptorEntry; accept
        # that too (the entry point itself is the opt-in here).
        if isinstance(obj, OfflineDecryptorEntry):
            try:
                register_offline_decryptor(obj)
                found[obj.protocol_name] = f"entrypoint:{ep.name}"
            except Exception as e:  # noqa: BLE001
                logger.warning(
                    "Failed to register offline decryptor from entry point %s: %s",
                    ep.name,
                    e,
                )


# ----------------------------------------------------------------------------
# Public API
# ----------------------------------------------------------------------------

_DISCOVERED: Optional[Dict[str, str]] = None
_DISCOVERED_LOCK = threading.Lock()


def discover_external_offline_decryptors(*, force: bool = False) -> Dict[str, str]:
    """Discover and register external offline decryptors from all sources.

    Scans the drop-in directory and the ``fritap.offline_decryptors`` entry-point
    group, registering every discovered :class:`OfflineDecryptorEntry` into the
    process-global registry. Returns a mapping of ``protocol_name`` -> source
    string (e.g. ``"dir:/path/file.py"`` or ``"entrypoint:<name>"``) for what was
    registered. Returns an empty mapping when discovery is disabled via
    ``FRITAP_DISABLE_OFFLINE_DECRYPTOR_DISCOVERY``.

    Results are cached after the first call; pass ``force=True`` to re-scan.
    Re-registration is idempotent in the registry, so re-runs are safe.

    Thread-safe: the scan + cache publish happen under a lock and the cache is
    only published once fully populated, so a concurrent caller never observes a
    partial result.
    """
    global _DISCOVERED
    if discovery_disabled():
        return {}
    if _DISCOVERED is not None and not force:
        return _DISCOVERED

    with _DISCOVERED_LOCK:
        if _DISCOVERED is not None and not force:
            return _DISCOVERED
        found: Dict[str, str] = {}
        _load_dir_decryptors(found)
        _load_entrypoint_decryptors(found)
        _DISCOVERED = found
        return found


def discovered_offline_decryptor_names() -> list[str]:
    """Return the sorted protocol names of all discovered external decryptors."""
    return sorted(discover_external_offline_decryptors())


__all__ = [
    "discover_external_offline_decryptors",
    "discovered_offline_decryptor_names",
    "discovery_disabled",
]
