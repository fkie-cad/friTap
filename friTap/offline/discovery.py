"""Discovery of external (plugin) offline decryptors.

Sources: the drop-in directory ``<user-data>/friTap/offline_decryptors/*.py``
(fallback ``~/.fritap/offline_decryptors/``) and the entry-point group
``fritap.offline_decryptors``. A discoverable module sets
``is_fritap_offline_decryptor = True``; every module-level
:class:`~friTap.offline.registry.OfflineDecryptorEntry` in it is registered
globally (the marker lives on the module because entries are frozen). An entry
point may also resolve directly to an entry. Per-source failures never abort
discovery; they are logged and exposed via :func:`offline_discovery_errors`.

Security: loading a drop-in or entry point executes its code. Set
``FRITAP_DISABLE_OFFLINE_DECRYPTOR_DISCOVERY=1`` to disable discovery.
"""
from __future__ import annotations

import logging
import threading
from pathlib import Path
from types import ModuleType
from typing import Dict, Optional, Tuple

from friTap import discovery_base
from friTap.offline.registry import (
    OFFLINE_DECRYPTOR_DISCOVERY_DISABLE_ENV,
    OFFLINE_DECRYPTOR_ENTRYPOINT_GROUP,
    OFFLINE_DECRYPTOR_MARKER_ATTR,
    OfflineDecryptorEntry,
    register_offline_decryptor,
)

logger = logging.getLogger("friTap.offline.discovery")

# Working buffer of the scan in progress. Only the scan in
# ``discover_external_offline_decryptors`` (which holds ``_DISCOVERED_LOCK``)
# fills and drains it; the per-source loaders keep their ``(found)`` signature.
_SCAN_ERRORS: list[Tuple[str, str]] = []


def _record_error(source: str, error: BaseException) -> None:
    """Collect one per-source failure as ``(source, "<Type>: <message>")``."""
    _SCAN_ERRORS.append((source, f"{type(error).__name__}: {error}"))


def discovery_disabled() -> bool:
    """True when ambient offline-decryptor discovery is opted out via the environment."""
    return discovery_base.discovery_disabled(OFFLINE_DECRYPTOR_DISCOVERY_DISABLE_ENV)


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


def _module_is_offline_decryptor(mod: ModuleType) -> bool:
    """True when *mod* opts in via the module-level discovery marker."""
    return bool(getattr(mod, OFFLINE_DECRYPTOR_MARKER_ATTR, False))


def _register_module_entries(mod: ModuleType, source: str, found: Dict[str, str]) -> None:
    """Register every module-level OfflineDecryptorEntry in an opted-in *mod*; a failing one is skipped."""
    if not _module_is_offline_decryptor(mod):
        return
    for attr_name in dir(mod):
        try:
            obj = getattr(mod, attr_name)
        except Exception as e:  # noqa: BLE001 - descriptor side effects
            logger.warning("Could not read attribute %s from %s: %s", attr_name, source, e)
            _record_error(source, e)
            continue
        if not isinstance(obj, OfflineDecryptorEntry):
            continue
        try:
            register_offline_decryptor(obj)
            found[obj.protocol_name] = source
        except Exception as e:  # noqa: BLE001 - one bad entry must not stop discovery
            logger.warning(
                "Failed to register offline decryptor %r from %s: %s",
                getattr(obj, "protocol_name", "<unknown>"),
                source,
                e,
            )
            _record_error(source, e)


def _record_dropin_failure(path: Path, error: BaseException) -> None:
    """Collect a drop-in file that failed to import (already logged by the loader)."""
    _record_error(f"dir:{path}", error)


def _load_dir_decryptors(found: Dict[str, str]) -> None:
    """Scan the drop-in directory for opt-in offline-decryptor modules."""
    for item, mod in discovery_base.iter_dropin_modules(
        _get_offline_decryptor_dir(), "fritap_offline_decryptor_", logger,
        label="offline-decryptor", on_error=_record_dropin_failure,
    ):
        _register_module_entries(mod, f"dir:{item}", found)


def _load_entrypoint_decryptors(found: Dict[str, str]) -> None:
    """Load decryptors advertised via the ``fritap.offline_decryptors`` group."""
    try:
        entry_points = _get_offline_decryptor_entry_points()
    except Exception as e:  # noqa: BLE001
        logger.error("Failed to enumerate offline-decryptor entry points: %s", e)
        _record_error("entrypoints", e)
        return

    for ep in entry_points:
        try:
            obj = ep.load()
        except Exception as e:  # noqa: BLE001
            logger.error("Failed to load offline-decryptor entry point %s: %s", ep.name, e)
            _record_error(f"entrypoint:{ep.name}", e)
            continue
        if isinstance(obj, ModuleType):
            _register_module_entries(obj, f"entrypoint:{ep.name}", found)
            continue
        # An entry point resolving directly to an entry is its own opt-in.
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
                _record_error(f"entrypoint:{ep.name}", e)


_DISCOVERED: Optional[Dict[str, str]] = None
# ``(source, error)`` pairs of the scan that produced ``_DISCOVERED``; replaced as
# a whole (immutable tuple) together with it, so readers need no lock.
_DISCOVERY_ERRORS: Tuple[Tuple[str, str], ...] = ()
_DISCOVERED_LOCK = threading.Lock()


def discover_external_offline_decryptors(*, force: bool = False) -> Dict[str, str]:
    """Discover and register external offline decryptors from all sources.

    Returns ``protocol_name`` -> source (``"dir:<file>"`` / ``"entrypoint:<name>"``),
    or ``{}`` when discovery is disabled. Cached after the first call; ``force``
    re-scans. The cache is published under a lock only once fully populated, so
    concurrent callers never see a partial result.
    """
    global _DISCOVERED, _DISCOVERY_ERRORS
    if discovery_disabled():
        return {}
    if _DISCOVERED is not None and not force:
        return _DISCOVERED

    with _DISCOVERED_LOCK:
        if _DISCOVERED is not None and not force:
            return _DISCOVERED
        found: Dict[str, str] = {}
        _SCAN_ERRORS.clear()
        try:
            _load_dir_decryptors(found)
            _load_entrypoint_decryptors(found)
            _DISCOVERY_ERRORS = tuple(_SCAN_ERRORS)
        finally:
            _SCAN_ERRORS.clear()
        _DISCOVERED = found
        return found


def offline_discovery_errors() -> list[Tuple[str, str]]:
    """Return the ``(source, "<Type>: <message>")`` failures of the last scan.

    *source* is ``"dir:<file>"``, ``"entrypoint:<name>"`` or ``"entrypoints"``
    (enumeration failed). Never triggers a scan; empty while disabled.
    """
    if discovery_disabled():
        return []
    return list(_DISCOVERY_ERRORS)


def discovered_offline_decryptor_names() -> list[str]:
    """Return the sorted protocol names of all discovered external decryptors."""
    return sorted(discover_external_offline_decryptors())


__all__ = [
    "discover_external_offline_decryptors",
    "discovered_offline_decryptor_names",
    "discovery_disabled",
    "offline_discovery_errors",
]
