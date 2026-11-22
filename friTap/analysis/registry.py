"""Analyzer registry: maps each analyzer's ``.name`` to a factory.

Decouples CLI / live-scan wiring from concrete analyzer classes. Concrete
imports stay lazy (inside the factories) to keep this module import-light and
free of cycles with ``friTap.analysis``.

Usage::

    from friTap.analysis.registry import resolve_analyzers

    analyzers = resolve_analyzers("credentials,ioc")
    analyzers = resolve_analyzers(None)            # all built-ins
    analyzers = resolve_analyzers("all", include_private_ips=True)
"""

from __future__ import annotations

import importlib
import logging
import threading
from typing import TYPE_CHECKING, Callable

logger = logging.getLogger("friTap.analysis.registry")

if TYPE_CHECKING:
    from friTap.analysis import BaseAnalyzer


def _make_ioc(*, include_private_ips: bool = False, **_ignored) -> "BaseAnalyzer":
    """Factory for IocAnalyzer."""
    from friTap.analysis.ioc import IocAnalyzer
    return IocAnalyzer(include_private_ips=include_private_ips)


def _make_credentials(**_ignored) -> "BaseAnalyzer":
    """Factory for CredentialAnalyzer."""
    from friTap.analysis.credentials import CredentialAnalyzer
    return CredentialAnalyzer()


def _make_protobuf(*, protobuf_schema: str | None = None, **_ignored) -> "BaseAnalyzer":
    """Factory for ProtobufAnalyzer."""
    from friTap.analysis.protobuf_analyzer import ProtobufAnalyzer
    return ProtobufAnalyzer(schema_path=protobuf_schema)


def _make_privacy(*, reveal_pii: bool = False, verbose: bool = False, **_ignored) -> "BaseAnalyzer":
    """Factory for PrivacyAnalyzer."""
    from friTap.analysis.privacy import PrivacyAnalyzer
    return PrivacyAnalyzer(reveal_pii=reveal_pii, verbose=verbose)


def _make_tls_hygiene(**_ignored) -> "BaseAnalyzer":
    """Factory for TlsHygieneAnalyzer."""
    from friTap.analysis.security import TlsHygieneAnalyzer
    return TlsHygieneAnalyzer()


def _make_applovin_mediate(
    *,
    reveal_pii: bool = False,
    applovin_sdk_keys=(),
    applovin_salts=(),
    app_bundles=(),
    **_ignored,
) -> "BaseAnalyzer":
    """Factory for AppLovinMediateAnalyzer (key material from CLI, else env vars)."""
    from friTap.analysis.applovin_mediate import AppLovinMediateAnalyzer
    return AppLovinMediateAnalyzer(
        sdk_keys=applovin_sdk_keys or (),
        salts_hex=applovin_salts or (),
        bundle_paths=app_bundles or (),
        reveal_pii=reveal_pii,
    )


# Keys must equal each analyzer class's ``.name``.
ANALYZER_REGISTRY: dict[str, Callable[..., "BaseAnalyzer"]] = {
    "ioc": _make_ioc,
    "credentials": _make_credentials,
    "privacy": _make_privacy,
    "protobuf": _make_protobuf,
    "tls_hygiene": _make_tls_hygiene,
    "applovin_mediate": _make_applovin_mediate,
}


# Externally discovered analyzers (drop-in dir / entry points / plugin bridge),
# kept apart from ANALYZER_REGISTRY. Each value returns the discovered instance.
_DISCOVERED: dict[str, Callable[..., "BaseAnalyzer"]] = {}
_DISCOVERY_DONE = False
# Reentrant so refresh_discovered() can call _ensure_discovered() while held.
_DISCOVERY_LOCK = threading.RLock()


def register_analyzer(name: str, factory: Callable[..., "BaseAnalyzer"]) -> None:
    """Register an analyzer factory by name (discovery layer and embedders).

    The analyzer becomes selectable in :func:`resolve_analyzers` and listed by
    :func:`available_analyzers`. A name colliding with a built-in logs a warning
    and the built-in wins.
    """
    if name in ANALYZER_REGISTRY:
        logger.warning(
            "analyzer %r collides with a built-in analyzer; the built-in is used", name)
    _DISCOVERED[name] = factory


def _const_factory(instance: "BaseAnalyzer") -> Callable[..., "BaseAnalyzer"]:
    """Wrap an already-constructed analyzer as a factory ignoring its kwargs."""
    def factory(**_ignored) -> "BaseAnalyzer":
        return instance
    return factory


def _ensure_discovered() -> None:
    """Run external-analyzer discovery once and populate ``_DISCOVERED``.

    Thread-safe (double-checked lock); the done-flag is set only after
    ``_DISCOVERED`` is complete so readers never see a partial set.
    """
    global _DISCOVERY_DONE
    if _DISCOVERY_DONE:
        return
    with _DISCOVERY_LOCK:
        if _DISCOVERY_DONE:
            return
        try:
            from friTap.analysis.discovery import discover_external_analyzers
            discovered = discover_external_analyzers()
        except Exception:  # pragma: no cover - never let discovery break resolution
            _DISCOVERY_DONE = True  # best-effort once
            return
        for name, found in discovered.items():
            if name in ANALYZER_REGISTRY:
                continue  # built-ins are never shadowed
            _DISCOVERED.setdefault(name, _const_factory(found.instance))
        _DISCOVERY_DONE = True


def refresh_discovered() -> None:
    """Re-scan external analyzers (TUI reload)."""
    global _DISCOVERY_DONE
    from friTap.analysis.discovery import discover_external_analyzers

    with _DISCOVERY_LOCK:
        _DISCOVERED.clear()
        _DISCOVERY_DONE = False
        discover_external_analyzers(force=True)
        _ensure_discovered()  # RLock allows re-acquire


def available_analyzers() -> list[str]:
    """Sorted built-in and discovered analyzer names."""
    _ensure_discovered()
    return sorted(set(ANALYZER_REGISTRY) | set(_DISCOVERED))


def _build(name: str, **opts) -> "BaseAnalyzer":
    """Instantiate a registered analyzer; ValueError on an unknown name."""
    factory = ANALYZER_REGISTRY.get(name) or _DISCOVERED.get(name)
    if factory is None:
        available = ", ".join(available_analyzers())
        raise ValueError(
            f"Unknown analyzer '{name}'. Available analyzers: {available}"
        )
    return factory(**opts)


# Opt-in marker for bare-``module`` auto-discovery: the runtime_checkable
# BaseAnalyzer protocol only checks attribute presence, so unrelated duck-typed
# classes would otherwise be instantiated.
ANALYZER_MARKER_ATTR = "is_fritap_analyzer"


def _is_discoverable_analyzer(obj: object, module) -> bool:
    """True for a class defined in *module* (not re-exported) and marked ``is_fritap_analyzer``."""
    if not isinstance(obj, type):
        return False
    if getattr(obj, "__module__", None) != module.__name__:
        return False
    return bool(getattr(obj, ANALYZER_MARKER_ATTR, False))


def _load_external_analyzers(analyzer_path: str) -> dict[str, "BaseAnalyzer"]:
    """Import an external ``module`` or ``module:Class`` and return ``.name`` -> instance.

    ``module:Class`` (preferred) only needs to satisfy :class:`BaseAnalyzer`; a bare
    module yields only classes defined in it with ``is_fritap_analyzer = True``.
    """
    from friTap.analysis import BaseAnalyzer

    module_name, _, class_name = analyzer_path.partition(":")
    module = importlib.import_module(module_name)

    found: dict[str, "BaseAnalyzer"] = {}
    if class_name:
        obj = getattr(module, class_name)
        instance = obj() if isinstance(obj, type) else obj
        if not isinstance(instance, BaseAnalyzer):
            raise ValueError(
                f"'{analyzer_path}' does not implement the BaseAnalyzer protocol"
            )
        found[instance.name] = instance
        return found

    for attr_name in dir(module):
        obj = getattr(module, attr_name)
        if not _is_discoverable_analyzer(obj, module):
            continue
        try:
            candidate = obj()
        except Exception:
            continue
        if isinstance(candidate, BaseAnalyzer):
            found[candidate.name] = candidate

    if not found:
        raise ValueError(
            f"No BaseAnalyzer implementations found in '{analyzer_path}'. "
            f"External analyzer classes must set '{ANALYZER_MARKER_ATTR} = True' "
            f"or be referenced explicitly as 'module:Class'."
        )
    return found


def resolve_analyzers(
    spec: str | None,
    *,
    analyzer_path: "str | list[str] | None" = None,
    **opts,
) -> list["BaseAnalyzer"]:
    """Resolve an analyzer *spec* into analyzer instances.

    *spec*: ``None``, ``"all"`` or ``""`` selects every available analyzer;
    otherwise comma-separated analyzer names.
    *analyzer_path*: ``"module"`` / ``"module:Class"`` (or a list) loaded for this
    call; these win over discovered analyzers of the same name.
    **opts are forwarded to the factories (e.g. ``include_private_ips``,
    ``protobuf_schema``, ``applovin_sdk_keys``/``applovin_salts``/``app_bundles``);
    unknown options are ignored.

    Raises ValueError for an unregistered name.
    """
    _ensure_discovered()  # so "all" and explicit names pick up user analyzers

    paths = [analyzer_path] if isinstance(analyzer_path, str) else (analyzer_path or [])
    external: dict[str, "BaseAnalyzer"] = {}
    for path in paths:
        if path:
            external.update(_load_external_analyzers(path))

    select_all = spec is None or spec in ("all", "")
    if select_all:
        names = list(available_analyzers())
        names += [n for n in external if n not in names]
    else:
        names = [n.strip() for n in spec.split(",") if n.strip()]

    analyzers: list["BaseAnalyzer"] = []
    for name in names:
        if name in external:
            analyzers.append(external[name])
        else:
            analyzers.append(_build(name, **opts))
    return analyzers


__all__ = [
    "ANALYZER_REGISTRY",
    "available_analyzers",
    "resolve_analyzers",
    "register_analyzer",
    "refresh_discovered",
]
