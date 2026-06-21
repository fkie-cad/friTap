"""
Analyzer registry — resolve analyzer names to BaseAnalyzer instances.

The registry maps short, user-facing names (the same string as each
analyzer's ``.name`` attribute) to zero-argument factories. This keeps the
CLI / live-scan wiring decoupled from the concrete analyzer classes and gives
a single place to register new built-in analyzers.

Usage::

    from friTap.analysis.registry import resolve_analyzers

    analyzers = resolve_analyzers("credentials,ioc")
    analyzers = resolve_analyzers(None)            # all built-ins
    analyzers = resolve_analyzers("all", include_private_ips=True)

Imports of the concrete analyzers are kept lazy (inside the factories) so this
module stays import-light and free of import cycles with ``friTap.analysis``.
"""

from __future__ import annotations

import importlib
import threading
from typing import Callable, TYPE_CHECKING

if TYPE_CHECKING:
    from friTap.analysis import BaseAnalyzer


def _make_ioc(*, include_private_ips: bool = False, **_ignored) -> "BaseAnalyzer":
    """Factory for IocAnalyzer (accepts the include_private_ips passthrough)."""
    from friTap.analysis.ioc import IocAnalyzer
    return IocAnalyzer(include_private_ips=include_private_ips)


def _make_credentials(**_ignored) -> "BaseAnalyzer":
    """Factory for CredentialAnalyzer (takes no configuration)."""
    from friTap.analysis.credentials import CredentialAnalyzer
    return CredentialAnalyzer()


def _make_protobuf(*, protobuf_schema: str | None = None, **_ignored) -> "BaseAnalyzer":
    """Factory for ProtobufAnalyzer (accepts an optional schema path)."""
    from friTap.analysis.protobuf_analyzer import ProtobufAnalyzer
    return ProtobufAnalyzer(schema_path=protobuf_schema)


def _make_privacy(*, reveal_pii: bool = False, verbose: bool = False, **_ignored) -> "BaseAnalyzer":
    """Factory for PrivacyAnalyzer (accepts reveal_pii / verbose passthroughs)."""
    from friTap.analysis.privacy import PrivacyAnalyzer
    return PrivacyAnalyzer(reveal_pii=reveal_pii, verbose=verbose)


# Name -> factory. Keys MUST equal each analyzer class's ``.name`` attribute.
ANALYZER_REGISTRY: dict[str, Callable[..., "BaseAnalyzer"]] = {
    "ioc": _make_ioc,
    "credentials": _make_credentials,
    "privacy": _make_privacy,
    "protobuf": _make_protobuf,
}


# Externally-discovered analyzers (drop-in dir / entry points / plugin bridge).
# Kept separate from ANALYZER_REGISTRY so an empty discovery is byte-for-byte
# identical to the pre-discovery behaviour. Each value is a zero-config factory
# that returns the already-constructed discovered instance.
_DISCOVERED: dict[str, Callable[..., "BaseAnalyzer"]] = {}
_DISCOVERY_DONE = False
# Reentrant so refresh_discovered() can call _ensure_discovered() while held.
_DISCOVERY_LOCK = threading.RLock()


def register_analyzer(name: str, factory: Callable[..., "BaseAnalyzer"]) -> None:
    """Register an analyzer factory by name.

    Used by the discovery layer (and any embedder) to add analyzers that then
    become selectable by *spec* in :func:`resolve_analyzers`, listable via
    :func:`available_analyzers`, and visible to the CLI / TUI — without editing
    :data:`ANALYZER_REGISTRY`.
    """
    _DISCOVERED[name] = factory


def _const_factory(instance: "BaseAnalyzer") -> Callable[..., "BaseAnalyzer"]:
    """Wrap an already-constructed analyzer as a factory ignoring its kwargs."""
    def factory(**_ignored) -> "BaseAnalyzer":
        return instance
    return factory


def _ensure_discovered() -> None:
    """Lazily run external-analyzer discovery once and populate ``_DISCOVERED``.

    Thread-safe: guarded by a lock with double-checked ``_DISCOVERY_DONE``, and
    the done-flag is published only *after* ``_DISCOVERED`` is fully populated
    so a concurrent reader never observes an empty/partial set.
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
            _DISCOVERY_DONE = True  # best-effort once; don't retry every call
            return
        for name, found in discovered.items():
            if name in ANALYZER_REGISTRY:
                # Never let an external analyzer shadow a built-in name.
                continue
            _DISCOVERED.setdefault(name, _const_factory(found.instance))
        _DISCOVERY_DONE = True


def refresh_discovered() -> None:
    """Force a re-scan of external analyzers (e.g. a TUI 'reload' action)."""
    global _DISCOVERY_DONE
    from friTap.analysis.discovery import discover_external_analyzers

    with _DISCOVERY_LOCK:
        _DISCOVERED.clear()
        _DISCOVERY_DONE = False
        discover_external_analyzers(force=True)
        _ensure_discovered()  # reentrant: RLock allows re-acquire on this thread


def available_analyzers() -> list[str]:
    """Return the sorted list of available analyzer names (built-in + discovered)."""
    _ensure_discovered()
    return sorted(set(ANALYZER_REGISTRY) | set(_DISCOVERED))


def _build(name: str, **opts) -> "BaseAnalyzer":
    """Instantiate a registered analyzer by name, raising on unknown names."""
    factory = ANALYZER_REGISTRY.get(name) or _DISCOVERED.get(name)
    if factory is None:
        available = ", ".join(available_analyzers())
        raise ValueError(
            f"Unknown analyzer '{name}'. Available analyzers: {available}"
        )
    return factory(**opts)


# Explicit opt-in marker an external analyzer class must set to be auto-discovered
# from a bare ``module`` reference. This stops the registry from blindly
# instantiating every class in the module (#7) — the runtime_checkable
# BaseAnalyzer protocol only checks attribute presence, so unrelated/imported
# duck-typed classes would otherwise be accepted and constructed.
ANALYZER_MARKER_ATTR = "is_fritap_analyzer"


def _is_discoverable_analyzer(obj: object, module) -> bool:
    """True if *obj* is a class an external module opts in to auto-discovery.

    Requires the class to be (a) defined in *module* itself (not merely imported
    into its namespace) and (b) explicitly marked via ``is_fritap_analyzer``.
    """
    if not isinstance(obj, type):
        return False
    # Only consider classes actually defined in this module, not re-exports.
    if getattr(obj, "__module__", None) != module.__name__:
        return False
    # Require the explicit opt-in marker rather than relying on duck typing.
    return bool(getattr(obj, ANALYZER_MARKER_ATTR, False))


def _load_external_analyzers(analyzer_path: str) -> dict[str, "BaseAnalyzer"]:
    """Import an external module (or ``module:Class``) and collect analyzers.

    Returns a mapping of ``.name`` -> instance. The explicit ``module:Class``
    form is preferred: the named class is instantiated and registered by its
    ``.name`` (only requiring it to satisfy the :class:`BaseAnalyzer` protocol).

    For a bare ``module`` reference, auto-discovery is restricted to classes
    *defined in that module* that explicitly opt in via the
    ``is_fritap_analyzer = True`` class attribute (#7) — we no longer
    instantiate every class in the module.
    """
    from friTap.analysis import BaseAnalyzer

    module_name, _, class_name = analyzer_path.partition(":")
    module = importlib.import_module(module_name)

    found: dict[str, "BaseAnalyzer"] = {}
    if class_name:
        # Explicit class reference: trust the caller, only verify the protocol.
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
    """Resolve an analyzer *spec* into a list of analyzer instances.

    Args:
        spec: ``None``, ``"all"`` or ``""`` selects every available analyzer
            (built-ins plus any auto-discovered external analyzers). Otherwise a
            comma-separated list of analyzer names (matching each analyzer's
            ``.name``).
        analyzer_path: Optional explicit ``"module"`` or ``"module:Class"``
            reference (or a list of them) to load external analyzers for this
            call. Explicitly-loaded analyzers take precedence over discovered
            ones of the same name and are registered by their ``.name`` so they
            can be selected via *spec*.
        **opts: Known passthrough options forwarded to the matching factory
            (e.g. ``include_private_ips`` for ioc, ``protobuf_schema`` for
            protobuf). Unknown options are ignored by the factories.

    Returns:
        A list of analyzer instances implementing :class:`BaseAnalyzer`.

    Raises:
        ValueError: When *spec* names an analyzer that is not registered.
    """
    # Ambient discovery (drop-in dir / entry points / plugin bridge) so that
    # both "all" and explicit names pick up user analyzers with no flags.
    _ensure_discovered()

    # Explicit path(s) override discovery for this call.
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
