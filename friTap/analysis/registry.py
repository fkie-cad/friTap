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


# Name -> factory. Keys MUST equal each analyzer class's ``.name`` attribute.
ANALYZER_REGISTRY: dict[str, Callable[..., "BaseAnalyzer"]] = {
    "ioc": _make_ioc,
    "credentials": _make_credentials,
    "protobuf": _make_protobuf,
}


def available_analyzers() -> list[str]:
    """Return the sorted list of built-in analyzer names."""
    return sorted(ANALYZER_REGISTRY)


def _build(name: str, **opts) -> "BaseAnalyzer":
    """Instantiate a registered analyzer by name, raising on unknown names."""
    factory = ANALYZER_REGISTRY.get(name)
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
    analyzer_path: str | None = None,
    **opts,
) -> list["BaseAnalyzer"]:
    """Resolve an analyzer *spec* into a list of analyzer instances.

    Args:
        spec: ``None``, ``"all"`` or ``""`` selects every built-in analyzer.
            Otherwise a comma-separated list of analyzer names (matching each
            analyzer's ``.name``).
        analyzer_path: Optional ``"module"`` or ``"module:Class"`` reference to
            load an external analyzer. External analyzers are registered by
            their ``.name`` and can then be selected via *spec*.
        **opts: Known passthrough options forwarded to the matching factory
            (e.g. ``include_private_ips`` for ioc, ``protobuf_schema`` for
            protobuf). Unknown options are ignored by the factories.

    Returns:
        A list of analyzer instances implementing :class:`BaseAnalyzer`.

    Raises:
        ValueError: When *spec* names an analyzer that is not registered.
    """
    external = _load_external_analyzers(analyzer_path) if analyzer_path else {}

    select_all = spec is None or spec in ("all", "")
    if select_all:
        names = available_analyzers() + [n for n in external if n not in ANALYZER_REGISTRY]
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
]
