#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Protocol handler registry."""

from __future__ import annotations
import importlib
import logging
import os
from typing import Any, Callable, Dict, List, Optional

from .base import ProtocolHandler


class ProtocolRegistry:
    """Registry of all available protocol handlers."""

    _PROCESSOR_MAP: dict[str, str] = {
        "ssh": "SSHKeyProcessor",
    #    "ipsec": "IPSecKeyProcessor",
        "tls": "TLSKeyProcessor",
    }

    _MODULE_MAP: dict[str, str] = {
        "ssh": ".ssh_extractor",
    #    "ipsec": ".ipsec_extractor",
        "tls": ".tls_extractor",
    }

    def __init__(self) -> None:
        self._handlers: Dict[str, ProtocolHandler] = {}
        self._logger = logging.getLogger("friTap.protocols")

    def register(self, handler: ProtocolHandler) -> None:
        self._handlers[handler.name] = handler
        self._logger.debug("Registered protocol handler: %s", handler.name)

    def get(self, protocol: str) -> Optional[ProtocolHandler]:
        return self._handlers.get(protocol)

    def get_all(self) -> List[ProtocolHandler]:
        return list(self._handlers.values())

    def auto_detect(self, detected_libraries: List[str]) -> List[ProtocolHandler]:
        """Given detected libraries, return matching protocol handlers."""
        matched = [
            handler for handler in self._handlers.values()
            if handler.matches_libraries(detected_libraries)
        ]
        if matched:
            return matched
        fallback = self._handlers.get("tls") or next(iter(self._handlers.values()))
        return [fallback]

    def list_protocols(self) -> List[str]:
        return list(self._handlers.keys())

    def get_agent_script_path(self, protocol: str, backend_name: str) -> Optional[str]:
        """Return the filesystem path to the hook script for a protocol+backend.

        Parameters
        ----------
        protocol
            Protocol name (e.g., 'ssh', 'ipsec', 'tls').
        backend_name
            Backend name (e.g., 'gdb', 'lldb').

        Returns
        -------
        str or None
            Absolute path to the script, or None if not found.
        """
        # Agent directories are siblings of the friTap package at project root
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        agent_dir = os.path.join(base_dir, f"agent_{backend_name}")
        script_path = os.path.join(agent_dir, protocol, f"{protocol}_key_extract.py")
        if os.path.isfile(script_path):
            return script_path
        return None

    def get_processor(self, protocol: str) -> Optional[Any]:
        """Return the key processor class for a protocol.

        Parameters
        ----------
        protocol
            Protocol name (e.g., 'ssh', 'ipsec', 'tls').

        Returns
        -------
        class or None
            The processor class (SSHKeyProcessor, IPSecKeyProcessor, TLSKeyProcessor).
        """
        class_name = self._PROCESSOR_MAP.get(protocol)
        if class_name is None:
            return None
        module_name = self._MODULE_MAP[protocol]
        try:
            mod = importlib.import_module(module_name, package="friTap.protocols")
            return getattr(mod, class_name)
        except (ImportError, AttributeError) as e:
            self._logger.warning("Could not load processor for '%s': %s", protocol, e)
            return None

    def get_compatibility_matrix(self) -> Dict[str, Dict[str, str]]:
        """Return the full protocol x backend support matrix.

        Returns
        -------
        dict
            Nested dict: {protocol_name: {backend_name: support_level}}.
        """
        matrix = {}
        for name, handler in self._handlers.items():
            matrix[name] = dict(handler.supported_backends)
        return matrix


# Companion-protocol expansion: some protocols, when selected, also require
# others (e.g. a TLS-wrapped protocol pulls in "tls" so the SSLKEYLOGFILE is
# captured to strip TLS first). Public built-ins add no implications; extension
# handlers declare theirs via register_protocol_handler(..., implies=[...]).
PROTOCOL_IMPLIES: dict[str, list[str]] = {}

# Handler factory tables (zero-arg callables returning a fresh ProtocolHandler).
# Built-ins are public and always available; extensions (optional/private
# protocols) self-register at runtime via register_protocol_handler() and are
# discovered by _discover_protocol_extensions(). The public core only ever
# iterates these tables — it never imports or names an extension's module.
_BUILTIN_HANDLER_FACTORIES: "dict[str, Callable[[], ProtocolHandler]]" = {}
_EXTENSION_HANDLER_FACTORIES: "dict[str, Callable[[], ProtocolHandler]]" = {}
_EXTENSIONS_DISCOVERED = False


def register_protocol_handler(name, factory, implies=None) -> None:
    """Register an extension protocol handler.

    Lets an optional/private protocol add itself to the registry, the CLI
    ``--protocol`` choices, and companion-protocol expansion WITHOUT the public
    core importing or naming its module. *factory* is a zero-arg callable
    returning a fresh :class:`ProtocolHandler`; *implies* lists companion
    protocol names the handler pulls in.
    """
    _EXTENSION_HANDLER_FACTORIES[name] = factory
    if implies:
        PROTOCOL_IMPLIES[name] = list(implies)


def _register_builtin_handler_factories() -> None:
    """Populate the public built-in factory table (deferred imports keep this
    module's import light and avoid cycles). Idempotent."""
    if _BUILTIN_HANDLER_FACTORIES:
        return
    from .tls_handler import TLSHandler
#    from .ipsec_handler import IPSecHandler # needs to be impl.
    from .ssh_handler import SSHHandler
    from .mtproto_handler import MTProtoHandler
    from .telegram_handler import TelegramHandler
    _BUILTIN_HANDLER_FACTORIES.update({
        "tls": TLSHandler,
#        "ipsec": IPSecHandler,  # needs to be impl.
        "ssh": SSHHandler,
        "mtproto": MTProtoHandler,
        "telegram": TelegramHandler,
    })


def _discover_protocol_extensions() -> None:
    """Import in-tree extension modules under ``protocols/_ext/`` so they
    self-register. Idempotent.

    A filtered build that omits an extension module simply has nothing to import
    here — no public code names it, so any protocol can be dropped from a build
    cleanly. A broken/optional extension is logged and skipped, never fatal.
    """
    global _EXTENSIONS_DISCOVERED
    if _EXTENSIONS_DISCOVERED:
        return
    _EXTENSIONS_DISCOVERED = True
    import pkgutil
    try:
        from . import _ext as _ext_pkg
    except Exception:
        return
    log = logging.getLogger("friTap.protocols")
    for info in pkgutil.iter_modules(_ext_pkg.__path__):
        if info.name.startswith("_"):
            continue
        try:
            importlib.import_module(f"{_ext_pkg.__name__}.{info.name}")
        except Exception as e:  # a broken/optional extension must not break core
            log.debug("skipping protocol extension %r: %s", info.name, e)


def _all_handler_factories() -> "dict[str, Callable[[], ProtocolHandler]]":
    """Return built-in + discovered extension factories (an extension never
    overrides a built-in of the same name)."""
    _register_builtin_handler_factories()
    _discover_protocol_extensions()
    factories = dict(_BUILTIN_HANDLER_FACTORIES)
    for name, factory in _EXTENSION_HANDLER_FACTORIES.items():
        factories.setdefault(name, factory)
    return factories


def available_protocol_names() -> List[str]:
    """Protocol names available in THIS build (built-ins + registered
    extensions), sorted. Excludes the meta values ``all``/``auto``. Drives the
    CLI ``--protocol`` choices so a filtered build advertises only what it ships.
    """
    return sorted(_all_handler_factories().keys())


def implied_protocols(name) -> List[str]:
    """Companion protocols pulled in by *name* (after extension discovery)."""
    _discover_protocol_extensions()
    return list(PROTOCOL_IMPLIES.get(name, []))


def expand_protocols(selected) -> set:
    """Return *selected* plus any companion protocols from PROTOCOL_IMPLIES."""
    _discover_protocol_extensions()
    out = set(selected)
    for proto in list(selected):
        out.update(PROTOCOL_IMPLIES.get(proto, []))
    return out


def create_default_registry(protocols: Optional[List[str]] = None) -> ProtocolRegistry:
    """Create a registry with built-in (and any registered extension) handlers.

    Parameters
    ----------
    protocols
        Names of protocols to register. ``None`` keeps the historical
        behaviour of registering everything available, so the no-arg
        callers (lazy discovery, tests, TUI menu) keep working.
    """
    factories = _all_handler_factories()
    known = set(factories)
    selected = set(protocols) if protocols is not None else known
    if not selected:
        raise ValueError("create_default_registry: at least one protocol required")
    unknown = selected - known
    if unknown:
        raise ValueError(
            f"create_default_registry: unknown protocol(s): {sorted(unknown)}; "
            f"known: {sorted(known)}"
        )

    # Expand companion protocols (e.g. a TLS-wrapped protocol also needs the TLS
    # handler to capture the SSLKEYLOGFILE used to strip TLS before app-layer
    # decryption). See PROTOCOL_IMPLIES / register_protocol_handler(implies=...).
    selected = expand_protocols(selected)

    # Deterministic registration order: built-ins first (TLS first, so it stays
    # the auto_detect fallback), then extensions sorted by name.
    registry = ProtocolRegistry()
    order = list(_BUILTIN_HANDLER_FACTORIES.keys()) + sorted(_EXTENSION_HANDLER_FACTORIES.keys())
    for name in order:
        if name in selected:
            factory = factories.get(name)
            if factory is not None:
                registry.register(factory())
    return registry
