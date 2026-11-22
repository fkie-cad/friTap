#!/usr/bin/env python3

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
        """Absolute path to the hook script for a protocol+backend, or ``None``."""
        # Agent directories are siblings of the friTap package at project root
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        agent_dir = os.path.join(base_dir, f"agent_{backend_name}")
        script_path = os.path.join(agent_dir, protocol, f"{protocol}_key_extract.py")
        if os.path.isfile(script_path):
            return script_path
        return None

    def get_processor(self, protocol: str) -> Optional[Any]:
        """Return the key processor class for a protocol, or ``None``."""
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
        """Return ``{protocol_name: {backend_name: support_level}}``."""
        matrix = {}
        for name, handler in self._handlers.items():
            matrix[name] = dict(handler.supported_backends)
        return matrix


# Companion protocols pulled in when a protocol is selected (e.g. a TLS-wrapped
# one needs "tls" to strip TLS first). Extensions declare theirs via
# register_protocol_handler(..., implies=[...]).
PROTOCOL_IMPLIES: dict[str, list[str]] = {}

# Handler factory tables (zero-arg callables returning a fresh ProtocolHandler).
# Extensions self-register via register_protocol_handler(); the public core only
# iterates these tables and never names an extension module.
_BUILTIN_HANDLER_FACTORIES: "dict[str, Callable[[], ProtocolHandler]]" = {}
_EXTENSION_HANDLER_FACTORIES: "dict[str, Callable[[], ProtocolHandler]]" = {}
_EXTENSIONS_DISCOVERED = False


def register_protocol_handler(name, factory, implies=None) -> None:
    """Register an extension handler. *factory* returns a fresh handler; *implies* lists companions."""
    _EXTENSION_HANDLER_FACTORIES[name] = factory
    if implies:
        PROTOCOL_IMPLIES[name] = list(implies)


def _register_builtin_handler_factories() -> None:
    """Populate the built-in factory table (deferred imports avoid cycles). Idempotent.

    A new built-in must also be added to the protocol allowlist in
    ``scripts/check_public_denylist.sh`` (pinned by
    ``tests/unit/test_public_leak_guard_protocols.py``)."""
    if _BUILTIN_HANDLER_FACTORIES:
        return
    from .ipsec_handler import IPSecHandler
    from .mtproto_handler import MTProtoHandler
    from .ssh_handler import SSHHandler
    from .telegram_handler import TelegramHandler
    from .tls_handler import TLSHandler
    _BUILTIN_HANDLER_FACTORIES.update({
        "tls": TLSHandler,
        "ipsec": IPSecHandler,
        "ssh": SSHHandler,
        "mtproto": MTProtoHandler,
        "telegram": TelegramHandler,
    })


def _discover_protocol_extensions() -> None:
    """Import modules under ``protocols/_ext/`` so they self-register. Idempotent.

    A broken or absent extension is logged and skipped, never fatal.
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
    """Built-in + extension factories; an extension never overrides a built-in."""
    _register_builtin_handler_factories()
    _discover_protocol_extensions()
    factories = dict(_BUILTIN_HANDLER_FACTORIES)
    for name, factory in _EXTENSION_HANDLER_FACTORIES.items():
        factories.setdefault(name, factory)
    return factories


def available_protocol_names() -> List[str]:
    """Sorted protocol names in this build, excluding the meta values ``all``/``auto``."""
    return sorted(_all_handler_factories().keys())


# Meta token selecting every custom cipher, e.g. `--protocol custom` -> rc4.
CUSTOM_GROUP = "custom"


def _is_custom_cipher(handler) -> bool:
    """True if *handler* is a custom cipher (duck-typed handlers may lack ``category``)."""
    return getattr(handler, "category", "protocol") == "custom_cipher"


def custom_cipher_handlers(include_upcoming: bool = False) -> List[ProtocolHandler]:
    """Fresh custom-cipher handlers sorted by name; one instantiation per factory.

    Upcoming ciphers are excluded unless *include_upcoming*; an explicit
    ``--protocol <name>`` still selects them."""
    handlers = (factory() for factory in _all_handler_factories().values())
    return sorted(
        (
            handler for handler in handlers
            if _is_custom_cipher(handler)
            and (include_upcoming or not getattr(handler, "upcoming", False))
        ),
        key=lambda handler: handler.name,
    )


def custom_cipher_names(include_upcoming: bool = False) -> List[str]:
    """Sorted names of the available custom-cipher handlers (see
    :func:`custom_cipher_handlers` for *include_upcoming*)."""
    return [handler.name for handler in custom_cipher_handlers(include_upcoming)]


def expand_custom_group(tokens, cipher_names: Optional[List[str]] = None) -> List[str]:
    """Replace each ``custom`` token in place with *cipher_names* (default:
    :func:`custom_cipher_names`, computed once), preserving order and
    dropping duplicates."""
    if cipher_names is None and CUSTOM_GROUP in tokens:
        cipher_names = custom_cipher_names()
    expanded: List[str] = []
    for token in tokens:
        expanded.extend(cipher_names if token == CUSTOM_GROUP else [token])
    return list(dict.fromkeys(expanded))


def order_protocol_selection(tokens, cipher_names: Optional[List[str]] = None) -> List[str]:
    """Order a protocol selection: non-custom protocols first, then custom
    ciphers, each keeping its relative order, with duplicates dropped.

    Keeps ``protocols[0]`` the primary (non-custom) protocol whenever one is
    selected. *cipher_names* defaults to every custom cipher (including
    upcoming ones, which may be selected explicitly by name).
    """
    unique = list(dict.fromkeys(tokens))
    if cipher_names is None:
        cipher_names = custom_cipher_names(include_upcoming=True)
    custom_ciphers = set(cipher_names)
    main_protocols = [t for t in unique if t not in custom_ciphers]
    return main_protocols + [t for t in unique if t in custom_ciphers]


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
    """Create a registry for *protocols* (``None`` = every available handler)."""
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

    selected = expand_protocols(selected)

    # Built-ins first (TLS first: it is the auto_detect fallback), then extensions by name.
    registry = ProtocolRegistry()
    order = list(_BUILTIN_HANDLER_FACTORIES.keys()) + sorted(_EXTENSION_HANDLER_FACTORIES.keys())
    for name in order:
        if name in selected:
            factory = factories.get(name)
            if factory is not None:
                registry.register(factory())
    return registry
