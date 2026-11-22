"""Parser registry for protocol detection and parser selection.

Built-in parsers come from a hardcoded spec list. External parsers are discovered
like analyzers (:mod:`friTap.analysis.discovery`): a drop-in directory plus a
setuptools entry-points group. A parser opts in with ``is_fritap_parser = True``
and may set ``PRIORITY`` (default 50). ``FRITAP_DISABLE_PARSER_DISCOVERY=1``
restores built-ins only.

Security: loading a ``.py`` file or entry point executes that code at import,
like the analyzer/plugin loaders.
"""

import importlib
import inspect
import logging
import threading
from dataclasses import dataclass, replace
from pathlib import Path

from ..discovery_base import (
    discovery_disabled, get_entry_points, iter_dropin_modules, resolve_dropin_dir,
)
from .base import BaseParser
from .hexdump import HexdumpParser

logger = logging.getLogger(__name__)

PARSER_ENTRY_POINT_GROUP = "fritap.parsers"
_DISABLE_ENV = "FRITAP_DISABLE_PARSER_DISCOVERY"
_DEFAULT_DISCOVERED_PRIORITY = 50

# Built-in transport pins to parsers outside this package, as
# ``transport -> "module:Class"``. Each is imported on the first lookup of its
# transport, so building the registry never loads the offline stack.
_BUILTIN_LAZY_PINS: dict[str, str] = {
    "telegram_e2e": "friTap.offline.mtproto.tl_parser:TelegramE2EParser",
    "mtproto": "friTap.offline.mtproto.tl_parser:MtprotoParser",
}


@dataclass(frozen=True)
class _TransportRule:
    """How the parser for one ``Flow.transport`` is chosen.

    ``pinned`` always handles the transport (no sniffing); ``allowed``, when set, is
    the only set sniffed (plus classes naming the transport in ``TRANSPORTS``).
    """

    pinned: "type[BaseParser] | None" = None
    allowed: "frozenset[type] | None" = None


_NO_RULE = _TransportRule()


class ParserRegistry:
    """Parsers tried in descending priority; the first ``can_parse()`` match wins, HexdumpParser is the fallback."""

    def __init__(self) -> None:
        self._parsers: list[tuple[int, type[BaseParser]]] = []
        # transport name (Flow.transport) -> its parser-selection rule
        self._rules: dict[str, _TransportRule] = {}
        # transport name -> "module:Class" pinned on first lookup
        self._lazy_pins: dict[str, str] = {}
        # serialises lazy-pin resolution (the default registry is process-global)
        self._lazy_pin_lock = threading.Lock()

    def _rule(self, transport: str | None) -> _TransportRule:
        if not transport:
            return _NO_RULE
        if transport in self._lazy_pins:
            self._resolve_lazy_pin(transport)
        return self._rules.get(transport, _NO_RULE)

    def pin_transport_lazy(self, transport: str, target: str) -> None:
        """Pin *transport* to ``"module:Class"``, imported on first lookup; on import failure the first lookup raises and later ones sniff."""
        self._lazy_pins[transport] = target

    def _resolve_lazy_pin(self, transport: str) -> None:
        """Import *transport*'s lazy pin once, even under concurrent first lookups.

        The pinned rule is stored before the lazy entry is dropped, so a thread seeing no
        lazy entry also sees the pin. The entry is dropped on import failure too.
        """
        with self._lazy_pin_lock:
            target = self._lazy_pins.get(transport)
            if target is None:
                return  # another thread resolved it while we waited
            try:
                module_path, _, cls_name = target.partition(":")
                parser_cls = getattr(importlib.import_module(module_path), cls_name)
                self._set_pinned(transport, parser_cls)
            finally:
                self._lazy_pins.pop(transport, None)

    def register(self, parser_cls: type[BaseParser], priority: int = 50) -> None:
        """Register *parser_cls* with *priority* (higher is tried first, default 50)."""
        self._parsers.append((priority, parser_cls))
        self._parsers.sort(key=lambda p: p[0], reverse=True)

    def pin_transport(self, transport: str, parser_cls: type[BaseParser]) -> None:
        """Always use *parser_cls* for flows of *transport*, bypassing sniffing.

        Decrypted TL payloads (MTProto, Secret Chats) are not self-identifying; e.g. a
        length prefix ``00 00 00 1a`` would parse as leading WebSocket CONTINUATION frames.
        """
        self._lazy_pins.pop(transport, None)  # an explicit pin replaces a lazy one
        self._set_pinned(transport, parser_cls)

    def _set_pinned(self, transport: str, parser_cls: type[BaseParser]) -> None:
        self._rules[transport] = replace(
            self._rules.get(transport, _NO_RULE), pinned=parser_cls,
        )

    def pinned_parser_for(self, transport: str | None) -> type[BaseParser] | None:
        """Return the parser class pinned to *transport*, or None."""
        return self._rule(transport).pinned

    def restrict_transport(self, transport: str, allowed) -> None:
        """Only sniff *allowed* parser classes for *transport*; Hexdump stays the fallback.

        QUIC streams are HTTP/3 or QUIC-native, so TCP parsers would mislabel control
        streams as HTTP/2 or WebSocket. A class may opt in with ``TRANSPORTS = ("quic", ...)``.
        """
        self._rules[transport] = replace(self._rule(transport), allowed=frozenset(allowed))

    def _candidates_for(self, transport: str | None) -> list[type[BaseParser]]:
        """Parser classes, in priority order, that may sniff *transport*."""
        allowed = self._rule(transport).allowed
        if allowed is None:
            return [parser_cls for _priority, parser_cls in self._parsers]
        return [
            parser_cls for _priority, parser_cls in self._parsers
            if parser_cls in allowed
            or transport in getattr(parser_cls, "TRANSPORTS", ())
        ]

    def detect(self, data: bytes, transport: str | None = None) -> BaseParser:
        """Return a parser instance for *data*.

        A parser pinned to *transport* wins; otherwise candidates are tried by priority
        (restricted transports sniff only their allowed set), falling back to Hexdump.
        ``transport=None`` is pure byte-sniffing.
        """
        pinned_cls = self.pinned_parser_for(transport)
        if pinned_cls is not None:
            return pinned_cls()
        for parser_cls in self._candidates_for(transport):
            try:
                parser = parser_cls()
                if parser.can_parse(data):
                    return parser
            except Exception:
                logger.warning(
                    "Parser %s.can_parse() raised; skipping",
                    parser_cls.__name__,
                    exc_info=logger.isEnabledFor(logging.DEBUG),
                )
        return HexdumpParser()


def _discovery_disabled() -> bool:
    """True when ambient parser discovery is opted out via the environment."""
    return discovery_disabled(_DISABLE_ENV)


def _resolve_parser_dir() -> Path:
    """The drop-in parsers directory (platform-native + legacy fallback); never created."""
    return resolve_dropin_dir("parsers", logger, create=False)


def _is_concrete_parser_class(obj: object) -> bool:
    """True if *obj* is a concrete ``BaseParser`` subclass (not the base itself)."""
    return inspect.isclass(obj) and issubclass(obj, BaseParser) and obj is not BaseParser


def _is_discoverable_parser(obj: object, mod) -> bool:
    """A class defined in *mod*, subclassing BaseParser, with the ``is_fritap_parser`` marker.

    Drop-in files are user-authored, so both the opt-in and module ownership (skipping
    imported subclasses) are required; entry points are curated and skip both.
    """
    return (
        _is_concrete_parser_class(obj)
        and getattr(obj, "is_fritap_parser", False) is True
        and getattr(obj, "__module__", None) == getattr(mod, "__name__", None)
    )


def _get_parser_entry_points() -> list:
    return get_entry_points(PARSER_ENTRY_POINT_GROUP)


def discover_external_parsers() -> list[tuple[type[BaseParser], int]]:
    """Discover ``(parser_cls, priority)`` from the drop-in dir and entry points; empty when disabled, one bad source never aborts the rest."""
    if _discovery_disabled():
        return []

    found: dict[str, tuple[type[BaseParser], int]] = {}

    def _add(cls: type) -> None:
        priority = int(getattr(cls, "PRIORITY", _DEFAULT_DISCOVERED_PRIORITY))
        found[f"{cls.__module__}.{cls.__qualname__}"] = (cls, priority)

    # 1) drop-in directory
    try:
        for _path, mod in iter_dropin_modules(
            _resolve_parser_dir(), "fritap_parser_", logger, label="parser",
        ):
            for attr in dir(mod):
                obj = getattr(mod, attr)
                if _is_discoverable_parser(obj, mod):
                    _add(obj)
    except Exception as e:  # noqa: BLE001
        logger.error("Parser directory discovery failed: %s", e)

    # 2) entry points
    try:
        for ep in _get_parser_entry_points():
            try:
                obj = ep.load()
            except Exception as e:  # noqa: BLE001
                logger.error("Failed to load parser entry point %s: %s", ep.name, e)
                continue
            if _is_concrete_parser_class(obj):
                _add(obj)
    except Exception as e:  # noqa: BLE001
        logger.error("Parser entry-point discovery failed: %s", e)

    return list(found.values())


_default_registry: ParserRegistry | None = None


def get_default_registry() -> ParserRegistry:
    """Return the default registry with all built-ins; a missing dependency (h11, h2) logs a warning and skips only that parser."""
    global _default_registry
    if _default_registry is None:
        _default_registry = ParserRegistry()

        _parser_specs: list[tuple[str, str, int]] = [
            (".http1", "Http1Parser", 100),
            (".http2", "Http2Parser", 90),
            (".websocket", "WebSocketParser", 85),
            (".http3", "Http3Parser", 80),
        ]
        builtin_classes: list[type[BaseParser]] = []
        for module_path, cls_name, priority in _parser_specs:
            try:
                mod = importlib.import_module(module_path, package=__package__)
                parser_cls = getattr(mod, cls_name)
                _default_registry.register(parser_cls, priority=priority)
                builtin_classes.append(parser_cls)
            except (ImportError, AttributeError) as exc:
                logger.warning(
                    "Parser %s unavailable (missing dependency): %s",
                    cls_name, exc,
                )
                if cls_name == "Http3Parser":
                    logger.warning("HTTP/3 parser unavailable; QUIC not restricted: %s", exc)

        # External parsers (drop-in dir + fritap.parsers entry points), e.g. a
        # user's Telegram/MTProto TL parser. Registered before the Hexdump
        # fallback; their own PRIORITY orders them against the built-ins.
        for parser_cls, priority in discover_external_parsers():
            try:
                _default_registry.register(parser_cls, priority=priority)
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "Discovered parser %s failed to register: %s",
                    getattr(parser_cls, "__name__", parser_cls), exc,
                )

        # HexdumpParser is always available as the guaranteed fallback
        _default_registry.register(HexdumpParser, priority=0)
        for transport, target in _BUILTIN_LAZY_PINS.items():
            _default_registry.pin_transport_lazy(transport, target)
        _apply_declared_transport_rules(_default_registry, builtin_classes)
    return _default_registry


def _apply_declared_transport_rules(registry: ParserRegistry, classes) -> None:
    """Restrict transports per ``EXCLUSIVE_TRANSPORTS`` declared on the built-in classes (see :meth:`ParserRegistry.restrict_transport`)."""
    exclusive: dict[str, set[type[BaseParser]]] = {}
    for parser_cls in classes:
        for transport in getattr(parser_cls, "EXCLUSIVE_TRANSPORTS", ()):
            exclusive.setdefault(transport, set()).add(parser_cls)
    for transport, allowed in exclusive.items():
        registry.restrict_transport(transport, allowed)
