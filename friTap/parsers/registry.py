"""Parser registry for protocol detection and parser selection.

Built-in parsers are registered from a hardcoded spec list. External parsers
(e.g. a user's Telegram/MTProto TL parser) are discovered the same way analyzers
are (:mod:`friTap.analysis.discovery`): a drop-in directory plus a setuptools
entry-points group. A discovered parser opts in with ``is_fritap_parser = True``
and may set a ``PRIORITY`` class attribute (default 50). Set
``FRITAP_DISABLE_PARSER_DISCOVERY=1`` to restore built-ins-only behaviour.

Security note: loading a ``.py`` file or an entry point *executes that code* at
import time, exactly like the analyzer/plugin loaders.
"""

import importlib
import importlib.metadata
import importlib.util
import inspect
import logging
import os
from dataclasses import dataclass, replace
from pathlib import Path

from .base import BaseParser
from .hexdump import HexdumpParser

logger = logging.getLogger(__name__)

PARSER_ENTRY_POINT_GROUP = "fritap.parsers"
_DISABLE_ENV = "FRITAP_DISABLE_PARSER_DISCOVERY"
_DEFAULT_DISCOVERED_PRIORITY = 50


@dataclass(frozen=True)
class _TransportRule:
    """How the parser for one transport (``Flow.transport``) is chosen.

    ``pinned`` - a parser class that always handles the transport, no sniffing.
    ``allowed`` - when set, the only parser classes sniffed for it (plus any
    class opting in via a ``TRANSPORTS`` attribute naming the transport).
    """

    pinned: "type[BaseParser] | None" = None
    allowed: "frozenset[type] | None" = None


_NO_RULE = _TransportRule()


class ParserRegistry:
    """Registry of protocol parsers, tried in priority order (highest first).

    When detecting a protocol, each registered parser's can_parse() is
    called in descending priority order. The first match wins. If none
    match, HexdumpParser is returned as the fallback.
    """

    def __init__(self) -> None:
        self._parsers: list[tuple[int, type[BaseParser]]] = []
        # transport name (Flow.transport) -> its parser-selection rule
        self._rules: dict[str, _TransportRule] = {}

    def _rule(self, transport: str | None) -> _TransportRule:
        """The selection rule for *transport* (the no-op rule when none/unset)."""
        return self._rules.get(transport, _NO_RULE) if transport else _NO_RULE

    def register(self, parser_cls: type[BaseParser], priority: int = 50) -> None:
        """Register a parser class for protocol detection.

        Args:
            parser_cls: The parser class to register.
            priority: Detection priority (higher = tried first). Default 50.
        """
        self._parsers.append((priority, parser_cls))
        self._parsers.sort(key=lambda p: p[0], reverse=True)

    def pin_transport(self, transport: str, parser_cls: type[BaseParser]) -> None:
        """Always use *parser_cls* for flows whose transport is *transport*.

        Pinned parsers bypass byte sniffing entirely: decrypted TL payloads
        (MTProto, Telegram Secret Chats) are not self-identifying and would
        otherwise be mis-detected (e.g. as WebSocket: a 4-byte big-endian
        length prefix like ``00 00 00 1a`` parses as leading CONTINUATION
        frames).
        """
        self._rules[transport] = replace(self._rule(transport), pinned=parser_cls)

    def pinned_parser_for(self, transport: str | None) -> type[BaseParser] | None:
        """Return the parser class pinned to *transport*, or None."""
        return self._rule(transport).pinned

    def restrict_transport(self, transport: str, allowed) -> None:
        """Only sniff the parser classes in *allowed* for *transport*.

        QUIC stream bytes are HTTP/3 (or a QUIC-native protocol) by
        construction; letting the TCP parsers sniff them mislabels control
        streams as HTTP/2 or WebSocket. A parser class may additionally opt
        in with ``TRANSPORTS = ("quic", ...)``. Hexdump stays the fallback.
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

        A parser pinned to *transport* wins outright; otherwise each candidate
        parser's can_parse() is tried in descending priority, falling back to
        HexdumpParser. A restricted transport only sniffs its allowed parsers.
        ``transport=None`` keeps the pure byte-sniffing behaviour.
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
    return os.environ.get(_DISABLE_ENV, "").strip() not in ("", "0", "false", "False")


def _resolve_parser_dir() -> Path:
    """Resolve the drop-in parsers directory (platform-native + legacy fallback)."""
    import platformdirs

    native_dir = Path(platformdirs.user_data_dir("friTap")) / "parsers"
    legacy_dir = Path.home() / ".fritap" / "parsers"
    if legacy_dir.exists() and not native_dir.exists():
        return legacy_dir
    return native_dir


def _is_concrete_parser_class(obj: object) -> bool:
    """True if *obj* is a concrete ``BaseParser`` subclass (not the base itself)."""
    return inspect.isclass(obj) and issubclass(obj, BaseParser) and obj is not BaseParser


def _is_discoverable_parser(obj: object, mod) -> bool:
    """A class defined in *mod*, subclassing BaseParser, opting in via the marker.

    Drop-in files are user-authored, so we require an explicit ``is_fritap_parser``
    opt-in AND module ownership (to skip BaseParser subclasses merely imported into
    the file). Entry points are curated by packaging and skip both checks.
    """
    return (
        _is_concrete_parser_class(obj)
        and getattr(obj, "is_fritap_parser", False) is True
        and getattr(obj, "__module__", None) == getattr(mod, "__name__", None)
    )


def _get_parser_entry_points() -> list:
    eps = importlib.metadata.entry_points()
    if hasattr(eps, "select"):
        return list(eps.select(group=PARSER_ENTRY_POINT_GROUP))
    return list(eps.get(PARSER_ENTRY_POINT_GROUP, []))


def discover_external_parsers() -> list[tuple[type[BaseParser], int]]:
    """Discover external parser classes from the drop-in dir + entry points.

    Returns a list of ``(parser_cls, priority)``. Empty when discovery is
    disabled. One bad source never aborts the others.
    """
    if _discovery_disabled():
        return []

    found: dict[str, tuple[type[BaseParser], int]] = {}

    def _add(cls: type) -> None:
        priority = int(getattr(cls, "PRIORITY", _DEFAULT_DISCOVERED_PRIORITY))
        found[f"{cls.__module__}.{cls.__qualname__}"] = (cls, priority)

    # 1) drop-in directory
    try:
        parser_dir = _resolve_parser_dir()
        if parser_dir.exists():
            for item in sorted(parser_dir.iterdir()):
                if item.suffix != ".py" or item.name.startswith("_"):
                    continue
                try:
                    spec = importlib.util.spec_from_file_location(
                        f"fritap_parser_{item.stem}", item
                    )
                    if not spec or not spec.loader:
                        continue
                    mod = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(mod)
                except Exception as e:  # noqa: BLE001
                    logger.error("Failed to load parser file %s: %s", item, e)
                    continue
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


# Global default registry (lazily initialized)
_default_registry: ParserRegistry | None = None


def get_default_registry() -> ParserRegistry:
    """Return the default registry with all built-in parsers registered.

    Individual parser imports are handled gracefully — a missing dependency
    (e.g. h11, h2) logs a warning but does not prevent other parsers from
    being registered.
    """
    global _default_registry
    if _default_registry is None:
        _default_registry = ParserRegistry()

        _parser_specs: list[tuple[str, str, int]] = [
            (".http1", "Http1Parser", 100),
            (".http2", "Http2Parser", 90),
            (".websocket", "WebSocketParser", 85),
            (".http3", "Http3Parser", 80),
        ]
        for module_path, cls_name, priority in _parser_specs:
            try:
                mod = importlib.import_module(module_path, package=__package__)
                parser_cls = getattr(mod, cls_name)
                _default_registry.register(parser_cls, priority=priority)
            except (ImportError, AttributeError) as exc:
                logger.warning(
                    "Parser %s unavailable (missing dependency): %s",
                    cls_name, exc,
                )

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
        _pin_telegram_transports(_default_registry)
        _restrict_quic_transport(_default_registry)
    return _default_registry


def _pin_telegram_transports(registry: ParserRegistry) -> None:
    """Pin the decrypted-TL transports to their Telegram parsers."""
    from .telegram_tl import MtprotoParser, TelegramE2EParser

    registry.pin_transport("telegram_e2e", TelegramE2EParser)
    registry.pin_transport("mtproto", MtprotoParser)


def _restrict_quic_transport(registry: ParserRegistry) -> None:
    """Sniff QUIC stream bytes only with the HTTP/3 parser (Hexdump fallback)."""
    try:
        from .http3 import Http3Parser
    except ImportError as exc:
        logger.warning("HTTP/3 parser unavailable; QUIC not restricted: %s", exc)
        return
    registry.restrict_transport("quic", {Http3Parser})
