"""Parser registry for protocol detection and parser selection."""

import importlib
import logging

from .base import BaseParser
from .hexdump import HexdumpParser

logger = logging.getLogger(__name__)


class ParserRegistry:
    """Registry of protocol parsers, tried in priority order (highest first).

    When detecting a protocol, each registered parser's can_parse() is
    called in descending priority order. The first match wins. If none
    match, HexdumpParser is returned as the fallback.
    """

    def __init__(self) -> None:
        self._parsers: list[tuple[int, type[BaseParser]]] = []

    def register(self, parser_cls: type[BaseParser], priority: int = 50) -> None:
        """Register a parser class for protocol detection.

        Args:
            parser_cls: The parser class to register.
            priority: Detection priority (higher = tried first). Default 50.
        """
        self._parsers.append((priority, parser_cls))
        self._parsers.sort(key=lambda p: p[0], reverse=True)

    def detect(self, data: bytes) -> BaseParser:
        """Try each parser's can_parse() in descending priority, return first match or HexdumpParser."""
        for _priority, parser_cls in self._parsers:
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

        # HexdumpParser is always available as the guaranteed fallback
        _default_registry.register(HexdumpParser, priority=0)
    return _default_registry
