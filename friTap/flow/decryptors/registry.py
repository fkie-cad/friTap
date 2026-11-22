"""Priority-ordered registry of layer decryptors.

The default registry is empty (a live extension seam). :meth:`DecryptorRegistry.resolve` returns
the highest-priority decryptor whose ``can_handle`` accepts the parent layer; there is no fallback
(an unhandled layer resolves to ``None``).
"""

from __future__ import annotations

import logging

from friTap.flow.decryptors.base import LayerDecryptor

logger = logging.getLogger(__name__)


class DecryptorRegistry:
    """Holds decryptor classes ordered by descending priority."""

    def __init__(self) -> None:
        # (priority, decryptor_cls), sorted by priority descending.
        self._entries: list[tuple[int, type]] = []

    def register(self, cls: type, priority: int = 50) -> None:
        """Register decryptor *cls* with *priority* (higher resolves first)."""
        self._entries.append((priority, cls))
        self._entries.sort(key=lambda entry: entry[0], reverse=True)

    def resolve(self, parent_layer, flow):
        """First decryptor whose ``can_handle`` accepts the layer, else ``None``; each candidate is probed in try/except so a misbehaving one only logs a warning."""
        for _priority, cls in self._entries:
            try:
                decryptor = cls()
                if decryptor.can_handle(parent_layer, flow):
                    return decryptor
            except Exception:
                logger.warning(
                    "Decryptor %s raised during resolve; skipping",
                    getattr(cls, "__name__", cls),
                    exc_info=True,
                )
        return None


_DEFAULT_DECRYPTOR_REGISTRY = DecryptorRegistry()


def get_default_decryptor_registry() -> DecryptorRegistry:
    """Return the process-global, intentionally empty decryptor registry."""
    return _DEFAULT_DECRYPTOR_REGISTRY


__all__ = [
    "LayerDecryptor",
    "DecryptorRegistry",
    "get_default_decryptor_registry",
]
