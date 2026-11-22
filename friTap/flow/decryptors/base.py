"""Abstract base for layer decryptors (parent-layer ciphertext -> child-layer plaintext)."""

from __future__ import annotations

from abc import ABC, abstractmethod


class LayerDecryptor(ABC):
    """Abstract decryptor that produces a child layer's plaintext bytes."""

    name: str = "unknown"

    @abstractmethod
    def can_handle(self, parent_layer, flow) -> bool:
        """Return True if this decryptor can decrypt *parent_layer*'s payload."""
        ...

    @abstractmethod
    def feed(self, data: bytes, direction: str) -> bytes:
        """Decrypt *data* for *direction* (``"read"``/``"write"``); may return ``b""``."""
        ...
