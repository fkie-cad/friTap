"""Abstract base for layer decryptors.

A layer decryptor turns the ciphertext bytes of a parent layer into the
plaintext bytes of a child layer (e.g. decrypting a record-layer payload).
Concrete implementations are registered with a
:class:`~friTap.flow.decryptors.registry.DecryptorRegistry`.
"""

from __future__ import annotations

from abc import ABC, abstractmethod


class LayerDecryptor(ABC):
    """Abstract decryptor that produces a child layer's plaintext bytes."""

    name: str = "unknown"

    @abstractmethod
    def can_handle(self, parent_layer, flow) -> bool:
        """Return True if this decryptor can decrypt *parent_layer*'s payload.

        Args:
            parent_layer: The :class:`ProtocolLayer` whose payload feeds this
                decryptor.
            flow: The owning flow-like object.
        """
        ...

    @abstractmethod
    def feed(self, data: bytes, direction: str) -> bytes:
        """Decrypt *data* for *direction* (``"read"`` or ``"write"``).

        Returns the resulting plaintext bytes (possibly ``b""``).
        """
        ...
