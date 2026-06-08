"""Layer-decryptor seam for the protocol-layer-stack feature.

Re-exports the decryptor abstractions for convenience. The default decryptor
registry is intentionally empty: it is a live-but-empty extension seam.
"""

from friTap.flow.decryptors.base import LayerDecryptor
from friTap.flow.decryptors.registry import (
    DecryptorRegistry,
    get_default_decryptor_registry,
)

__all__ = [
    "LayerDecryptor",
    "DecryptorRegistry",
    "get_default_decryptor_registry",
]
