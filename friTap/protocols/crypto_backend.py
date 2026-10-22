"""The one ``cryptography`` availability probe — a side-effect-free leaf.

MTProto, Signal and the TLS 1.3 peel all gate on the same optional
``cryptography`` backend. Each keeps its own public name
(:func:`friTap.protocols.mtproto_backend.mtproto_backend_available`,
:func:`friTap.offline.tls.backend.backend_available`, ...) as an alias of
:func:`cryptography_ciphers_available`.
"""

from __future__ import annotations


def cryptography_ciphers_available() -> bool:
    """Return True if the optional ``cryptography`` cipher backend is importable.

    Probes the block-cipher primitives (MTProto/Signal floor) plus the AEAD and
    HKDF modules (TLS 1.3 peel), so a True answer satisfies every caller. Never
    raises and imports lazily, so importing this module costs nothing.
    """
    try:
        import cryptography.hazmat.primitives.ciphers.aead  # noqa: F401
        import cryptography.hazmat.primitives.kdf.hkdf  # noqa: F401
        from cryptography.hazmat.primitives.ciphers import (  # type: ignore  # noqa: F401
            Cipher,
            algorithms,
            modes,
        )

        return True
    except Exception:  # noqa: BLE001 - any import/probe failure means "unavailable"
        return False


__all__ = ["cryptography_ciphers_available"]
